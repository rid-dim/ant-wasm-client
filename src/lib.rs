//! Browser WASM client for the Autonomi WebRTC-Direct lane (ADR-0010),
//! no-relay architecture.
//!
//! Connects an ordinary web page directly to the Autonomi network — no
//! signaling server, no CA certificate, no installation. A bootstrap
//! connection solves initial contact only; the client then asks it which
//! peers are closest to an address and opens its *own* WebRTC connections to
//! those nodes, fetching and storing directly against the responsible peers
//! exactly like the native client. Load spreads across the network.
//!
//! All security properties live here: every node's DTLS certificate is
//! pinned by fingerprint, its identity is verified post-quantum (ML-DSA-65 +
//! PeerId pinning) inside the mandatory PQC tunnel (ML-KEM-768 +
//! ChaCha20-Poly1305), and every chunk is verified against its BLAKE3
//! content address before use.
//!
//! ```js
//! const client = await WasmClient.connect(bootIp, bootPort, bootCertHash, bootPeerId);
//! const bytes  = await client.download(addressHex);   // verified + decrypted
//! ```

mod conn;
mod discovery;
mod evm;
mod framing;
pub mod payment;
mod protocol;
mod retrieval;
mod sdp;
mod tunnel;
mod webrtc;

use conn::NodeConnection;
use discovery::PeerConnectInfo;
use protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteResponse,
};
use retrieval::Retrieval;
use self_encryption::bytes::Bytes;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// Close-group size — a single-node payment needs exactly this many quotes.
const CLOSE_GROUP_SIZE: usize = 7;
/// A quorum of the close group (`CLOSE_GROUP_SIZE / 2 + 1`).
const CLOSE_GROUP_MAJORITY: usize = 4;
/// The data-type tag for a plain chunk (`DATA_TYPE_CHUNK`).
const DATA_TYPE_CHUNK: u32 = 0;
/// Connect+quote attempts per close-group peer before failing the store
/// (WebRTC handshakes are occasionally flaky).
const QUOTE_ATTEMPTS: usize = 3;

/// A connected client: one bootstrap session plus a pool of direct
/// connections to the peers discovery hands out.
#[wasm_bindgen]
pub struct WasmClient {
    bootstrap: Rc<NodeConnection>,
    /// Direct connections keyed by peer id, opened on demand.
    pool: RefCell<HashMap<[u8; 32], Rc<NodeConnection>>>,
}

#[wasm_bindgen]
impl WasmClient {
    /// Connect to a bootstrap node and establish the authenticated PQC
    /// tunnel.
    ///
    /// * `ip`, `port` — the bootstrap node's WebRTC listener address.
    /// * `cert_hash_hex` — SHA-256 fingerprint of its DTLS certificate.
    /// * `peer_id_hex` — expected identity (`BLAKE3` of its ML-DSA-65 public
    ///   key); empty string skips pinning (discouraged).
    pub async fn connect(
        ip: String,
        port: u16,
        cert_hash_hex: String,
        peer_id_hex: String,
    ) -> Result<WasmClient, JsValue> {
        let expected = parse_opt_peer_id(&peer_id_hex).map_err(js_err)?;
        let bootstrap = NodeConnection::connect(&ip, port, &cert_hash_hex, expected.as_ref())
            .await
            .map_err(js_err)?;
        let bootstrap = Rc::new(bootstrap);
        let mut pool = HashMap::new();
        pool.insert(bootstrap.peer_id(), Rc::clone(&bootstrap));
        Ok(WasmClient {
            bootstrap,
            pool: RefCell::new(pool),
        })
    }

    /// The bootstrap node's `PeerId` (hex).
    #[wasm_bindgen(getter)]
    pub fn peer_id(&self) -> String {
        hex::encode(self.bootstrap.peer_id())
    }

    /// Number of open node connections (bootstrap + direct peers).
    #[wasm_bindgen(getter)]
    pub fn connection_count(&self) -> usize {
        self.pool.borrow().len()
    }

    /// Download, verify, and decrypt a public file by its data-map address
    /// (64 hex chars), fetching each chunk directly from a responsible peer.
    pub async fn download(&self, address_hex: String) -> Result<Vec<u8>, JsValue> {
        let address = parse_address(&address_hex).map_err(js_err)?;

        let map_bytes = self.get_direct(address).await.map_err(js_err)?;
        let mut retrieval = Retrieval::begin(address, &map_bytes).map_err(js_err)?;

        while !retrieval.is_complete() {
            let addrs = retrieval.required_addresses();
            // Fetch this round's chunks concurrently: each goes to its own
            // responsible peer over its own connection, and the per-connection
            // lock keeps any two that share a peer from racing.
            let fetched =
                futures::future::join_all(addrs.iter().map(|a| self.get_direct(*a))).await;
            for (addr, result) in addrs.iter().zip(fetched) {
                let bytes = result.map_err(js_err)?;
                retrieval.supply(*addr, &bytes).map_err(js_err)?;
            }
            retrieval.advance().map_err(js_err)?;
        }
        retrieval.finish().map_err(js_err)
    }

    /// Fetch one raw chunk by address (64 hex), directly from a responsible
    /// peer, verified against its address.
    pub async fn fetch_chunk(&self, address_hex: String) -> Result<Vec<u8>, JsValue> {
        let address = parse_address(&address_hex).map_err(js_err)?;
        self.get_direct(address).await.map_err(js_err)
    }

    /// Fetch a chunk from the peers responsible for its address: discover
    /// the close group via the bootstrap connection, then try each peer over
    /// its own direct connection.
    async fn get_direct(&self, address: [u8; 32]) -> Result<Vec<u8>, String> {
        let peers = self.bootstrap.closest_peers(address).await?;
        if peers.is_empty() {
            return Err("discovery returned no peers".into());
        }
        let mut last_err = String::new();
        for peer in &peers {
            let conn = match self.connection_for(peer).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            match conn.get_verified(address).await {
                Ok(content) => return Ok(content),
                Err(e) => last_err = e,
            }
        }
        Err(format!(
            "no responsible peer served {}: {last_err}",
            hex::encode(address)
        ))
    }

    /// One connect + quote + verify attempt against a discovered peer.
    ///
    /// Returns the verified quote (for this exact address, signed by this
    /// exact peer) plus the `already_stored` flag and any commitment sidecar.
    async fn try_quote(
        &self,
        peer: &PeerConnectInfo,
        address: [u8; 32],
        data_size: usize,
    ) -> Result<(payment::Quote, bool, Option<Vec<u8>>), String> {
        let conn = self.connection_for(peer).await?;
        let (quote_bytes, already_stored, commitment) =
            request_quote(&conn, address, data_size).await?;
        let quote = payment::parse_quote(&quote_bytes).map_err(|e| format!("quote parse: {e}"))?;
        if quote.content != address {
            return Err("quote is for a different address".into());
        }
        if blake3::hash(&quote.pub_key).as_bytes() != &peer.peer_id {
            return Err("quote public key does not match the peer id".into());
        }
        if !payment::verify_quote(&quote) {
            return Err("quote signature verification failed".into());
        }
        Ok((quote, already_stored, commitment))
    }

    /// Get or open a direct connection to a discovered peer.
    async fn connection_for(&self, peer: &PeerConnectInfo) -> Result<Rc<NodeConnection>, String> {
        if let Some(conn) = self.pool.borrow().get(&peer.peer_id) {
            return Ok(Rc::clone(conn));
        }
        let conn = NodeConnection::connect(
            &peer.ip,
            peer.port,
            &hex::encode(peer.cert_hash),
            Some(&peer.peer_id),
        )
        .await?;
        let conn = Rc::new(conn);
        self.pool
            .borrow_mut()
            .insert(peer.peer_id, Rc::clone(&conn));
        Ok(conn)
    }

    /// Encrypt, pay for, and store `data` on the network, returning the
    /// public file address (the data-map chunk address, 64 hex chars).
    ///
    /// Payment is MetaMask-free: `pay` is an async JS function
    /// `(to_hex, calldata_hex) => Promise<txHashHex>` that submits the
    /// prepared calldata with whatever wallet the page holds and resolves to
    /// the 32-byte transaction hash (hex). This client only *builds* the
    /// ERC-20 `approve` and `payForQuotes` calldata — it never signs or
    /// broadcasts.
    ///
    /// * `token_addr_hex` — the payment ERC-20 token contract (20 bytes hex).
    /// * `vault_addr_hex` — the payment-vault contract that `payForQuotes` is
    ///   sent to and that `approve` authorizes as spender.
    pub async fn upload(
        &self,
        data: Vec<u8>,
        token_addr_hex: String,
        vault_addr_hex: String,
        pay: js_sys::Function,
    ) -> Result<String, JsValue> {
        let token = parse_eth_address(&token_addr_hex).map_err(js_err)?;
        let vault = parse_eth_address(&vault_addr_hex).map_err(js_err)?;

        // 1. Self-encrypt into content chunks + a data map.
        let (data_map, chunks) = self_encryption::encrypt(Bytes::from(data))
            .map_err(|e| js_err(format!("self-encryption failed: {e}")))?;

        // 2. Ordered store list: every content chunk first.
        let mut items: Vec<([u8; 32], Vec<u8>)> = chunks
            .iter()
            .map(|c| {
                let content = c.content.to_vec();
                let address: [u8; 32] = *blake3::hash(&content).as_bytes();
                (address, content)
            })
            .collect();

        // Shrink the data map: for a large file its serialized form exceeds a
        // chunk, so it is recursively encrypted into wrapper chunks (stored
        // here) until the root map is small. A no-op for small files
        // (`data_map.len() <= 3`), which keeps their map flat. `get_root_data_map`
        // walks the wrappers back on download.
        let shrunk = self_encryption::shrink_data_map(data_map, |name, bytes| {
            items.push((name.0, bytes.to_vec()));
            Ok(())
        })
        .map_err(|e| js_err(format!("data map shrink failed: {e}")))?
        .0;

        // The data-map chunk: rmp-serialized (possibly shrunk) map, addressed
        // by its BLAKE3. This address is the public file address.
        let map_bytes = rmp_serde::to_vec(&shrunk)
            .map_err(|e| js_err(format!("data map serialize failed: {e}")))?;
        let map_address: [u8; 32] = *blake3::hash(&map_bytes).as_bytes();
        items.push((map_address, map_bytes));

        // 3. Store each item against its responsible close group.
        for (address, content) in &items {
            self.store_one(*address, content, token, vault, &pay)
                .await
                .map_err(js_err)?;
        }

        // 4. The data-map address is the public file address.
        Ok(hex::encode(map_address))
    }

    /// The peers currently responsible for an address, as JSON
    /// (`[{peer_id, ip, port, cert_hash}]`, hex-encoded) — for diagnostics
    /// and the upload flow driven from JS.
    pub async fn closest_peers_json(&self, address_hex: String) -> Result<String, JsValue> {
        let address = parse_address(&address_hex).map_err(js_err)?;
        let peers = self
            .bootstrap
            .closest_peers(address)
            .await
            .map_err(js_err)?;
        let items: Vec<String> = peers
            .iter()
            .map(|p| {
                format!(
                    r#"{{"peer_id":"{}","ip":"{}","port":{},"cert_hash":"{}"}}"#,
                    hex::encode(p.peer_id),
                    p.ip,
                    p.port,
                    hex::encode(p.cert_hash)
                )
            })
            .collect();
        Ok(format!("[{}]", items.join(",")))
    }
}

/// One responsible peer that returned a verified quote for a chunk.
struct QuotedPeer {
    peer_id: [u8; 32],
    conn: Rc<NodeConnection>,
    quote: payment::Quote,
    commitment: Option<Vec<u8>>,
}

impl WasmClient {
    /// Store one chunk: quote, pay, and PUT against its close group.
    async fn store_one(
        &self,
        address: [u8; 32],
        content: &[u8],
        token: [u8; 20],
        vault: [u8; 20],
        pay: &js_sys::Function,
    ) -> Result<(), String> {
        let peers = self.bootstrap.closest_peers(address).await?;
        if peers.len() < CLOSE_GROUP_SIZE {
            return Err(format!(
                "need at least {CLOSE_GROUP_SIZE} responsible peers for {}, discovery returned {}",
                hex::encode(address),
                peers.len()
            ));
        }

        // A single-node payment proof must carry a quote from every one of the
        // address's closest peers, so all `CLOSE_GROUP_SIZE` must quote. WebRTC
        // handshakes are occasionally flaky (see the PoC findings), so retry
        // each peer's connect+quote a few times before giving up — the native
        // client retries adaptively for the same reason.
        let mut quoted: Vec<QuotedPeer> = Vec::with_capacity(CLOSE_GROUP_SIZE);
        let mut already_stored_count = 0usize;
        for peer in peers.iter().take(CLOSE_GROUP_SIZE) {
            let mut last: String = "no attempt".into();
            let mut got = false;
            for attempt in 0..QUOTE_ATTEMPTS {
                match self.try_quote(peer, address, content.len()).await {
                    Ok((quote, already_stored, commitment)) => {
                        if already_stored {
                            already_stored_count += 1;
                            if already_stored_count >= CLOSE_GROUP_MAJORITY {
                                return Ok(());
                            }
                        }
                        // A responsible peer opened a connection; reuse it for
                        // the PUT.
                        let conn = self.connection_for(peer).await?;
                        quoted.push(QuotedPeer {
                            peer_id: peer.peer_id,
                            conn,
                            quote,
                            commitment,
                        });
                        got = true;
                        break;
                    }
                    Err(e) => {
                        last = e;
                        // Drop a possibly-broken cached connection before retry.
                        if attempt + 1 < QUOTE_ATTEMPTS {
                            self.pool.borrow_mut().remove(&peer.peer_id);
                        }
                    }
                }
            }
            if !got {
                return Err(format!(
                    "close-group peer {} did not give a valid quote for {} after {QUOTE_ATTEMPTS} tries: {last}",
                    hex::encode(peer.peer_id),
                    hex::encode(address)
                ));
            }
        }

        // Compute the single-node payment split (order matches `quoted`).
        let quotes: Vec<payment::Quote> = quoted.iter().map(|q| q.quote.clone()).collect();
        let payments = evm::payment_split(&quotes)?;
        let total = evm::total_amount(&payments);

        // Pay: approve the vault to pull `total`, then payForQuotes.
        let approve = evm::approve_calldata(vault, total);
        call_pay(pay, &to_hex(&token), &hex_0x(&approve)).await?;

        let pay_for_quotes = evm::pay_for_quotes_calldata(&payments);
        let tx_hex = call_pay(pay, &to_hex(&vault), &hex_0x(&pay_for_quotes)).await?;
        let tx_hash = parse_tx_hash(&tx_hex)?;

        // Build the tagged single-node proof.
        let peer_quotes: Vec<([u8; 32], payment::Quote)> = quoted
            .iter()
            .map(|q| (q.peer_id, q.quote.clone()))
            .collect();
        let sidecars: Vec<Vec<u8>> = quoted.iter().filter_map(|q| q.commitment.clone()).collect();
        let proof_bytes = payment::serialize_single_node_proof(peer_quotes, tx_hash, sidecars)
            .map_err(|e| format!("proof serialize failed: {e}"))?;

        // PUT to each responsible peer; require a majority to accept. Retry a
        // peer whose connection blipped, same as the quote phase.
        let mut accepted = 0usize;
        let mut last_err = String::new();
        for peer in &quoted {
            for attempt in 0..QUOTE_ATTEMPTS {
                match put_chunk(&peer.conn, address, content, &proof_bytes).await {
                    Ok(true) => {
                        accepted += 1;
                        break;
                    }
                    Ok(false) => break, // a definitive rejection, not a blip
                    Err(e) => {
                        last_err = e;
                        if attempt + 1 == QUOTE_ATTEMPTS {
                            // give up on this peer
                        }
                    }
                }
            }
        }
        if accepted < CLOSE_GROUP_MAJORITY {
            return Err(format!(
                "chunk {} accepted by only {accepted} of {CLOSE_GROUP_SIZE} peers: {last_err}",
                hex::encode(address)
            ));
        }
        Ok(())
    }
}

/// Send a `ChunkQuoteRequest` and return `(quote_bytes, already_stored,
/// commitment)` on success.
async fn request_quote(
    conn: &NodeConnection,
    address: [u8; 32],
    data_size: usize,
) -> Result<(Vec<u8>, bool, Option<Vec<u8>>), String> {
    let request = ChunkMessage {
        request_id: 1,
        body: ChunkMessageBody::QuoteRequest(ChunkQuoteRequest {
            address,
            data_size: data_size as u64,
            data_type: DATA_TYPE_CHUNK,
        }),
    };
    let response = conn.chunk_round_trip(&request).await?;
    match response.body {
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
            quote,
            already_stored,
            commitment,
        }) => Ok((quote, already_stored, commitment)),
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(e)) => {
            Err(format!("quote error: {e}"))
        }
        _ => Err("unexpected response to quote request".into()),
    }
}

/// Send a `ChunkPutRequest`; return `Ok(true)` if stored or already present.
async fn put_chunk(
    conn: &NodeConnection,
    address: [u8; 32],
    content: &[u8],
    proof_bytes: &[u8],
) -> Result<bool, String> {
    let request = ChunkMessage {
        request_id: 1,
        body: ChunkMessageBody::PutRequest(ChunkPutRequest {
            address,
            content: content.to_vec(),
            payment_proof: Some(proof_bytes.to_vec()),
        }),
    };
    let response = conn.chunk_round_trip(&request).await?;
    match response.body {
        ChunkMessageBody::PutResponse(ChunkPutResponse::Success { .. })
        | ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { .. }) => Ok(true),
        ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
            Err(format!("payment required: {message}"))
        }
        ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => Err(format!("put error: {e}")),
        _ => Err("unexpected response to put request".into()),
    }
}

/// Invoke the JS payment callback and await the resolved transaction hash hex.
async fn call_pay(
    pay: &js_sys::Function,
    to_hex: &str,
    calldata_hex: &str,
) -> Result<String, String> {
    let result = pay
        .call2(
            &JsValue::NULL,
            &JsValue::from_str(to_hex),
            &JsValue::from_str(calldata_hex),
        )
        .map_err(|e| format!("pay callback threw: {}", js_display(&e)))?;
    // Accept both a Promise and a plain value.
    let promise = js_sys::Promise::resolve(&result);
    let resolved = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|e| format!("pay callback rejected: {}", js_display(&e)))?;
    resolved
        .as_string()
        .ok_or_else(|| "pay callback did not resolve to a string tx hash".to_string())
}

fn js_display(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            js_sys::JSON::stringify(value)
                .ok()
                .and_then(|s| s.as_string())
        })
        .unwrap_or_else(|| "<non-string JS error>".to_string())
}

/// `0x`-prefixed hex of a 20-byte address.
fn to_hex(addr: &[u8; 20]) -> String {
    hex_0x(addr)
}

/// `0x`-prefixed lowercase hex of a byte slice.
fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn parse_eth_address(text: &str) -> Result<[u8; 20], String> {
    let trimmed = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    let bytes = hex::decode(trimmed).map_err(|e| format!("address is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "address must be 20 bytes (40 hex chars)".to_string())
}

fn parse_tx_hash(text: &str) -> Result<[u8; 32], String> {
    let trimmed = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    let bytes = hex::decode(trimmed).map_err(|e| format!("tx hash is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "tx hash must be 32 bytes (64 hex chars)".to_string())
}

/// BLAKE3 content address of a blob (matches the network's addressing).
#[wasm_bindgen]
pub fn content_address(bytes: &[u8]) -> Vec<u8> {
    blake3::hash(bytes).as_bytes().to_vec()
}

fn parse_address(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|e| format!("address is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "address must be 64 hex characters".to_string())
}

fn parse_opt_peer_id(hex_str: &str) -> Result<Option<[u8; 32]>, String> {
    if hex_str.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("peer_id_hex: {e}"))?;
    Ok(Some(
        bytes
            .try_into()
            .map_err(|_| "peer_id_hex must be 32 bytes".to_string())?,
    ))
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}
