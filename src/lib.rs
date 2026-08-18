//! Browser WASM client for the Autonomi WebRTC-Direct lane (ADR-0010).
//!
//! Connects an ordinary web page directly to an ant-node — no signaling
//! server, no CA certificate, no installation. All security properties live
//! in this client: the DTLS certificate is pinned by fingerprint, the
//! node's identity is verified post-quantum (ML-DSA-65 + PeerId pinning),
//! every message rides the mandatory PQC tunnel (ML-KEM-768 +
//! ChaCha20-Poly1305), and every chunk is verified against its BLAKE3
//! content address before use.
//!
//! ```js
//! const client = await WasmClient.connect("127.0.0.1", 20123, certHashHex, peerIdHex);
//! const bytes = await client.download(addressHex);   // verified + decrypted
//! ```

mod framing;
mod protocol;
mod retrieval;
mod sdp;
mod tunnel;
mod webrtc;

use protocol::{ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody};
use retrieval::Retrieval;
use tunnel::{ClientHandshake, SessionCipher, MAX_SEQ};
use wasm_bindgen::prelude::*;
use webrtc::Transport;

/// A connected, authenticated client session.
#[wasm_bindgen]
pub struct WasmClient {
    transport: Transport,
    cipher: SessionCipher,
    peer_id: [u8; 32],
    next_seq: std::cell::Cell<u32>,
}

#[wasm_bindgen]
impl WasmClient {
    /// Connect to a node and establish the authenticated PQC tunnel.
    ///
    /// * `ip`, `port` — the node's WebRTC listener address.
    /// * `cert_hash_hex` — SHA-256 fingerprint of the node's DTLS
    ///   certificate (64 hex chars, from the devnet manifest).
    /// * `peer_id_hex` — expected node identity (`BLAKE3` of its ML-DSA-65
    ///   public key); pass an empty string to skip pinning (discouraged).
    pub async fn connect(
        ip: String,
        port: u16,
        cert_hash_hex: String,
        peer_id_hex: String,
    ) -> Result<WasmClient, JsValue> {
        let transport = Transport::connect(&ip, port, &cert_hash_hex)
            .await
            .map_err(js_err)?;

        // PQC handshake: first frame out is the ClientHello, first frame in
        // is the ServerAccept.
        let (handshake, hello) = ClientHandshake::start().map_err(js_err)?;
        transport.send_frame(&hello).map_err(js_err)?;
        let accept = transport.recv_frame().await.map_err(js_err)?;

        let expected_peer_id: Option<[u8; 32]> = if peer_id_hex.is_empty() {
            None
        } else {
            let bytes = hex::decode(&peer_id_hex)
                .map_err(|e| js_err(format!("peer_id_hex: {e}")))?;
            Some(
                bytes
                    .try_into()
                    .map_err(|_| js_err("peer_id_hex must be 32 bytes"))?,
            )
        };
        let established = handshake
            .finish(&accept, expected_peer_id.as_ref())
            .map_err(js_err)?;

        Ok(WasmClient {
            transport,
            cipher: established.cipher,
            peer_id: established.peer_id,
            next_seq: std::cell::Cell::new(1),
        })
    }

    /// The connected node's PeerId (hex).
    #[wasm_bindgen(getter)]
    pub fn peer_id(&self) -> String {
        hex::encode(self.peer_id)
    }

    /// Fetch one raw chunk by its address (64 hex chars), verified against
    /// the address before returning.
    pub async fn fetch_chunk(&self, address_hex: String) -> Result<Vec<u8>, JsValue> {
        let address = parse_address(&address_hex).map_err(js_err)?;
        let content = self.get_verified(address).await.map_err(js_err)?;
        Ok(content)
    }

    /// Download, verify, and decrypt a public file by its data-map address
    /// (64 hex chars). Returns the plaintext bytes.
    pub async fn download(&self, address_hex: String) -> Result<Vec<u8>, JsValue> {
        let address = parse_address(&address_hex).map_err(js_err)?;

        // 1. The address holds the (possibly shrunk) data map chunk.
        let map_bytes = self.get_verified(address).await.map_err(js_err)?;
        let mut retrieval = Retrieval::begin(address, &map_bytes).map_err(js_err)?;

        // 2. Fetch required chunks until complete (resolving shrunk maps).
        while !retrieval.is_complete() {
            for chunk_address in retrieval.required_addresses() {
                let bytes = self.get_verified(chunk_address).await.map_err(js_err)?;
                retrieval.supply(chunk_address, &bytes).map_err(js_err)?;
            }
            retrieval.advance().map_err(js_err)?;
        }

        // 3. Decrypt and reassemble.
        retrieval.finish().map_err(js_err)
    }

    /// One encrypted GET round-trip; verifies the content against the
    /// requested address before returning.
    async fn get_verified(&self, address: [u8; 32]) -> Result<Vec<u8>, String> {
        let seq = self.next_seq.get();
        if seq >= MAX_SEQ {
            return Err("session sequence space exhausted; reconnect".into());
        }
        self.next_seq.set(seq + 1);

        let request = ChunkMessage {
            request_id: u64::from(seq),
            body: ChunkMessageBody::GetRequest(ChunkGetRequest { address }),
        };
        let envelope = self.cipher.seal_request(seq, &request.encode()?)?;
        self.transport.send_frame(&envelope)?;

        // Requests are issued sequentially, so the next response frame
        // answers this request; the seq check guards against desync.
        let frame = self.transport.recv_frame().await?;
        let (resp_seq, plaintext) = self.cipher.open_response(&frame)?;
        if resp_seq != seq {
            return Err(format!("response seq {resp_seq} does not match request {seq}"));
        }
        let response = ChunkMessage::decode(&plaintext)?;
        match response.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                address: resp_address,
                content,
            }) => {
                // The trust boundary: content must hash to the address WE
                // requested.
                if resp_address != address {
                    return Err("response address mismatch".into());
                }
                let computed: [u8; 32] = *blake3::hash(&content).as_bytes();
                if computed != address {
                    return Err(format!(
                        "chunk {} failed BLAKE3 verification",
                        hex::encode(address)
                    ));
                }
                Ok(content)
            }
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => {
                Err(format!("not found: {}", hex::encode(address)))
            }
            ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => {
                Err(format!("node error: {e}"))
            }
            _ => Err("unexpected response type".into()),
        }
    }
}

/// BLAKE3 content address of a blob (matches the network's addressing).
#[wasm_bindgen]
pub fn content_address(bytes: &[u8]) -> Vec<u8> {
    blake3::hash(bytes).as_bytes().to_vec()
}

fn parse_address(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim();
    let bytes = hex::decode(text).map_err(|e| format!("address is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "address must be 64 hex characters".to_string())
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}
