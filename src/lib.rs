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
mod framing;
pub mod payment;
mod protocol;
mod retrieval;
mod sdp;
mod tunnel;
mod webrtc;

use conn::NodeConnection;
use discovery::PeerConnectInfo;
use retrieval::Retrieval;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

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
            for chunk_address in retrieval.required_addresses() {
                let bytes = self.get_direct(chunk_address).await.map_err(js_err)?;
                retrieval.supply(chunk_address, &bytes).map_err(js_err)?;
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

    /// The peers currently responsible for an address, as JSON
    /// (`[{peer_id, ip, port, cert_hash}]`, hex-encoded) — for diagnostics
    /// and the upload flow driven from JS.
    pub async fn closest_peers_json(&self, address_hex: String) -> Result<String, JsValue> {
        let address = parse_address(&address_hex).map_err(js_err)?;
        let peers = self.bootstrap.closest_peers(address).await.map_err(js_err)?;
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
