//! Client mirror of the node's discovery protocol (tag 0x02).
//!
//! ⚠️ Postcard is not self-describing: field and variant order here must
//! match `ant-node/src/webrtc/discovery.rs` exactly.

use serde::{Deserialize, Serialize};

/// Protocol tag: tunnel plaintext is a passthrough `ChunkMessage`.
pub const PROTO_CHUNK: u8 = 0x01;
/// Protocol tag: tunnel plaintext is a [`DiscoveryMessage`].
pub const PROTO_DISCOVERY: u8 = 0x02;

/// Wire envelope for the discovery protocol family (postcard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    /// Sender-assigned identifier, echoed back in the response.
    pub request_id: u64,
    /// The message body.
    pub body: DiscoveryBody,
}

/// Discovery message bodies. Variant order is wire-relevant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryBody {
    /// Browser → node: who is closest to this address?
    ClosestPeersRequest(ClosestPeersRequest),
    /// Node → browser: directly-connectable peers.
    ClosestPeersResponse(ClosestPeersResponse),
    /// Node → browser: request-level failure.
    Error(String),
}

/// Closest-peers query for one address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosestPeersRequest {
    /// The content address to locate.
    pub address: [u8; 32],
}

/// Directly-connectable peers, closest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosestPeersResponse {
    /// Connect facts for each reachable close-group peer.
    pub peers: Vec<PeerConnectInfo>,
}

/// Everything needed to open a direct WebRTC connection to a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnectInfo {
    /// The peer's identity (BLAKE3 of its ML-DSA-65 public key).
    pub peer_id: [u8; 32],
    /// IP address (text, v4 or v6).
    pub ip: String,
    /// WebRTC listener UDP port.
    pub port: u16,
    /// SHA-256 fingerprint of the peer's DTLS certificate.
    pub cert_hash: [u8; 32],
}

impl DiscoveryMessage {
    /// Encode with postcard.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        postcard::to_stdvec(self).map_err(|e| format!("discovery encode: {e}"))
    }

    /// Decode with postcard.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        postcard::from_bytes(data).map_err(|e| format!("discovery decode: {e}"))
    }
}
