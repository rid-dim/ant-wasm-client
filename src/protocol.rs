//! Byte-exact mirror of the `autonomi.ant.chunk.v1` wire types.
//!
//! The canonical definitions live in the `ant-protocol` crate, which cannot
//! be compiled to wasm because it depends on the native saorsa network stack.
//! This module mirrors the postcard-encoded types instead.
//!
//! ⚠️ **Postcard is not self-describing.** Enum variant ORDER, struct field
//! ORDER, and field TYPES here must match `ant-protocol`'s `src/chunk.rs`
//! exactly, or the bytes will decode to garbage. (`bytes::Bytes` on the
//! native side serializes identically to `Vec<u8>`.) When ant-protocol gains
//! wasm support, delete this module and depend on it directly.
//!
//! Mirrored from ant-protocol 2.3.2.

use serde::{Deserialize, Serialize};

/// Content-addressed identifier (32 bytes) — BLAKE3 of the content.
pub type XorName = [u8; 32];

/// Maximum wire message size (mirror of `MAX_WIRE_MESSAGE_SIZE`).
pub const MAX_WIRE_MESSAGE_SIZE: usize = 5 * 1024 * 1024;

/// Wire-format wrapper pairing a sender-assigned `request_id` with a body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMessage {
    /// Sender-assigned identifier, echoed back in the response.
    pub request_id: u64,
    /// The protocol message body.
    pub body: ChunkMessageBody,
}

impl ChunkMessage {
    /// Encode with postcard.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        postcard::to_stdvec(self).map_err(|e| format!("encode failed: {e}"))
    }

    /// Decode with postcard (size-capped).
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(format!("message too large: {} bytes", data.len()));
        }
        postcard::from_bytes(data).map_err(|e| format!("decode failed: {e}"))
    }
}

/// All chunk protocol message types. Variant order is wire-relevant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkMessageBody {
    /// Request to store a chunk.
    PutRequest(ChunkPutRequest),
    /// Response to a PUT request.
    PutResponse(ChunkPutResponse),
    /// Request to retrieve a chunk.
    GetRequest(ChunkGetRequest),
    /// Response to a GET request.
    GetResponse(ChunkGetResponse),
    /// Request a storage quote.
    QuoteRequest(ChunkQuoteRequest),
    /// Response with a storage quote.
    QuoteResponse(ChunkQuoteResponse),
    /// Request a merkle candidate quote for batch payments.
    MerkleCandidateQuoteRequest(MerkleCandidateQuoteRequest),
    /// Response with a merkle candidate quote.
    MerkleCandidateQuoteResponse(MerkleCandidateQuoteResponse),
}

/// Request to store a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutRequest {
    /// BLAKE3 of `content`.
    pub address: XorName,
    /// The chunk data (native side uses `Bytes`; wire-identical).
    pub content: Vec<u8>,
    /// Optional serialized `ProofOfPayment`.
    pub payment_proof: Option<Vec<u8>>,
}

/// Response to a PUT request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkPutResponse {
    /// Stored.
    Success {
        /// Echoed address.
        address: XorName,
    },
    /// Already present (no payment consumed).
    AlreadyExists {
        /// Echoed address.
        address: XorName,
    },
    /// Payment missing or insufficient.
    PaymentRequired {
        /// Human-readable reason.
        message: String,
    },
    /// An error occurred.
    Error(ProtocolError),
}

/// Request to retrieve a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetRequest {
    /// The content address.
    pub address: XorName,
}

/// Response to a GET request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkGetResponse {
    /// Found.
    Success {
        /// Echoed address.
        address: XorName,
        /// The chunk bytes.
        content: Vec<u8>,
    },
    /// Not stored here (or anywhere the gateway could reach).
    NotFound {
        /// Echoed address.
        address: XorName,
    },
    /// An error occurred.
    Error(ProtocolError),
}

/// Request a storage quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkQuoteRequest {
    /// The content address to be stored.
    pub address: XorName,
    /// Payload size in bytes.
    pub data_size: u64,
    /// Data type tag (0 = chunk).
    pub data_type: u32,
}

/// Response with a storage quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkQuoteResponse {
    /// Quote generated.
    Success {
        /// Serialized `PaymentQuote` (rmp-serde, opaque here).
        quote: Vec<u8>,
        /// Chunk already stored — skip payment.
        already_stored: bool,
        /// ADR-0004 commitment sidecar (opaque).
        #[serde(default)]
        commitment: Option<Vec<u8>>,
    },
    /// An error occurred.
    Error(ProtocolError),
}

/// Request a merkle candidate quote (mirrored for enum-order fidelity;
/// unused by the download path). Field order is wire-relevant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCandidateQuoteRequest {
    /// The content address.
    pub address: XorName,
    /// Data type tag.
    pub data_type: u32,
    /// Payload size in bytes.
    pub data_size: u64,
    /// Merkle payment timestamp (unix secs).
    pub merkle_payment_timestamp: u64,
}

/// Response with a merkle candidate quote (mirrored; unused here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MerkleCandidateQuoteResponse {
    /// Candidate quote generated.
    Success {
        /// Serialized candidate node (opaque).
        candidate_node: Vec<u8>,
        /// ADR-0004 commitment sidecar (opaque).
        #[serde(default)]
        commitment: Option<Vec<u8>>,
    },
    /// An error occurred.
    Error(ProtocolError),
}

/// Protocol-level error (variant order is wire-relevant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolError {
    /// Message serialization failed.
    SerializationFailed(String),
    /// Message deserialization failed.
    DeserializationFailed(String),
    /// Wire message exceeds the maximum allowed size.
    MessageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max_size: usize,
    },
    /// Chunk exceeds maximum size.
    ChunkTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max_size: usize,
    },
    /// Content address mismatch.
    AddressMismatch {
        /// Expected address.
        expected: XorName,
        /// Computed address.
        actual: XorName,
    },
    /// Storage operation failed.
    StorageFailed(String),
    /// Payment verification failed.
    PaymentFailed(String),
    /// Quote generation failed.
    QuoteFailed(String),
    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(m) => write!(f, "serialization failed: {m}"),
            Self::DeserializationFailed(m) => write!(f, "deserialization failed: {m}"),
            Self::MessageTooLarge { size, max_size } => {
                write!(f, "message size {size} exceeds maximum {max_size}")
            }
            Self::ChunkTooLarge { size, max_size } => {
                write!(f, "chunk size {size} exceeds maximum {max_size}")
            }
            Self::AddressMismatch { .. } => write!(f, "address mismatch"),
            Self::StorageFailed(m) => write!(f, "storage failed: {m}"),
            Self::PaymentFailed(m) => write!(f, "payment failed: {m}"),
            Self::QuoteFailed(m) => write!(f, "quote failed: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}
