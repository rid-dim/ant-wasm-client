//! Byte-exact mirror of the `evmlib` payment types (rmp / MessagePack).
//!
//! The canonical definitions live in `evmlib` (`PaymentQuote`,
//! `ProofOfPayment`) and `ant-protocol` (`PaymentProof`, the tagged
//! single-node proof envelope). Neither compiles to wasm — `evmlib` pulls in
//! `alloy` with a native provider/transport stack — so this module mirrors
//! the *wire encoding* instead, with no dependency on evmlib, alloy or
//! xor_name.
//!
//! ⚠️ **Field ORDER is wire-relevant.** `rmp_serde::to_vec` uses the compact
//! struct encoding: a struct becomes a msgpack ARRAY of its field values, so
//! names are absent and order is everything. The trailing `#[serde(default)]`
//! fields (ADR-0004) exist because rmp only supplies defaults for MISSING
//! TRAILING array elements.
//!
//! The exact encodings mirrored here (verified against fixtures generated
//! with the real evmlib 0.9.1 / ant-protocol 2.3.2 — see
//! `tests/payment_wire.rs`):
//!
//! | native type | rmp encoding |
//! |---|---|
//! | `XorName` (`xor_name` 5, newtype `[u8; 32]`) | array of 32 uints (`dc 00 20 …`) |
//! | `SystemTime` (serde) | 2-element array `[secs u64, nanos u32]` |
//! | `Amount` = alloy `U256` (ruint, non-human-readable) | `bin` of 32 **big-endian** bytes (`c4 20 …`) |
//! | `Address` = alloy `Address` (`FixedBytes<20>`) | `bin` of 20 bytes (`c4 14 …`) |
//! | `TxHash` = alloy `FixedBytes<32>` | `bin` of 32 bytes (`c4 20 …`) |
//! | `EncodedPeerId` (`serde_byte_array` → `&[u8]` seq) | array of 32 uints |
//! | `Vec<u8>` (`pub_key`, `signature`, sidecars) | array of uints |
//!
//! Mirrored from evmlib 0.9.1 and ant-protocol 2.3.2.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Version tag prefixed to a serialized single-node payment proof.
///
/// Mirror of `ant_protocol::PROOF_TAG_SINGLE_NODE` (ant-protocol 2.3.2,
/// `src/chunk.rs`).
pub const PROOF_TAG_SINGLE_NODE: u8 = 0x01;

/// A `SystemTime` as serde encodes it: seconds and nanoseconds since the
/// UNIX epoch, in that order (rmp: a 2-element array).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    /// Whole seconds since `UNIX_EPOCH` (serde field `secs_since_epoch`).
    pub secs: u64,
    /// Sub-second nanoseconds (serde field `nanos_since_epoch`).
    pub nanos: u32,
}

impl Timestamp {
    /// A timestamp at `secs` seconds past the epoch, with no sub-second part.
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        Self { secs, nanos: 0 }
    }
}

/// Mirror of `evmlib::PaymentQuote` — a node's signed price for storing one
/// piece of content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    /// The content paid for (`XorName`).
    pub content: [u8; 32],
    /// The local node time when the quote was created.
    pub timestamp: Timestamp,
    /// The node-calculated price, big-endian (`U256`).
    #[serde(with = "bin_bytes_32")]
    pub price: [u8; 32],
    /// The node's EVM wallet address.
    #[serde(with = "bin_bytes_20")]
    pub rewards_address: [u8; 20],
    /// The node's ML-DSA-65 public key.
    pub pub_key: Vec<u8>,
    /// The node's ML-DSA-65 signature over [`bytes_for_sig`].
    pub signature: Vec<u8>,
    /// ADR-0004: number of keys in the storage commitment the price came
    /// from; `0` for a baseline quote. Tail-placed with `serde(default)` so
    /// an old 6-field quote still decodes.
    #[serde(default)]
    pub committed_key_count: u32,
    /// ADR-0004: the pin (commitment hash) of that storage commitment.
    #[serde(default)]
    pub commitment_pin: Option<[u8; 32]>,
}

/// Mirror of `evmlib::ProofOfPayment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfPayment {
    /// One `(peer id, quote)` pair per node that quoted.
    pub peer_quotes: Vec<(PeerId, Quote)>,
}

/// Mirror of `evmlib::EncodedPeerId`: a raw 32-byte peer identity (BLAKE3 of
/// the node's ML-DSA-65 public key), encoded as a msgpack array of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId(#[serde(with = "seq_bytes_32")] pub [u8; 32]);

/// Mirror of `ant_protocol::payment::proof::PaymentProof` — the quotes plus
/// the on-chain transaction hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentProof {
    /// The quote-based proof.
    pub proof_of_payment: ProofOfPayment,
    /// Transaction hashes from the on-chain payment (`TxHash`, 32 bytes).
    pub tx_hashes: Vec<TxHash>,
    /// ADR-0004 commitment sidecars: opaque serialized commitment blobs.
    #[serde(default)]
    pub commitment_sidecars: Vec<Vec<u8>>,
}

/// Mirror of `evmlib::common::TxHash` (alloy `FixedBytes<32>`): 32 bytes
/// encoded as a msgpack `bin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxHash(#[serde(with = "bin_bytes_32")] pub [u8; 32]);

/// Anything that can go wrong decoding or encoding payment wire bytes.
#[derive(Debug)]
pub enum PaymentError {
    /// The msgpack payload could not be decoded.
    Decode(String),
    /// The value could not be encoded.
    Encode(String),
    /// The proof bytes did not start with [`PROOF_TAG_SINGLE_NODE`].
    BadProofTag(Option<u8>),
}

impl core::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "payment decode failed: {e}"),
            Self::Encode(e) => write!(f, "payment encode failed: {e}"),
            Self::BadProofTag(Some(tag)) => {
                write!(f, "unexpected proof tag byte 0x{tag:02x}")
            }
            Self::BadProofTag(None) => write!(f, "empty proof bytes"),
        }
    }
}

impl std::error::Error for PaymentError {}

/// Decode a `PaymentQuote` from its rmp bytes.
///
/// # Errors
/// Returns [`PaymentError::Decode`] if the bytes are not a valid quote.
pub fn parse_quote(bytes: &[u8]) -> Result<Quote, PaymentError> {
    rmp_serde::from_slice(bytes).map_err(|e| PaymentError::Decode(e.to_string()))
}

/// Encode a quote back to rmp bytes (byte-identical to evmlib's encoding).
///
/// # Errors
/// Returns [`PaymentError::Encode`] if serialization fails.
pub fn encode_quote(quote: &Quote) -> Result<Vec<u8>, PaymentError> {
    rmp_serde::to_vec(quote).map_err(|e| PaymentError::Encode(e.to_string()))
}

/// The exact payload the node signs — mirror of `PaymentQuote::bytes_for_sig`.
///
/// `content ‖ secs_le(u64) ‖ price_le(32) ‖ rewards_address(20) ‖
/// committed_key_count_le(u32) ‖ pin_tag ‖ [pin(32)]`, where `pin_tag` is
/// `0` for `None` and `1` followed by the 32-byte pin for `Some`.
///
/// Note the endianness flip: the price is stored big-endian on the wire
/// (alloy) but signed **little-endian** (`Amount::to_le_bytes::<32>()`), and
/// the sub-second part of the timestamp is not signed at all.
#[must_use]
pub fn bytes_for_sig(quote: &Quote) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 8 + 32 + 20 + 4 + 33);
    bytes.extend_from_slice(&quote.content);
    bytes.extend_from_slice(&quote.timestamp.secs.to_le_bytes());
    let mut price_le = quote.price;
    price_le.reverse();
    bytes.extend_from_slice(&price_le);
    bytes.extend_from_slice(&quote.rewards_address);
    bytes.extend_from_slice(&quote.committed_key_count.to_le_bytes());
    match &quote.commitment_pin {
        Some(pin) => {
            bytes.push(1u8);
            bytes.extend_from_slice(pin);
        }
        None => bytes.push(0u8),
    }
    bytes
}

/// Verify a quote's ML-DSA-65 signature.
///
/// Checks `q.signature` (fips204 ml-dsa-65, empty context) over
/// [`bytes_for_sig`] using `q.pub_key`. Returns `false` if the key or
/// signature is the wrong length or fails to parse — this only proves the
/// key that produced the quote signed it; binding that key to the expected
/// node identity (`blake3(q.pub_key) == expected_peer_id`) is the caller's
/// responsibility.
///
/// fips204 verify API: `ml_dsa_65::PublicKey` implements `SerDes`
/// (`try_from_bytes([u8; PK_LEN=1952])`) and `Verifier`
/// (`verify(msg, sig: &[u8; SIG_LEN=3309], ctx) -> bool`), so the key and
/// signature must be exactly those fixed sizes.
#[must_use]
pub fn verify_quote(quote: &Quote) -> bool {
    use fips204::ml_dsa_65::{PublicKey, PK_LEN, SIG_LEN};
    use fips204::traits::{SerDes, Verifier};

    let Ok(pk_bytes) = <[u8; PK_LEN]>::try_from(quote.pub_key.as_slice()) else {
        return false;
    };
    let Ok(sig) = <[u8; SIG_LEN]>::try_from(quote.signature.as_slice()) else {
        return false;
    };
    let Ok(pk) = PublicKey::try_from_bytes(pk_bytes) else {
        return false;
    };
    pk.verify(&bytes_for_sig(quote), &sig, &[])
}

/// The quote hash — mirror of `PaymentQuote::hash()`:
/// `keccak256(bytes_for_sig ‖ pub_key ‖ signature)`.
///
/// (`evmlib::cryptography::hash` is `alloy::primitives::keccak256`, i.e.
/// legacy Keccak-256, **not** SHA3-256.)
#[must_use]
pub fn quote_hash(quote: &Quote) -> [u8; 32] {
    let mut bytes = bytes_for_sig(quote);
    bytes.extend_from_slice(&quote.pub_key);
    bytes.extend_from_slice(&quote.signature);
    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Build the tagged single-node payment proof bytes a node expects on a PUT:
/// [`PROOF_TAG_SINGLE_NODE`] followed by `rmp_serde::to_vec(&PaymentProof)`.
///
/// # Errors
/// Returns [`PaymentError::Encode`] if serialization fails.
pub fn serialize_single_node_proof(
    peer_quotes: Vec<([u8; 32], Quote)>,
    tx_hash: [u8; 32],
    sidecars: Vec<Vec<u8>>,
) -> Result<Vec<u8>, PaymentError> {
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: peer_quotes
                .into_iter()
                .map(|(peer, quote)| (PeerId(peer), quote))
                .collect(),
        },
        tx_hashes: vec![TxHash(tx_hash)],
        commitment_sidecars: sidecars,
    };
    encode_proof(&proof)
}

/// Encode an arbitrary [`PaymentProof`] with the single-node tag byte.
///
/// # Errors
/// Returns [`PaymentError::Encode`] if serialization fails.
pub fn encode_proof(proof: &PaymentProof) -> Result<Vec<u8>, PaymentError> {
    let body = rmp_serde::to_vec(proof).map_err(|e| PaymentError::Encode(e.to_string()))?;
    let mut tagged = Vec::with_capacity(1 + body.len());
    tagged.push(PROOF_TAG_SINGLE_NODE);
    tagged.extend_from_slice(&body);
    Ok(tagged)
}

/// Decode tagged single-node proof bytes.
///
/// # Errors
/// Returns [`PaymentError::BadProofTag`] if the tag byte is missing or wrong,
/// [`PaymentError::Decode`] if the payload is malformed.
pub fn parse_single_node_proof(bytes: &[u8]) -> Result<PaymentProof, PaymentError> {
    match bytes.first() {
        Some(&PROOF_TAG_SINGLE_NODE) => {}
        other => return Err(PaymentError::BadProofTag(other.copied())),
    }
    rmp_serde::from_slice(&bytes[1..]).map_err(|e| PaymentError::Decode(e.to_string()))
}

/// A fixed-size byte array encoded as a msgpack `bin` (alloy `FixedBytes`,
/// ruint `U256` in non-human-readable form).
macro_rules! bin_bytes_mod {
    ($name:ident, $n:literal) => {
        mod $name {
            use serde::de::{Error, SeqAccess, Visitor};
            use serde::{Deserializer, Serializer};

            pub fn serialize<S: Serializer>(
                bytes: &[u8; $n],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&bytes[..])
            }

            struct BinVisitor;

            impl<'de> Visitor<'de> for BinVisitor {
                type Value = [u8; $n];

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "exactly {} bytes", $n)
                }

                fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    <[u8; $n]>::try_from(v).map_err(|_| {
                        E::custom(format!("expected {} bytes, got {}", $n, v.len()))
                    })
                }

                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut out = [0u8; $n];
                    for (i, slot) in out.iter_mut().enumerate() {
                        *slot = seq
                            .next_element()?
                            .ok_or_else(|| Error::invalid_length(i, &self))?;
                    }
                    Ok(out)
                }
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<[u8; $n], D::Error> {
                deserializer.deserialize_bytes(BinVisitor)
            }
        }
    };
}

bin_bytes_mod!(bin_bytes_32, 32);
bin_bytes_mod!(bin_bytes_20, 20);

/// A 32-byte array encoded as a msgpack ARRAY of uints — the shape evmlib's
/// `serde_byte_array` helper produces (it serializes `&bytes[..]`, a slice,
/// which serde encodes as a sequence, and deserializes via `Vec<u8>`).
mod seq_bytes_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&bytes[..], serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            let len = v.len();
            serde::de::Error::custom(format!("Expected 32 bytes, got {len}"))
        })
    }
}
