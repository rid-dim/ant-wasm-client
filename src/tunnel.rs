//! Client side of the application-layer PQC tunnel (ADR-0010).
//!
//! Wire format and nonce discipline are identical to the node's
//! `src/webrtc/tunnel.rs` (contexts `ant-webrtc-pqc-v1` /
//! `ant-webrtc-auth-v1`):
//!
//! ```text
//! Type 0x01 ClientHello:  [version: 2B BE u16][ek: 1184B]
//! Type 0x02 ServerAccept: [version: 2B BE u16][ct: 1088B][pubkey: 1952B][sig: 3309B]
//! Type 0x03 Encrypted:    [seq: 4B BE u32][ciphertext...]
//! ```
//!
//! The client generates a fresh ML-KEM-768 keypair per session, verifies the
//! node's ML-DSA-65 signature over `context || ek || ct`, pins
//! `PeerId = BLAKE3(pubkey)`, and derives the ChaCha20-Poly1305 session key
//! as `BLAKE3-derive-key(context, shared_secret)`.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, KeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as DsaSerDes, Verifier};

/// PQC tunnel protocol version.
pub const PQC_VERSION: u16 = 2;
/// ML-KEM-768 encapsulation key size.
pub const ML_KEM_768_EK_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size.
pub const ML_KEM_768_CT_SIZE: usize = 1088;
/// ML-DSA-65 public key size.
pub const ML_DSA_65_PK_SIZE: usize = 1952;
/// ML-DSA-65 signature size.
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

const KDF_CONTEXT: &str = "ant-webrtc-pqc-v1";
const AUTH_SIGN_CONTEXT: &[u8] = b"ant-webrtc-auth-v1";

/// Maximum sequence number before the session must be torn down.
pub const MAX_SEQ: u32 = u32::MAX - 1;

/// Message direction for nonce construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Browser → node.
    ClientToServer,
    /// Node → browser.
    ServerToClient,
}

/// An in-flight client handshake (holds the decapsulation key).
pub struct ClientHandshake {
    dk: ml_kem_768::DecapsKey,
    ek_bytes: [u8; ML_KEM_768_EK_SIZE],
}

/// Result of a completed handshake.
pub struct Established {
    /// The session cipher.
    pub cipher: SessionCipher,
    /// The node's PeerId (BLAKE3 of its ML-DSA-65 public key).
    pub peer_id: [u8; 32],
}

impl ClientHandshake {
    /// Generate a fresh keypair and produce the `ClientHello` frame payload.
    pub fn start() -> Result<(Self, Vec<u8>), String> {
        let (ek, dk) = ml_kem_768::KG::try_keygen().map_err(|e| format!("ML-KEM keygen: {e}"))?;
        let ek_bytes: [u8; ML_KEM_768_EK_SIZE] = KemSerDes::into_bytes(ek);

        let mut hello = Vec::with_capacity(1 + 2 + ML_KEM_768_EK_SIZE);
        hello.push(0x01);
        hello.extend_from_slice(&PQC_VERSION.to_be_bytes());
        hello.extend_from_slice(&ek_bytes);

        Ok((Self { dk, ek_bytes }, hello))
    }

    /// Process the `ServerAccept` frame: verify version, signature, and the
    /// pinned PeerId, then derive the session cipher.
    pub fn finish(
        self,
        accept_frame: &[u8],
        expected_peer_id: Option<&[u8; 32]>,
    ) -> Result<Established, String> {
        let expected_len = 1 + 2 + ML_KEM_768_CT_SIZE + ML_DSA_65_PK_SIZE + ML_DSA_65_SIG_SIZE;
        if accept_frame.len() < expected_len {
            return Err(format!(
                "ServerAccept too short: {} bytes",
                accept_frame.len()
            ));
        }
        if accept_frame[0] != 0x02 {
            return Err(format!(
                "expected ServerAccept type 0x02, got 0x{:02x}",
                accept_frame[0]
            ));
        }
        let version = u16::from_be_bytes([accept_frame[1], accept_frame[2]]);
        if version != PQC_VERSION {
            return Err(format!("unsupported PQC version {version}"));
        }

        let ct_start = 3;
        let pk_start = ct_start + ML_KEM_768_CT_SIZE;
        let sig_start = pk_start + ML_DSA_65_PK_SIZE;

        let mut ct = [0u8; ML_KEM_768_CT_SIZE];
        ct.copy_from_slice(&accept_frame[ct_start..pk_start]);
        let mut pubkey = [0u8; ML_DSA_65_PK_SIZE];
        pubkey.copy_from_slice(&accept_frame[pk_start..sig_start]);
        let mut signature = [0u8; ML_DSA_65_SIG_SIZE];
        signature.copy_from_slice(&accept_frame[sig_start..sig_start + ML_DSA_65_SIG_SIZE]);

        // Verify the node's signature over the handshake transcript.
        let mut auth_message =
            Vec::with_capacity(AUTH_SIGN_CONTEXT.len() + ML_KEM_768_EK_SIZE + ML_KEM_768_CT_SIZE);
        auth_message.extend_from_slice(AUTH_SIGN_CONTEXT);
        auth_message.extend_from_slice(&self.ek_bytes);
        auth_message.extend_from_slice(&ct);

        let vk = <ml_dsa_65::PublicKey as DsaSerDes>::try_from_bytes(pubkey)
            .map_err(|_| "invalid ML-DSA-65 public key".to_string())?;
        if !vk.verify(&auth_message, &signature, &[]) {
            return Err("ML-DSA-65 signature verification failed".into());
        }

        // Pin the node identity: PeerId = BLAKE3(pubkey).
        let peer_id: [u8; 32] = *blake3::hash(&pubkey).as_bytes();
        if let Some(expected) = expected_peer_id {
            if &peer_id != expected {
                return Err(format!(
                    "PeerId mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(peer_id)
                ));
            }
        }

        // Decapsulate and derive the session key.
        let ct = <ml_kem_768::CipherText as KemSerDes>::try_from_bytes(ct)
            .map_err(|_| "invalid ML-KEM-768 ciphertext".to_string())?;
        let ss = self
            .dk
            .try_decaps(&ct)
            .map_err(|_| "ML-KEM-768 decapsulation failed".to_string())?;
        let ss_bytes: [u8; 32] = KemSerDes::into_bytes(ss);

        Ok(Established {
            cipher: SessionCipher::from_shared_secret(&ss_bytes),
            peer_id,
        })
    }
}

/// Symmetric cipher for an established session.
pub struct SessionCipher {
    key: [u8; 32],
}

impl SessionCipher {
    /// Derive from the ML-KEM shared secret.
    pub fn from_shared_secret(ss: &[u8; 32]) -> Self {
        Self {
            key: blake3::derive_key(KDF_CONTEXT, ss),
        }
    }

    /// Encrypt a request payload and wrap it in an Encrypted envelope.
    pub fn seal_request(&self, seq: u32, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = build_nonce(seq, Direction::ClientToServer);
        let ciphertext = cipher
            .encrypt(&nonce.into(), plaintext)
            .map_err(|_| "encryption failed".to_string())?;
        let mut envelope = Vec::with_capacity(1 + 4 + ciphertext.len());
        envelope.push(0x03);
        envelope.extend_from_slice(&seq.to_be_bytes());
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Unwrap an Encrypted envelope and decrypt the response payload.
    ///
    /// Returns `(seq, plaintext)`.
    pub fn open_response(&self, envelope: &[u8]) -> Result<(u32, Vec<u8>), String> {
        if envelope.len() < 5 || envelope[0] != 0x03 {
            return Err("invalid Encrypted envelope".into());
        }
        let seq = u32::from_be_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = build_nonce(seq, Direction::ServerToClient);
        let plaintext = cipher
            .decrypt(&nonce.into(), &envelope[5..])
            .map_err(|_| "decryption failed (tampered or wrong session)".to_string())?;
        Ok((seq, plaintext))
    }
}

fn build_nonce(seq: u32, direction: Direction) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&seq.to_be_bytes());
    nonce[4] = match direction {
        Direction::ClientToServer => 0x00,
        Direction::ServerToClient => 0x01,
    };
    nonce
}
