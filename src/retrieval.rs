//! Verified retrieval state machine — ported from the proven
//! autonomi-webrtc-direct-poc `wasm-client` (MIT), unchanged in substance.
//!
//! Everything that decides whether returned bytes are trustworthy lives
//! here: address verification, data-map walking, self-decryption. The
//! transport is somebody else's problem. `supply` verifies every chunk
//! against the address it was requested under (the address *is* the BLAKE3
//! hash of the bytes), so the serving node can refuse but cannot lie.

use self_encryption::bytes::Bytes;
use self_encryption::{decrypt, get_root_data_map, verify_chunk, DataMap, EncryptedChunk, XorName};
use std::collections::HashMap;

/// An in-progress retrieval of one piece of content.
pub struct Retrieval {
    map: DataMap,
    root_resolved: bool,
    cache: HashMap<XorName, EncryptedChunk>,
}

impl Retrieval {
    /// Start from the chunk stored at a public address (must verify and be a
    /// MessagePack data map).
    pub fn begin(address: [u8; 32], bytes: &[u8]) -> Result<Self, String> {
        let address = XorName(address);
        verify_chunk(address, bytes)
            .map_err(|e| format!("data map chunk failed verification: {e}"))?;
        let map: DataMap = rmp_serde::from_slice(bytes)
            .map_err(|e| format!("address does not hold a data map: {e}"))?;
        let root_resolved = !map.is_child();
        Ok(Self {
            map,
            root_resolved,
            cache: HashMap::new(),
        })
    }

    /// Addresses still needed (32-byte each).
    pub fn required_addresses(&self) -> Vec<[u8; 32]> {
        self.map
            .infos()
            .iter()
            .filter(|info| !self.cache.contains_key(&info.dst_hash))
            .map(|info| info.dst_hash.0)
            .collect()
    }

    /// Accept bytes for one address, verifying them first.
    pub fn supply(&mut self, address: [u8; 32], bytes: &[u8]) -> Result<(), String> {
        let address = XorName(address);
        let chunk = verify_chunk(address, bytes)
            .map_err(|e| format!("chunk {} failed verification: {e}", hex::encode(address.0)))?;
        self.cache.insert(address, chunk);
        Ok(())
    }

    /// Resolve a shrunk (child) data map once its wrapper chunks are present.
    pub fn advance(&mut self) -> Result<(), String> {
        if self.root_resolved || !self.required_addresses().is_empty() {
            return Ok(());
        }
        let cache = &self.cache;
        let mut fetch = |address: XorName| {
            cache
                .get(&address)
                .map(|chunk| chunk.content.clone())
                .ok_or_else(|| {
                    self_encryption::Error::Generic(format!(
                        "missing wrapper chunk {}",
                        hex::encode(address.0)
                    ))
                })
        };
        let root = get_root_data_map(self.map.clone(), &mut fetch)
            .map_err(|e| format!("failed to resolve the root data map: {e}"))?;
        self.map = root;
        self.root_resolved = true;
        Ok(())
    }

    /// True once the root map is resolved and every content chunk is held.
    pub fn is_complete(&self) -> bool {
        self.root_resolved && self.required_addresses().is_empty()
    }

    /// Total chunks referenced by the current map (for progress reporting).
    #[allow(dead_code)]
    pub fn chunk_count(&self) -> usize {
        self.map.infos().len()
    }

    /// Decrypt and reassemble.
    pub fn finish(&self) -> Result<Vec<u8>, String> {
        if !self.is_complete() {
            return Err("cannot finish: chunks missing or root map unresolved".into());
        }
        let chunks: Vec<EncryptedChunk> = self
            .map
            .infos()
            .iter()
            .map(|info| {
                self.cache
                    .get(&info.dst_hash)
                    .cloned()
                    .ok_or_else(|| format!("missing chunk {}", hex::encode(info.dst_hash.0)))
            })
            .collect::<Result<_, _>>()?;
        let plaintext: Bytes =
            decrypt(&self.map, &chunks).map_err(|e| format!("decryption failed: {e}"))?;
        Ok(plaintext.to_vec())
    }
}
