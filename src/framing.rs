//! `DataChannel` framing — mirror of the node's `src/webrtc/framing.rs`.
//!
//! One application frame = 4-byte big-endian length prefix + payload, split
//! across `DataChannel` messages of at most [`MAX_DC_MESSAGE_SIZE`] bytes.

use crate::protocol::MAX_WIRE_MESSAGE_SIZE;

/// Maximum size of a single `DataChannel` message we send.
pub const MAX_DC_MESSAGE_SIZE: usize = 16 * 1024;

/// Maximum size of one reassembled frame.
pub const MAX_FRAME_SIZE: usize = MAX_WIRE_MESSAGE_SIZE + 64;

/// Encode one frame.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(4 + payload.len());
    #[allow(clippy::cast_possible_truncation)]
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

/// Split an encoded frame into `DataChannel`-sized messages.
pub fn split_messages(wire: &[u8]) -> impl Iterator<Item = &[u8]> {
    wire.chunks(MAX_DC_MESSAGE_SIZE)
}

/// Reassembly buffer for incoming messages.
#[derive(Default)]
pub struct FrameBuf {
    buf: Vec<u8>,
}

impl FrameBuf {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append bytes; return the next complete frame if one finished. Call
    /// again with an empty slice to drain buffered frames.
    pub fn push(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.buf.extend_from_slice(data);
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.buf[0..4]);
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_FRAME_SIZE {
            return Err(format!("declared frame length {len} out of range"));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let payload = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(payload))
    }
}
