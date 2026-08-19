//! One authenticated connection to a single node.
//!
//! Wraps a WebRTC transport plus its established PQC session, and speaks the
//! two tunnel lanes: the chunk protocol (tag 0x01) and discovery (0x02).
//! Requests are issued sequentially per connection and correlated by the
//! monotonic sequence number.

use crate::discovery::{DiscoveryBody, DiscoveryMessage, PROTO_CHUNK, PROTO_DISCOVERY};
use crate::protocol::{ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody};
use crate::tunnel::{ClientHandshake, SessionCipher, MAX_SEQ};
use crate::webrtc::Transport;
use std::cell::Cell;

/// An authenticated session with one node.
pub struct NodeConnection {
    transport: Transport,
    cipher: SessionCipher,
    peer_id: [u8; 32],
    next_seq: Cell<u32>,
}

impl NodeConnection {
    /// Connect to `ip:port`, pinning the certificate fingerprint and (unless
    /// empty) the node's `PeerId`, then establish the PQC tunnel.
    pub async fn connect(
        ip: &str,
        port: u16,
        cert_hash_hex: &str,
        expected_peer_id: Option<&[u8; 32]>,
    ) -> Result<Self, String> {
        let transport = Transport::connect(ip, port, cert_hash_hex).await?;

        let (handshake, hello) = ClientHandshake::start()?;
        transport.send_frame(&hello)?;
        let accept = transport.recv_frame().await?;
        let established = handshake.finish(&accept, expected_peer_id)?;

        Ok(Self {
            transport,
            cipher: established.cipher,
            peer_id: established.peer_id,
            next_seq: Cell::new(1),
        })
    }

    /// The connected node's `PeerId`.
    pub fn peer_id(&self) -> [u8; 32] {
        self.peer_id
    }

    fn next_seq(&self) -> Result<u32, String> {
        let seq = self.next_seq.get();
        if seq >= MAX_SEQ {
            return Err("session sequence space exhausted; reconnect".into());
        }
        self.next_seq.set(seq + 1);
        Ok(seq)
    }

    /// Send one tagged request plaintext and return the response plaintext
    /// (tag stripped), verifying the sequence and tag.
    async fn round_trip(&self, tag: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
        let seq = self.next_seq()?;
        let mut tagged = Vec::with_capacity(1 + payload.len());
        tagged.push(tag);
        tagged.extend_from_slice(payload);
        let envelope = self.cipher.seal_request(seq, &tagged)?;
        self.transport.send_frame(&envelope)?;

        let frame = self.transport.recv_frame().await?;
        let (resp_seq, plaintext) = self.cipher.open_response(&frame)?;
        if resp_seq != seq {
            return Err(format!(
                "response seq {resp_seq} does not match request {seq}"
            ));
        }
        if plaintext.first() != Some(&tag) {
            return Err("unexpected response protocol tag".into());
        }
        Ok(plaintext[1..].to_vec())
    }

    /// One GET round-trip, verifying the content hashes to `address`.
    pub async fn get_verified(&self, address: [u8; 32]) -> Result<Vec<u8>, String> {
        let request = ChunkMessage {
            request_id: u64::from(self.next_seq.get()),
            body: ChunkMessageBody::GetRequest(ChunkGetRequest { address }),
        };
        let plaintext = self.round_trip(PROTO_CHUNK, &request.encode()?).await?;
        let response = ChunkMessage::decode(&plaintext)?;
        match response.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                address: resp_address,
                content,
            }) => {
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

    /// Ask this node which peers are closest to `address`.
    pub async fn closest_peers(
        &self,
        address: [u8; 32],
    ) -> Result<Vec<crate::discovery::PeerConnectInfo>, String> {
        let request = DiscoveryMessage {
            request_id: u64::from(self.next_seq.get()),
            body: DiscoveryBody::ClosestPeersRequest(crate::discovery::ClosestPeersRequest {
                address,
            }),
        };
        let plaintext = self.round_trip(PROTO_DISCOVERY, &request.encode()?).await?;
        let response = DiscoveryMessage::decode(&plaintext)?;
        match response.body {
            DiscoveryBody::ClosestPeersResponse(r) => Ok(r.peers),
            DiscoveryBody::Error(e) => Err(format!("discovery error: {e}")),
            DiscoveryBody::ClosestPeersRequest(_) => Err("unexpected discovery response".into()),
        }
    }

    /// Send an already-encoded chunk-protocol message and return the decoded
    /// response (used for quotes and PUT, whose bodies the caller builds).
    #[allow(dead_code)] // wired up by the upload flow (M5 stage B)
    pub async fn chunk_round_trip(&self, request: &ChunkMessage) -> Result<ChunkMessage, String> {
        let plaintext = self.round_trip(PROTO_CHUNK, &request.encode()?).await?;
        ChunkMessage::decode(&plaintext)
    }
}
