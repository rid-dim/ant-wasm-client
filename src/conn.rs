//! One authenticated connection to a single node.
//!
//! Wraps a WebRTC transport plus its established PQC session, and speaks the
//! two tunnel lanes: the chunk protocol (tag 0x01) and discovery (0x02).
//! Requests are issued sequentially per connection and correlated by the
//! monotonic sequence number.

use crate::discovery::{
    DiscoveryBody, DiscoveryMessage, SignalRelayBody, SignalRelayMessage, SignalRelayRequest,
    PROTO_CHUNK, PROTO_DISCOVERY, PROTO_SIGNAL,
};
use crate::protocol::{ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody};
use crate::tunnel::{ClientHandshake, SessionCipher, MAX_SEQ};
use crate::webrtc::Transport;
use futures::lock::Mutex;
use std::cell::Cell;

/// An authenticated session with one node.
///
/// A connection carries one request at a time: each round-trip sends a
/// sequence-numbered request and awaits the matching response frame, so two
/// overlapping round-trips on the same connection would mismatch. The
/// `request_lock` serialises callers, which lets higher layers fan out
/// requests across *different* connections concurrently (parallel download)
/// while requests to the *same* connection queue safely.
pub struct NodeConnection {
    transport: Transport,
    cipher: SessionCipher,
    peer_id: [u8; 32],
    next_seq: Cell<u32>,
    request_lock: Mutex<()>,
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
        Self::establish(transport, expected_peer_id).await
    }

    /// Connect to a NAT'd target node via full ICE, relaying SDP through
    /// `relay` (a node we already have an open tunnel to). `stun` is `ip:port`
    /// of any reachable node used as the browser's ICE/STUN server.
    pub async fn connect_via_relay(
        relay: &NodeConnection,
        stun: &str,
        target_peer_id: [u8; 32],
    ) -> Result<Self, String> {
        let transport = Transport::connect_via_relay(stun, |offer_sdp| {
            relay.signal_relay(target_peer_id, offer_sdp)
        })
        .await?;
        Self::establish(transport, Some(&target_peer_id)).await
    }

    /// Run the PQC handshake over an open transport and build the session.
    async fn establish(
        transport: Transport,
        expected_peer_id: Option<&[u8; 32]>,
    ) -> Result<Self, String> {
        let (handshake, hello) = ClientHandshake::start()?;
        transport.send_frame(&hello)?;
        let accept = transport.recv_frame().await?;
        let established = handshake.finish(&accept, expected_peer_id)?;

        Ok(Self {
            transport,
            cipher: established.cipher,
            peer_id: established.peer_id,
            next_seq: Cell::new(1),
            request_lock: Mutex::new(()),
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
        // Hold the request lock for the whole send→recv cycle so overlapping
        // callers on this connection queue instead of racing on the response
        // frame / sequence number.
        let _guard = self.request_lock.lock().await;
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

    /// Ask this (reachable) node to relay an ICE offer to a NAT'd target
    /// node, returning the target's SDP answer.
    pub async fn signal_relay(
        &self,
        target_peer_id: [u8; 32],
        sdp_offer: String,
    ) -> Result<String, String> {
        let request = SignalRelayMessage {
            request_id: u64::from(self.next_seq.get()),
            body: SignalRelayBody::Request(SignalRelayRequest {
                target_peer_id,
                sdp_offer,
            }),
        };
        let plaintext = self.round_trip(PROTO_SIGNAL, &request.encode()?).await?;
        let response = SignalRelayMessage::decode(&plaintext)?;
        match response.body {
            SignalRelayBody::Response(r) => Ok(r.sdp_answer),
            SignalRelayBody::Error(e) => Err(format!("signal relay error: {e}")),
            SignalRelayBody::Request(_) => Err("unexpected signal-relay response".into()),
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
