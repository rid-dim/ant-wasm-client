//! Browser WebRTC-Direct connection via `web-sys`.
//!
//! Opens an `RTCPeerConnection` to a node without a signaling server: the
//! offer is munged with a self-chosen ufrag, the answer is synthesized
//! locally from the node's `ip:port` and certificate fingerprint (which the
//! browser pins), and a pre-negotiated `DataChannel` (id 0) carries
//! length-prefixed frames.
//!
//! Connection flow adapted from the MIT-licensed `webrtc-direct-client`
//! crate (vastrum/webrtc-direct).

use crate::framing::{encode_frame, split_messages, FrameBuf};
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcDataChannel, RtcDataChannelState, RtcPeerConnection, RtcSdpType,
    RtcSessionDescriptionInit,
};

/// A connected WebRTC-Direct transport carrying framed messages.
pub struct Transport {
    _connection: RtcPeerConnection,
    data_channel: RtcDataChannel,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(web_sys::Event)>,
    receiver: RefCell<mpsc::UnboundedReceiver<Vec<u8>>>,
    frame_buf: RefCell<FrameBuf>,
}

impl Transport {
    /// Connect to `ip:port` pinning the certificate `fingerprint_hex`
    /// (SHA-256, plain hex).
    pub async fn connect(ip: &str, port: u16, fingerprint_hex: &str) -> Result<Self, String> {
        let config = web_sys::RtcConfiguration::new();
        config.set_ice_servers(&js_sys::Array::new());
        let pc = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|e| format!("RTCPeerConnection: {e:?}"))?;

        let dc_init = web_sys::RtcDataChannelInit::new();
        dc_init.set_negotiated(true);
        dc_init.set_id(0);
        let dc = pc.create_data_channel_with_data_channel_dict("ant", &dc_init);

        // Self-chosen ufrag: 64 hex chars (32 random bytes).
        let mut ufrag_bytes = [0u8; 32];
        getrandom::getrandom(&mut ufrag_bytes).map_err(|e| format!("getrandom: {e}"))?;
        let ufrag = hex::encode(ufrag_bytes);

        let offer = JsFuture::from(pc.create_offer())
            .await
            .map_err(|e| format!("createOffer: {e:?}"))?;
        let offer: web_sys::RtcSessionDescription = offer.unchecked_into();
        let munged_sdp = crate::sdp::munge_offer(&offer.sdp(), &ufrag)?;
        let local = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        local.set_sdp(&munged_sdp);
        JsFuture::from(pc.set_local_description(&local))
            .await
            .map_err(|e| format!("setLocalDescription: {e:?}"))?;

        let colon_fp = crate::sdp::fingerprint_to_colon_form(fingerprint_hex);
        let answer_sdp = crate::sdp::server_answer(ip, port, &ufrag, &colon_fp);
        let remote = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        remote.set_sdp(&answer_sdp);
        JsFuture::from(pc.set_remote_description(&remote))
            .await
            .map_err(|e| format!("setRemoteDescription: {e:?}"))?;

        Self::wait_for_open(&dc).await?;
        dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

        let (tx, receiver) = mpsc::unbounded();
        let close_tx = tx.clone();
        let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
            let Ok(buf) = event.data().dyn_into::<js_sys::ArrayBuffer>() else {
                return;
            };
            let bytes = js_sys::Uint8Array::new(&buf).to_vec();
            let _ = tx.unbounded_send(bytes);
        }) as Box<dyn FnMut(MessageEvent)>);
        let on_close = Closure::wrap(Box::new(move |_: web_sys::Event| {
            close_tx.close_channel();
        }) as Box<dyn FnMut(web_sys::Event)>);
        dc.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        dc.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        Ok(Self {
            _connection: pc,
            data_channel: dc,
            _on_message: on_message,
            _on_close: on_close,
            receiver: RefCell::new(receiver),
            frame_buf: RefCell::new(FrameBuf::new()),
        })
    }

    async fn wait_for_open(dc: &RtcDataChannel) -> Result<(), String> {
        if dc.ready_state() == RtcDataChannelState::Open {
            return Ok(());
        }
        let (tx, rx) = oneshot::channel::<()>();
        let tx = Rc::new(RefCell::new(Some(tx)));
        let notify = Closure::wrap(Box::new(move || {
            if let Some(tx) = tx.borrow_mut().take() {
                let _ = tx.send(());
            }
        }) as Box<dyn FnMut()>);
        dc.set_onopen(Some(notify.as_ref().unchecked_ref()));
        dc.set_onerror(Some(notify.as_ref().unchecked_ref()));

        let timeout = gloo_timers::future::TimeoutFuture::new(15_000);
        futures::future::select(Box::pin(rx), Box::pin(timeout)).await;

        dc.set_onopen(None);
        dc.set_onerror(None);

        if dc.ready_state() == RtcDataChannelState::Open {
            Ok(())
        } else {
            Err(format!(
                "DataChannel did not open (state: {:?})",
                dc.ready_state()
            ))
        }
    }

    /// Send one application frame.
    pub fn send_frame(&self, payload: &[u8]) -> Result<(), String> {
        let wire = encode_frame(payload);
        for msg in split_messages(&wire) {
            self.data_channel
                .send_with_u8_array(msg)
                .map_err(|e| format!("DataChannel send: {e:?}"))?;
        }
        Ok(())
    }

    /// Receive the next complete application frame.
    ///
    /// The `receiver` borrow is held across the await, which is sound here:
    /// a `NodeConnection` issues one request at a time, so there is never a
    /// second concurrent `recv_frame` on the same connection to clash with
    /// the borrow.
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn recv_frame(&self) -> Result<Vec<u8>, String> {
        loop {
            if let Some(frame) = self.frame_buf.borrow_mut().push(&[])? {
                return Ok(frame);
            }
            let raw = self
                .receiver
                .borrow_mut()
                .next()
                .await
                .ok_or_else(|| "connection closed".to_string())?;
            if let Some(frame) = self.frame_buf.borrow_mut().push(&raw)? {
                return Ok(frame);
            }
        }
    }
}
