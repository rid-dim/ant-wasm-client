//! SDP munging for signaling-less WebRTC-Direct (client side).
//!
//! The browser generates its offer, we replace its ICE credentials with our
//! chosen ufrag (used as both ufrag and password), and synthesize the
//! server's answer locally from `ip:port + certificate fingerprint`.
//!
//! Adapted from the MIT-licensed `webrtc-direct` protocol crate
//! (vastrum/webrtc-direct), following the libp2p WebRTC-Direct spec.

/// Replace `a=ice-ufrag:` and `a=ice-pwd:` values in an SDP offer.
///
/// Returns the munged SDP; errors if the offer lacks either line.
pub fn munge_offer(sdp: &str, ufrag: &str) -> Result<String, String> {
    let mut out = String::with_capacity(sdp.len() + 64);
    let mut replaced = 0;
    for line in sdp.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with("a=ice-ufrag:") {
            out.push_str("a=ice-ufrag:");
            out.push_str(ufrag);
            replaced += 1;
        } else if line.starts_with("a=ice-pwd:") {
            out.push_str("a=ice-pwd:");
            out.push_str(ufrag);
            replaced += 1;
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    if replaced != 2 {
        return Err(format!(
            "SDP offer missing ice-ufrag/ice-pwd (replaced {replaced})"
        ));
    }
    Ok(out)
}

/// Synthesize the server's SDP answer.
///
/// `fingerprint_colon` is the SHA-256 certificate fingerprint in
/// `AA:BB:…` form. The server is ICE-lite and DTLS-passive.
pub fn server_answer(ip: &str, port: u16, ufrag: &str, fingerprint_colon: &str) -> String {
    let v = if ip.contains(':') { "IP6" } else { "IP4" };
    format!(
        "v=0\r\n\
         o=- 0 0 IN {v} {ip}\r\n\
         s=-\r\n\
         t=0 0\r\n\
         a=ice-lite\r\n\
         m=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\n\
         c=IN {v} {ip}\r\n\
         a=mid:0\r\n\
         a=ice-options:ice2\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{ufrag}\r\n\
         a=fingerprint:sha-256 {fingerprint_colon}\r\n\
         a=setup:passive\r\n\
         a=sctp-port:5000\r\n\
         a=max-message-size:5242880\r\n\
         a=candidate:1467250027 1 UDP 1467250027 {ip} {port} typ host\r\n\
         a=end-of-candidates\r\n"
    )
}

/// Format a hex fingerprint (no colons) as `AA:BB:…` for SDP.
pub fn fingerprint_to_colon_form(hex_fp: &str) -> String {
    hex_fp
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("").to_uppercase())
        .collect::<Vec<_>>()
        .join(":")
}
