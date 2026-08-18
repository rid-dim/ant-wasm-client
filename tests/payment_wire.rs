//! The payment mirror must reproduce evmlib's bytes exactly.
//!
//! The fixtures in `tests/fixtures/` were generated with the REAL
//! `evmlib` 0.9.1 / `ant-protocol` 2.3.2 types by the throwaway native crate
//! kept alongside them (`tests/fixtures/fixture-gen`, `cargo run --release`
//! from that directory): `payment_quote.rmp` is
//! `rmp_serde::to_vec(&PaymentQuote)`, `single_node_proof.bin` is
//! `ant_protocol::payment::proof::serialize_single_node_proof(&PaymentProof)`,
//! and `payment_quote.json` carries the same values in readable form plus the
//! hex of `bytes_for_sig()` and `hash()`.

use ant_wasm_client::payment::{
    bytes_for_sig, encode_quote, parse_quote, parse_single_node_proof, quote_hash,
    serialize_single_node_proof, PeerId, Quote, Timestamp, PROOF_TAG_SINGLE_NODE,
};
use serde_json::Value;

const QUOTE_RMP: &[u8] = include_bytes!("fixtures/payment_quote.rmp");
const PROOF_BIN: &[u8] = include_bytes!("fixtures/single_node_proof.bin");
const QUOTE_JSON: &str = include_str!("fixtures/payment_quote.json");

fn json() -> Value {
    serde_json::from_str(QUOTE_JSON).expect("fixture json")
}

fn hex32(v: &Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(v.as_str().expect("hex string")).expect("hex"));
    out
}

fn hex20(v: &Value) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&hex::decode(v.as_str().expect("hex string")).expect("hex"));
    out
}

/// Rebuild a [`Quote`] purely from the JSON description of it.
fn quote_from_json(q: &Value) -> Quote {
    Quote {
        content: hex32(&q["content_hex"]),
        timestamp: Timestamp {
            secs: q["timestamp_secs"].as_u64().expect("secs"),
            nanos: u32::try_from(q["timestamp_nanos"].as_u64().expect("nanos")).expect("u32"),
        },
        price: hex32(&q["price_be_hex"]),
        rewards_address: hex20(&q["rewards_address_hex"]),
        pub_key: vec![
            u8::try_from(q["pub_key_fill"].as_u64().expect("fill")).expect("u8");
            usize::try_from(q["pub_key_len"].as_u64().expect("len")).expect("usize")
        ],
        signature: vec![
            u8::try_from(q["signature_fill"].as_u64().expect("fill")).expect("u8");
            usize::try_from(q["signature_len"].as_u64().expect("len")).expect("usize")
        ],
        committed_key_count: u32::try_from(q["committed_key_count"].as_u64().expect("count"))
            .expect("u32"),
        commitment_pin: match &q["commitment_pin_hex"] {
            Value::Null => None,
            v => Some(hex32(v)),
        },
    }
}

#[test]
fn decodes_every_field_of_the_evmlib_quote() {
    let doc = json();
    let expected = &doc["quote"];
    let quote = parse_quote(QUOTE_RMP).expect("decode fixture quote");

    assert_eq!(hex::encode(quote.content), expected["content_hex"]);
    assert_eq!(quote.timestamp.secs, expected["timestamp_secs"]);
    assert_eq!(u64::from(quote.timestamp.nanos), expected["timestamp_nanos"]);
    assert_eq!(hex::encode(quote.price), expected["price_be_hex"]);
    assert_eq!(
        hex::encode(quote.rewards_address),
        expected["rewards_address_hex"]
    );
    assert_eq!(quote.pub_key.len() as u64, expected["pub_key_len"]);
    assert!(quote
        .pub_key
        .iter()
        .all(|b| u64::from(*b) == expected["pub_key_fill"].as_u64().unwrap()));
    assert_eq!(quote.signature.len() as u64, expected["signature_len"]);
    assert!(quote
        .signature
        .iter()
        .all(|b| u64::from(*b) == expected["signature_fill"].as_u64().unwrap()));
    assert_eq!(
        u64::from(quote.committed_key_count),
        expected["committed_key_count"]
    );
    assert_eq!(
        quote.commitment_pin.map(hex::encode),
        expected["commitment_pin_hex"].as_str().map(str::to_owned)
    );

    // ... and the JSON description alone rebuilds the identical value.
    assert_eq!(quote, quote_from_json(expected));
}

#[test]
fn reencodes_the_quote_byte_for_byte() {
    let quote = parse_quote(QUOTE_RMP).expect("decode fixture quote");
    let bytes = encode_quote(&quote).expect("encode quote");
    assert_eq!(bytes, QUOTE_RMP, "re-encoded quote differs from evmlib's");

    // And building the quote from scratch (no decode step) is identical too.
    let built = quote_from_json(&json()["quote"]);
    assert_eq!(encode_quote(&built).expect("encode built"), QUOTE_RMP);
}

#[test]
fn matches_the_signed_payload_and_quote_hash() {
    let doc = json();
    let expected = &doc["quote"];
    let quote = parse_quote(QUOTE_RMP).expect("decode fixture quote");

    assert_eq!(
        hex::encode(bytes_for_sig(&quote)),
        expected["bytes_for_sig_hex"],
        "bytes_for_sig mismatch"
    );
    assert_eq!(
        hex::encode(quote_hash(&quote)),
        expected["hash_hex"],
        "quote hash (keccak256) mismatch"
    );
}

#[test]
fn builds_the_tagged_single_node_proof_byte_for_byte() {
    let doc = json();
    let proof = &doc["proof"];

    assert_eq!(
        u64::from(PROOF_TAG_SINGLE_NODE),
        proof["tag_byte"].as_u64().expect("tag"),
        "proof tag byte mismatch"
    );

    let peer_quotes: Vec<([u8; 32], Quote)> = proof["peer_quotes"]
        .as_array()
        .expect("peer_quotes")
        .iter()
        .map(|pq| (hex32(&pq["peer_id_hex"]), quote_from_json(&pq["quote"])))
        .collect();
    assert_eq!(peer_quotes.len(), 7);

    let tx_hash = hex32(&proof["tx_hashes_hex"][0]);
    let sidecars: Vec<Vec<u8>> = proof["commitment_sidecars_hex"]
        .as_array()
        .expect("sidecars")
        .iter()
        .map(|v| hex::decode(v.as_str().expect("hex string")).expect("hex"))
        .collect();
    assert_eq!(sidecars.len(), 2);

    let bytes =
        serialize_single_node_proof(peer_quotes.clone(), tx_hash, sidecars.clone()).expect("encode");
    assert_eq!(bytes.len(), proof["total_len"].as_u64().expect("len") as usize);
    assert_eq!(bytes, PROOF_BIN, "proof bytes differ from ant-protocol's");
}

#[test]
fn decodes_the_tagged_single_node_proof() {
    let doc = json();
    let expected = &doc["proof"];
    let decoded = parse_single_node_proof(PROOF_BIN).expect("decode proof");

    assert_eq!(decoded.proof_of_payment.peer_quotes.len(), 7);
    for (pq, expected_pq) in decoded
        .proof_of_payment
        .peer_quotes
        .iter()
        .zip(expected["peer_quotes"].as_array().expect("peer_quotes"))
    {
        assert_eq!(hex::encode(pq.0 .0), expected_pq["peer_id_hex"]);
        assert_eq!(pq.1, quote_from_json(&expected_pq["quote"]));
    }
    assert_eq!(decoded.tx_hashes.len(), 1);
    assert_eq!(
        hex::encode(decoded.tx_hashes[0].0),
        expected["tx_hashes_hex"][0]
    );
    assert_eq!(
        decoded
            .commitment_sidecars
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        expected["commitment_sidecars_hex"]
            .as_array()
            .expect("sidecars")
            .iter()
            .map(|v| v.as_str().expect("str").to_owned())
            .collect::<Vec<_>>()
    );

    // A wrong / missing tag byte is rejected rather than mis-parsed.
    assert!(parse_single_node_proof(&[]).is_err());
    let mut bad = PROOF_BIN.to_vec();
    bad[0] = 0x02;
    assert!(parse_single_node_proof(&bad).is_err());
}

#[test]
fn old_format_quote_decodes_via_trailing_defaults() {
    // ADR-0004: a 6-field (pre-commitment) quote must still decode, with the
    // two tail fields defaulted — the reason they are `serde(default)` and
    // last. Build one by truncating the 8-element array header to 6.
    let quote = parse_quote(QUOTE_RMP).expect("decode fixture quote");
    let mut old = encode_quote(&Quote {
        committed_key_count: 0,
        commitment_pin: None,
        ..quote.clone()
    })
    .expect("encode");
    assert_eq!(old[0], 0x98, "8-field fixarray header expected");
    old[0] = 0x96; // 6-field array
    old.truncate(old.len() - 2); // drop the two tail values (0x00, 0xc0)

    let decoded = parse_quote(&old).expect("decode old-format quote");
    assert_eq!(decoded.committed_key_count, 0);
    assert_eq!(decoded.commitment_pin, None);
    assert_eq!(decoded.content, quote.content);
    assert_eq!(decoded.signature, quote.signature);
}

#[test]
fn peer_id_encodes_as_a_msgpack_array_not_a_bin() {
    // evmlib's `serde_byte_array` writes a slice (a seq), so a peer id is an
    // array of 32 uints, while alloy's FixedBytes/U256 are msgpack `bin`s.
    let encoded = rmp_serde::to_vec(&PeerId([0x01; 32])).expect("encode");
    assert_eq!(&encoded[..3], &[0xdc, 0x00, 0x20]); // array16, len 32
    assert_eq!(encoded.len(), 3 + 32);
}
