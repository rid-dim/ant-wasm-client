//! Generates byte-exact fixtures with the REAL evmlib / ant-protocol types.

use ant_protocol::payment::proof::{serialize_single_node_proof, PaymentProof};
use evmlib::common::{Address, Amount, TxHash};
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment};
use serde_json::json;
use std::time::{Duration, UNIX_EPOCH};
use xor_name::XorName;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32 * 7 + seed as u32 * 31 + 3) % 256) as u8)
        .collect()
}

fn arr32(seed: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&pattern(32, seed));
    a
}

fn arr20(seed: u8) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&pattern(20, seed));
    a
}

/// A quote built from purely deterministic parameters.
struct QuoteSpec {
    content_seed: u8,
    secs: u64,
    nanos: u32,
    /// big-endian 32-byte price
    price_be: [u8; 32],
    addr_seed: u8,
    pub_key_fill: u8,
    pub_key_len: usize,
    sig_fill: u8,
    sig_len: usize,
    committed_key_count: u32,
    commitment_pin: Option<[u8; 32]>,
}

impl QuoteSpec {
    fn build(&self) -> PaymentQuote {
        PaymentQuote {
            content: XorName(arr32(self.content_seed)),
            timestamp: UNIX_EPOCH + Duration::new(self.secs, self.nanos),
            price: Amount::from_be_bytes(self.price_be),
            rewards_address: Address::from(arr20(self.addr_seed)),
            pub_key: vec![self.pub_key_fill; self.pub_key_len],
            signature: vec![self.sig_fill; self.sig_len],
            committed_key_count: self.committed_key_count,
            commitment_pin: self.commitment_pin,
        }
    }

    fn json(&self) -> serde_json::Value {
        let q = self.build();
        json!({
            "content_hex": hex::encode(q.content.0),
            "timestamp_secs": self.secs,
            "timestamp_nanos": self.nanos,
            "price_be_hex": hex::encode(self.price_be),
            "price_dec": q.price.to_string(),
            "rewards_address_hex": hex::encode(q.rewards_address.as_slice()),
            "pub_key_fill": self.pub_key_fill,
            "pub_key_len": self.pub_key_len,
            "signature_fill": self.sig_fill,
            "signature_len": self.sig_len,
            "committed_key_count": self.committed_key_count,
            "commitment_pin_hex": self.commitment_pin.map(hex::encode),
            "bytes_for_sig_hex": hex::encode(q.bytes_for_sig()),
            "hash_hex": hex::encode(q.hash().as_slice()),
        })
    }
}

fn price_be(hi: u8) -> [u8; 32] {
    // 0x0123456789abcdef... style, varied by `hi`
    let mut p = [0u8; 32];
    for (i, b) in p.iter_mut().enumerate() {
        *b = ((i as u32 * 17 + hi as u32 * 5) % 256) as u8;
    }
    p
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("fixtures")?;

    // ---- 1. the single canonical PaymentQuote -------------------------------
    let main_spec = QuoteSpec {
        content_seed: 1,
        secs: 1_700_000_000,
        nanos: 123_456_789,
        price_be: {
            let mut p = [0u8; 32];
            // 0x00000000000000000000000000000000000000000000000ddeadbeefcafe0001
            let tail = hex::decode("00000000000000000000000000000000000000000000000d\
                                    deadbeefcafe0001")
                .unwrap();
            p.copy_from_slice(&tail);
            p
        },
        addr_seed: 2,
        pub_key_fill: 7,
        pub_key_len: 1952,
        sig_fill: 9,
        sig_len: 3309,
        committed_key_count: 424_242,
        commitment_pin: Some(arr32(3)),
    };
    let quote = main_spec.build();
    let rmp = rmp_serde::to_vec(&quote)?;
    std::fs::write("fixtures/payment_quote.rmp", &rmp)?;

    // sanity: roundtrip through the real type
    let back: PaymentQuote = rmp_serde::from_slice(&rmp)?;
    assert_eq!(back, quote, "evmlib roundtrip failed");
    assert_eq!(rmp_serde::to_vec(&back)?, rmp);

    // ---- 2. the 7-quote single node proof ----------------------------------
    // Deliberately varied: baseline (count 0 / pin None) quotes, high-byte
    // fills (exercise msgpack 2-byte uint elements), zero price, nanos = 0.
    let proof_specs: Vec<(u8, QuoteSpec)> = vec![
        (
            10,
            QuoteSpec {
                content_seed: 11,
                secs: 1_700_000_001,
                nanos: 0,
                price_be: price_be(1),
                addr_seed: 12,
                pub_key_fill: 7,
                pub_key_len: 1952,
                sig_fill: 9,
                sig_len: 3309,
                committed_key_count: 0,
                commitment_pin: None,
            },
        ),
        (
            20,
            QuoteSpec {
                content_seed: 11,
                secs: 1_700_000_002,
                nanos: 999_999_999,
                price_be: [0u8; 32],
                addr_seed: 22,
                pub_key_fill: 0xAA,
                pub_key_len: 1952,
                sig_fill: 0xFF,
                sig_len: 3309,
                committed_key_count: 1,
                commitment_pin: Some(arr32(23)),
            },
        ),
        (
            30,
            QuoteSpec {
                content_seed: 11,
                secs: 1_700_000_003,
                nanos: 1,
                price_be: price_be(3),
                addr_seed: 32,
                pub_key_fill: 0x80,
                pub_key_len: 1952,
                sig_fill: 0x7F,
                sig_len: 3309,
                committed_key_count: 4_294_967_295,
                commitment_pin: Some([0u8; 32]),
            },
        ),
        (
            40,
            QuoteSpec {
                content_seed: 11,
                secs: 0,
                nanos: 0,
                price_be: price_be(4),
                addr_seed: 42,
                pub_key_fill: 0,
                pub_key_len: 1952,
                sig_fill: 1,
                sig_len: 3309,
                committed_key_count: 300,
                commitment_pin: None,
            },
        ),
        (
            50,
            QuoteSpec {
                content_seed: 11,
                secs: 1_700_000_005,
                nanos: 500_000_000,
                price_be: price_be(5),
                addr_seed: 52,
                pub_key_fill: 7,
                pub_key_len: 1952,
                sig_fill: 9,
                sig_len: 3309,
                committed_key_count: 65_536,
                commitment_pin: Some(arr32(53)),
            },
        ),
        (
            60,
            QuoteSpec {
                content_seed: 11,
                secs: 4_294_967_296,
                nanos: 7,
                price_be: {
                    let mut p = [0xFFu8; 32];
                    p[0] = 0xFF;
                    p
                },
                addr_seed: 62,
                pub_key_fill: 7,
                pub_key_len: 1952,
                sig_fill: 9,
                sig_len: 3309,
                committed_key_count: 0,
                commitment_pin: None,
            },
        ),
        (
            70,
            QuoteSpec {
                content_seed: 11,
                secs: 1_700_000_007,
                nanos: 42,
                price_be: price_be(7),
                addr_seed: 72,
                pub_key_fill: 7,
                pub_key_len: 1952,
                sig_fill: 9,
                sig_len: 3309,
                committed_key_count: 128,
                commitment_pin: Some(arr32(73)),
            },
        ),
    ];

    let peer_quotes: Vec<(EncodedPeerId, PaymentQuote)> = proof_specs
        .iter()
        .map(|(peer_seed, spec)| (EncodedPeerId::new(arr32(*peer_seed)), spec.build()))
        .collect();

    let tx_hash_bytes = arr32(90);
    let sidecars: Vec<Vec<u8>> = vec![pattern(37, 91), pattern(600, 92)];

    let payment_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: peer_quotes.clone(),
        },
        tx_hashes: vec![TxHash::from(tx_hash_bytes)],
        commitment_sidecars: sidecars.clone(),
    };
    let tagged = serialize_single_node_proof(&payment_proof)?;
    std::fs::write("fixtures/single_node_proof.bin", &tagged)?;

    // ---- 3. the JSON cross-check -------------------------------------------
    let doc = json!({
        "quote": main_spec.json(),
        "quote_rmp_len": rmp.len(),
        "quote_rmp_head_hex": hex::encode(&rmp[..64.min(rmp.len())]),
        "proof": {
            "tag_byte": ant_protocol::PROOF_TAG_SINGLE_NODE,
            "peer_quotes": proof_specs
                .iter()
                .map(|(peer_seed, spec)| json!({
                    "peer_id_hex": hex::encode(arr32(*peer_seed)),
                    "quote": spec.json(),
                }))
                .collect::<Vec<_>>(),
            "tx_hashes_hex": [hex::encode(tx_hash_bytes)],
            "commitment_sidecars_hex": sidecars.iter().map(hex::encode).collect::<Vec<_>>(),
            "total_len": tagged.len(),
        },
    });
    std::fs::write(
        "fixtures/payment_quote.json",
        serde_json::to_string_pretty(&doc)? + "\n",
    )?;

    // ---- 4. wire-format probes (printed, for the mirror author) ------------
    println!("quote rmp len = {}", rmp.len());
    println!("quote rmp first 80 bytes: {}", hex::encode(&rmp[..80]));
    println!("proof len = {}", tagged.len());
    println!("proof first 16 bytes: {}", hex::encode(&tagged[..16]));

    // isolate individual encodings
    println!(
        "XorName alone: {}",
        hex::encode(rmp_serde::to_vec(&XorName(arr32(1)))?)
    );
    println!(
        "SystemTime alone: {}",
        hex::encode(rmp_serde::to_vec(&(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789)))?)
    );
    println!(
        "Amount alone: {}",
        hex::encode(rmp_serde::to_vec(&Amount::from_be_bytes(price_be(1)))?)
    );
    println!(
        "Amount zero: {}",
        hex::encode(rmp_serde::to_vec(&Amount::from_be_bytes([0u8; 32]))?)
    );
    println!(
        "Address alone: {}",
        hex::encode(rmp_serde::to_vec(&Address::from(arr20(2)))?)
    );
    println!(
        "EncodedPeerId alone: {}",
        hex::encode(rmp_serde::to_vec(&EncodedPeerId::new(arr32(10)))?)
    );
    println!(
        "TxHash alone: {}",
        hex::encode(rmp_serde::to_vec(&TxHash::from(arr32(90)))?)
    );
    println!(
        "Option<[u8;32]> Some: {}",
        hex::encode(rmp_serde::to_vec(&Some(arr32(3)))?)
    );
    println!(
        "Option<[u8;32]> None: {}",
        hex::encode(rmp_serde::to_vec(&Option::<[u8; 32]>::None)?)
    );
    println!(
        "Vec<u8> len 5: {}",
        hex::encode(rmp_serde::to_vec(&vec![7u8, 200, 9, 0, 255])?)
    );

    Ok(())
}
