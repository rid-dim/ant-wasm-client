//! Hand-rolled EVM ABI calldata for the two on-chain calls the upload flow
//! needs, plus the big-endian 256-bit arithmetic and the single-node payment
//! split.
//!
//! No `alloy`/`ethers`: those pull a native provider/transport stack that does
//! not compile to wasm. The browser never signs or broadcasts here — it hands
//! the finished `(to, calldata)` pair to a JS callback (MetaMask, a viem
//! wallet, …) which submits it and returns the transaction hash. So this
//! module only needs to *encode* calldata, never talk to a node.
//!
//! The two calls mirror `evmlib` 0.9.1 (`external_signer.rs` /
//! `contract/payment_vault`):
//!
//! * ERC-20 `approve(spender, amount)` — let the payment vault pull `amount`
//!   of the payment token.
//! * `payForQuotes(DataPayment[])` where
//!   `DataPayment = (address rewardsAddress, uint256 amount, bytes32 quoteHash)`.
//!
//! The split itself mirrors the node's `SingleNodePayment::from_quotes`:
//! exactly seven quotes, sorted ascending by price, the median (index 3) pays
//! `price × 3` and everyone else pays nothing.

use crate::payment::{quote_hash, Quote};
use core::cmp::Ordering;
use sha3::{Digest, Keccak256};

/// One `DataPayment` for `payForQuotes`: `(rewardsAddress, amount_be,
/// quoteHash)` — the ABI struct order the contract expects.
pub type DataPayment = ([u8; 20], [u8; 32], [u8; 32]);

/// ERC-20 `approve(address,uint256)` selector — `keccak256(sig)[..4]`.
pub const ERC20_APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// The number of quotes a single-node payment requires (mirror of
/// `CLOSE_GROUP_SIZE`).
pub const CLOSE_GROUP_SIZE: usize = 7;

/// Left-pad a 20-byte address into a 32-byte ABI word.
#[must_use]
fn word_from_address(addr: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&addr);
    word
}

/// ABI calldata for ERC-20 `approve(spender, amount)`:
/// selector ‖ left-pad-32(spender) ‖ amount (32-byte big-endian).
#[must_use]
pub fn approve_calldata(spender: [u8; 20], amount: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&ERC20_APPROVE_SELECTOR);
    out.extend_from_slice(&word_from_address(spender));
    out.extend_from_slice(&amount);
    out
}

/// The `payForQuotes((address,uint256,bytes32)[])` selector,
/// `keccak256(sig)[..4]`.
#[must_use]
pub fn pay_for_quotes_selector() -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(b"payForQuotes((address,uint256,bytes32)[])");
    let digest: [u8; 32] = hasher.finalize().into();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// ABI calldata for `payForQuotes(DataPayment[])`, where
/// `DataPayment = (address rewardsAddress, uint256 amount, bytes32 quoteHash)`.
///
/// The single parameter is a dynamic array of a *static* 3-word struct, so the
/// encoding is: selector ‖ offset(0x20) ‖ length ‖ (rewards ‖ amount ‖
/// quoteHash) per element. No per-element offsets — every element is static.
#[must_use]
pub fn pay_for_quotes_calldata(payments: &[DataPayment]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64 + payments.len() * 96);
    out.extend_from_slice(&pay_for_quotes_selector());

    // Head: offset to the (only) dynamic parameter — one word past this head.
    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    out.extend_from_slice(&offset);

    // Array length, big-endian in the low bytes.
    let mut len_word = [0u8; 32];
    len_word[24..].copy_from_slice(&(payments.len() as u64).to_be_bytes());
    out.extend_from_slice(&len_word);

    for (rewards, amount, quote_hash) in payments {
        out.extend_from_slice(&word_from_address(*rewards));
        out.extend_from_slice(amount);
        out.extend_from_slice(quote_hash);
    }
    out
}

/// Big-endian 256-bit addition (wrapping past 2^256, which the callers never
/// reach — a total of seven small prices).
#[must_use]
pub fn u256_add(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

/// Big-endian 256-bit multiply by a `u64` (wrapping past 2^256).
#[must_use]
pub fn u256_mul_u64(a: [u8; 32], m: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u128;
    for i in (0..32).rev() {
        let prod = u128::from(a[i]) * u128::from(m) + carry;
        out[i] = (prod & 0xff) as u8;
        carry = prod >> 8;
    }
    out
}

/// Compare two big-endian 256-bit integers.
#[must_use]
pub fn u256_cmp(a: [u8; 32], b: [u8; 32]) -> Ordering {
    // Big-endian byte order is the numeric order.
    a.cmp(&b)
}

/// Sum a set of `(rewards, amount, quote_hash)` payments into one 256-bit
/// approve amount.
#[must_use]
pub fn total_amount(payments: &[DataPayment]) -> [u8; 32] {
    payments
        .iter()
        .fold([0u8; 32], |acc, (_, amount, _)| u256_add(acc, *amount))
}

/// Compute the single-node payment split for exactly seven quotes — mirror of
/// the node's `SingleNodePayment::from_quotes`.
///
/// Quotes are ranked ascending by price; the median (rank index 3) is paid
/// `price × 3`, everyone else zero. The returned vector is in the SAME order
/// as `quotes` so it lines up with the `ProofOfPayment` peer-quote order.
///
/// # Errors
/// Returns an error string unless exactly [`CLOSE_GROUP_SIZE`] quotes are given.
pub fn payment_split(quotes: &[Quote]) -> Result<Vec<DataPayment>, String> {
    if quotes.len() != CLOSE_GROUP_SIZE {
        return Err(format!(
            "payment split needs exactly {CLOSE_GROUP_SIZE} quotes, got {}",
            quotes.len()
        ));
    }

    // Rank the quote indices ascending by price.
    let mut ranked: Vec<usize> = (0..quotes.len()).collect();
    ranked.sort_by(|&i, &j| u256_cmp(quotes[i].price, quotes[j].price));
    let median_idx = ranked[3];
    let median_price_x3 = u256_mul_u64(quotes[median_idx].price, 3);

    Ok(quotes
        .iter()
        .enumerate()
        .map(|(i, q)| {
            let amount = if i == median_idx {
                median_price_x3
            } else {
                [0u8; 32]
            };
            (q.rewards_address, amount, quote_hash(q))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u256_from_u64(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }

    #[test]
    fn approve_selector_matches_keccak() {
        let mut hasher = Keccak256::new();
        hasher.update(b"approve(address,uint256)");
        let digest: [u8; 32] = hasher.finalize().into();
        assert_eq!(&digest[..4], &ERC20_APPROVE_SELECTOR);
    }

    #[test]
    fn pay_for_quotes_selector_is_b6c2141b() {
        assert_eq!(pay_for_quotes_selector(), [0xb6, 0xc2, 0x14, 0x1b]);
    }

    #[test]
    fn approve_calldata_layout() {
        let spender = [0xabu8; 20];
        let amount = u256_from_u64(0x1234);
        let data = approve_calldata(spender, amount);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[..4], &ERC20_APPROVE_SELECTOR);
        // spender left-padded: first 12 bytes zero, then the address.
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &spender);
        assert_eq!(&data[36..], &amount);
    }

    #[test]
    fn pay_for_quotes_calldata_layout() {
        let payments = vec![
            ([0x11u8; 20], u256_from_u64(5), [0x22u8; 32]),
            ([0x33u8; 20], u256_from_u64(0), [0x44u8; 32]),
        ];
        let data = pay_for_quotes_calldata(&payments);
        assert_eq!(data.len(), 4 + 32 + 32 + 2 * 96);
        assert_eq!(&data[..4], &pay_for_quotes_selector());
        // offset word == 0x20
        assert_eq!(data[4 + 31], 0x20);
        assert_eq!(&data[4..4 + 31], &[0u8; 31]);
        // length word == 2
        assert_eq!(data[4 + 63], 2);
        // first element: rewards left-padded, then amount, then quote hash.
        let el0 = &data[68..68 + 96];
        assert_eq!(&el0[..12], &[0u8; 12]);
        assert_eq!(&el0[12..32], &[0x11u8; 20]);
        assert_eq!(&el0[32..64], &u256_from_u64(5));
        assert_eq!(&el0[64..96], &[0x22u8; 32]);
    }

    #[test]
    fn u256_add_carries() {
        let a = u256_from_u64(0x00ff);
        let b = u256_from_u64(0x0001);
        assert_eq!(u256_add(a, b), u256_from_u64(0x0100));

        // Carry across a byte boundary at the very top word.
        let mut big = [0xffu8; 32];
        big[0] = 0x00;
        let one = u256_from_u64(1);
        let mut expected = [0u8; 32];
        expected[0] = 0x01;
        assert_eq!(u256_add(big, one), expected);
    }

    #[test]
    fn u256_mul_u64_basic() {
        assert_eq!(u256_mul_u64(u256_from_u64(7), 3), u256_from_u64(21));
        assert_eq!(u256_mul_u64(u256_from_u64(0), 99), u256_from_u64(0));
        // A value that carries across byte boundaries.
        assert_eq!(
            u256_mul_u64(u256_from_u64(0x0100), 0x0100),
            u256_from_u64(0x0001_0000)
        );
        // u64::MAX * 2 = 2^65 - 2, which needs bit 64 (a 65-bit result).
        let mut expected = [0u8; 32];
        expected[23] = 0x01;
        expected[24..].copy_from_slice(&0xffff_ffff_ffff_fffeu64.to_be_bytes());
        assert_eq!(u256_mul_u64(u256_from_u64(u64::MAX), 2), expected);
    }

    #[test]
    fn u256_cmp_orders_numerically() {
        assert_eq!(u256_cmp(u256_from_u64(1), u256_from_u64(2)), Ordering::Less);
        assert_eq!(
            u256_cmp(u256_from_u64(2), u256_from_u64(2)),
            Ordering::Equal
        );
        assert_eq!(
            u256_cmp(u256_from_u64(0x0100), u256_from_u64(0x00ff)),
            Ordering::Greater
        );
    }

    fn quote_with(price: u64, rewards: u8) -> Quote {
        use crate::payment::Timestamp;
        Quote {
            content: [0u8; 32],
            timestamp: Timestamp::from_secs(0),
            price: u256_from_u64(price),
            rewards_address: [rewards; 20],
            pub_key: vec![1u8; 4],
            signature: vec![2u8; 4],
            committed_key_count: 0,
            commitment_pin: None,
        }
    }

    #[test]
    fn payment_split_pays_only_the_median() {
        // Prices 10,20,30,40,50,60,70 -> sorted median (index 3) = 40.
        let quotes: Vec<Quote> = (1..=7).map(|i| quote_with(i * 10, i as u8)).collect();
        let split = payment_split(&quotes).expect("split");
        assert_eq!(split.len(), 7);

        // Exactly one non-zero payment, and it is 40 * 3 = 120.
        let paying: Vec<&([u8; 20], [u8; 32], [u8; 32])> = split
            .iter()
            .filter(|(_, amt, _)| *amt != [0u8; 32])
            .collect();
        assert_eq!(paying.len(), 1);
        assert_eq!(paying[0].1, u256_from_u64(120));
        // The median is the quote priced 40 -> rewards address == 4.
        assert_eq!(paying[0].0, [4u8; 20]);

        // Order is preserved: the paying entry sits at input index 3.
        assert_eq!(split[3].1, u256_from_u64(120));

        // Total is the single median payment.
        assert_eq!(total_amount(&split), u256_from_u64(120));
    }

    #[test]
    fn payment_split_requires_seven() {
        let quotes: Vec<Quote> = (0..6).map(|_| quote_with(1, 0)).collect();
        assert!(payment_split(&quotes).is_err());
    }

    #[test]
    fn payment_split_order_matches_input_when_unsorted() {
        // Deliberately unsorted prices; median value is the 4th smallest.
        let prices = [70u64, 10, 50, 30, 20, 60, 40];
        let quotes: Vec<Quote> = prices
            .iter()
            .enumerate()
            .map(|(i, &p)| quote_with(p, i as u8))
            .collect();
        let split = payment_split(&quotes).expect("split");
        // sorted: 10,20,30,40,50,60,70 -> median 40, which is input index 6.
        assert_eq!(split[6].1, u256_from_u64(120));
        for (i, (_, amt, _)) in split.iter().enumerate() {
            if i != 6 {
                assert_eq!(*amt, [0u8; 32]);
            }
        }
    }
}
