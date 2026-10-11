//! The few TRC-20 ABI shapes the monitor reads and writes. Call data is lowercase hex without `0x`:
//! a 4-byte selector, then 32-byte words. Selectors are the first 4 bytes of the Keccak-256 of the
//! signature (VERIFIED 2026-10-11 with a Keccak-256 implementation self-tested on the empty-input
//! vector `c5d24601…`; `a9059cbb` also matches the TRON documentation).

/// `transfer(address,uint256)`: the one call shape the Guard may co-sign.
pub const TRANSFER: &str = "a9059cbb";
/// `transferFrom(address,address,uint256)`: spends an allowance.
pub const TRANSFER_FROM: &str = "23b872dd";
/// Calls that raise an allowance: `approve(address,uint256)`, `increaseApproval(address,uint256)`
/// (TRON USDT) and `increaseAllowance(address,uint256)` (OpenZeppelin tokens).
pub const RAISE_ALLOWANCE: [&str; 3] = ["095ea7b3", "d73dd623", "39509351"];

/// Read-only functions, by signature (the form `triggerconstantcontract` takes).
pub const ALLOWANCE: &str = "allowance(address,address)";
pub const BALANCE_OF: &str = "balanceOf(address)";

/// Hex length of call data with a selector and two words: the only length `transfer` may have.
pub const TWO_WORD_CALL: usize = 8 + 2 * 64;

/// The call's selector, if the data has one.
pub fn selector(data: &str) -> Option<&str> {
    data.get(..8)
}

/// Argument word `i` (from 0), if the data is long enough.
pub fn word(data: &str, i: usize) -> Option<&str> {
    data.get(8 + 64 * i..8 + 64 * (i + 1))
}

/// The address in an argument word, as 21-byte hex with the `41` prefix, and whether the word is
/// clean (its upper 12 bytes are zero). Older token compilers ignore dirty upper bytes, so the
/// address returned is the one such a token would use.
pub fn address(word: &str) -> (String, bool) {
    let clean = word.len() == 64 && word.bytes().take(24).all(|b| b == b'0');
    (format!("41{}", word.get(24..).unwrap_or_default()), clean)
}

/// The amount in an argument word, saturated to `u128::MAX` (which exceeds every cap) when it does
/// not fit or is not hex, so a malformed word can only make the monitor more alarmed.
pub fn amount(word: &str) -> u128 {
    let fits = word.len() == 64 && word.bytes().take(32).all(|b| b == b'0');
    match word.get(32..) {
        Some(low) if fits => u128::from_str_radix(low, 16).unwrap_or(u128::MAX),
        _ => u128::MAX,
    }
}

/// A word holding `value` (big-endian), as returned by a read-only call.
pub fn word_amount(value: &[u8; 32]) -> u128 {
    amount(&hex::encode(value))
}

/// Encodes a 21-byte hex address (`41…`) as an argument word.
pub fn encode_address(address: &str) -> String {
    format!("{:0>64}", address.get(2..).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TO: &str = "415e33cfa37d730a43063e70ff5381acfc7895e086";

    #[test]
    fn decodes_a_transfer_call() {
        let data = format!("{TRANSFER}{}{:064x}", encode_address(TO), 1_000_000u64);
        assert_eq!(data.len(), TWO_WORD_CALL);
        assert_eq!(selector(&data), Some(TRANSFER));
        assert_eq!(address(word(&data, 0).unwrap()), (TO.to_owned(), true));
        assert_eq!(amount(word(&data, 1).unwrap()), 1_000_000);
        assert_eq!(word(&data, 2), None);
    }

    #[test]
    fn dirty_or_oversized_words_are_flagged() {
        let dirty = format!("ff{:0>62}", &TO[2..]);
        assert_eq!(address(&dirty), (TO.to_owned(), false));
        // An amount above u128 (here 2^255), or not hex, saturates.
        assert_eq!(amount(&format!("8{}", "0".repeat(63))), u128::MAX);
        assert_eq!(amount(&"z".repeat(64)), u128::MAX);
        assert_eq!(amount("01"), u128::MAX);
        assert_eq!(word_amount(&[0xff; 32]), u128::MAX);
        let mut seven = [0u8; 32];
        seven[31] = 7;
        assert_eq!(word_amount(&seven), 7);
    }
}
