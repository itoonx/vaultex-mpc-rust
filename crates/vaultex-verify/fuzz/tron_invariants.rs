//! Invariants of the strict TRON decoder, checked on every input by the `tron_decode` fuzz target
//! and by the stable smoke test `tests/tron_fuzz_smoke.rs`, so they compile and run in CI without
//! libFuzzer or a nightly toolchain.
//!
//! For any input, under an owner-permission and an active-permission wallet: decoding never panics
//! and is deterministic. If the input is accepted, it is at most `MAX_RAW_BYTES`, the intent's
//! `tx_hash` is SHA-256 of the input, the sign input is exactly the input under SHA-256, the sender
//! is the wallet, and the expiry, the fee limit and a native amount are within the decoder's hard
//! ceilings.

use vaultex_types::{Address, AssetId, EcdsaHash, NetworkId, SignInput, TxHash, WalletId, U256};
use vaultex_verify::tron::{
    decode, TronDecodeCtx, MAX_FEE_LIMIT_SUN, MAX_NATIVE_AMOUNT_SUN, MAX_RAW_BYTES, MAX_VALIDITY_MS,
};

/// The wallet and token of the seed corpus (synthetic test addresses).
const WALLET: [u8; 21] = [
    0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11,
];
const TOKEN: [u8; 21] = [
    0x41, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
    0x99, 0x99, 0x99, 0x99, 0x99,
];
/// Inside the seed corpus's validity windows.
const NOW_MS: u64 = 1_700_000_010_000;

/// Checks the invariants on `data`; returns under how many of the two wallet contexts (permission
/// 0 and 2) it was accepted. Panics if an invariant is broken.
pub fn check(data: &[u8]) -> usize {
    let wallet_id = WalletId::new("fuzz-wallet").expect("valid wallet id");
    let network = NetworkId::new("tron:3448148188").expect("allowlisted network");
    let allowlist = [TOKEN];
    let mut accepted = 0;
    for permission_id in [0, 2] {
        let ctx = TronDecodeCtx {
            wallet_id: &wallet_id,
            network,
            wallet_address: WALLET,
            permission_id,
            trc20_allowlist: &allowlist,
            now_ms: NOW_MS,
            max_validity_ms: MAX_VALIDITY_MS,
            max_fee_limit_sun: MAX_FEE_LIMIT_SUN,
            max_clock_skew_ms: 120_000,
            claimed_txid: None,
        };
        let first = decode(data, &ctx);
        assert_eq!(first, decode(data, &ctx), "decode is not deterministic");
        if let Ok((intent, sign_input)) = first {
            accepted += 1;
            assert!(data.len() <= MAX_RAW_BYTES);
            assert_eq!(intent.tx_hash, TxHash::of(data));
            assert_eq!(
                sign_input,
                SignInput::EcdsaPreimage {
                    hash: EcdsaHash::Sha256,
                    bytes: data.to_vec()
                }
            );
            assert_eq!(intent.sender, Address(WALLET.to_vec()));
            assert!(intent.not_after_ms > NOW_MS);
            assert!(intent.not_after_ms <= NOW_MS + MAX_VALIDITY_MS);
            assert!(intent.fee_cap <= U256::from(MAX_FEE_LIMIT_SUN));
            assert!(intent.amount > U256::from(0));
            if intent.asset == AssetId::Native {
                assert!(intent.amount <= U256::from(MAX_NATIVE_AMOUNT_SUN));
            }
        }
    }
    accepted
}
