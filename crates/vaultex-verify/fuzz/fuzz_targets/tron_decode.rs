//! cargo-fuzz target for the strict TRON decoder (ROADMAP M6 #8: at least 24 CPU-hours, 0
//! crashes). Skeleton: not run yet. The campaign needs the nightly toolchain, `cargo-fuzz` and a
//! compute budget, which are owner decisions.
//!
//! From `crates/vaultex-verify`:
//! `cargo +nightly fuzz run tron_decode fuzz/corpus/tron_decode -- -timeout=1 -rss_limit_mb=512`
//!
//! The invariants live in `../tron_invariants.rs`; `tests/tron_fuzz_smoke.rs` runs them on stable.

#![no_main]

#[path = "../tron_invariants.rs"]
mod tron_invariants;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    tron_invariants::check(data);
});
