//! Vaultex verifier kernel (working name until ADR-12).
//!
//! In M6 (WS-05) the kernel decodes the exact unsigned transaction a signer is asked to sign,
//! evaluates the installed quorum-signed policy bundle, checks the initiator and approver
//! statements and the velocity cap, and records a signed, hash-chained receipt, using the types in
//! [`vaultex_types`]. It fails closed: anything it does not understand is refused.
//!
//! # Status
//!
//! - [`tron`]: the strict TRON decoder (M6 #2). Implemented.
//! - Policy bundle, approvals, velocity and receipts: not implemented yet.
//!
//! Boundary (ROADMAP M6 #1): this crate depends only on `vaultex-types` and pure crates. No MPC,
//! transport, async-runtime or network crate may appear in its dependency tree
//! (`.github/workflows/kernel.yml` checks with `cargo tree`), and its `clippy.toml` bans clock,
//! environment and socket access: time and storage are parameters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod tron;
