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
//! - [`velocity`] and [`breaker`]: velocity caps behind the [`velocity::VelocityStore`] trait,
//!   with an fsync'd file implementation; the per-signer cap calibration helper; the auto-pause
//!   state machine (M6 #5). The M-of-N unpause waits on the policy bundle (ADR-11).
//! - [`receipt`]: Ed25519-signed, hash-chained receipts for accepts and refusals, an fsync'd
//!   receipt log ([`receipt::ReceiptLog`]), and the offline log verifier
//!   ([`receipt::verify_log`], also the `vaultex-receipts` binary) (M6 #6). Implemented.
//! - Policy bundle and approvals: not implemented yet.
//!
//! Boundary (ROADMAP M6 #1): this crate depends only on `vaultex-types` and pure crates. No MPC,
//! transport, async-runtime or network crate may appear in its dependency tree
//! (`.github/workflows/kernel.yml` checks with `cargo tree`), and its `clippy.toml` bans clock,
//! environment and socket access: time is a parameter, and storage is a local file
//! ([`velocity::FileStore`], [`receipt::ReceiptLog`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod amount;
pub mod breaker;
mod durable;
pub mod receipt;
pub mod tron;
pub mod velocity;
