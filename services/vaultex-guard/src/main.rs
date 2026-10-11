//! Vaultex Guard (ROADMAP M7 #1, WS-06): an additive co-signer that verifies every request with
//! the kernel before it co-signs. **Skeleton: it refuses everything by exiting non-zero.**

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("vaultex-guard: not implemented yet; this build refuses every request");
    ExitCode::from(2)
}
