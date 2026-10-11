//! Vaultex outflow monitor (ROADMAP M7 #3, WS-07): watches the chain, matches every outflow to a
//! receipt, alerts on approvals and allowances, and can only freeze. **Skeleton: it does nothing
//! and exits non-zero.**

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("vaultex-monitor: not implemented yet");
    ExitCode::from(2)
}
