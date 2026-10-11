//! `vaultex-monitor refill-check`: run before every transfer from the cold treasury to the float
//! (ROADMAP RF-4: "every refill first checks that the allowance is 0"; runbook RB-9).
//!
//! It prints a report and passes only if, on **every** provider, at its solidified height:
//! 1. the monitor has scanned at least up to that height (its cursor for the provider);
//! 2. every allowance from the float, on every listed token, to every spender in the watched set
//!    is 0;
//! 3. the float's balance of the asset plus the refill stays at or under its ceiling minus the
//!    headroom;
//!
//! and, from the monitor's own state:
//! 4. the Guard's receipt history verifies against the pinned key and the anchored head;
//! 5. every severity-1 alert is closed by a record (`closed.txt`);
//! 6. every float-signed transaction up to the lowest solidified height has an accept receipt, or
//!    its `MR-04` alert is closed by a record (owner-signed ceremony, incident or drill
//!    transactions never have a receipt).
//!
//! The report goes into the evidence pack, signed with the monitor evidence key under the
//! `vaultex-refill-check-v1` namespace (`docs/ops/evidence-pack.md`). Balance reconciliation
//! (MR-13 clean), the permission snapshot and the Guard-state checks of RB-9 come with later tasks
//! and are listed as not checked: a PASS here does not cover them.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};
use vaultex_types::Decision;

use crate::abi;
use crate::cursor::Cursor;
use crate::matcher::{Config, State, ANCHOR, TRX};
use crate::provider::{Provider, ProviderError};
use crate::receipts::{load_anchor, ReceiptFeed};
use crate::watcher::address_base58;

/// The report, line by line: checks are marked `[ok]` or `[FAIL]`.
#[derive(Default)]
struct Report {
    text: String,
    fails: u32,
}

impl Report {
    fn check(&mut self, ok: bool, text: String) {
        self.fails += u32::from(!ok);
        let _ = writeln!(self.text, "[{}] {text}", if ok { "ok" } else { "FAIL" });
    }

    fn note(&mut self, text: String) {
        let _ = writeln!(self.text, "{text}");
    }
}

/// The report text and whether it passed. An `Err` means the check could not complete (a
/// provider or file could not be read): that is never a pass.
pub async fn check<P: Provider>(
    providers: &[P],
    cfg: &Config,
    dir: &Path,
    asset: &str,
    amount: u128,
    now_ms: u64,
) -> Result<(String, bool), String> {
    let caps = cfg
        .assets
        .get(asset)
        .ok_or_else(|| format!("{} is not a configured asset", address_base58(asset)))?;
    let state = State::load(dir).map_err(|e| format!("state: {e}"))?;
    let spenders = cfg.spender_set(&state.outflows);
    let float = &cfg.float;
    let asset_name = if asset == TRX {
        TRX.to_owned()
    } else {
        address_base58(asset)
    };

    let mut r = Report::default();
    r.note(format!(
        "vaultex-monitor refill-check v1\nchecked_at_ms: {now_ms}\nnetwork: {}\nfloat: {}\n\
         refill: {amount} {asset_name}",
        cfg.network.as_str(),
        address_base58(float),
    ));
    let digest = Sha256::digest(spenders.iter().cloned().collect::<Vec<_>>().join("\n"));
    r.note(format!(
        "spender set: {} address(es), sha256 {}",
        spenders.len(),
        hex::encode(digest)
    ));
    for s in &spenders {
        r.note(format!("  spender {}", address_base58(s)));
    }

    let mut lowest_solid = u64::MAX;
    for p in providers {
        let failed = |e: ProviderError| format!("{}: {e}", p.name());
        let solid = p.solid_height().await.map_err(failed)?;
        lowest_solid = lowest_solid.min(solid);
        let cursor = Cursor::load(&dir.join(format!("{}.cursor", p.name())))
            .map_err(|e| format!("{}: {e}", p.name()))?;
        let scanned = cursor.as_ref().and_then(|c| c.tip()).map(|(h, _)| *h);
        r.check(
            scanned.is_some_and(|h| h >= solid),
            format!(
                "{}: solidified height {solid}, scanned up to {}",
                p.name(),
                scanned.map_or("nothing".into(), |h| h.to_string())
            ),
        );
        for token in cfg.tokens() {
            for spender in &spenders {
                let params = abi::encode_address(float) + &abi::encode_address(spender);
                let value = p
                    .call(float, token, abi::ALLOWANCE, &params, true)
                    .await
                    .map_err(failed)?;
                r.check(
                    value == [0; 32],
                    format!(
                        "{}: allowance on {} to {}: {}",
                        p.name(),
                        address_base58(token),
                        address_base58(spender),
                        abi::word_amount(&value)
                    ),
                );
            }
        }
        let balance = if asset == TRX {
            p.trx_balance(float, true).await.map(u128::from)
        } else {
            let params = abi::encode_address(float);
            let word = p.call(float, asset, abi::BALANCE_OF, &params, true).await;
            word.map(|w| abi::word_amount(&w))
        }
        .map_err(failed)?;
        let limit = caps.ceiling - caps.headroom; // the config guarantees headroom <= ceiling
        r.check(
            balance.saturating_add(amount) <= limit,
            format!(
                "{}: balance {balance} + refill {amount} <= ceiling {} - headroom {} = {limit}",
                p.name(),
                caps.ceiling,
                caps.headroom
            ),
        );
    }

    let anchor = load_anchor(&dir.join(ANCHOR)).map_err(|e| format!("anchor: {e}"))?;
    let mut feed = ReceiptFeed::new(cfg.receipt_log.clone(), cfg.receipt_key, anchor);
    let accepted: HashSet<String> = match feed.poll() {
        Ok(bodies) => {
            // A frame still being written is not evidence either way: run the check again.
            let len = std::fs::metadata(&cfg.receipt_log).map_or(0, |m| m.len());
            let head = feed
                .head()
                .map_or("empty".into(), |h| format!("head seq {}", h.seq));
            r.check(
                len == feed.verified_len() as u64,
                format!("receipt history verifies to its end ({head})"),
            );
            bodies
                .iter()
                .filter(|b| b.decision == Decision::Accept)
                .filter(|b| b.wallet_id == cfg.wallet && b.network == cfg.network)
                .map(|b| hex::encode(b.tx_hash.0))
                .collect()
        }
        Err(b) => {
            r.check(false, format!("receipt history: {b}"));
            HashSet::new()
        }
    };

    let open: Vec<_> = state
        .alerts
        .iter()
        .filter(|a| a.severity == 1 && !state.closed.contains_key(&a.id))
        .collect();
    r.check(
        open.is_empty(),
        format!("open severity-1 alerts: {}", open.len()),
    );
    for a in open {
        r.note(format!("  open {}: {}", a.id, a.detail));
    }
    let unmatched: Vec<_> = state
        .outflows
        .iter()
        .filter(|o| o.height <= lowest_solid)
        .filter(|o| !accepted.contains(&o.txid))
        .filter(|o| !state.closed.contains_key(&format!("MR-04:{}", o.txid)))
        .collect();
    r.check(
        unmatched.is_empty(),
        format!(
            "float-signed transactions without a receipt or a closed record: {}",
            unmatched.len()
        ),
    );
    for o in unmatched {
        r.note(format!("  unmatched {} at height {}", o.txid, o.height));
    }

    let pass = r.fails == 0;
    r.note(
        "not checked here (later tasks; RB-9 requires them too): balance reconciliation \
         (MR-13 clean), the permission snapshot and the Guard state"
            .into(),
    );
    r.note(format!("result: {}", if pass { "PASS" } else { "FAIL" }));
    Ok((r.text, pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::tests::{config, event, trc20, txid, FLOAT, PAYEE, TOKEN};
    use crate::matcher::{Matcher, CLOSED};
    use crate::provider::{Block, Word};
    use crate::receipts::tests::Writer;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Mutex;

    /// A provider that answers state reads from a table and records them.
    #[derive(Default)]
    struct Table {
        solid: u64,
        trx: u64,
        words: HashMap<(String, String), Word>,
        calls: Mutex<Vec<(String, bool)>>,
    }

    impl Provider for Table {
        fn name(&self) -> &str {
            "a"
        }
        async fn latest(&self) -> Result<Block, ProviderError> {
            unimplemented!()
        }
        async fn block(&self, _: u64) -> Result<Block, ProviderError> {
            unimplemented!()
        }
        async fn solid_height(&self) -> Result<u64, ProviderError> {
            Ok(self.solid)
        }
        async fn call(
            &self,
            caller: &str,
            contract: &str,
            function: &str,
            params: &str,
            solid: bool,
        ) -> Result<Word, ProviderError> {
            assert_eq!(caller, FLOAT);
            self.calls
                .lock()
                .unwrap()
                .push((function.to_owned(), solid));
            let key = (contract.to_owned(), params.to_owned());
            Ok(self.words.get(&key).copied().unwrap_or_default())
        }
        async fn trx_balance(&self, address: &str, solid: bool) -> Result<u64, ProviderError> {
            assert!(address == FLOAT && solid);
            Ok(self.trx)
        }
    }

    async fn run(p: &Table, cfg: &Config, dir: &Path, asset: &str, amount: u128) -> (String, bool) {
        check(std::slice::from_ref(p), cfg, dir, asset, amount, 7)
            .await
            .unwrap()
    }

    fn word(n: u8) -> Word {
        let mut w = [0; 32];
        w[31] = n;
        w
    }

    /// A state directory with a cursor at `scanned` and a receipt log holding `receipts`.
    fn setup(dir: &Path, scanned: u64, receipts: &[String]) -> Config {
        let mut cfg = config("allowlist");
        cfg.receipt_log = dir.join("receipts.log");
        let mut w = Writer::start();
        for txid in receipts {
            w.accept(txid, 1);
        }
        fs::write(&cfg.receipt_log, &w.log).unwrap();
        let mut cursor = Cursor::default();
        cursor.push(scanned, "00".repeat(32));
        cursor.save(&dir.join("a.cursor")).unwrap();
        cfg
    }

    #[tokio::test]
    async fn passes_only_when_every_check_holds() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = setup(dir.path(), 200, &[txid(1)]);
        let mut m = Matcher::open(cfg.clone(), dir.path(), 0).unwrap();
        m.observe(&[event(1, 0, trc20(PAYEE, 10))], 0).unwrap();
        drop(m);
        let mut p = Table {
            solid: 150,
            trx: 800_000_000,
            ..Table::default()
        };

        let (report, pass) = run(&p, &cfg, dir.path(), TRX, 100_000_000).await;
        assert!(pass, "{report}");
        assert!(report.ends_with("result: PASS\n"), "{report}");
        // A PASS names the RB-9 conditions it does not cover.
        assert!(
            report.contains("balance reconciliation (MR-13 clean)"),
            "{report}"
        );
        assert!(report.contains("spender set: 1 address(es)"));
        // Every read is at solidified height: one allowance (one token, one spender), no balanceOf.
        assert_eq!(
            *p.calls.lock().unwrap(),
            [(abi::ALLOWANCE.to_owned(), true)]
        );

        // A non-zero allowance fails it.
        let params = abi::encode_address(FLOAT) + &abi::encode_address(PAYEE);
        p.words.insert((TOKEN.to_owned(), params.clone()), word(1));
        let (report, pass) = run(&p, &cfg, dir.path(), TRX, 1).await;
        assert!(!pass);
        assert!(report.contains("[FAIL] a: allowance on T"), "{report}");
        p.words.remove(&(TOKEN.to_owned(), params));

        // So does a refill that would take the balance past the ceiling minus the headroom.
        let (_, pass) = run(&p, &cfg, dir.path(), TRX, 100_000_001).await;
        assert!(!pass);
        // A token refill reads balanceOf.
        let balance = (TOKEN.to_owned(), abi::encode_address(FLOAT));
        p.words.insert(balance, word(200));
        assert!(run(&p, &cfg, dir.path(), TOKEN, 8800).await.1);
        assert!(!run(&p, &cfg, dir.path(), TOKEN, 8801).await.1);

        // A monitor that has not scanned up to the solidified height fails it.
        p.solid = 201;
        assert!(!run(&p, &cfg, dir.path(), TRX, 1).await.1);
    }

    #[tokio::test]
    async fn open_alerts_and_unmatched_transactions_fail_it_until_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = setup(dir.path(), 200, &[]);
        let mut m = Matcher::open(cfg.clone(), dir.path(), 0).unwrap();
        // An owner-signed transaction (a ceremony): MR-02 now, MR-04 after the grace period.
        let mut owner = trc20(PAYEE, 10);
        owner.permission_id = 0;
        m.observe(&[event(1, 0, owner)], 0).unwrap();
        m.tick(60_000).unwrap();
        drop(m);
        let p = Table {
            solid: 150,
            ..Table::default()
        };

        let (report, pass) = run(&p, &cfg, dir.path(), TRX, 1).await;
        assert!(!pass);
        assert!(report.contains("open severity-1 alerts: 2"), "{report}");
        assert!(
            report.contains("without a receipt or a closed record: 1"),
            "{report}"
        );

        let records = format!(
            "MR-02:{0} CER-5 transcript\nMR-04:{0} CER-5 transcript\n",
            txid(1)
        );
        fs::write(dir.path().join(CLOSED), records).unwrap();
        let (report, pass) = run(&p, &cfg, dir.path(), TRX, 1).await;
        assert!(pass, "{report}");

        // A receipt history that does not verify, or ends in a torn frame, fails it.
        for log in [&b"\x00\x00\x00\x00"[..], b"\x05\x00\x00\x00torn"] {
            fs::write(&cfg.receipt_log, log).unwrap();
            let (report, pass) = run(&p, &cfg, dir.path(), TRX, 1).await;
            assert!(!pass);
            assert!(report.contains("[FAIL] receipt history"), "{report}");
        }
    }
}
