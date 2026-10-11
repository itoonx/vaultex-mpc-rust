//! Gapless block watcher over one provider.
//!
//! The watcher scans heights strictly in order from its persisted cursor, links every block to its
//! parent, and reports each transaction that a watched address signed. Rules:
//! - **Gapless.** A height that cannot be fetched is retried, never skipped.
//! - **Forks.** If a block does not link to the remembered tip, the tip was orphaned: the watcher
//!   reports a [`Event::Reorg`] and re-scans that height. Events already reported for the orphaned
//!   block stand (an unauthorised signature is an incident even if its block is dropped).
//! - **At least once.** The caller delivers a step's events, then calls [`Watcher::commit`]. A crash
//!   in between replays them; consumers de-duplicate by `txid` and `block_id`.
//!
//! Each provider gets its own watcher and cursor, so an event seen by any provider is reported
//! ("alarm on any"). Cross-provider agreement at solidified height is not implemented yet.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::abi;
use crate::cursor::{Cursor, DEPTH};
use crate::provider::{Block, Contract, Provider, ProviderError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A transaction with a contract owned by a watched address, in a block at latest height
    /// (not yet solidified).
    WatchedTx {
        provider: String,
        height: u64,
        block_id: String,
        block_time_ms: i64,
        txid: String,
        /// The first contract that a watched address owns, and how many the transaction has.
        contract_index: usize,
        contracts: usize,
        contract: Contract,
        result: Option<String>,
    },
    /// A transaction that no watched address signed, calling `transferFrom` on a listed token
    /// with a watched address as the source: it spends an allowance of that address.
    TokenPull {
        provider: String,
        height: u64,
        block_id: String,
        block_time_ms: i64,
        txid: String,
        contract: Contract,
        result: Option<String>,
    },
    /// Block `height` with id `orphaned_id` left this provider's chain; it is scanned again.
    Reorg {
        provider: String,
        height: u64,
        orphaned_id: String,
    },
}

#[derive(Debug)]
pub enum Progress {
    /// One block was processed (or one orphaned tip dropped). The events may be empty.
    Scanned(Vec<Event>),
    /// Nothing new: the cursor is at the provider's head.
    AtHead,
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("fork deeper than the {DEPTH} remembered blocks (reached height {0})")]
    DeepReorg(u64),
}

pub struct Watcher<P> {
    provider: P,
    watch: HashSet<String>,
    /// Token contracts whose `transferFrom` calls are checked for a watched source.
    tokens: HashSet<String>,
    cursor: Cursor,
    path: PathBuf,
    /// Next height to scan; `None` until a fresh cursor learns the provider's head.
    next: Option<u64>,
    /// The last head block fetched, reused when it is the next block to scan.
    head: Option<Block>,
    head_height: Option<u64>,
}

impl<P: Provider> Watcher<P> {
    /// Opens the watcher on the cursor at `path`. Without a cursor file, scanning starts at
    /// `start`, or at the provider's head when `start` is `None`; with one, it resumes after its
    /// tip and `start` is ignored.
    pub fn open(
        provider: P,
        watch: HashSet<String>,
        tokens: HashSet<String>,
        path: PathBuf,
        start: Option<u64>,
    ) -> io::Result<Self> {
        let cursor = Cursor::load(&path)?.unwrap_or_default();
        let next = cursor.tip().map(|(h, _)| h + 1).or(start);
        Ok(Self {
            provider,
            watch,
            tokens,
            cursor,
            path,
            next,
            head: None,
            head_height: None,
        })
    }

    pub fn name(&self) -> &str {
        self.provider.name()
    }

    /// (last scanned height, last seen head height), for health reporting.
    pub fn heights(&self) -> (Option<u64>, Option<u64>) {
        (self.cursor.tip().map(|(h, _)| *h), self.head_height)
    }

    /// Processes at most one block. On error the cursor does not move, so the same height is
    /// retried.
    pub async fn step(&mut self) -> Result<Progress, WatchError> {
        let need_head = match (&self.head, self.next) {
            (Some(head), Some(next)) => head.height < next,
            _ => true,
        };
        if need_head {
            let head = self.provider.latest().await?;
            self.head_height = Some(head.height);
            self.next.get_or_insert(head.height);
            self.head = Some(head);
        }
        let next = self
            .next
            .expect("set from the cursor, the start height or the head");
        let head_height = self.head.as_ref().expect("fetched above").height;
        if next > head_height {
            return Ok(Progress::AtHead);
        }
        let block = if next == head_height {
            self.head.take().expect("head checked above")
        } else {
            self.provider.block(next).await?
        };

        if let Some((tip_height, tip_id)) = self.cursor.tip() {
            if block.parent_id != *tip_id {
                let (height, orphaned_id) = (*tip_height, tip_id.clone());
                self.cursor.pop();
                if self.cursor.is_empty() && self.cursor.is_truncated() {
                    return Err(WatchError::DeepReorg(height));
                }
                self.next = Some(height);
                return Ok(Progress::Scanned(vec![Event::Reorg {
                    provider: self.name().to_owned(),
                    height,
                    orphaned_id,
                }]));
            }
        }

        let mut events = Vec::new();
        for tx in &block.txs {
            let watched = tx
                .contracts
                .iter()
                .position(|c| self.watch.contains(&c.owner));
            if let Some(i) = watched {
                events.push(Event::WatchedTx {
                    provider: self.name().to_owned(),
                    height: block.height,
                    block_id: block.id.clone(),
                    block_time_ms: block.time_ms,
                    txid: tx.txid.clone(),
                    contract_index: i,
                    contracts: tx.contracts.len(),
                    contract: tx.contracts[i].clone(),
                    result: tx.result.clone(),
                });
            } else if let Some(c) = tx.contracts.iter().find(|c| self.pulls_from_watched(c)) {
                events.push(Event::TokenPull {
                    provider: self.name().to_owned(),
                    height: block.height,
                    block_id: block.id.clone(),
                    block_time_ms: block.time_ms,
                    txid: tx.txid.clone(),
                    contract: c.clone(),
                    result: tx.result.clone(),
                });
            }
        }
        self.next = Some(block.height + 1);
        self.cursor.push(block.height, block.id);
        Ok(Progress::Scanned(events))
    }

    /// A direct `transferFrom` call on a listed token whose source is watched. A spend routed
    /// through another contract is not visible here; it needs a standing allowance, which the
    /// matcher's allowance checks catch first.
    fn pulls_from_watched(&self, c: &Contract) -> bool {
        c.kind == "TriggerSmartContract"
            && self.tokens.contains(&c.contract_address)
            && abi::selector(&c.data) == Some(abi::TRANSFER_FROM)
            && abi::word(&c.data, 0).is_some_and(|w| self.watch.contains(&abi::address(w).0))
    }

    /// Persists the cursor. Call it after the events of every step before it were delivered.
    pub fn commit(&self) -> io::Result<()> {
        self.cursor.save(&self.path)
    }
}

/// Decodes a base58check TRON address (`T…`) to the lowercase 21-byte hex form used in block JSON.
/// A typo must fail here: a mistyped address would silently watch nothing.
pub fn address_hex(addr: &str) -> Result<String, String> {
    let raw = bs58::decode(addr)
        .into_vec()
        .map_err(|e| format!("{addr}: not base58 ({e})"))?;
    if raw.len() != 25 {
        return Err(format!("{addr}: not a TRON address (wrong length)"));
    }
    let (body, check) = raw.split_at(21);
    let sum = Sha256::digest(Sha256::digest(body));
    if body[0] != 0x41 || sum[..4] != *check {
        return Err(format!("{addr}: not a TRON address (prefix or checksum)"));
    }
    Ok(hex::encode(body))
}

/// Renders a 21-byte hex address (`41…`) as base58check (`T…`), for people. Anything else is
/// returned unchanged.
pub fn address_base58(hex_addr: &str) -> String {
    match hex::decode(hex_addr) {
        Ok(body) if body.len() == 21 => {
            let sum = Sha256::digest(Sha256::digest(&body));
            bs58::encode([&body[..], &sum[..4]].concat()).into_string()
        }
        _ => hex_addr.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Tx, Word};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const FLOAT: &str = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
    const OTHER: &str = "41313bd9f0dc4e4b2a787470b8dea27e58be82fc53";
    const TOKEN: &str = "41eca9bc828a3005b9a3b909f2cc5c2a54794de05f";

    /// Block id for `height` on fork `fork`; it encodes the height like TRON ids do.
    fn id(height: u64, fork: u8) -> String {
        format!("{height:016x}{fork:048x}")
    }

    fn tx(txid: &str, owner: &str) -> Tx {
        Tx {
            txid: txid.into(),
            result: Some("SUCCESS".into()),
            contracts: vec![Contract {
                kind: "TransferContract".into(),
                owner: owner.into(),
                ..Contract::default()
            }],
        }
    }

    #[derive(Default)]
    struct Chain {
        blocks: BTreeMap<u64, Block>,
        head: u64,
        fail_next: Option<ProviderError>,
    }

    /// An in-memory provider whose chain a test can rewrite between steps.
    #[derive(Default)]
    struct Fake(Mutex<Chain>);

    impl Fake {
        /// Appends (or replaces) `height` on fork `fork`, linked to `height - 1` on `parent_fork`.
        fn put(&self, height: u64, fork: u8, parent_fork: u8, txs: Vec<Tx>) {
            let mut c = self.0.lock().unwrap();
            c.blocks.insert(
                height,
                Block {
                    height,
                    id: id(height, fork),
                    parent_id: id(height.wrapping_sub(1), parent_fork),
                    time_ms: height as i64 * 3000,
                    txs,
                },
            );
            c.head = c.head.max(height);
        }

        fn take_failure(&self) -> Result<(), ProviderError> {
            self.0.lock().unwrap().fail_next.take().map_or(Ok(()), Err)
        }
    }

    impl Provider for &Fake {
        fn name(&self) -> &str {
            "fake"
        }

        async fn latest(&self) -> Result<Block, ProviderError> {
            self.take_failure()?;
            let c = self.0.lock().unwrap();
            Ok(c.blocks[&c.head].clone())
        }

        async fn block(&self, height: u64) -> Result<Block, ProviderError> {
            self.take_failure()?;
            let c = self.0.lock().unwrap();
            c.blocks
                .get(&height)
                .filter(|_| height <= c.head)
                .cloned()
                .ok_or_else(|| ProviderError::Unavailable("block not available".into()))
        }

        // The watcher reads blocks only.
        async fn solid_height(&self) -> Result<u64, ProviderError> {
            unimplemented!()
        }
        async fn call(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: bool,
        ) -> Result<Word, ProviderError> {
            unimplemented!()
        }
        async fn trx_balance(&self, _: &str, _: bool) -> Result<u64, ProviderError> {
            unimplemented!()
        }
    }

    fn open<'a>(fake: &'a Fake, dir: &tempfile::TempDir, start: Option<u64>) -> Watcher<&'a Fake> {
        let watch = HashSet::from([FLOAT.to_owned()]);
        let tokens = HashSet::from([TOKEN.to_owned()]);
        Watcher::open(fake, watch, tokens, dir.path().join("fake.cursor"), start).unwrap()
    }

    /// Steps (committing after each) until the watcher is at head; returns all events.
    async fn drain(w: &mut Watcher<&Fake>) -> Result<Vec<Event>, WatchError> {
        let mut all = Vec::new();
        while let Progress::Scanned(events) = w.step().await? {
            all.extend(events);
            w.commit().unwrap();
        }
        Ok(all)
    }

    fn summary(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                Event::WatchedTx { height, txid, .. } => format!("tx {height} {txid}"),
                Event::TokenPull { height, txid, .. } => format!("pull {height} {txid}"),
                Event::Reorg { height, .. } => format!("reorg {height}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn scans_every_height_and_reports_only_watched_signers() {
        let fake = Fake::default();
        fake.put(10, 0, 0, vec![]);
        fake.put(11, 0, 0, vec![tx("a", FLOAT), tx("b", OTHER)]);
        fake.put(12, 0, 0, vec![tx("c", OTHER)]);
        fake.put(13, 0, 0, vec![]);
        fake.put(14, 0, 0, vec![tx("d", FLOAT)]);
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, Some(10));

        let events = drain(&mut w).await.unwrap();
        assert_eq!(summary(&events), ["tx 11 a", "tx 14 d"]);
        assert_eq!(w.heights(), (Some(14), Some(14)));
        let Event::WatchedTx {
            provider,
            block_id,
            contract,
            contracts,
            ..
        } = &events[1]
        else {
            unreachable!()
        };
        assert_eq!(
            (provider.as_str(), contract.owner.as_str()),
            ("fake", FLOAT)
        );
        assert_eq!((block_id.as_str(), *contracts), (id(14, 0).as_str(), 1));

        // New blocks are picked up on the next poll.
        fake.put(15, 0, 0, vec![tx("e", FLOAT)]);
        assert_eq!(summary(&drain(&mut w).await.unwrap()), ["tx 15 e"]);
    }

    #[tokio::test]
    async fn a_fresh_cursor_starts_at_the_head() {
        let fake = Fake::default();
        fake.put(41, 0, 0, vec![tx("old", FLOAT)]);
        fake.put(42, 0, 0, vec![tx("new", FLOAT)]);
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, None);
        assert_eq!(summary(&drain(&mut w).await.unwrap()), ["tx 42 new"]);
    }

    #[tokio::test]
    async fn resumes_after_the_committed_tip_and_replays_what_was_not_committed() {
        let fake = Fake::default();
        for h in 10..=13 {
            fake.put(h, 0, 0, vec![tx(&format!("t{h}"), FLOAT)]);
        }
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, Some(10));
        for _ in 0..2 {
            w.step().await.unwrap();
            w.commit().unwrap();
        }
        w.step().await.unwrap(); // height 12, delivered but never committed (a crash)
        drop(w);

        // The start height is ignored once a cursor exists.
        let mut w = open(&fake, &dir, Some(0));
        assert_eq!(
            summary(&drain(&mut w).await.unwrap()),
            ["tx 12 t12", "tx 13 t13"]
        );
    }

    #[tokio::test]
    async fn a_fork_at_the_tip_is_reported_and_rescanned() {
        let fake = Fake::default();
        for h in 10..=12 {
            fake.put(h, 0, 0, vec![]);
        }
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, Some(10));
        drain(&mut w).await.unwrap();

        // Height 12 is replaced; the new head 13 builds on the replacement.
        fake.put(12, 1, 0, vec![tx("x", FLOAT)]);
        fake.put(13, 1, 1, vec![tx("y", FLOAT)]);
        let events = drain(&mut w).await.unwrap();
        assert_eq!(summary(&events), ["reorg 12", "tx 12 x", "tx 13 y"]);
        assert_eq!(
            events[0],
            Event::Reorg {
                provider: "fake".into(),
                height: 12,
                orphaned_id: id(12, 0),
            }
        );
    }

    #[tokio::test]
    async fn a_fork_is_detected_across_a_restart() {
        let fake = Fake::default();
        for h in 10..=12 {
            fake.put(h, 0, 0, vec![]);
        }
        let dir = tempfile::tempdir().unwrap();
        drain(&mut open(&fake, &dir, Some(10))).await.unwrap();

        fake.put(11, 1, 0, vec![]);
        fake.put(12, 1, 1, vec![]);
        fake.put(13, 1, 1, vec![tx("z", FLOAT)]);
        let mut w = open(&fake, &dir, None);
        assert_eq!(
            summary(&drain(&mut w).await.unwrap()),
            ["reorg 12", "reorg 11", "tx 13 z"]
        );
    }

    #[tokio::test]
    async fn a_fork_below_the_remembered_blocks_stops_the_watcher() {
        let fake = Fake::default();
        let top = DEPTH as u64 + 8;
        for h in 0..=top {
            fake.put(h, 0, 0, vec![]);
        }
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, Some(0));
        drain(&mut w).await.unwrap();

        // Every remembered block, and the one below them, is replaced.
        for h in 5..=top + 1 {
            fake.put(h, 1, if h == 5 { 0 } else { 1 }, vec![]);
        }
        match drain(&mut w).await {
            Err(WatchError::DeepReorg(h)) => assert_eq!(h, top + 1 - DEPTH as u64),
            other => panic!("expected a deep reorg, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_fork_of_the_start_block_is_not_deep() {
        let fake = Fake::default();
        fake.put(10, 0, 0, vec![]);
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, Some(10));
        drain(&mut w).await.unwrap();

        fake.put(10, 1, 0, vec![tx("s", FLOAT)]);
        fake.put(11, 1, 1, vec![]);
        assert_eq!(
            summary(&drain(&mut w).await.unwrap()),
            ["reorg 10", "tx 10 s"]
        );
    }

    #[tokio::test]
    async fn a_provider_error_changes_nothing_and_the_height_is_retried() {
        let fake = Fake::default();
        fake.put(10, 0, 0, vec![]);
        fake.put(11, 0, 0, vec![tx("r", FLOAT)]);
        let dir = tempfile::tempdir().unwrap();
        let mut w = open(&fake, &dir, Some(10));
        fake.0.lock().unwrap().fail_next = Some(ProviderError::RateLimited {
            status: 429,
            retry_after: None,
        });
        assert!(matches!(
            w.step().await,
            Err(WatchError::Provider(ProviderError::RateLimited { .. }))
        ));
        assert_eq!(w.heights().0, None);
        // A height the provider does not serve yet is retried too, not skipped.
        fake.0.lock().unwrap().blocks.remove(&10);
        assert!(matches!(w.step().await, Err(WatchError::Provider(_))));
        fake.put(10, 0, 0, vec![]);
        assert_eq!(summary(&drain(&mut w).await.unwrap()), ["tx 11 r"]);
    }

    #[tokio::test]
    async fn reports_transfer_from_calls_that_pull_from_a_watched_address() {
        let call = |token: &str, selector: &str, from: &str| Tx {
            txid: format!("{selector}-{}", &token[2..6]),
            result: Some("SUCCESS".into()),
            contracts: vec![Contract {
                kind: "TriggerSmartContract".into(),
                owner: OTHER.into(),
                contract_address: token.into(),
                data: format!(
                    "{selector}{}{}{:064x}",
                    abi::encode_address(from),
                    abi::encode_address(OTHER),
                    5
                ),
                ..Contract::default()
            }],
        };
        let fake = Fake::default();
        fake.put(
            10,
            0,
            0,
            vec![
                call(TOKEN, abi::TRANSFER_FROM, FLOAT),
                call(TOKEN, abi::TRANSFER_FROM, OTHER), // another source
                call(OTHER, abi::TRANSFER_FROM, FLOAT), // not a listed token
                call(TOKEN, abi::TRANSFER, FLOAT),      // not transferFrom
            ],
        );
        let dir = tempfile::tempdir().unwrap();
        let events = drain(&mut open(&fake, &dir, Some(10))).await.unwrap();
        assert_eq!(summary(&events), ["pull 10 23b872dd-eca9"]);
    }

    #[test]
    fn decodes_tron_addresses_and_rejects_typos() {
        // TRON USDT; its hex form is the widely published `41a614…`.
        assert_eq!(
            address_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap(),
            FLOAT
        );
        assert_eq!(
            address_hex("TETXp15LarnzBPTubWzTA79qpvguRZn2cE").unwrap(),
            OTHER
        );
        assert_eq!(address_base58(FLOAT), "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assert_eq!(address_base58("41ab"), "41ab");
        for bad in [
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u", // checksum
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", // Bitcoin (prefix 0x00)
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSz",       // length
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj60", // `0` is not base58
        ] {
            assert!(address_hex(bad).is_err(), "{bad}");
        }
    }
}
