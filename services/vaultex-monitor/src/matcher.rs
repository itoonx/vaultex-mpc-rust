//! Receipt matching and the outflow rules (ROADMAP §3.4 RF-4, M7 #3).
//!
//! Every transaction the float signs must match an **accept receipt** from the Guard for the same
//! transaction id, wallet and network. Independently of the Guard, the monitor re-checks what the
//! chain shows against its own configuration, which is the written loss budget, not the Guard's
//! policy bundle. Rule ids and severities follow the alert catalogue in `docs/ops/runbooks.md`:
//!
//! | Rule | Fires on | Severity |
//! |---|---|---|
//! | MR-01 | a float-signed transaction that is not one TRX transfer or one contract call | 1, freeze |
//! | MR-02 | a float-signed transaction under a permission other than the configured ones | 1, freeze |
//! | MR-03 | a float-signed contract call that is not a plain `transfer` on a listed token with no value attached | 1, freeze |
//! | MR-04 | a float-signed transaction with no accept receipt after the grace period | 1, freeze |
//! | MR-06 | a receipt history that fails verification, or a receipt dated after its transaction's block | 1, freeze |
//! | MR-07 | a float-signed call that raises an allowance on a listed token by a non-zero amount | 1, freeze; refills blocked |
//! | MR-08 | a non-zero allowance from the float on a listed token (periodic reads) | 1, freeze; refills blocked |
//! | MR-09 | a `transferFrom` on a listed token that moves the float's tokens | 1, freeze |
//! | MR-10 | a monitor cap exceeded: per transaction, or rolling 24 h amount or count, per asset (the fee-spend cap is not built yet) | 1, freeze |
//! | MR-11 | a destination off the allowlist (allowlist mode), or never paid before (open mode) | 1, freeze / 2 |
//! | MR-19 | an allowance-raising call by the float with a zero amount | info |
//!
//! "Freeze" marks the alerts the soft-freeze path will act on; until that path exists (T07-4) an
//! alert is only reported. Caps and destinations are judged on what the chain shows, never on the
//! Guard's decode. A transaction is counted once, by transaction id, whichever provider reports it
//! first, and stays counted if its block is later orphaned (an unauthorised signature is an
//! incident either way).
//!
//! State lives in the state directory, next to the cursors: `outflows.jsonl` (every float-signed
//! transaction, as classified) and `alerts.jsonl` (every alert raised), both appended with an
//! fsync per line; `receipts.anchor` (the last verified receipt head); and `closed.txt`, which the
//! operator maintains: one `<alert id> <record reference>` line per alert that a ceremony,
//! incident or drill record has closed. The refill check reads them.
//!
//! A transaction's alerts are journaled before the transaction itself, and it counts as seen only
//! once both are: after a crash or a write error in between, the restarted monitor classifies it
//! again, and the alerts already journaled are not raised twice (they are deduplicated by id).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use vaultex_types::{Decision, Ed25519Pub, NetworkId, ReceiptBodyV1, WalletId};

use crate::abi;
use crate::provider::{Contract, Word};
use crate::receipts::Broken;
use crate::watcher::{address_base58, address_hex, Event};

/// The asset name of TRX in caps, journals and reports; tokens are named by contract (hex).
pub const TRX: &str = "TRX";
const DAY_MS: i64 = 86_400_000;
/// The Guard records a receipt before it releases its signature, so a receipt cannot postdate the
/// block that includes the transaction by more than clock error. ESTIMATE: receipt times are whole
/// seconds, and a clock offset above 500 ms already pages (MR-20).
const MAX_RECEIPT_SKEW_MS: i64 = 5_000;

pub const OUTFLOWS: &str = "outflows.jsonl";
pub const ALERTS: &str = "alerts.jsonl";
pub const CLOSED: &str = "closed.txt";
pub const ANCHOR: &str = "receipts.anchor";

// ---------------------------------------------------------------------------------------------
// Configuration

/// `monitor.json`, as written at the genesis ceremony. Addresses are base58 (`T…`), amounts are
/// integers in base units (sun for TRX).
// ponytail: JSON, because no TOML parser is in Cargo.lock yet; the ops docs say `monitor.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// CAIP-2 network id, for example `tron:3448148188` (Nile).
    network: String,
    /// The Guard's wallet id for the float.
    wallet_id: String,
    float: String,
    /// Permission ids the float may sign under (the active permission the Guard co-signs).
    permission_ids: Vec<u32>,
    /// The Guard's receipt public key, hex.
    receipt_key: String,
    /// The copy of the Guard's receipt log that the monitor reads.
    receipt_log: PathBuf,
    #[serde(default = "default_grace_ms")]
    grace_ms: u64,
    trx: Caps,
    /// Listed tokens by contract address.
    #[serde(default)]
    tokens: BTreeMap<String, Caps>,
    destinations: Destinations,
    /// Extra addresses whose allowances from the float are read.
    #[serde(default)]
    spenders: Vec<String>,
}

/// ESTIMATE: covers the receipt export lag; the Guard writes a receipt before it signs.
fn default_grace_ms() -> u64 {
    10_000
}

/// The monitor's own limits for one asset, in base units.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caps {
    pub per_tx: u128,
    pub per_24h: u128,
    pub count_24h: u32,
    /// The float's balance ceiling, and the headroom kept below it for refills.
    pub ceiling: u128,
    pub headroom: u128,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destinations {
    mode: Mode,
    allow: Vec<String>,
}

/// Allowlist mode freezes on any destination off the list; open mode pages on a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Allowlist,
    Open,
}

/// The validated configuration; addresses are 21-byte hex (`41…`).
#[derive(Clone, Debug)]
pub struct Config {
    pub network: NetworkId,
    pub wallet: WalletId,
    pub float: String,
    pub permission_ids: BTreeSet<u32>,
    pub receipt_key: Ed25519Pub,
    pub receipt_log: PathBuf,
    pub grace_ms: u64,
    /// Caps by asset: [`TRX`] or a token contract.
    pub assets: BTreeMap<String, Caps>,
    pub mode: Mode,
    pub allow: BTreeSet<String>,
    pub spenders: BTreeSet<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let f: ConfigFile = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let network = NetworkId::new(&f.network)
            .ok()
            .filter(|n| n.as_str().starts_with("tron:"))
            .ok_or(format!("network {:?}: not a TRON network", f.network))?;
        let wallet = WalletId::new(&f.wallet_id)
            .map_err(|_| format!("wallet_id {:?}: use [a-z0-9-]", f.wallet_id))?;
        let mut key = [0u8; 32];
        hex::decode_to_slice(&f.receipt_key, &mut key)
            .map_err(|_| "receipt_key: expected 64 hex digits".to_owned())?;
        if f.permission_ids.is_empty() {
            return Err("permission_ids: name at least one".into());
        }
        let hexes = |list: &[String]| -> Result<BTreeSet<String>, String> {
            list.iter().map(|a| address_hex(a)).collect()
        };
        let mut assets = BTreeMap::from([(TRX.to_owned(), f.trx)]);
        for (token, caps) in f.tokens {
            assets.insert(address_hex(&token)?, caps);
        }
        if let Some((asset, _)) = assets.iter().find(|(_, c)| c.headroom > c.ceiling) {
            return Err(format!("{asset}: headroom above the ceiling"));
        }
        Ok(Self {
            network,
            wallet,
            float: address_hex(&f.float)?,
            permission_ids: f.permission_ids.into_iter().collect(),
            receipt_key: Ed25519Pub(key),
            receipt_log: f.receipt_log,
            grace_ms: f.grace_ms,
            assets,
            mode: f.destinations.mode,
            allow: hexes(&f.destinations.allow)?,
            spenders: hexes(&f.spenders)?,
        })
    }

    /// Listed token contracts.
    pub fn tokens(&self) -> impl Iterator<Item = &String> {
        self.assets.keys().filter(|a| *a != TRX)
    }

    /// Whose allowances from the float are read: the configured spenders, the allowlisted
    /// destinations, and every spender the float has ever raised an allowance for. Any allowance
    /// on a listed token needs such a float-signed call (the onboarding checklist excludes tokens
    /// with signature-based approvals), so this set covers every allowance the float can have.
    pub fn spender_set(&self, outflows: &[Outflow]) -> BTreeSet<String> {
        let approved = outflows.iter().filter_map(|o| o.spender.clone());
        let mut set: BTreeSet<String> = self.spenders.union(&self.allow).cloned().collect();
        set.extend(approved);
        set
    }
}

// ---------------------------------------------------------------------------------------------
// Journals

/// A float-signed transaction, as the monitor classified it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outflow {
    pub txid: String,
    pub height: u64,
    pub block_time_ms: i64,
    /// [`TRX`] or a listed token, when the transaction is a transfer of one.
    pub asset: Option<String>,
    pub to: Option<String>,
    pub amount: u128,
    /// The spender of a non-zero allowance-raising call.
    pub spender: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// `<rule>:<subject>`; an alert is raised once per id.
    pub id: String,
    pub rule: String,
    /// 1 (page, and freeze if `freeze`), 2 (page), 3 (information).
    pub severity: u8,
    pub freeze: bool,
    pub detail: String,
    pub at_ms: u64,
}

/// An append-only JSON-lines file, synced after every line. After a failed write it refuses
/// every later one, so no line is ever appended behind a torn one.
struct Journal {
    file: File,
    failed: bool,
}

impl Journal {
    /// Opens `path` for appending. A last line without its newline is a write that never
    /// completed (and was never acted on): it is cut off.
    fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let text = fs::read(path)?;
        let complete = text.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        if complete < text.len() {
            file.set_len(complete as u64)?;
            file.sync_all()?;
        }
        Ok(Self {
            file,
            failed: false,
        })
    }

    fn append<T: Serialize>(&mut self, record: &T) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("an earlier write to this journal failed"));
        }
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let written = self
            .file
            .write_all(&line)
            .and_then(|()| self.file.sync_data());
        self.failed = written.is_err();
        written
    }
}

/// Reads a journal: every complete line must parse (a damaged line is an error, never skipped).
fn read_journal<T: DeserializeOwned>(path: &Path) -> io::Result<Vec<T>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let complete = text.rfind('\n').map_or("", |i| &text[..i]);
    complete
        .lines()
        .map(|l| {
            serde_json::from_str(l).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })
        })
        .collect()
}

/// What the state directory holds, read-only.
pub struct State {
    pub outflows: Vec<Outflow>,
    pub alerts: Vec<Alert>,
    /// Alert ids closed by a record, with the record reference.
    pub closed: BTreeMap<String, String>,
}

impl State {
    pub fn load(dir: &Path) -> io::Result<Self> {
        let closed_path = dir.join(CLOSED);
        let text = match fs::read_to_string(&closed_path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let mut closed = BTreeMap::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once(char::is_whitespace) {
                Some((id, record)) if !record.trim().is_empty() => {
                    closed.insert(id.to_owned(), record.trim().to_owned());
                }
                _ => {
                    let msg = format!("{}: {line:?} needs a record reference", CLOSED);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
                }
            }
        }
        Ok(Self {
            outflows: read_journal(&dir.join(OUTFLOWS))?,
            alerts: read_journal(&dir.join(ALERTS))?,
            closed,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Matcher

pub struct Matcher {
    cfg: Config,
    outflows: Journal,
    alerts: Journal,
    history: Vec<Outflow>,
    seen: HashSet<String>,
    raised: HashSet<String>,
    /// Accept receipts for this wallet and network: transaction id → receipt time (s).
    accepted: HashMap<String, u64>,
    /// Transactions waiting for their receipt: id → (deadline, block time), both in ms.
    pending: BTreeMap<String, (u64, i64)>,
    /// `<provider>:<token>:<spender>` whose last allowance read was non-zero.
    nonzero: HashSet<String>,
}

/// Rule findings for one transaction, merged into one alert per rule.
#[derive(Default)]
struct Findings(BTreeMap<&'static str, (u8, bool, Vec<String>)>);

impl Findings {
    fn add(&mut self, rule: &'static str, severity: u8, freeze: bool, why: String) {
        let entry = self.0.entry(rule).or_insert((severity, freeze, Vec::new()));
        entry.2.push(why);
    }
}

impl Matcher {
    /// Opens the journals in `dir` and reloads them. Every journaled transaction waits for its
    /// receipt again (the receipt index is rebuilt from the receipt log), and alerts already
    /// raised are not raised twice.
    pub fn open(cfg: Config, dir: &Path, now_ms: u64) -> io::Result<Self> {
        let outflows = Journal::open(&dir.join(OUTFLOWS))?;
        let alerts = Journal::open(&dir.join(ALERTS))?;
        let state = State::load(dir)?;
        let deadline = now_ms + cfg.grace_ms;
        Ok(Self {
            seen: state.outflows.iter().map(|o| o.txid.clone()).collect(),
            pending: state
                .outflows
                .iter()
                .map(|o| (o.txid.clone(), (deadline, o.block_time_ms)))
                .collect(),
            raised: state.alerts.into_iter().map(|a| a.id).collect(),
            history: state.outflows,
            cfg,
            outflows,
            alerts,
            accepted: HashMap::new(),
            nonzero: HashSet::new(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Current spender set (see [`Config::spender_set`]).
    pub fn spenders(&self) -> BTreeSet<String> {
        self.cfg.spender_set(&self.history)
    }

    /// Classifies the transactions of one scanned block and returns the alerts they raise. On an
    /// error the monitor must stop: the transaction being classified is not marked seen.
    pub fn observe(&mut self, events: &[Event], now_ms: u64) -> io::Result<Vec<Alert>> {
        let mut out = Vec::new();
        for event in events {
            match event {
                Event::WatchedTx {
                    height,
                    block_time_ms,
                    txid,
                    contracts,
                    contract,
                    ..
                } if contract.owner == self.cfg.float => {
                    let tx = (txid.as_str(), *height, *block_time_ms, *contracts);
                    out.extend(self.float_tx(tx, contract, now_ms)?);
                }
                Event::TokenPull { txid, contract, .. } => {
                    out.extend(self.pull(txid, contract, now_ms)?);
                }
                _ => {}
            }
        }
        Ok(out)
    }

    fn float_tx(
        &mut self,
        (txid, height, block_time_ms, contracts): (&str, u64, i64, usize),
        c: &Contract,
        now_ms: u64,
    ) -> io::Result<Vec<Alert>> {
        if self.seen.contains(txid) {
            return Ok(Vec::new()); // the other provider, or a re-inclusion after a fork
        }
        let mut f = Findings::default();
        let mut outflow = Outflow {
            txid: txid.to_owned(),
            height,
            block_time_ms,
            asset: None,
            to: None,
            amount: 0,
            spender: None,
        };
        if contracts != 1 {
            f.add(
                "MR-01",
                1,
                true,
                format!("{contracts} contracts in one transaction"),
            );
        }
        match c.kind.as_str() {
            "TransferContract" => {
                outflow.asset = Some(TRX.to_owned());
                outflow.to = Some(c.to.clone());
                // ponytail: a negative amount cannot be valid on chain; it counts as zero.
                outflow.amount = u128::try_from(c.amount).unwrap_or(0);
            }
            "TriggerSmartContract" => self.contract_call(c, &mut outflow, &mut f),
            other => f.add("MR-01", 1, true, format!("contract type {other}")),
        }
        if !self.cfg.permission_ids.contains(&c.permission_id) {
            let why = format!("signed under permission {}", c.permission_id);
            f.add("MR-02", 1, true, why);
        }
        if let (Some(asset), Some(to)) = (&outflow.asset, &outflow.to) {
            self.caps(asset, to, outflow.amount, block_time_ms, &mut f);
        }

        // Alerts first, then the transaction, then the in-memory state (see the module doc).
        let mut alerts = self.raise_findings(txid, f, now_ms)?;
        let receipt = self.accepted.get(txid).copied();
        if let Some(time_s) = receipt {
            alerts.extend(self.check_time(txid, time_s, block_time_ms, now_ms)?);
        }
        self.outflows.append(&outflow)?;
        self.seen.insert(txid.to_owned());
        self.history.push(outflow);
        if receipt.is_none() {
            let deadline = now_ms + self.cfg.grace_ms;
            self.pending
                .insert(txid.to_owned(), (deadline, block_time_ms));
        }
        Ok(alerts)
    }

    /// Checks a float-signed contract call: only `transfer` on a listed token, with exactly two
    /// clean words and no value attached, is an outflow the Guard may co-sign.
    fn contract_call(&self, c: &Contract, outflow: &mut Outflow, f: &mut Findings) {
        let token = &c.contract_address;
        let listed = token != TRX && self.cfg.assets.contains_key(token);
        if !listed {
            let why = format!("call to {}, not a listed token", address_base58(token));
            f.add("MR-03", 1, true, why);
        }
        if c.call_value != 0 || c.call_token_value != 0 {
            f.add("MR-03", 1, true, "value attached to the call".into());
        }
        let hex_ok = c.data.bytes().all(|b| b.is_ascii_hexdigit());
        let (first, second) = (
            abi::word(&c.data, 0).unwrap_or_default(),
            abi::word(&c.data, 1).unwrap_or_default(),
        );
        match abi::selector(&c.data) {
            Some(abi::TRANSFER) => {
                let (to, clean) = abi::address(first);
                if c.data.len() != abi::TWO_WORD_CALL || !clean || !hex_ok {
                    f.add("MR-03", 1, true, "non-canonical transfer call data".into());
                }
                if listed {
                    outflow.asset = Some(token.clone());
                    outflow.to = Some(to);
                    outflow.amount = abi::amount(second);
                }
            }
            Some(s) if abi::RAISE_ALLOWANCE.contains(&s) => {
                f.add("MR-03", 1, true, format!("allowance-raising call {s}"));
                let (spender, _) = abi::address(first);
                let value = abi::amount(second);
                let on = address_base58(token);
                let to = address_base58(&spender);
                if value == 0 {
                    f.add(
                        "MR-19",
                        3,
                        false,
                        format!("zero allowance for {to} on {on}"),
                    );
                } else {
                    let why = format!("allowance of {value} for {to} on {on}");
                    // A listed token holds the float's funds; any other call is MR-03 already.
                    if listed {
                        f.add("MR-07", 1, true, why);
                    }
                    outflow.spender = Some(spender);
                }
            }
            s => {
                let why = format!("selector {}", s.unwrap_or("(none)"));
                f.add("MR-03", 1, true, why);
            }
        }
    }

    /// Monitor caps (MR-10) and destination checks (MR-11), against earlier history.
    fn caps(&self, asset: &str, to: &str, amount: u128, time_ms: i64, f: &mut Findings) {
        let name = if asset == TRX {
            TRX.to_owned()
        } else {
            address_base58(asset)
        };
        if let Some(caps) = self.cfg.assets.get(asset) {
            if amount > caps.per_tx {
                let why = format!(
                    "{amount} {name} above the per-transaction cap {}",
                    caps.per_tx
                );
                f.add("MR-10", 1, true, why);
            }
            // The history does not hold this transaction yet: it starts the sums.
            let window = self.history.iter().filter(|o| {
                o.asset.as_deref() == Some(asset)
                    && o.block_time_ms > time_ms - DAY_MS
                    && o.block_time_ms <= time_ms
            });
            let (sum, count) = window.fold((amount, 1u64), |(s, n), o| {
                (s.saturating_add(o.amount), n + 1)
            });
            if sum > caps.per_24h {
                let why = format!("{sum} {name} in 24 h, above the cap {}", caps.per_24h);
                f.add("MR-10", 1, true, why);
            }
            if count > u64::from(caps.count_24h) {
                let why = format!(
                    "{count} {name} transfers in 24 h, above the cap {}",
                    caps.count_24h
                );
                f.add("MR-10", 1, true, why);
            }
        }
        if !self.cfg.allow.contains(to) {
            let dest = address_base58(to);
            match self.cfg.mode {
                Mode::Allowlist => f.add("MR-11", 1, true, format!("{dest} is not allowlisted")),
                Mode::Open if !self.history.iter().any(|o| o.to.as_deref() == Some(to)) => {
                    f.add("MR-11", 2, false, format!("new destination {dest}"))
                }
                Mode::Open => {}
            }
        }
    }

    /// MR-09: a `transferFrom` that takes the float's tokens; the float did not sign it.
    fn pull(&mut self, txid: &str, c: &Contract, now_ms: u64) -> io::Result<Vec<Alert>> {
        let (from, _) = abi::address(abi::word(&c.data, 0).unwrap_or_default());
        let amount = abi::amount(abi::word(&c.data, 2).unwrap_or_default());
        let listed = self.cfg.tokens().any(|t| *t == c.contract_address);
        if from != self.cfg.float || !listed || amount == 0 {
            return Ok(Vec::new());
        }
        let why = format!(
            "{amount} of {} taken from the float by {} under an allowance",
            address_base58(&c.contract_address),
            address_base58(&c.owner)
        );
        let mut f = Findings::default();
        f.add("MR-09", 1, true, why);
        self.raise_findings(txid, f, now_ms)
    }

    /// Indexes newly verified receipts and settles the transactions waiting for them.
    pub fn receipts(&mut self, bodies: &[ReceiptBodyV1], now_ms: u64) -> io::Result<Vec<Alert>> {
        let mut alerts = Vec::new();
        for b in bodies {
            let ours = b.wallet_id == self.cfg.wallet && b.network == self.cfg.network;
            if b.decision != Decision::Accept || !ours {
                continue;
            }
            let txid = hex::encode(b.tx_hash.0);
            self.accepted.insert(txid.clone(), b.time_s);
            if let Some(&(_, block_time_ms)) = self.pending.get(&txid) {
                alerts.extend(self.check_time(&txid, b.time_s, block_time_ms, now_ms)?);
                self.pending.remove(&txid);
            }
        }
        Ok(alerts)
    }

    fn check_time(
        &mut self,
        txid: &str,
        time_s: u64,
        block_time_ms: i64,
        now_ms: u64,
    ) -> io::Result<Vec<Alert>> {
        let receipt_ms = i64::try_from(time_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        if receipt_ms <= block_time_ms.saturating_add(MAX_RECEIPT_SKEW_MS) {
            return Ok(Vec::new());
        }
        let why = format!(
            "receipt dated {} s after the block that includes the transaction",
            (receipt_ms - block_time_ms) / 1000
        );
        let mut f = Findings::default();
        f.add("MR-06", 1, true, why);
        self.raise_findings(txid, f, now_ms)
    }

    /// MR-06 for a receipt history that fails verification.
    pub fn broken_receipts(&mut self, b: &Broken, now_ms: u64) -> io::Result<Vec<Alert>> {
        let mut f = Findings::default();
        f.add("MR-06", 1, true, b.to_string());
        self.raise_findings(&format!("log-{}-{}", b.offset, b.check), f, now_ms)
    }

    /// MR-04 for every transaction whose grace period has run out without an accept receipt.
    pub fn tick(&mut self, now_ms: u64) -> io::Result<Vec<Alert>> {
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, (deadline, _))| *deadline <= now_ms)
            .map(|(txid, _)| txid.clone())
            .collect();
        let mut alerts = Vec::new();
        for txid in due {
            let mut f = Findings::default();
            let why = format!("no accept receipt within {} ms", self.cfg.grace_ms);
            f.add("MR-04", 1, true, why);
            alerts.extend(self.raise_findings(&txid, f, now_ms)?);
            self.pending.remove(&txid);
        }
        Ok(alerts)
    }

    /// MR-08: one allowance read from the float to `spender` on `token`, by `provider`. Raised
    /// once per stretch of non-zero reads from that provider.
    pub fn allowance(
        &mut self,
        provider: &str,
        token: &str,
        spender: &str,
        value: &Word,
        now_ms: u64,
    ) -> io::Result<Vec<Alert>> {
        let key = format!("{provider}:{token}:{spender}");
        if *value == [0; 32] {
            self.nonzero.remove(&key);
            return Ok(Vec::new());
        }
        if self.nonzero.contains(&key) {
            return Ok(Vec::new());
        }
        let why = format!(
            "allowance of {} for {} on {} (read by {provider})",
            abi::word_amount(value),
            address_base58(spender),
            address_base58(token)
        );
        let mut f = Findings::default();
        f.add("MR-08", 1, true, why);
        let alerts = self.raise_findings(&format!("{key}:{}", now_ms / 1000), f, now_ms)?;
        self.nonzero.insert(key);
        Ok(alerts)
    }

    /// Journals one alert per rule, unless an alert with that id is already journaled. An id
    /// counts as raised only once its line is written.
    fn raise_findings(
        &mut self,
        subject: &str,
        f: Findings,
        now_ms: u64,
    ) -> io::Result<Vec<Alert>> {
        let mut alerts = Vec::new();
        for (rule, (severity, freeze, why)) in f.0 {
            let alert = Alert {
                id: format!("{rule}:{subject}"),
                rule: rule.to_owned(),
                severity,
                freeze,
                detail: why.join("; "),
                at_ms: now_ms,
            };
            if !self.raised.contains(&alert.id) {
                self.alerts.append(&alert)?;
                self.raised.insert(alert.id.clone());
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::receipts::tests::{Writer, NILE, WALLET};

    pub const FLOAT: &str = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
    pub const TOKEN: &str = "41eca9bc828a3005b9a3b909f2cc5c2a54794de05f";
    pub const PAYEE: &str = "415e33cfa37d730a43063e70ff5381acfc7895e086";
    pub const STRANGER: &str = "41313bd9f0dc4e4b2a787470b8dea27e58be82fc53";
    const T0: i64 = 1_791_000_000_000;

    pub fn config(mode: &str) -> Config {
        let b58 = address_base58;
        Config::parse(&format!(
            r#"{{
              "network": "{NILE}", "wallet_id": "{WALLET}", "float": "{}",
              "permission_ids": [2],
              "receipt_key": "{}", "receipt_log": "receipts.log",
              "trx": {{"per_tx": 100000000, "per_24h": 500000000, "count_24h": 30,
                       "ceiling": 1000000000, "headroom": 100000000}},
              "tokens": {{"{}": {{"per_tx": 1000, "per_24h": 1500, "count_24h": 3,
                                  "ceiling": 10000, "headroom": 1000}}}},
              "destinations": {{"mode": "{mode}", "allow": ["{}"]}}
            }}"#,
            b58(FLOAT),
            hex::encode(Writer::start().key.verifying_key().to_bytes()),
            b58(TOKEN),
            b58(PAYEE),
        ))
        .unwrap()
    }

    pub fn transfer_data(to: &str, amount: u128) -> String {
        format!("{}{}{amount:064x}", abi::TRANSFER, abi::encode_address(to))
    }

    pub fn trc20(to: &str, amount: u128) -> Contract {
        Contract {
            kind: "TriggerSmartContract".into(),
            owner: FLOAT.into(),
            permission_id: 2,
            contract_address: TOKEN.into(),
            data: transfer_data(to, amount),
            ..Contract::default()
        }
    }

    pub fn txid(n: u8) -> String {
        format!("{n:02x}{}", "0".repeat(62))
    }

    pub fn event(n: u8, minutes: i64, contract: Contract) -> Event {
        Event::WatchedTx {
            provider: "a".into(),
            height: 100 + u64::from(n),
            block_id: "00".repeat(32),
            block_time_ms: T0 + minutes * 60_000,
            txid: txid(n),
            contract_index: 0,
            contracts: 1,
            contract,
            result: Some("SUCCESS".into()),
        }
    }

    fn rules(alerts: &[Alert]) -> Vec<String> {
        alerts.iter().map(|a| a.rule.clone()).collect()
    }

    fn open(dir: &tempfile::TempDir, mode: &str) -> Matcher {
        Matcher::open(config(mode), dir.path(), 0).unwrap()
    }

    #[test]
    fn config_is_validated() {
        let ok = config("allowlist");
        assert_eq!(ok.float, FLOAT);
        assert_eq!(ok.tokens().collect::<Vec<_>>(), [TOKEN]);
        assert_eq!(ok.spender_set(&[]), BTreeSet::from([PAYEE.to_owned()]));
        let good = r#"{"network": "tron:3448148188", "wallet_id": "w", "float": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
          "permission_ids": [2], "receipt_key": "0000000000000000000000000000000000000000000000000000000000000000",
          "receipt_log": "r", "trx": {"per_tx": 1, "per_24h": 1, "count_24h": 1, "ceiling": 2, "headroom": 1},
          "destinations": {"mode": "open", "allow": []}}"#;
        assert!(Config::parse(good).is_ok());
        for (from, to) in [
            ("tron:3448148188", "eip155:1"), // not TRON
            (
                "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u",
            ), // typo
            ("[2]", "[]"),                   // no permission
            ("\"headroom\": 1", "\"headroom\": 3"), // above the ceiling
            ("\"open\"", "\"loose\""),       // unknown mode
            ("\"r\",", "\"r\", \"extra\": 1,"), // unknown field
        ] {
            assert!(Config::parse(&good.replace(from, to)).is_err(), "{to}");
        }
    }

    #[test]
    fn every_float_signed_transaction_needs_an_accept_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "allowlist");
        let w = Writer::start();
        let ts = (T0 / 1000) as u64;

        // Receipt first, then the transaction: matched at once.
        let body = w.body(&txid(1), true, ts);
        assert!(m.receipts(&[body], 0).unwrap().is_empty());
        assert!(m
            .observe(&[event(1, 0, trc20(PAYEE, 10))], 0)
            .unwrap()
            .is_empty());

        // Transaction first; its receipt arrives within the grace period.
        assert!(m
            .observe(&[event(2, 0, trc20(PAYEE, 10))], 1_000)
            .unwrap()
            .is_empty());
        let late = w.body(&txid(2), true, ts);
        assert!(m.receipts(&[late], 2_000).unwrap().is_empty());
        assert!(m.tick(60_000).unwrap().is_empty());

        // A refusal, or an accept for another wallet, does not match: MR-04 after the grace period.
        assert!(m
            .observe(&[event(3, 0, trc20(PAYEE, 10))], 1_000)
            .unwrap()
            .is_empty());
        let refused = w.body(&txid(3), false, ts);
        let mut elsewhere = w.body(&txid(3), true, ts);
        elsewhere.wallet_id = WalletId::new("other").unwrap();
        assert!(m.receipts(&[refused, elsewhere], 2_000).unwrap().is_empty());
        assert!(m.tick(10_999).unwrap().is_empty());
        let alerts = m.tick(11_000).unwrap();
        assert_eq!(rules(&alerts), ["MR-04"]);
        assert_eq!(alerts[0].id, format!("MR-04:{}", txid(3)));
        assert!((alerts[0].severity, alerts[0].freeze) == (1, true));

        // The same transaction from the other provider, or after a fork, counts once.
        assert!(m
            .observe(&[event(3, 0, trc20(PAYEE, 10))], 20_000)
            .unwrap()
            .is_empty());
        assert!(m.tick(99_000).unwrap().is_empty());
    }

    #[test]
    fn a_receipt_dated_after_its_block_is_an_integrity_alert() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "allowlist");
        let w = Writer::start();
        m.observe(&[event(1, 0, trc20(PAYEE, 10))], 0).unwrap();
        let backfilled = w.body(&txid(1), true, (T0 / 1000) as u64 + 6);
        assert_eq!(rules(&m.receipts(&[backfilled], 0).unwrap()), ["MR-06"]);
    }

    #[test]
    fn categorical_checks_on_what_the_float_signed() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "allowlist");
        let call = |data: String| Contract {
            data,
            ..trc20(PAYEE, 0)
        };
        let cases: Vec<(Contract, Vec<&str>)> = vec![
            (
                Contract {
                    kind: "AccountPermissionUpdateContract".into(),
                    owner: FLOAT.into(),
                    ..Contract::default()
                },
                vec!["MR-01", "MR-02"],
            ),
            (
                Contract {
                    permission_id: 0,
                    ..trc20(PAYEE, 10)
                },
                vec!["MR-02"],
            ),
            (
                Contract {
                    contract_address: STRANGER.into(),
                    ..trc20(PAYEE, 10)
                },
                vec!["MR-03"],
            ),
            (
                Contract {
                    call_value: 1,
                    ..trc20(PAYEE, 10)
                },
                vec!["MR-03"],
            ),
            (
                call(format!("{}00", transfer_data(PAYEE, 10))),
                vec!["MR-03"],
            ),
            (
                call(format!("{}{}", abi::TRANSFER_FROM, "00".repeat(96))),
                vec!["MR-03"],
            ),
            (
                call(format!(
                    "{}{}{:064x}",
                    "095ea7b3",
                    abi::encode_address(STRANGER),
                    5
                )),
                vec!["MR-03", "MR-07"],
            ),
            (
                call(format!(
                    "{}{}{:064x}",
                    "d73dd623",
                    abi::encode_address(STRANGER),
                    0
                )),
                vec!["MR-03", "MR-19"],
            ),
        ];
        for (n, (contract, want)) in cases.into_iter().enumerate() {
            let alerts = m.observe(&[event(n as u8, 0, contract)], 0).unwrap();
            assert_eq!(rules(&alerts), want, "case {n}");
        }
        // The non-zero approval's spender joins the allowance reads; the zero one does not.
        assert!(m.spenders().contains(STRANGER));
        assert_eq!(m.spenders().len(), 2);
    }

    #[test]
    fn caps_count_per_asset_over_a_rolling_day() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "allowlist");
        let trx = |amount| Contract {
            kind: "TransferContract".into(),
            owner: FLOAT.into(),
            permission_id: 2,
            to: PAYEE.into(),
            amount,
            ..Contract::default()
        };
        // Per transaction.
        assert_eq!(
            rules(&m.observe(&[event(1, 0, trc20(PAYEE, 1001))], 0).unwrap()),
            ["MR-10"]
        );
        assert!(m
            .observe(&[event(2, 0, trx(100_000_000))], 0)
            .unwrap()
            .is_empty());
        // 24 h amount: 1001 already counts, so 500 more crosses 1500.
        assert_eq!(
            rules(&m.observe(&[event(3, 1, trc20(PAYEE, 500))], 0).unwrap()),
            ["MR-10"]
        );
        // A day later the window has moved on; the count cap (3) then binds on the fourth.
        assert!(m
            .observe(&[event(4, 1441, trc20(PAYEE, 400))], 0)
            .unwrap()
            .is_empty());
        assert!(m
            .observe(&[event(5, 1442, trc20(PAYEE, 400))], 0)
            .unwrap()
            .is_empty());
        assert!(m
            .observe(&[event(6, 1443, trc20(PAYEE, 400))], 0)
            .unwrap()
            .is_empty());
        let alerts = m.observe(&[event(7, 1444, trc20(PAYEE, 1))], 0).unwrap();
        assert_eq!(rules(&alerts), ["MR-10"]);
        assert!(alerts[0].detail.contains("4 "), "{}", alerts[0].detail);
        // An amount too large for u128 saturates and trips the cap.
        let mut huge = trc20(PAYEE, 0);
        huge.data = format!(
            "{}{}{}",
            abi::TRANSFER,
            abi::encode_address(PAYEE),
            "f".repeat(64)
        );
        assert_eq!(
            rules(&m.observe(&[event(8, 3000, huge)], 0).unwrap()),
            ["MR-10"]
        );
    }

    #[test]
    fn destinations_in_allowlist_and_open_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "allowlist");
        let alerts = m.observe(&[event(1, 0, trc20(STRANGER, 1))], 0).unwrap();
        assert_eq!(rules(&alerts), ["MR-11"]);
        assert!((alerts[0].severity, alerts[0].freeze) == (1, true));

        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "open");
        assert!(m
            .observe(&[event(1, 0, trc20(PAYEE, 1))], 0)
            .unwrap()
            .is_empty());
        let alerts = m.observe(&[event(2, 0, trc20(STRANGER, 1))], 0).unwrap();
        assert_eq!(rules(&alerts), ["MR-11"]);
        assert!((alerts[0].severity, alerts[0].freeze) == (2, false));
        assert!(alerts[0].detail.starts_with("new destination T"));
        // Only the first payment to a destination is new.
        assert!(m
            .observe(&[event(3, 0, trc20(STRANGER, 1))], 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn allowance_spends_and_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "allowlist");
        let pull = |from: &str, amount: u128| Event::TokenPull {
            provider: "a".into(),
            height: 1,
            block_id: "00".repeat(32),
            block_time_ms: T0,
            txid: txid(9),
            contract: Contract {
                kind: "TriggerSmartContract".into(),
                owner: STRANGER.into(),
                contract_address: TOKEN.into(),
                data: format!(
                    "{}{}{}{amount:064x}",
                    abi::TRANSFER_FROM,
                    abi::encode_address(from),
                    abi::encode_address(STRANGER)
                ),
                ..Contract::default()
            },
            result: None,
        };
        assert!(m.observe(&[pull(FLOAT, 0)], 0).unwrap().is_empty());
        assert!(m.observe(&[pull(PAYEE, 5)], 0).unwrap().is_empty());
        assert_eq!(rules(&m.observe(&[pull(FLOAT, 5)], 0).unwrap()), ["MR-09"]);
        // A spend is not a float-signed transaction: no receipt is expected.
        assert!(m.tick(u64::MAX).unwrap().is_empty());

        let mut five = [0u8; 32];
        five[31] = 5;
        let zero = [0u8; 32];
        assert!(m.allowance("a", TOKEN, PAYEE, &zero, 0).unwrap().is_empty());
        let alerts = m.allowance("a", TOKEN, PAYEE, &five, 1_000).unwrap();
        assert_eq!(rules(&alerts), ["MR-08"]);
        assert!(alerts[0].detail.starts_with("allowance of 5 for T"));
        // Repeated non-zero reads do not repeat the alert; a new stretch does.
        assert!(m
            .allowance("a", TOKEN, PAYEE, &five, 61_000)
            .unwrap()
            .is_empty());
        assert!(m
            .allowance("a", TOKEN, PAYEE, &zero, 121_000)
            .unwrap()
            .is_empty());
        assert_eq!(
            m.allowance("a", TOKEN, PAYEE, &five, 181_000)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_crash_after_the_alerts_and_before_the_outflow_classifies_again() {
        let w = Writer::start();
        let receipt = || w.body(&txid(1), true, (T0 / 1000) as u64);
        // Guard-accepted, but above the per-transaction cap and off the allowlist.
        let tx = event(1, 0, trc20(STRANGER, 1001));
        // `kept` alert lines survive the crash: all, one (a crash between them), or none.
        for (kept, again) in [(2, vec![]), (1, vec!["MR-11"]), (0, vec!["MR-10", "MR-11"])] {
            let dir = tempfile::tempdir().unwrap();
            let mut m = open(&dir, "allowlist");
            m.receipts(&[receipt()], 0).unwrap();
            let first = m.observe(std::slice::from_ref(&tx), 0).unwrap();
            assert_eq!(rules(&first), ["MR-10", "MR-11"]);
            drop(m);
            let outflows = fs::read_to_string(dir.path().join(OUTFLOWS)).unwrap();
            let alerts = fs::read_to_string(dir.path().join(ALERTS)).unwrap();
            let alerts: String = alerts.split_inclusive('\n').take(kept).collect();
            fs::write(dir.path().join(OUTFLOWS), "").unwrap();
            fs::write(dir.path().join(ALERTS), alerts).unwrap();

            // The rescan after the restart classifies and journals it again.
            let mut m = open(&dir, "allowlist");
            m.receipts(&[receipt()], 0).unwrap();
            let raised = m.observe(std::slice::from_ref(&tx), 0).unwrap();
            assert_eq!(rules(&raised), again, "kept {kept}");
            let state = State::load(dir.path()).unwrap();
            assert_eq!(
                fs::read_to_string(dir.path().join(OUTFLOWS)).unwrap(),
                outflows
            );
            assert_eq!(state.alerts, first, "each alert once, as first raised");
            // From now on it counts once, and its receipt still matches it (no MR-04).
            assert!(m.observe(std::slice::from_ref(&tx), 0).unwrap().is_empty());
            assert!(m.tick(u64::MAX).unwrap().is_empty());
        }
    }

    #[test]
    fn a_failed_alert_write_leaves_the_transaction_unseen() {
        let tx = event(1, 0, trc20(STRANGER, 1001));
        for restart in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut m = open(&dir, "allowlist");
            m.alerts.failed = true; // as after an I/O error
            assert!(m.observe(std::slice::from_ref(&tx), 0).is_err());
            let state = State::load(dir.path()).unwrap();
            assert!(state.outflows.is_empty() && state.alerts.is_empty());
            if restart {
                drop(m);
                m = open(&dir, "allowlist");
            } else {
                m.alerts.failed = false;
            }
            // Nothing was marked seen or raised: every finding comes back.
            let alerts = m.observe(std::slice::from_ref(&tx), 0).unwrap();
            assert_eq!(rules(&alerts), ["MR-10", "MR-11"], "restart {restart}");
            assert_eq!(State::load(dir.path()).unwrap().outflows.len(), 1);
        }
    }

    #[test]
    fn state_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = open(&dir, "open");
        m.observe(&[event(1, 0, trc20(PAYEE, 700))], 0).unwrap();
        m.observe(&[event(2, 0, trc20(STRANGER, 1))], 0).unwrap();
        assert_eq!(rules(&m.tick(20_000).unwrap()), ["MR-04", "MR-04"]);
        drop(m);
        // A torn last line (a crash mid-write) is cut off on reopen.
        let mut f = OpenOptions::new()
            .append(true)
            .open(dir.path().join(ALERTS))
            .unwrap();
        f.write_all(b"{\"id\":").unwrap();

        let mut m = Matcher::open(config("open"), dir.path(), 30_000).unwrap();
        // Caps and known destinations carry over; raised alerts are not raised again.
        let alerts = m
            .observe(&[event(3, 1, trc20(STRANGER, 900))], 30_000)
            .unwrap();
        assert_eq!(rules(&alerts), ["MR-10"]);
        let w = Writer::start();
        let receipt = w.body(&txid(1), true, (T0 / 1000) as u64);
        assert!(m.receipts(&[receipt], 31_000).unwrap().is_empty());
        let due = m.tick(99_000).unwrap();
        assert_eq!(
            due.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
            [format!("MR-04:{}", txid(3))]
        );

        let state = State::load(dir.path()).unwrap();
        assert_eq!(state.outflows.len(), 3);
        assert_eq!(state.alerts.len(), 5); // MR-11, 2 × MR-04, MR-10, MR-04
        fs::write(
            dir.path().join(CLOSED),
            "# closed\nMR-04:x  CER-5 transcript\n\n",
        )
        .unwrap();
        let state = State::load(dir.path()).unwrap();
        assert_eq!(state.closed["MR-04:x"], "CER-5 transcript");
        fs::write(dir.path().join(CLOSED), "MR-04:x\n").unwrap();
        assert!(State::load(dir.path()).is_err());
    }
}
