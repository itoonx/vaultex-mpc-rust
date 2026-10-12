//! Vaultex outflow monitor (ROADMAP M7 #3, WS-07): watches the chain, matches every outflow to a
//! receipt, alerts on approvals and allowances, and can only freeze.
//!
//! - `vaultex-monitor watch` follows TRON on at least two independent public providers, each with
//!   its own persisted cursor, and prints JSON lines on stdout: `watched_tx` (a transaction signed
//!   by a watched address, per provider: "alarm on any"), `token_pull` (a `transferFrom` taking a
//!   watched address's tokens), `reorg`, `provider_health` (every minute), `no_healthy_provider`
//!   and `provider_failed`. With `--config monitor.json` it also matches the float's transactions
//!   to the Guard's receipts, reads the float's allowances every minute, and prints `alert` lines
//!   (rules MR-01–MR-04, MR-06–MR-11 and MR-19: see [`matcher`]).
//! - `vaultex-monitor refill-check` runs the check required before every refill ([`refill`]):
//!   exit 0 PASS, 1 FAIL, 2 could not complete.
//!
//! `watch` exits with status 1 when its last provider watcher stops, and at once when the
//! matcher's journal or the output fails: it fails closed rather than run on without scanning or
//! recording.
//!
//! Not built yet: the soft-freeze path (T07-4; alerts marked `freeze` are only reported), the
//! independent intent-digest check (MR-05, after the `INTENT_V1` RFC), the fee-spend cap of
//! MR-10, token event logs, solidified-height agreement between providers, balance reconciliation
//! (MR-13) and the permission snapshot.

mod abi;
mod cursor;
mod matcher;
mod provider;
mod receipts;
mod refill;
mod watcher;

use std::collections::HashSet;
use std::convert::Infallible;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use serde::Serialize;
use serde_json::json;
use tokio::task::JoinSet;

use matcher::{Alert, Config, Matcher, TRX};
use provider::{Backoff, HttpProvider, Provider, ProviderError};
use receipts::{load_anchor, save_anchor, ReceiptFeed};
use watcher::{Progress, WatchError, Watcher};

/// Providers as (name, URL).
type BuiltIn = &'static [(&'static str, &'static str)];

/// Built-in public providers, all keyless: two per network, run by different operators, with the
/// network's CAIP-2 id. Sources (fetched 2026-10-11): developers.tron.network/docs/networks
/// (TronGrid for mainnet and Nile; the community-run `api.nileex.io` for Nile) and
/// tron.publicnode.com (PublicNode mainnet). Shasta has a single documented endpoint, so it needs
/// `--provider`.
const NETWORKS: &[(&str, &str, BuiltIn)] = &[
    (
        "mainnet",
        "tron:728126428",
        &[
            ("trongrid", "https://api.trongrid.io"),
            ("publicnode", "https://tron-rpc.publicnode.com"),
        ],
    ),
    (
        "nile",
        "tron:3448148188",
        &[
            ("trongrid-nile", "https://nile.trongrid.io"),
            ("nileex", "https://api.nileex.io"),
        ],
    ),
];

/// TRON produces a block every 3 s.
const POLL: Duration = Duration::from_secs(3);
/// A provider with no successful call for this long is degraded.
const DEGRADED_AFTER: Duration = Duration::from_secs(300);
const HEALTH_EVERY: Duration = Duration::from_secs(60);
/// How often the receipt log is read; well inside the matcher's grace period.
const RECEIPT_POLL: Duration = Duration::from_secs(2);
/// How often each provider reads the float's allowances (rule MR-08).
const ALLOWANCE_EVERY: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(version, about = "Vaultex outflow monitor")]
enum Cli {
    /// Follow the chain on two or more providers and print JSON lines on stdout.
    Watch(WatchArgs),
    /// Check, before a refill, that the float has no allowance and every outflow is accounted for.
    RefillCheck(RefillArgs),
}

#[derive(clap::Args)]
struct Sources {
    /// Network whose built-in public providers to use: mainnet or nile.
    #[arg(
        long,
        required_unless_present = "providers",
        conflicts_with = "providers"
    )]
    network: Option<String>,
    /// Use these providers instead, as NAME=URL (repeat; at least two).
    #[arg(long = "provider", value_name = "NAME=URL", value_parser = parse_provider)]
    providers: Vec<(String, String)>,
    /// Minimum spacing between two requests to one provider, in milliseconds.
    #[arg(long, default_value_t = 350)]
    min_interval_ms: u64,
}

#[derive(clap::Args)]
struct WatchArgs {
    #[command(flatten)]
    sources: Sources,
    /// TRON address (T…) whose transactions to report (repeat). Without one and without
    /// `--config`, the watcher only scans, which serves as a provider soak test.
    #[arg(long = "watch", value_name = "ADDRESS", value_parser = watcher::address_hex)]
    watch: Vec<String>,
    /// Directory for one cursor file per provider and the matcher's state. Use one per network.
    #[arg(long)]
    state_dir: PathBuf,
    /// First height to scan for a provider without a cursor (default: its current head).
    #[arg(long)]
    from_height: Option<u64>,
    /// The monitor configuration (`monitor.json`): watch its float, match its transactions to
    /// the Guard's receipts, and raise alerts.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(clap::Args)]
struct RefillArgs {
    #[command(flatten)]
    sources: Sources,
    /// The monitor configuration (`monitor.json`).
    #[arg(long)]
    config: PathBuf,
    /// The state directory that `watch --config` keeps.
    #[arg(long)]
    state_dir: PathBuf,
    /// The asset to refill: TRX, or a listed token's address (T…).
    #[arg(long, value_parser = parse_asset)]
    asset: String,
    /// The refill amount, in base units (sun for TRX).
    #[arg(long)]
    amount: u128,
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse() {
        Cli::Watch(args) => {
            let Err(e) = run(args).await;
            eprintln!("vaultex-monitor: {e}");
            ExitCode::FAILURE
        }
        Cli::RefillCheck(args) => match refill_check(args).await {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                eprintln!("vaultex-monitor: refill check could not complete: {e}");
                ExitCode::from(2)
            }
        },
    }
}

fn parse_asset(s: &str) -> Result<String, String> {
    if s == TRX {
        Ok(TRX.to_owned())
    } else {
        watcher::address_hex(s)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn parse_provider(s: &str) -> Result<(String, String), String> {
    let (name, url) = s.split_once('=').ok_or("expected NAME=URL")?;
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !name_ok {
        return Err(format!(
            "provider name {name:?}: use letters, digits, '-' or '_'"
        ));
    }
    // Plain http only for a provider on this machine (local node, tests).
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("provider URL {url:?}: {e}"))?;
    let local_http = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if !(parsed.scheme() == "https" || local_http) {
        return Err(format!(
            "provider URL {url:?}: must start with https:// (http:// only for localhost)"
        ));
    }
    Ok((name.to_owned(), url.to_owned()))
}

/// The providers to use: at least two, with distinct names (they name the cursor files) and URLs.
fn resolve_providers(args: &Sources) -> Result<Vec<(String, String)>, String> {
    let list: Vec<(String, String)> = if args.providers.is_empty() {
        let network = args.network.as_deref().unwrap_or_default();
        let (_, _, built_in) =
            NETWORKS
                .iter()
                .find(|(n, _, _)| *n == network)
                .ok_or_else(|| {
                    format!("unknown network {network:?}: use mainnet, nile or --provider")
                })?;
        built_in
            .iter()
            .map(|(n, u)| (n.to_string(), u.to_string()))
            .collect()
    } else {
        args.providers.clone()
    };
    let names: HashSet<&str> = list.iter().map(|(n, _)| n.as_str()).collect();
    let urls: HashSet<&str> = list.iter().map(|(_, u)| u.as_str()).collect();
    if list.len() < 2 || names.len() != list.len() || urls.len() != list.len() {
        return Err("need at least two providers with distinct names and URLs".into());
    }
    Ok(list)
}

/// With a built-in network, the configuration must name the same network.
fn check_network(cfg: &Config, sources: &Sources) -> Result<(), String> {
    let Some(name) = &sources.network else {
        return Ok(()); // custom providers: the operator vouches for them
    };
    match NETWORKS.iter().find(|(n, _, _)| n == name) {
        Some((_, caip2, _)) if *caip2 == cfg.network.as_str() => Ok(()),
        _ => Err(format!(
            "--network {name} does not match the configured network {}",
            cfg.network.as_str()
        )),
    }
}

fn http_providers(sources: &Sources) -> Result<Vec<HttpProvider>, String> {
    let interval = Duration::from_millis(sources.min_interval_ms);
    resolve_providers(sources)?
        .into_iter()
        .map(|(name, url)| {
            HttpProvider::new(&name, &url, interval).map_err(|e| format!("{name}: {e}"))
        })
        .collect()
}

async fn refill_check(args: RefillArgs) -> Result<bool, String> {
    let cfg = Config::load(&args.config)?;
    check_network(&cfg, &args.sources)?;
    let providers = http_providers(&args.sources)?;
    let (report, pass) = refill::check(
        &providers,
        &cfg,
        &args.state_dir,
        &args.asset,
        args.amount,
        now_ms(),
    )
    .await?;
    print!("{report}");
    Ok(pass)
}

/// The matcher with its receipt source, when `watch` runs with a configuration.
struct Monitor {
    matcher: Arc<Mutex<Matcher>>,
    feed: ReceiptFeed,
    anchor: PathBuf,
}

impl Monitor {
    fn open(path: &Path, sources: &Sources, state_dir: &Path) -> Result<Self, String> {
        let cfg = Config::load(path)?;
        check_network(&cfg, sources)?;
        let anchor = state_dir.join(matcher::ANCHOR);
        let head = load_anchor(&anchor).map_err(|e| format!("{}: {e}", anchor.display()))?;
        let feed = ReceiptFeed::new(cfg.receipt_log.clone(), cfg.receipt_key, head);
        let matcher = Matcher::open(cfg, state_dir, now_ms())
            .map_err(|e| format!("{}: {e}", state_dir.display()))?;
        Ok(Self {
            matcher: Arc::new(Mutex::new(matcher)),
            feed,
            anchor,
        })
    }

    /// Reads new receipts, anchors the new head, and settles transactions whose grace ran out.
    fn poll(&mut self) -> Result<(), String> {
        let now = now_ms();
        let polled = self.feed.poll();
        if let (Ok(bodies), Some(head)) = (&polled, self.feed.head()) {
            if !bodies.is_empty() {
                save_anchor(&self.anchor, head)
                    .map_err(|e| format!("cannot persist the receipt anchor: {e}"))?;
            }
        }
        let mut m = self.matcher.lock().unwrap();
        let mut alerts = match polled {
            Ok(bodies) => m.receipts(&bodies, now),
            Err(broken) => m.broken_receipts(&broken, now),
        }
        .map_err(journal_error)?;
        alerts.extend(m.tick(now).map_err(journal_error)?);
        drop(m);
        emit_alerts(&alerts).map_err(|e| format!("cannot write alerts: {e}"))
    }
}

fn journal_error(e: io::Error) -> String {
    format!("cannot journal: {e}")
}

/// Why a provider's watcher stopped.
enum Stop {
    /// Its cursor or its provider's chain data failed: only this provider stops.
    Provider(String),
    /// The shared matcher journal or the output failed: the whole monitor stops.
    Fatal(String),
}

async fn run(args: WatchArgs) -> Result<Infallible, String> {
    let providers = http_providers(&args.sources)?;
    std::fs::create_dir_all(&args.state_dir)
        .map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let monitor = match &args.config {
        Some(path) => Some(Monitor::open(path, &args.sources, &args.state_dir)?),
        None => None,
    };
    let mut watch: HashSet<String> = args.watch.iter().cloned().collect();
    let mut tokens = HashSet::new();
    if let Some(m) = &monitor {
        let m = m.matcher.lock().unwrap();
        watch.insert(m.config().float.clone());
        tokens.extend(m.config().tokens().cloned());
    }
    if watch.is_empty() {
        eprintln!("vaultex-monitor: no --watch address or --config; scanning only");
    }

    let mut watchers = JoinSet::new();
    let mut readers = JoinSet::new();
    let mut healths = Vec::new();
    for provider in providers {
        let provider = Arc::new(provider);
        let name = provider.name().to_owned();
        let cursor = args.state_dir.join(format!("{name}.cursor"));
        let w = Watcher::open(
            Arc::clone(&provider),
            watch.clone(),
            tokens.clone(),
            cursor,
            args.from_height,
        )
        .map_err(|e| format!("{name}: {e}"))?;
        let health = Arc::new(Mutex::new(Health::new(&name)));
        healths.push(Arc::clone(&health));
        let matcher = monitor.as_ref().map(|m| Arc::clone(&m.matcher));
        if let Some(matcher) = matcher.clone() {
            let name = format!("{name} (allowance reads)");
            readers.spawn(async move {
                let Err(e) = allowance_loop(provider, matcher).await;
                (name, e)
            });
        }
        watchers.spawn(async move {
            let Err(e) = watch_loop(w, health, matcher).await;
            (name, e)
        });
    }
    supervise(watchers, readers, monitor, healths).await
}

/// Runs until the monitor must stop: when the last provider watcher has stopped, a watcher or an
/// allowance reader hits a fatal error (they only end on one), or the receipt poll fails.
async fn supervise(
    mut watchers: JoinSet<(String, Stop)>,
    mut readers: JoinSet<(String, String)>,
    mut monitor: Option<Monitor>,
    healths: Vec<Arc<Mutex<Health>>>,
) -> Result<Infallible, String> {
    let mut tick = tokio::time::interval(HEALTH_EVERY);
    tick.tick().await; // the first tick is immediate
    let mut receipt_tick = tokio::time::interval(RECEIPT_POLL);
    loop {
        tokio::select! {
            _ = receipt_tick.tick(), if monitor.is_some() => {
                monitor.as_mut().expect("guarded by the branch condition").poll()?;
            }
            done = watchers.join_next() => {
                let Some(done) = done else {
                    return Err("every provider watcher stopped".into());
                };
                let (name, error) = match done.map_err(|e| format!("watcher task failed: {e}"))? {
                    (name, Stop::Fatal(e)) => return Err(format!("{name}: {e}")),
                    (name, Stop::Provider(e)) => (name, e),
                };
                eprintln!("vaultex-monitor: {name} stopped: {error}");
                emit(&[json!({"kind": "provider_failed", "provider": name, "error": error})])
                    .map_err(|e| format!("cannot write to stdout: {e}"))?;
            }
            Some(done) = readers.join_next(), if !readers.is_empty() => {
                let (name, error) = done.map_err(|e| format!("allowance task failed: {e}"))?;
                return Err(format!("{name}: {error}"));
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let mut lines: Vec<_> = healths.iter().map(|h| h.lock().unwrap().report(now)).collect();
                if lines.iter().all(|l| l["degraded"] == true) {
                    lines.push(json!({"kind": "no_healthy_provider"}));
                }
                emit(&lines).map_err(|e| format!("cannot write to stdout: {e}"))?;
            }
        }
    }
}

/// Runs one provider's watcher until it must stop: provider errors back off and retry; a cursor
/// failure or a fork deeper than the cursor remembers stops this provider (fail closed: its health
/// turns degraded and the failure is printed); a matcher journal or output failure stops the
/// monitor. With a matcher, a step's transactions are classified and journaled before its events
/// are printed and its cursor is committed.
async fn watch_loop<P: Provider>(
    mut w: Watcher<P>,
    health: Arc<Mutex<Health>>,
    matcher: Option<Arc<Mutex<Matcher>>>,
) -> Result<Infallible, Stop> {
    let name = w.name().to_owned();
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    loop {
        match w.step().await {
            Ok(progress) => {
                health.lock().unwrap().ok(w.heights());
                backoff.reset();
                match progress {
                    Progress::Scanned(events) => {
                        let alerts = match &matcher {
                            Some(m) => m
                                .lock()
                                .unwrap()
                                .observe(&events, now_ms())
                                .map_err(|e| Stop::Fatal(journal_error(e)))?,
                            None => Vec::new(),
                        };
                        // stdout is shared by every task: an output failure is the monitor's.
                        emit(&events)
                            .map_err(|e| Stop::Fatal(format!("cannot write events: {e}")))?;
                        emit_alerts(&alerts)
                            .map_err(|e| Stop::Fatal(format!("cannot write alerts: {e}")))?;
                        w.commit().map_err(|e| {
                            Stop::Provider(format!("cannot persist the cursor: {e}"))
                        })?;
                    }
                    Progress::AtHead => tokio::time::sleep(POLL).await,
                }
            }
            Err(WatchError::Provider(e)) => {
                health.lock().unwrap().failed(&e);
                let wait = backoff.delay(&e);
                eprintln!(
                    "vaultex-monitor: {name}: {e}; retrying in {} s",
                    wait.as_secs_f32()
                );
                tokio::time::sleep(wait).await;
            }
            Err(fatal) => return Err(Stop::Provider(fatal.to_string())),
        }
    }
}

/// Reads the float's allowances on every listed token to every spender in the watched set, once
/// a minute, on one provider (rule MR-08). A failed read ends the round; the next round retries.
/// It ends only on a matcher journal or output failure, which stops the monitor.
async fn allowance_loop<P: Provider>(
    p: P,
    matcher: Arc<Mutex<Matcher>>,
) -> Result<Infallible, String> {
    let mut tick = tokio::time::interval(ALLOWANCE_EVERY);
    loop {
        tick.tick().await;
        let (float, tokens, spenders) = {
            let m = matcher.lock().unwrap();
            let tokens: Vec<String> = m.config().tokens().cloned().collect();
            (m.config().float.clone(), tokens, m.spenders())
        };
        'round: for token in &tokens {
            for spender in &spenders {
                let params = abi::encode_address(&float) + &abi::encode_address(spender);
                match p.call(&float, token, abi::ALLOWANCE, &params, false).await {
                    Ok(value) => {
                        let alerts = matcher
                            .lock()
                            .unwrap()
                            .allowance(p.name(), token, spender, &value, now_ms())
                            .map_err(journal_error)?;
                        emit_alerts(&alerts).map_err(|e| format!("cannot write alerts: {e}"))?;
                    }
                    Err(e) => {
                        eprintln!("vaultex-monitor: {}: allowance read failed: {e}", p.name());
                        break 'round;
                    }
                }
            }
        }
    }
}

/// Prints alerts as `alert` JSON lines.
fn emit_alerts(alerts: &[Alert]) -> io::Result<()> {
    emit(&alerts.iter().map(alert_line).collect::<Vec<_>>())
}

fn alert_line(a: &Alert) -> serde_json::Value {
    let mut line = json!(a);
    line["kind"] = "alert".into();
    line
}

/// Writes one JSON line per item to stdout and flushes, so a line is delivered before the cursor
/// that covers it is committed.
fn emit<T: Serialize>(items: &[T]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    for item in items {
        serde_json::to_writer(&mut out, item)?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// Per-provider counters since start, reported every [`HEALTH_EVERY`].
struct Health {
    provider: String,
    scanned: Option<u64>,
    head: Option<u64>,
    rate_limited: u64,
    errors: u64,
    last_error: Option<String>,
    /// Last successful step; the start time until then (a grace period).
    last_ok: Instant,
}

impl Health {
    fn new(provider: &str) -> Self {
        Self {
            provider: provider.to_owned(),
            scanned: None,
            head: None,
            rate_limited: 0,
            errors: 0,
            last_error: None,
            last_ok: Instant::now(),
        }
    }

    fn ok(&mut self, (scanned, head): (Option<u64>, Option<u64>)) {
        self.scanned = scanned;
        self.head = head;
        self.last_ok = Instant::now();
    }

    fn failed(&mut self, e: &ProviderError) {
        match e {
            ProviderError::RateLimited { .. } => self.rate_limited += 1,
            ProviderError::Unavailable(_) => self.errors += 1,
        }
        self.last_error = Some(e.to_string());
    }

    fn report(&self, now: Instant) -> serde_json::Value {
        let quiet = now.saturating_duration_since(self.last_ok);
        json!({
            "kind": "provider_health",
            "provider": self.provider,
            "scanned": self.scanned,
            "head": self.head,
            "lag": self.scanned.zip(self.head).map(|(s, h)| h.saturating_sub(s)),
            "rate_limited": self.rate_limited,
            "errors": self.errors,
            "last_error": self.last_error,
            "secs_since_ok": quiet.as_secs(),
            "degraded": quiet >= DEGRADED_AFTER,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn args(cli: &[&str]) -> Result<Sources, clap::Error> {
        let argv = ["vaultex-monitor", "watch", "--state-dir", "s"];
        match Cli::try_parse_from(argv.iter().chain(cli))? {
            Cli::Watch(a) => Ok(a.sources),
            Cli::RefillCheck(_) => unreachable!(),
        }
    }

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_built_in_network_has_two_distinct_keyless_providers() {
        for (network, _, _) in NETWORKS {
            let list = resolve_providers(&args(&["--network", network]).unwrap()).unwrap();
            assert!(list.len() >= 2, "{network}");
            assert!(list.iter().all(|(_, url)| url.starts_with("https://")));
        }
        assert!(resolve_providers(&args(&["--network", "shasta"]).unwrap()).is_err());
    }

    #[test]
    fn custom_providers_need_two_distinct_entries() {
        let ok = args(&[
            "--provider",
            "a=https://a.example",
            "--provider",
            "b=http://127.0.0.1:8090",
        ]);
        assert_eq!(resolve_providers(&ok.unwrap()).unwrap().len(), 2);
        // Remote providers must use https; plain http only for this machine.
        for url in [
            "http://b.example",
            "http://127.0.0.1.evil.example",
            "ftp://b.example",
        ] {
            let provider = format!("b={url}");
            assert!(parse_provider(&provider).is_err(), "{url}");
        }
        assert!(parse_provider("b=http://localhost:8090").is_ok());
        for bad in [
            vec!["--provider", "a=https://a.example"],
            vec![
                "--provider",
                "a=https://a.example",
                "--provider",
                "a=https://b.example",
            ],
            vec![
                "--provider",
                "a=https://x.example",
                "--provider",
                "b=https://x.example",
            ],
        ] {
            assert!(resolve_providers(&args(&bad).unwrap()).is_err(), "{bad:?}");
        }
        // Names become file names; URLs need a scheme; network and providers are exclusive.
        assert!(args(&["--provider", "../x=https://a.example"]).is_err());
        assert!(args(&["--provider", "a=a.example"]).is_err());
        assert!(args(&["--network", "nile", "--provider", "a=https://a.example"]).is_err());
        assert!(args(&[]).is_err());
        assert!(args(&[
            "--network",
            "nile",
            "--watch",
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u"
        ])
        .is_err());
    }

    #[test]
    fn refill_check_arguments_and_network_match() {
        let parse = |extra: &[&str]| {
            let argv = [
                "vaultex-monitor",
                "refill-check",
                "--config",
                "m.json",
                "--state-dir",
                "s",
                "--network",
                "nile",
            ];
            match Cli::try_parse_from(argv.iter().chain(extra)) {
                Ok(Cli::RefillCheck(a)) => Ok((a.asset, a.amount)),
                Ok(Cli::Watch(_)) => unreachable!(),
                Err(e) => Err(e),
            }
        };
        assert_eq!(
            parse(&["--asset", "TRX", "--amount", "5"]).unwrap(),
            (TRX.to_owned(), 5)
        );
        let usdt = parse(&[
            "--asset",
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
            "--amount",
            "1",
        ]);
        assert_eq!(
            usdt.unwrap().0,
            "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        );
        assert!(parse(&["--asset", "trx", "--amount", "5"]).is_err());
        assert!(parse(&["--asset", "TRX", "--amount", "-1"]).is_err());
        assert!(parse(&["--asset", "TRX"]).is_err());

        let cfg = matcher::tests::config("open"); // a Nile configuration
        assert!(check_network(&cfg, &args(&["--network", "nile"]).unwrap()).is_ok());
        assert!(check_network(&cfg, &args(&["--network", "mainnet"]).unwrap()).is_err());
        let custom = args(&[
            "--provider",
            "a=https://a.example",
            "--provider",
            "b=https://b.example",
        ]);
        assert!(check_network(&cfg, &custom.unwrap()).is_ok());
    }

    #[test]
    fn alerts_print_as_alert_lines() {
        let a = Alert {
            id: "MR-04:ab".into(),
            rule: "MR-04".into(),
            severity: 1,
            freeze: true,
            detail: "no accept receipt".into(),
            at_ms: 5,
        };
        let line = alert_line(&a);
        assert_eq!(line["kind"], "alert");
        assert_eq!(line["id"], "MR-04:ab");
        assert_eq!(line["freeze"], true);
    }

    #[tokio::test]
    async fn the_monitor_stops_with_its_last_watcher_or_on_a_fatal_error() {
        let healths = || vec![Arc::new(Mutex::new(Health::new("a")))];
        // Allowance readers never end on their own; they must not keep the monitor up.
        let readers = || {
            let mut set = JoinSet::new();
            set.spawn(std::future::pending::<(String, String)>());
            set
        };
        let mut watchers = JoinSet::new();
        watchers.spawn(async { ("a".to_owned(), Stop::Provider("cursor".into())) });
        watchers.spawn(async { ("b".to_owned(), Stop::Provider("deep fork".into())) });
        let Err(e) = supervise(watchers, readers(), None, healths()).await;
        assert_eq!(e, "every provider watcher stopped");

        // A journal or output failure stops it at once, while another watcher still runs.
        let mut watchers = JoinSet::new();
        watchers.spawn(std::future::pending());
        watchers.spawn(async { ("a".to_owned(), Stop::Fatal("cannot journal: full".into())) });
        let Err(e) = supervise(watchers, readers(), None, healths()).await;
        assert_eq!(e, "a: cannot journal: full");

        // So does an allowance reader's.
        let mut watchers = JoinSet::new();
        watchers.spawn(std::future::pending());
        let mut failing = JoinSet::new();
        failing.spawn(async {
            (
                "a (allowance reads)".to_owned(),
                "cannot journal".to_owned(),
            )
        });
        let Err(e) = supervise(watchers, failing, None, healths()).await;
        assert_eq!(e, "a (allowance reads): cannot journal");
    }

    #[test]
    fn health_turns_degraded_after_a_quiet_period() {
        let mut h = Health::new("p");
        h.failed(&ProviderError::RateLimited {
            status: 429,
            retry_after: None,
        });
        h.failed(&ProviderError::Unavailable("timeout".into()));
        let r = h.report(Instant::now());
        assert_eq!(
            (r["rate_limited"].as_u64(), r["errors"].as_u64()),
            (Some(1), Some(1))
        );
        assert_eq!(r["degraded"], false);

        h.ok((Some(90), Some(100)));
        let later = Instant::now() + DEGRADED_AFTER;
        assert_eq!(h.report(later)["lag"], 10);
        assert_eq!(h.report(later)["degraded"], true);
    }
}
