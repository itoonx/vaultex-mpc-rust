//! Vaultex outflow monitor (ROADMAP M7 #3, WS-07): watches the chain, matches every outflow to a
//! receipt, alerts on approvals and allowances, and can only freeze.
//!
//! **Status: chain watcher only (T07-2).** `vaultex-monitor watch` follows TRON on at least two
//! independent public providers, each with its own persisted cursor, and prints JSON lines on
//! stdout:
//! - `watched_tx`: a transaction signed by a watched address, per provider ("alarm on any");
//! - `reorg`: a block left a provider's chain and is scanned again;
//! - `provider_health` (every minute) and `no_healthy_provider` (every provider degraded);
//! - `provider_failed`: a provider's watcher stopped on a fatal error.
//!
//! Receipt matching, token-event logs, solidified-height agreement, alerts and the freeze path
//! come in later tasks (T07-3, T07-4).

mod cursor;
mod provider;
mod watcher;

use std::collections::HashSet;
use std::convert::Infallible;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;
use serde_json::json;

use provider::{Backoff, HttpProvider, Provider, ProviderError};
use watcher::{Progress, WatchError, Watcher};

/// Built-in public providers, all keyless: two per network, run by different operators.
/// Sources (fetched 2026-10-11): developers.tron.network/docs/networks (TronGrid for mainnet and
/// Nile; the community-run `api.nileex.io` for Nile) and tron.publicnode.com (PublicNode mainnet).
/// Shasta has a single documented endpoint, so it needs `--provider`.
const NETWORKS: &[(&str, &[(&str, &str)])] = &[
    (
        "mainnet",
        &[
            ("trongrid", "https://api.trongrid.io"),
            ("publicnode", "https://tron-rpc.publicnode.com"),
        ],
    ),
    (
        "nile",
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

#[derive(Parser)]
#[command(version, about = "Vaultex outflow monitor (chain watcher only so far)")]
enum Cli {
    /// Follow the chain on two or more providers and print JSON lines on stdout.
    Watch(WatchArgs),
}

#[derive(clap::Args)]
struct WatchArgs {
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
    /// TRON address (T…) whose transactions to report (repeat). Without one, the watcher only
    /// scans, which serves as a provider soak test.
    #[arg(long = "watch", value_name = "ADDRESS", value_parser = watcher::address_hex)]
    watch: Vec<String>,
    /// Directory for one cursor file per provider. Use one directory per network.
    #[arg(long)]
    state_dir: PathBuf,
    /// First height to scan for a provider without a cursor (default: its current head).
    #[arg(long)]
    from_height: Option<u64>,
    /// Minimum spacing between two requests to one provider, in milliseconds.
    #[arg(long, default_value_t = 350)]
    min_interval_ms: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let Cli::Watch(args) = Cli::parse();
    let Err(e) = run(args).await;
    eprintln!("vaultex-monitor: {e}");
    ExitCode::FAILURE
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
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("provider URL {url:?}: must start with https://"));
    }
    Ok((name.to_owned(), url.to_owned()))
}

/// The providers to watch: at least two, with distinct names (they name the cursor files) and URLs.
fn resolve_providers(args: &WatchArgs) -> Result<Vec<(String, String)>, String> {
    let list: Vec<(String, String)> = if args.providers.is_empty() {
        let network = args.network.as_deref().unwrap_or_default();
        let (_, built_in) = NETWORKS
            .iter()
            .find(|(n, _)| *n == network)
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

async fn run(args: WatchArgs) -> Result<Infallible, String> {
    let providers = resolve_providers(&args)?;
    std::fs::create_dir_all(&args.state_dir)
        .map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let watch: HashSet<String> = args.watch.iter().cloned().collect();
    if watch.is_empty() {
        eprintln!("vaultex-monitor: no --watch address; scanning only");
    }

    let mut tasks = tokio::task::JoinSet::new();
    let mut healths = Vec::new();
    for (name, url) in providers {
        let interval = Duration::from_millis(args.min_interval_ms);
        let provider =
            HttpProvider::new(&name, &url, interval).map_err(|e| format!("{name}: {e}"))?;
        let cursor = args.state_dir.join(format!("{name}.cursor"));
        let w = Watcher::open(provider, watch.clone(), cursor, args.from_height)
            .map_err(|e| format!("{name}: {e}"))?;
        let health = Arc::new(Mutex::new(Health::new(&name)));
        healths.push(Arc::clone(&health));
        tasks.spawn(async move {
            let Err(e) = watch_loop(w, health).await;
            (name, e)
        });
    }

    let mut tick = tokio::time::interval(HEALTH_EVERY);
    tick.tick().await; // the first tick is immediate
    loop {
        tokio::select! {
            done = tasks.join_next() => {
                let Some(done) = done else {
                    return Err("every provider watcher stopped".into());
                };
                let (name, error) = done.map_err(|e| format!("watcher task failed: {e}"))?;
                eprintln!("vaultex-monitor: {name} stopped: {error}");
                emit(&[json!({"kind": "provider_failed", "provider": name, "error": error})])
                    .map_err(|e| format!("cannot write to stdout: {e}"))?;
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

/// Runs one provider's watcher until a fatal error: provider errors back off and retry, cursor or
/// output failures stop it (fail closed: its health turns degraded and the failure is printed).
async fn watch_loop<P: Provider>(
    mut w: Watcher<P>,
    health: Arc<Mutex<Health>>,
) -> Result<Infallible, String> {
    let name = w.name().to_owned();
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    loop {
        match w.step().await {
            Ok(progress) => {
                health.lock().unwrap().ok(w.heights());
                backoff.reset();
                match progress {
                    Progress::Scanned(events) => {
                        emit(&events).map_err(|e| format!("cannot write events: {e}"))?;
                        w.commit()
                            .map_err(|e| format!("cannot persist the cursor: {e}"))?;
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
            Err(fatal) => return Err(fatal.to_string()),
        }
    }
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

    fn args(cli: &[&str]) -> Result<WatchArgs, clap::Error> {
        let argv = ["vaultex-monitor", "watch", "--state-dir", "s"];
        Cli::try_parse_from(argv.iter().chain(cli)).map(|Cli::Watch(a)| a)
    }

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_built_in_network_has_two_distinct_keyless_providers() {
        for (network, _) in NETWORKS {
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
