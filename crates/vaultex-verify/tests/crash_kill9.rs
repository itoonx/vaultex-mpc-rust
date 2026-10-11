//! `kill -9` crash tests for the velocity store and the breaker (ROADMAP M6 #5).
//!
//! A child process (this test binary, re-run with only `kill9_child` selected) charges new intents
//! in a loop through `Breaker<FileStore>`, printing `ACK <i>` after each charge is durable, until
//! the window's count limit refuses and the breaker pauses. The parent `SIGKILL`s it after a
//! random delay, reopens the store and checks that:
//!
//! - the store reopens: the dead child's lock is gone, and a torn tail would be truncated;
//! - every acknowledged charge is durable;
//! - the durable charges are intents `0..n`, each exactly once: no double charge after a restart,
//!   including the retry of its last charge that every child makes on startup;
//! - usage is the sum of the durable charges, and `n` never exceeds the count limit;
//! - once a pause is durable it stays, and it only comes with a full window.
//!
//! The phases: kills while charging with a limit no child reaches (the test fails if no kill lands
//! between charges); kills around a reachable limit; one child that runs to the limit unharmed;
//! kills while paused.
//!
//! `kill -9` keeps what the process had already written (it sits in the page cache), so this
//! tests ordering and recovery, not power loss. Torn frames are covered by the store's unit tests.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use vaultex_types::{tagged_digest, AssetId, IntentDigest, WalletId, U256};
use vaultex_verify::breaker::{Breaker, BreakerConfig, BreakerState, PauseCause};
use vaultex_verify::velocity::{
    Charge, FileStore, LimitRefusal, Reserved, VelocityKey, VelocityStore, WindowLimit,
};

const STORE_VAR: &str = "VAULTEX_KILL9_STORE";
const LIMIT_VAR: &str = "VAULTEX_KILL9_MAX_COUNT";
const AMOUNT: u64 = 1_000_000;
const BASE_MS: u64 = 1_700_000_000_000;

fn key() -> VelocityKey {
    VelocityKey {
        wallet_id: WalletId::new("kill9-wallet").unwrap(),
        asset: AssetId::Native,
    }
}

fn digest(i: u32) -> IntentDigest {
    IntentDigest(tagged_digest("VAULTEX-TEST/KILL9-INTENT/v1", &i))
}

/// Charge for intent `i`, made when the store holds `n` charges (the clock moves 1 s per charge).
fn charge(i: u32, n: u32) -> Charge {
    Charge {
        key: key(),
        intent_digest: digest(i),
        amount: U256::from(AMOUNT),
        fee: U256::from(0),
        at_ms: BASE_MS + u64::from(n) * 1_000,
    }
}

fn limits(max_count: u32) -> [WindowLimit; 1] {
    [WindowLimit {
        window_ms: 86_400_000,
        max_amount: U256::from(u64::MAX),
        max_count,
        max_fee: U256::from(0),
    }]
}

fn config() -> BreakerConfig {
    BreakerConfig {
        refusal_threshold: 10,
        refusal_window_ms: 60_000,
        pause_on_cap_hit: true,
        max_clock_skew_ms: 60_000,
    }
}

fn count(store: &impl VelocityStore) -> u32 {
    store.usage(&key(), u64::MAX, 0).count
}

#[test]
#[ignore = "child process of the kill -9 tests: does nothing unless the parent starts it"]
fn kill9_child() {
    // Test plumbing, not kernel code: the parent passes the store and the limit.
    #[allow(clippy::disallowed_methods)]
    let (Some(path), Some(max)) = (std::env::var_os(STORE_VAR), std::env::var_os(LIMIT_VAR)) else {
        return;
    };
    let max_count: u32 = max.to_str().unwrap().parse().unwrap();
    let limits = limits(max_count);
    let mut breaker = Breaker::new(FileStore::open(&path).unwrap(), config());
    let mut out = std::io::stdout().lock();
    // libtest has printed "test kill9_child ... " with no newline; start the protocol on its own.
    writeln!(out).unwrap();

    // A caller retrying its last request, whose answer it may never have seen.
    let n = count(breaker.store());
    if n > 0 && breaker.state() == BreakerState::Running {
        assert_eq!(
            breaker.reserve(&charge(n - 1, n), &limits),
            Ok(Reserved::AlreadyCharged)
        );
        assert_eq!(count(breaker.store()), n, "a retry must not charge again");
    }
    loop {
        let n = count(breaker.store());
        match breaker.reserve(&charge(n, n), &limits) {
            Ok(Reserved::Charged) => {
                writeln!(out, "ACK {n}").unwrap();
                out.flush().unwrap();
            }
            Err(LimitRefusal::Exceeded { .. } | LimitRefusal::Paused(_)) => {
                writeln!(out, "CAP").unwrap();
                return;
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }
}

/// Runs a child on the store at `path`. With `kill_after`, `SIGKILL`s it after that delay.
fn run_child(path: &Path, max_count: u32, kill_after: Option<Duration>) -> Vec<String> {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "kill9_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(STORE_VAR, path)
        .env(LIMIT_VAR, max_count.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(delay) = kill_after {
        std::thread::sleep(delay);
        // SIGKILL on Unix. An error only means the child already exited (it reached the limit).
        let _ = child.kill();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.code().is_none_or(|code| code == 0),
        "child failed ({:?}):\n{stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    stdout.lines().map(str::to_owned).collect()
}

/// Reopens the store and checks the invariants. Returns the charge count and whether it is
/// paused.
fn check(path: &Path, max_count: u32, acked: &[u32], was_paused: bool) -> (u32, bool) {
    let store = FileStore::open(path).expect("the store reopens after kill -9");
    let n = count(&store);
    assert!(n <= max_count, "{n} charges exceed the limit {max_count}");
    // n records and n distinct digests: each of 0..n is charged exactly once.
    for i in 0..n {
        assert!(store.is_charged(&digest(i)), "charge {i} of {n} is missing");
    }
    for &i in acked {
        assert!(
            i < n,
            "acknowledged charge {i} is not durable ({n} durable)"
        );
    }
    let used = store.usage(&key(), u64::MAX, 0);
    assert_eq!(used.amount, U256::from(u64::from(n) * AMOUNT));
    let pause = store.pause();
    assert!(
        !was_paused || pause.is_some(),
        "a durable pause disappeared"
    );
    if let Some(p) = pause {
        assert_eq!((p.cause, n), (PauseCause::CapHit, max_count));
    }
    (n, pause.is_some())
}

/// State threaded through the kill loops.
struct Run {
    path: PathBuf,
    rng: u64,
    n: u32,
    paused: bool,
    /// Children killed after at least one acknowledged charge and before reaching the limit.
    killed_while_charging: u32,
}

impl Run {
    /// `cycles` children against `max_count`, each `SIGKILL`ed after a random delay of 0–39 ms.
    fn kill_loop(&mut self, cycles: u32, max_count: u32) {
        for cycle in 0..cycles {
            // xorshift64, fixed seed: a failing run can be replayed.
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            let delay = Duration::from_millis(self.rng % 40);
            let lines = run_child(&self.path, max_count, Some(delay));
            let acked: Vec<u32> = lines
                .iter()
                .filter_map(|l| l.strip_prefix("ACK "))
                .map(|i| i.parse().unwrap())
                .collect();
            if !acked.is_empty() && !lines.iter().any(|l| l == "CAP") {
                self.killed_while_charging += 1;
            }
            let (n, paused) = check(&self.path, max_count, &acked, self.paused);
            assert!(
                n >= self.n,
                "cycle {cycle}: charges went from {} to {n}",
                self.n
            );
            (self.n, self.paused) = (n, paused);
        }
    }
}

fn kill9_cycles(name: &str, cycles: u32) {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "vaultex-verify-kill9-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut run = Run {
        path: dir.join("velocity.log"),
        rng: 0x9E37_79B9_7F4A_7C15,
        n: 0,
        paused: false,
        killed_while_charging: 0,
    };

    // 1. Kills while charging, with a limit no child reaches.
    run.kill_loop(cycles, u32::MAX);
    assert!(
        run.killed_while_charging > 0,
        "no child was killed between charges, so nothing was tested ({} charges)",
        run.n
    );
    // 2. Kills around the limit: some children hit it, and the breaker pauses.
    let cap = run.n + 5;
    run.kill_loop(10, cap);
    // 3. One child runs to the limit unharmed, so every run ends there, paused.
    let lines = run_child(&run.path, cap, None);
    assert!(lines.iter().any(|l| l == "CAP"), "{lines:?}");
    assert_eq!(check(&run.path, cap, &[], run.paused), (cap, true));
    run.paused = true;
    // 4. Kills while paused: the pause stays, and nothing more is charged.
    run.kill_loop(3, cap);
    assert_eq!(run.n, cap);
    eprintln!(
        "kill -9: {} children killed while charging, {} charges",
        run.killed_while_charging, run.n
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn kill9_while_charging_keeps_every_acknowledged_charge_once() {
    kill9_cycles("smoke", 30);
}

#[test]
#[ignore = "soak: 1,000 kill -9 cycles (several minutes); run with --ignored"]
fn kill9_soak() {
    kill9_cycles("soak", 1_000);
}
