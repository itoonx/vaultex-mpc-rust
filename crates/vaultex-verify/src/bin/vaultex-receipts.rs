//! `vaultex-receipts`: the offline receipt-log verifier (ROADMAP M6 #6).
//!
//! ```text
//! vaultex-receipts verify <LOG> [--key <HEX>] [--after <SEQ>:<DIGEST_HEX>]
//! ```
//!
//! Checks every receipt of a receipt-log file or export against the log rules of
//! `vaultex_verify::receipt` and prints a summary. `--key` pins the signer's published receipt
//! key (recommended; without it the first receipt's key is adopted and the output says so).
//! `--after` verifies a segment that starts right after an anchored checkpoint.
//!
//! Exit status: 0 the log is valid, 1 it is not, 2 usage or I/O error. It reads only the file
//! named, and never touches the network.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use vaultex_types::{Ed25519Pub, ReceiptDigest, RefusalCode};
use vaultex_verify::receipt::{verify_log, Checkpoint, LogSummary};

const USAGE: &str =
    "usage: vaultex-receipts verify <LOG> [--key <HEX>] [--after <SEQ>:<DIGEST_HEX>]";

fn main() -> ExitCode {
    // ponytail: hand-rolled arguments keep CLI crates out of the kernel; this moves to
    // vaultex-cli-admin (with `replay`) when the admin CLIs land (T05-8).
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Some((path, key, after))) => run(&path, key, after),
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("error: {msg}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

type Args = (String, Option<Ed25519Pub>, Option<Checkpoint>);

fn parse(args: &[String]) -> Result<Option<Args>, String> {
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        None | Some("-h" | "--help" | "help") => return Ok(None),
        Some("verify") => {}
        Some(other) => return Err(format!("unknown command {other:?}")),
    }
    let (mut path, mut key, mut after) = (None, None, None);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--key" => key = Some(Ed25519Pub(hex32(value()?)?)),
            "--after" => {
                let v = value()?;
                let (seq, digest) = v
                    .split_once(':')
                    .ok_or("--after takes <SEQ>:<DIGEST_HEX>")?;
                after = Some(Checkpoint {
                    seq: seq
                        .parse()
                        .map_err(|_| format!("bad sequence number {seq:?}"))?,
                    digest: ReceiptDigest(hex32(digest)?),
                });
            }
            "-h" | "--help" => return Ok(None),
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag:?}")),
            _ if path.is_none() => path = Some(arg.clone()),
            _ => return Err("more than one log file".into()),
        }
    }
    let path = path.ok_or("no log file given")?;
    Ok(Some((path, key, after)))
}

fn run(path: &str, key: Option<Ed25519Pub>, after: Option<Checkpoint>) -> ExitCode {
    // ponytail: reads the whole log; a year of receipts at Phase-1 volumes is a few MB.
    let log = match std::fs::read(path) {
        Ok(log) => log,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    match verify_log(&log, key, after) {
        Ok(summary) => {
            print_summary(path, log.len(), &summary);
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("INVALID: {path}: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_summary(path: &str, bytes: usize, s: &LogSummary) {
    println!("VALID: {path} ({bytes} bytes)");
    println!("receipts:   {}", s.receipts);
    match (s.key, s.key_pinned) {
        (Some(k), true) => println!("signer key: {} (pinned)", hex(&k.0)),
        (Some(k), false) => println!(
            "signer key: {} (NOT pinned: compare it with the published receipt key)",
            hex(&k.0)
        ),
        (None, _) => println!("signer key: none"),
    }
    match s.head {
        Some(h) => println!("head:       seq {} digest {}", h.seq, hex(&h.digest.0)),
        None => println!("head:       none (empty log)"),
    }
    if let Some((first, last)) = s.time_s {
        println!("time:       {first} to {last} (Unix seconds)");
    }
    println!("accepts:    {}", s.accepts);
    println!("refusals:   {}", s.refusals.values().sum::<u64>());
    for (code, n) in &s.refusals {
        let name = RefusalCode(*code).name().unwrap_or("UNKNOWN");
        println!("  {name} (0x{code:04x}): {n}");
    }
    println!(
        "note:       a valid log may still be a prefix; compare the head with the anchored one"
    );
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let bad = || format!("expected 64 hex digits, got {s:?}");
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
