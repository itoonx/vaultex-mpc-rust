//! Receipts v1 (ROADMAP M6 #6) against the shared vector file
//! `vectors/RECEIPT_V1/receipt_v1.json` (KAT plan KAT-19 and KAT-20), plus the checks that only
//! make sense in Rust: the writer reproduces the vector log byte for byte, the decoder produces
//! the vectors' intents and refusal, every single-bit flip and every cut of a valid log is
//! caught, and the `vaultex-receipts` binary agrees with the library.
//!
//! The expected values come from a separate stdlib-Python implementation (BCS, SHA-256 and
//! RFC 8032 Ed25519 written from scratch, self-tested against RFC 8032 §7.1 and contracts vector
//! V-08); see `generated_by` in the file. The independent oracle (T13-2) will read the same file.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use ed25519_dalek::SigningKey;
use serde_json::Value;
use vaultex_types::{
    from_canonical_strict, to_canonical, ChainId, Decision, Ed25519Pub, IntentDigest, NetworkId,
    ReceiptBodyV1, ReceiptDigest, ReceiptV1, Refusal, RefusalCode, RequestId, TxHash, WalletId,
};
use vaultex_verify::receipt::{
    verify_log, Check, Checkpoint, DecisionRecord, LogError, ReceiptLog, VERIFIER_VERSION,
};
use vaultex_verify::tron::{
    decode, TronDecodeCtx, TronRefusal, MAX_FEE_LIMIT_SUN, MAX_VALIDITY_MS,
};

const VECTORS: &str = include_str!("../vectors/RECEIPT_V1/receipt_v1.json");
const ALL_CHECKS: [Check; 10] = [
    Check::Truncated,
    Check::Malformed,
    Check::SignerKey,
    Check::Signature,
    Check::Seq,
    Check::Prev,
    Check::Time,
    Check::Network,
    Check::AcceptWithoutIntent,
    Check::PolicyRollback,
];

// ───────────────────────────── JSON helpers ─────────────────────────────

fn file() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn vector(id: &str) -> Value {
    file()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap_or_else(|| panic!("no vector {id}"))
        .clone()
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex(v
        .as_str()
        .unwrap_or_else(|| panic!("expected hex, got {v}")))
}

fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

fn opt_b32(v: &Value) -> Option<[u8; 32]> {
    (!v.is_null()).then(|| b32(v))
}

/// Integers are decimal strings in the vector files (KAT plan §2).
fn num(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

fn code(v: &Value) -> RefusalCode {
    let s = v.as_str().unwrap();
    RefusalCode(u16::from_str_radix(s.strip_prefix("0x").unwrap(), 16).unwrap())
}

fn decision(v: &Value) -> Decision {
    match v["kind"].as_str().unwrap() {
        "accept" => Decision::Accept,
        "refuse" => {
            let code = code(&v["code"]);
            // KAT plan §2: the code and its name must agree with the registry.
            assert_eq!(code.name(), v["name"].as_str(), "{v}");
            Decision::Refuse(Refusal {
                code,
                rule_index: (!v["rule_index"].is_null())
                    .then(|| u32::try_from(num(&v["rule_index"])).unwrap()),
            })
        }
        other => panic!("unknown decision kind {other}"),
    }
}

fn record(v: &Value) -> DecisionRecord {
    DecisionRecord {
        request_id: RequestId(bytes(&v["request_id"]).try_into().unwrap()),
        wallet_id: WalletId::new(v["wallet_id"].as_str().unwrap()).unwrap(),
        chain: ChainId(u16::try_from(num(&v["chain"])).unwrap()),
        network: NetworkId::new(v["network"].as_str().unwrap()).unwrap(),
        tx_hash: TxHash(b32(&v["tx_hash"])),
        intent_digest: opt_b32(&v["intent_digest"]).map(IntentDigest),
        policy_version: num(&v["policy_version"]),
        policy_digest: b32(&v["policy_digest"]),
        decision: decision(&v["decision"]),
    }
}

fn verify_input(v: &Value) -> (Vec<u8>, Option<Ed25519Pub>, Option<Checkpoint>) {
    let input = &v["input"];
    let key = opt_b32(&input["key"]).map(Ed25519Pub);
    let after = (!input["after"].is_null()).then(|| Checkpoint {
        seq: num(&input["after"]["seq"]),
        digest: ReceiptDigest(b32(&input["after"]["digest"])),
    });
    (bytes(&input["log"]), key, after)
}

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vaultex-receipt-vectors-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("receipts.log")
}

// ───────────────────────────── the vector file ─────────────────────────────

#[test]
fn vector_file_is_well_formed_and_covers_every_check() {
    let f = file();
    assert_eq!(f["rfc"], "RECEIPT_V1");
    let names: Vec<&str> = f["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["check"].as_str().unwrap())
        .collect();
    // The file lists the rules in the order the verifier applies them.
    assert_eq!(names, ALL_CHECKS.map(Check::name));

    let vectors = f["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty(), "no vacuous pass (KAT plan R10)");
    let mut ids = std::collections::BTreeSet::new();
    for v in vectors {
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["base", "description", "expect", "id", "input", "rule"],
            "{}",
            v["id"]
        );
        assert!(
            ids.insert(v["id"].as_str().unwrap()),
            "duplicate id {}",
            v["id"]
        );
        if let Some(base) = v["base"].as_str() {
            assert!(
                vectors.iter().any(|b| b["id"] == base),
                "unknown base {base}"
            );
        }
    }
    // Every rule has a refuse vector (KAT plan R2).
    for check in ALL_CHECKS {
        assert!(
            vectors
                .iter()
                .any(|v| v["expect"]["invalid"]["check"] == check.name()),
            "no vector for {}",
            check.name()
        );
    }
}

#[test]
fn writer_reproduces_the_vector_receipts_and_log() {
    let v = vector("RECEIPT_V1-A-001");
    let input = &v["input"];
    let expect = &v["expect"];
    assert_eq!(
        input["verifier_version"].as_str().unwrap(),
        format!(
            "{}.{}.{}",
            VERIFIER_VERSION.major, VERIFIER_VERSION.minor, VERIFIER_VERSION.patch
        ),
        "the vectors pin the verifier version; regenerate them after a version bump"
    );
    let seed: [u8; 32] = b32(&input["signer_seed"]);
    let path = temp_path("writer");
    let mut log = ReceiptLog::open(&path, SigningKey::from_bytes(&seed)).unwrap();

    let steps = input["steps"].as_array().unwrap();
    let want = expect["receipts"].as_array().unwrap();
    assert_eq!(steps.len(), want.len());
    for (step, want) in steps.iter().zip(want) {
        let receipt = log
            .append(&record(&step["record"]), num(&step["now_ms"]))
            .unwrap();
        let body_bcs = to_canonical(&receipt.body).unwrap();
        assert_eq!(to_hex(&body_bcs), want["body_bcs"], "{}", step["note"]);
        assert_eq!(receipt.body.digest().0, b32(&want["digest"]));
        assert_eq!(to_hex(&receipt.signature.0), want["signature"]);
        assert_eq!(
            to_hex(&to_canonical(&receipt).unwrap()),
            want["receipt_bcs"]
        );

        // The listed body fields decode to the same body.
        let fields = &want["body"];
        let decoded: ReceiptBodyV1 = from_canonical_strict(&body_bcs).unwrap();
        assert_eq!(decoded.signer_key.0, b32(&fields["signer_key"]));
        assert_eq!(decoded.seq, num(&fields["seq"]));
        assert_eq!(decoded.prev.0, b32(&fields["prev"]));
        assert_eq!(decoded.time_s, num(&fields["time_s"]));
        assert_eq!(decoded.decision, decision(&fields["decision"]));
    }
    assert_eq!(to_hex(&std::fs::read(&path).unwrap()), expect["log"]);
    let head = log.head().unwrap();
    assert_eq!(head.seq, num(&expect["head"]["seq"]));
    assert_eq!(head.digest.0, b32(&expect["head"]["digest"]));
}

#[test]
fn verifier_matches_every_vector() {
    let f = file();
    let mut checked = 0;
    for v in f["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        if v["input"]["log"].is_null() {
            continue; // the writer vector
        }
        let (log, key, after) = verify_input(v);
        let got = verify_log(&log, key, after);
        let expect = &v["expect"];
        if let Some(want) = expect.get("valid") {
            let s = got.unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(s.receipts, num(&want["receipts"]), "{id}");
            assert_eq!(s.accepts, num(&want["accepts"]), "{id}");
            let refusals: BTreeMap<u16, u64> = want["refusals"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(c, n)| (code(&Value::String(c.clone())).0, num(n)))
                .collect();
            assert_eq!(s.refusals, refusals, "{id}");
            assert_eq!(s.key.map(|k| k.0), opt_b32(&want["key"]), "{id}");
            assert_eq!(Some(s.key_pinned), want["key_pinned"].as_bool(), "{id}");
            if want["head"].is_null() {
                assert_eq!(s.head, None, "{id}");
            } else {
                let head = s.head.unwrap();
                assert_eq!(head.seq, num(&want["head"]["seq"]), "{id}");
                assert_eq!(head.digest.0, b32(&want["head"]["digest"]), "{id}");
            }
        } else {
            let want = &expect["invalid"];
            let e = got.err().unwrap_or_else(|| panic!("{id}: accepted"));
            assert_eq!(e.check.name(), want["check"], "{id}: {e}");
            assert_eq!(e.index, num(&want["index"]), "{id}: {e}");
        }
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} verify vectors");
}

/// The receipts' intents and refusal are what the strict TRON decoder makes of the transactions.
#[test]
fn decoder_produces_the_vector_intents_and_refusal() {
    const TRC20: &str = "0a0200012208010203040506070840e0a499ffbc315aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541111111111111111111111111111111111111111112154199999999999999999999999999999999999999992244a9059cbb000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000f42407080d095ffbc31900180c2d72f";
    const NATIVE: &str = "0a0200012208010203040506070840e0a499ffbc315a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15411111111111111111111111111111111111111111121541222222222222222222222222222222222222222218c0843d7080d095ffbc31";
    let trc20 = hex(TRC20);
    // The same transaction with a memo (raw field 10) after `expiration`.
    let cut = TRC20.find("5aae01").unwrap() / 2;
    let memo = [&trc20[..cut], &hex("5203686921"), &trc20[cut..]].concat();
    let mut owner = [0x11; 21];
    owner[0] = 0x41;
    let mut token = [0x99; 21];
    token[0] = 0x41;
    let allowlist = [token];

    let v = vector("RECEIPT_V1-A-001");
    let steps = v["input"]["steps"].as_array().unwrap();
    for (raw, step) in [trc20, memo, hex(NATIVE)].iter().zip(steps) {
        let rec = record(&step["record"]);
        assert_eq!(TxHash::of(raw), rec.tx_hash);
        let ctx = TronDecodeCtx {
            wallet_id: &rec.wallet_id,
            network: rec.network,
            wallet_address: owner,
            permission_id: 0,
            trc20_allowlist: &allowlist,
            now_ms: num(&step["now_ms"]),
            max_validity_ms: MAX_VALIDITY_MS,
            max_fee_limit_sun: MAX_FEE_LIMIT_SUN,
            max_clock_skew_ms: 120_000,
            claimed_txid: None,
        };
        match decode(raw, &ctx) {
            Ok((intent, _)) => assert_eq!(Some(intent.digest()), rec.intent_digest),
            Err(refusal) => {
                assert_eq!(refusal, TronRefusal::MemoPresent);
                assert_eq!(rec.intent_digest, None);
                assert_eq!(Decision::Refuse(refusal.refusal()), rec.decision);
            }
        }
    }
}

// ───────────────────────────── adversarial (R6) ─────────────────────────────

fn valid_log() -> (Vec<u8>, Ed25519Pub) {
    let (log, key, _) = verify_input(&vector("RECEIPT_V1-A-002"));
    (log, key.unwrap())
}

/// Frame boundaries of `log`: (start, end) of each frame.
fn frames(log: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < log.len() {
        let len = u32::from_le_bytes(log[at..at + 4].try_into().unwrap()) as usize;
        out.push((at, at + 4 + len));
        at += 4 + len;
    }
    out
}

#[test]
fn every_single_bit_flip_is_detected() {
    let (log, key) = valid_log();
    let frames = frames(&log);
    for bit in 0..log.len() * 8 {
        let mut bad = log.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        let e: LogError = verify_log(&bad, Some(key), None)
            .err()
            .unwrap_or_else(|| panic!("bit {bit} flipped and the log still verifies"));
        // The failure is reported at the receipt whose frame holds the flipped bit.
        let index = frames
            .iter()
            .position(|&(s, e)| (s..e).contains(&(bit / 8)));
        assert_eq!(Some(e.index as usize), index, "bit {bit}: {e}");
    }
}

#[test]
fn every_cut_is_a_valid_prefix_or_truncated() {
    let (log, key) = valid_log();
    let frames = frames(&log);
    for cut in 0..=log.len() {
        let complete = frames.iter().filter(|&&(_, e)| e <= cut).count() as u64;
        match verify_log(&log[..cut], Some(key), None) {
            Ok(s) => {
                // KI-16: a cut at a receipt boundary cannot be told from a shorter log.
                assert!(
                    frames.iter().any(|&(_, e)| e == cut) || cut == 0,
                    "cut {cut}"
                );
                assert_eq!(s.receipts, complete);
            }
            Err(e) => {
                assert_eq!(e.check, Check::Truncated, "cut {cut}: {e}");
                assert_eq!(e.index, complete, "cut {cut}");
            }
        }
    }
}

#[test]
fn receipts_from_another_signer_cannot_be_spliced_in() {
    // A second signer writes the same records; its receipts never fit into the first log,
    // pinned key or not, because the key differs.
    let v = vector("RECEIPT_V1-A-001");
    let path = temp_path("splice");
    let mut other = ReceiptLog::open(&path, SigningKey::from_bytes(&[0x05; 32])).unwrap();
    let mut spliced = Vec::new();
    for step in v["input"]["steps"].as_array().unwrap() {
        let r: ReceiptV1 = other
            .append(&record(&step["record"]), num(&step["now_ms"]))
            .unwrap();
        let bytes = to_canonical(&r).unwrap();
        spliced.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        spliced.extend_from_slice(&bytes);
    }
    let (log, key) = valid_log();
    let first = frames(&log)[0].1;
    let second = frames(&spliced)[0].1;
    let mixed = [&log[..first], &spliced[second..]].concat();
    let e = verify_log(&mixed, Some(key), None).unwrap_err();
    assert_eq!((e.index, e.check), (1, Check::SignerKey));
    let e = verify_log(&mixed, None, None).unwrap_err();
    assert_eq!((e.index, e.check), (1, Check::SignerKey));
}

// ───────────────────────────── the offline verifier binary ─────────────────────────────

fn run_bin(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_vaultex-receipts"))
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap(), text)
}

#[test]
fn binary_verifies_valid_logs_and_names_the_failed_check() {
    let (log, key) = valid_log();
    let head = vector("RECEIPT_V1-A-002")["expect"]["valid"]["head"]["digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = temp_path("bin");
    std::fs::write(&path, &log).unwrap();
    let path = path.to_str().unwrap();
    let key = to_hex(&key.0);

    let (status, out) = run_bin(&["verify", path, "--key", &key]);
    assert_eq!(status, 0, "{out}");
    for line in [
        "VALID",
        "receipts:   3",
        "(pinned)",
        &format!("head:       seq 2 digest {head}"),
        "accepts:    1",
        "TX_SHAPE_NOT_ALLOWED (0x0206): 1",
        "AMOUNT_OVER_TX_CAP (0x0307): 1",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }

    let (status, out) = run_bin(&["verify", path]);
    assert_eq!(status, 0, "{out}");
    assert!(out.contains("NOT pinned"), "{out}");

    // A segment from an anchored checkpoint.
    let r0 = &vector("RECEIPT_V1-A-001")["expect"]["receipts"][0]["digest"];
    let segment = temp_path("bin-segment");
    std::fs::write(&segment, &log[frames(&log)[0].1..]).unwrap();
    let after = format!("0:{}", r0.as_str().unwrap());
    let (status, out) = run_bin(&[
        "verify",
        segment.to_str().unwrap(),
        "--key",
        &key,
        "--after",
        &after,
    ]);
    assert_eq!(status, 0, "{out}");

    let (status, out) = run_bin(&["verify", path, "--key", &"00".repeat(32)]);
    assert_eq!(status, 1, "{out}");
    assert!(
        out.contains("INVALID") && out.contains("receipt 0") && out.contains("SIGNER_KEY"),
        "{out}"
    );

    let (bad_log, bad_key, _) = verify_input(&vector("RECEIPT_V1-R-015"));
    std::fs::write(path, bad_log).unwrap();
    let (status, out) = run_bin(&["verify", path, "--key", &to_hex(&bad_key.unwrap().0)]);
    assert_eq!(status, 1, "{out}");
    assert!(out.contains("receipt 2") && out.contains("PREV"), "{out}");

    // Only a request for help, alone, exits 0 without verifying anything.
    for help in ["-h", "--help", "help"] {
        let (status, out) = run_bin(&[help]);
        assert_eq!(status, 0, "{help}: {out}");
        assert!(out.contains("usage:") && !out.contains("VALID"), "{out}");
    }
    for usage in [
        &["verify"][..],
        &[],
        &["verify", path, "--help"],
        &["verify", path, "-h"],
        &["--help", "verify", path],
        &["verify", path, "--key", "zz"],
        &["frobnicate"],
    ] {
        let (status, out) = run_bin(usage);
        assert_eq!(status, 2, "{usage:?}: {out}");
        assert!(out.contains("usage:"), "{usage:?}: {out}");
    }
    let (status, _) = run_bin(&["verify", "/nonexistent/vaultex-receipts.log"]);
    assert_eq!(status, 2);
}
