//! The Guard's receipts, as the monitor reads them.
//!
//! [`ReceiptFeed`] tails a copy of the Guard's receipt log (frames of `u32 LE length ‖
//! BCS(ReceiptV1)`) and verifies every receipt itself before the matcher may use it. It shares only
//! the wire types with the kernel (`vaultex-types`); the checks are the monitor's own, written from
//! the receipt format (ROADMAP WS-07: a different implementer from the Guard):
//! - the receipt is signed by the **pinned** Guard receipt key (strict Ed25519);
//! - `seq` counts up from 0 without gaps, and `prev` names the previous receipt's digest;
//! - time never goes backwards; the network belongs to the chain; an accept names an intent;
//! - the policy version never goes backwards, and one version never names two digests;
//! - bytes already verified never change, and the log reaches the **anchored head**: the last head
//!   this monitor verified, persisted in its own state, so a rewritten or cut-back history shows.
//!
//! Any failure is a receipt-integrity incident (rule MR-06). The feed then stays failed: every
//! later poll reports the same failure, until an operator has investigated and restarts it.
//!
//! ponytail: the Guard's read-only receipt export (T06-5) does not exist yet, so the feed reads a
//! file. A torn last frame (a write in progress) is simply not read yet.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use vaultex_types::{from_canonical_strict, Decision, Ed25519Pub, ReceiptBodyV1, ReceiptV1};

use crate::cursor::write_atomic;

/// Largest receipt a frame may hold (a receipt is under 400 bytes).
pub const MAX_RECEIPT_BYTES: usize = 1024;

/// A position in the receipt chain: what the monitor anchors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub digest: [u8; 32],
}

/// Where the receipt history breaks. `check` uses the receipt-format check names (`SIGNATURE`,
/// `SEQ`, …) plus `REWRITTEN`, `ANCHOR` and `UNREADABLE` for the monitor's own checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Broken {
    /// Receipts before the failing one.
    pub index: u64,
    /// Byte offset of its frame.
    pub offset: u64,
    pub check: &'static str,
}

impl fmt::Display for Broken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt history breaks at receipt {} (byte {}): {}",
            self.index, self.offset, self.check
        )
    }
}

pub struct ReceiptFeed {
    path: PathBuf,
    key: Ed25519Pub,
    anchor: Option<Head>,
    /// Bytes verified so far, and the SHA-256 of exactly those bytes.
    len: usize,
    prefix: [u8; 32],
    receipts: u64,
    head: Option<Head>,
    time_s: u64,
    policy: Option<(u64, [u8; 32])>,
    failed: Option<Broken>,
}

impl ReceiptFeed {
    /// A feed over the log at `path`, signed by `key`, that must reach `anchor`.
    pub fn new(path: PathBuf, key: Ed25519Pub, anchor: Option<Head>) -> Self {
        Self {
            path,
            key,
            anchor,
            len: 0,
            prefix: Sha256::digest([]).into(),
            receipts: 0,
            head: None,
            time_s: 0,
            policy: None,
            failed: None,
        }
    }

    /// The last verified receipt.
    pub fn head(&self) -> Option<Head> {
        self.head
    }

    /// Bytes of the log verified so far; anything after them is an incomplete frame.
    pub fn verified_len(&self) -> usize {
        self.len
    }

    /// Reads the receipts appended since the last poll, verifies them, and returns their bodies.
    pub fn poll(&mut self) -> Result<Vec<ReceiptBodyV1>, Broken> {
        if let Some(b) = &self.failed {
            return Err(b.clone());
        }
        let result = self.read();
        if let Err(b) = &result {
            self.failed = Some(b.clone());
        }
        result
    }

    fn read(&mut self) -> Result<Vec<ReceiptBodyV1>, Broken> {
        let broken = |feed: &Self, offset: usize, check| Broken {
            index: feed.receipts,
            offset: offset as u64,
            check,
        };
        let log = match fs::read(&self.path) {
            Ok(log) => log,
            // Nothing written or copied yet; fine only while nothing has been verified or anchored.
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.len == 0 => Vec::new(),
            Err(_) => return Err(broken(self, self.len, "UNREADABLE")),
        };
        let unchanged = log
            .get(..self.len)
            .is_some_and(|p| <[u8; 32]>::from(Sha256::digest(p)) == self.prefix);
        if !unchanged {
            return Err(broken(self, 0, "REWRITTEN"));
        }

        let mut new = Vec::new();
        let mut at = self.len;
        while let Some(header) = log.get(at..at + 4) {
            let len = u32::from_le_bytes(header.try_into().expect("4 bytes")) as usize;
            if len == 0 || len > MAX_RECEIPT_BYTES {
                return Err(broken(self, at, "MALFORMED"));
            }
            let Some(frame) = log.get(at + 4..at + 4 + len) else {
                break; // a frame still being written
            };
            let receipt = from_canonical_strict::<ReceiptV1>(frame)
                .map_err(|_| broken(self, at, "MALFORMED"))?;
            let head = self
                .check(&receipt)
                .map_err(|check| broken(self, at, check))?;
            if self.anchor.is_some_and(|a| a.seq == head.seq && a != head) {
                return Err(broken(self, at, "ANCHOR"));
            }
            self.head = Some(head);
            self.receipts += 1;
            at += 4 + len;
            new.push(receipt.body);
        }
        // The anchored head must be in the log: a shorter history was cut back.
        if let Some(a) = self.anchor {
            if self.head.is_none_or(|h| h.seq < a.seq) {
                return Err(broken(self, at, "ANCHOR"));
            }
        }
        self.len = at;
        self.prefix = Sha256::digest(&log[..at]).into();
        Ok(new)
    }

    /// Checks `receipt` as the next one; on success records it and returns the new head.
    fn check(&mut self, receipt: &ReceiptV1) -> Result<Head, &'static str> {
        let body = &receipt.body;
        if body.signer_key != self.key {
            return Err("SIGNER_KEY");
        }
        let digest = body.digest().0;
        let signed = VerifyingKey::from_bytes(&self.key.0)
            .and_then(|k| k.verify_strict(&digest, &Signature::from_bytes(&receipt.signature.0)));
        if signed.is_err() {
            return Err("SIGNATURE");
        }
        let (want_seq, want_prev) = match self.head {
            Some(h) => (h.seq.checked_add(1).ok_or("SEQ")?, h.digest),
            None => (0, [0; 32]),
        };
        if body.seq != want_seq {
            return Err("SEQ");
        }
        if body.prev.0 != want_prev {
            return Err("PREV");
        }
        if body.time_s < self.time_s {
            return Err("TIME");
        }
        if body.network.chain() != body.chain {
            return Err("NETWORK");
        }
        if body.decision == Decision::Accept && body.intent_digest.is_none() {
            return Err("ACCEPT_WITHOUT_INTENT");
        }
        if let Some((version, policy)) = self.policy {
            let same_version = body.policy_version == version;
            if body.policy_version < version || (same_version && body.policy_digest != policy) {
                return Err("POLICY_ROLLBACK");
            }
        }
        self.time_s = body.time_s;
        self.policy = Some((body.policy_version, body.policy_digest));
        Ok(Head {
            seq: body.seq,
            digest,
        })
    }
}

/// Loads the anchored head (`<seq> <digest hex>`); `None` if there is none yet.
pub fn load_anchor(path: &Path) -> io::Result<Option<Head>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bad = || io::Error::new(io::ErrorKind::InvalidData, format!("{}", path.display()));
    let (seq, digest) = text.trim_end().split_once(' ').ok_or_else(bad)?;
    let mut head = Head {
        seq: seq.parse().map_err(|_| bad())?,
        digest: [0; 32],
    };
    hex::decode_to_slice(digest, &mut head.digest).map_err(|_| bad())?;
    Ok(Some(head))
}

/// Persists the anchored head, atomically and durably.
pub fn save_anchor(path: &Path, head: Head) -> io::Result<()> {
    let text = format!("{} {}\n", head.seq, hex::encode(head.digest));
    write_atomic(path, text.as_bytes())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use vaultex_types::{
        to_canonical, ChainId, IntentDigest, NetworkId, ReceiptDigest, Refusal, RefusalCode,
        RequestId, Sig64, TxHash, VerifierVersion, WalletId,
    };

    pub const NILE: &str = "tron:3448148188";
    pub const WALLET: &str = "float-1";

    pub fn key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    /// Appends one well-formed receipt for `txid` to `log` (a test stand-in for the Guard).
    pub struct Writer {
        pub key: SigningKey,
        pub head: Option<Head>,
        pub log: Vec<u8>,
    }

    impl Writer {
        pub fn start() -> Self {
            Self {
                key: key(),
                head: None,
                log: Vec::new(),
            }
        }

        pub fn body(&self, txid: &str, accept: bool, time_s: u64) -> ReceiptBodyV1 {
            let mut tx_hash = [0; 32];
            hex::decode_to_slice(txid, &mut tx_hash).unwrap();
            ReceiptBodyV1 {
                signer_key: Ed25519Pub(self.key.verifying_key().to_bytes()),
                seq: self.head.map_or(0, |h| h.seq + 1),
                prev: ReceiptDigest(self.head.map_or([0; 32], |h| h.digest)),
                time_s,
                request_id: RequestId([7; 16]),
                wallet_id: WalletId::new(WALLET).unwrap(),
                chain: ChainId::TRON,
                network: NetworkId::new(NILE).unwrap(),
                tx_hash: TxHash(tx_hash),
                intent_digest: accept.then_some(IntentDigest([9; 32])),
                policy_version: 1,
                policy_digest: [5; 32],
                verifier_version: VerifierVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                decision: if accept {
                    Decision::Accept
                } else {
                    Decision::Refuse(Refusal {
                        code: RefusalCode::TX_SELECTOR_NOT_ALLOWED,
                        rule_index: None,
                    })
                },
            }
        }

        /// Signs `body` and appends its frame; returns the frame.
        pub fn push(&mut self, body: ReceiptBodyV1) -> Vec<u8> {
            let digest = body.digest().0;
            self.head = Some(Head {
                seq: body.seq,
                digest,
            });
            let receipt = ReceiptV1 {
                signature: Sig64(self.key.sign(&digest).to_bytes()),
                body,
            };
            let bytes = to_canonical(&receipt).unwrap();
            let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
            frame.extend(bytes);
            self.log.extend(&frame);
            frame
        }

        pub fn accept(&mut self, txid: &str, time_s: u64) {
            let body = self.body(txid, true, time_s);
            self.push(body);
        }
    }

    fn pinned() -> Ed25519Pub {
        Ed25519Pub(key().verifying_key().to_bytes())
    }

    const TX_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const TX_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn tails_a_growing_log_and_waits_for_torn_frames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.log");
        let mut feed = ReceiptFeed::new(path.clone(), pinned(), None);
        assert_eq!(feed.poll().unwrap(), vec![]); // no file yet

        let mut w = Writer::start();
        w.accept(TX_A, 100);
        let b = w.body(TX_B, false, 101);
        let frame = w.push(b);
        // The second frame is only half written.
        let cut = w.log.len() - frame.len() / 2;
        fs::write(&path, &w.log[..cut]).unwrap();
        let got = feed.poll().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(hex::encode(got[0].tx_hash.0), TX_A);
        assert!(feed.verified_len() < cut);

        fs::write(&path, &w.log).unwrap();
        let got = feed.poll().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 1);
        assert_eq!(feed.head(), w.head);
        assert_eq!(feed.poll().unwrap(), vec![]);
    }

    #[test]
    fn a_changed_history_or_a_cut_back_log_breaks_the_feed_for_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.log");
        let mut w = Writer::start();
        w.accept(TX_A, 100);
        w.accept(TX_B, 101);
        fs::write(&path, &w.log).unwrap();
        let mut feed = ReceiptFeed::new(path.clone(), pinned(), None);
        feed.poll().unwrap();

        // One verified byte changes: the feed fails, and stays failed even once it is restored.
        let mut tampered = w.log.clone();
        tampered[10] ^= 1;
        fs::write(&path, &tampered).unwrap();
        assert_eq!(feed.poll().unwrap_err().check, "REWRITTEN");
        fs::write(&path, &w.log).unwrap();
        assert_eq!(feed.poll().unwrap_err().check, "REWRITTEN");

        // After a restart, the anchored head must still be in the log.
        let anchor = w.head;
        let first = w.log.len() / 2; // both frames have the same length
        fs::write(&path, &w.log[..first]).unwrap();
        let mut restarted = ReceiptFeed::new(path.clone(), pinned(), anchor);
        assert_eq!(restarted.poll().unwrap_err().check, "ANCHOR");

        // A different history of the same length does not reach the anchor either.
        let mut other = Writer::start();
        other.accept(TX_B, 100);
        other.accept(TX_A, 101);
        fs::write(&path, &other.log).unwrap();
        let mut restarted = ReceiptFeed::new(path, pinned(), anchor);
        let err = restarted.poll().unwrap_err();
        assert_eq!((err.check, err.index), ("ANCHOR", 1));
    }

    #[test]
    fn the_anchor_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.anchor");
        assert_eq!(load_anchor(&path).unwrap(), None);
        let head = Head {
            seq: 41,
            digest: [0xab; 32],
        };
        save_anchor(&path, head).unwrap();
        assert_eq!(load_anchor(&path).unwrap(), Some(head));
        fs::write(&path, "41 nothex\n").unwrap();
        assert!(load_anchor(&path).is_err());
    }

    /// Cross-implementation check: the monitor's own reader reaches the same verdict as the
    /// RECEIPT_V1 vectors on every vector that verifies a whole log against a pinned key.
    #[test]
    fn agrees_with_the_receipt_v1_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/vaultex-verify/vectors/RECEIPT_V1/receipt_v1.json"
        );
        let doc: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("log");
        let mut checked = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let input = &v["input"];
            let (Some(log), Some(key)) = (input["log"].as_str(), input["key"].as_str()) else {
                continue; // writer vectors, and logs verified without a pinned key
            };
            if !input["after"].is_null() {
                continue; // segments from a checkpoint: the monitor always reads from seq 0
            }
            let mut pin = [0u8; 32];
            hex::decode_to_slice(key, &mut pin).unwrap();
            let bytes = hex::decode(log).unwrap();
            fs::write(&file, &bytes).unwrap();
            let mut feed = ReceiptFeed::new(file.clone(), Ed25519Pub(pin), None);
            let verdict = match feed.poll() {
                Ok(got) if feed.verified_len() == bytes.len() => Ok(got.len() as u64),
                Ok(got) => Err(("TRUNCATED", got.len() as u64)),
                Err(b) => Err((b.check, b.index)),
            };
            let id = v["id"].as_str().unwrap();
            let expect = &v["expect"];
            if let Some(valid) = expect.get("valid") {
                let n: u64 = valid["receipts"].as_str().unwrap().parse().unwrap();
                assert_eq!(verdict, Ok(n), "{id}");
            } else {
                let invalid = &expect["invalid"];
                let index: u64 = invalid["index"].as_str().unwrap().parse().unwrap();
                let check = invalid["check"].as_str().unwrap();
                assert_eq!(verdict, Err((check, index)), "{id}");
            }
            checked += 1;
        }
        assert!(checked >= 20, "only {checked} vectors applied");
    }
}
