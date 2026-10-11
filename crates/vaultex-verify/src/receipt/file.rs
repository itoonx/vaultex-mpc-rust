//! [`ReceiptLog`]: the fsync'd, append-only receipt log of one signer.
//!
//! # Durability
//!
//! - **Append:** the receipt is checked against the log rules, written and `sync_data`'d; only
//!   then is it returned. The caller releases a signature only after that, so every signature has
//!   a durable receipt. After a failed write the log refuses further writes until reopened.
//! - **Create:** the new file and its directory entry are synced before first use.
//! - **One process:** the file is locked exclusively while open ([`StoreError::Locked`]).
//! - **Open:** the whole log is verified against the receipt key before anything is appended. A
//!   damaged **last** frame (cut short, undecodable, or with a bad signature) is a write that never
//!   completed, so it was never acknowledged: it is truncated. It is the last frame only if
//!   nothing after its offset can be a later receipt: the signer key appears there only at the
//!   start of its own body, followed by the expected `seq`. Any other failure, including a damaged
//!   header with receipts behind it or a last receipt that is well signed but breaks a chain
//!   rule, is [`ReceiptLogError::Invalid`] and the log refuses to open; it must be restored, not
//!   repaired.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use vaultex_types::{to_canonical, Ed25519Pub, ReceiptBodyV1, ReceiptDigest, ReceiptV1, Sig64};

use super::{
    encode_frame, read_log, split_frame, Check, Checkpoint, DecisionRecord, LogError, LogVerifier,
    MAX_FRAME_BYTES, VERIFIER_VERSION,
};
use crate::durable::{self, io_err};
use crate::velocity::StoreError;

/// Why the receipt log could not open or append. Every one fails closed: no receipt, so no
/// signature.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptLogError {
    /// The file could not be locked, read or written, or an earlier write failed.
    Store(StoreError),
    /// The log on disk breaks a log rule (on open).
    Invalid(LogError),
    /// The record would break a log rule; nothing was written.
    Rejected(Check),
}

impl From<StoreError> for ReceiptLogError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// The signed, hash-chained receipt log of one signer, in one file. See the module docs for the
/// durability rules and [`crate::receipt`] for the format.
pub struct ReceiptLog {
    file: File,
    key: SigningKey,
    state: LogVerifier,
    len: u64,
    failed: bool,
}

impl fmt::Debug for ReceiptLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptLog")
            .field("key", &self.public_key())
            .field("head", &self.head())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl ReceiptLog {
    /// Opens the log at `path`, creating it if absent; takes its exclusive lock; verifies every
    /// receipt against `key`'s public key; and truncates a torn last frame.
    pub fn open(path: impl AsRef<Path>, key: SigningKey) -> Result<Self, ReceiptLogError> {
        let mut file = durable::open_locked(path.as_ref())?;
        let mut log = Vec::new();
        file.read_to_end(&mut log).map_err(io_err)?;
        let public = Ed25519Pub(key.verifying_key().to_bytes());
        let mut state = LogVerifier::new(Some(public), None);
        let mut len = log.len() as u64;
        if let Err(e) = read_log(&log, &mut state) {
            // A failed push changes nothing, so `next_seq` is the failing receipt's expected seq.
            if !is_torn(&log, &e, &public, state.next_seq) {
                return Err(ReceiptLogError::Invalid(e));
            }
            durable::truncate(&file, e.offset)?;
            len = e.offset;
        }
        Ok(Self {
            file,
            key,
            state,
            len,
            failed: false,
        })
    }

    /// Records `record` as the next receipt, dated `now_ms` (milliseconds since the Unix epoch)
    /// but never before the previous receipt, and returns the receipt once it is durable.
    pub fn append(
        &mut self,
        record: &DecisionRecord,
        now_ms: u64,
    ) -> Result<ReceiptV1, ReceiptLogError> {
        if self.failed {
            return Err(StoreError::Failed.into());
        }
        let head = self.state.summary().head;
        let body = ReceiptBodyV1 {
            signer_key: self.public_key(),
            seq: head.map_or(0, |h| h.seq.saturating_add(1)),
            prev: head.map_or(ReceiptDigest([0; 32]), |h| h.digest),
            // A clock behind the last receipt (the breaker refuses that) keeps the chain ordered.
            time_s: (now_ms / 1000).max(self.state.summary().time_s.map_or(0, |(_, last)| last)),
            request_id: record.request_id,
            wallet_id: record.wallet_id.clone(),
            chain: record.chain,
            network: record.network,
            tx_hash: record.tx_hash,
            intent_digest: record.intent_digest,
            policy_version: record.policy_version,
            policy_digest: record.policy_digest,
            verifier_version: VERIFIER_VERSION,
            decision: record.decision,
        };
        let receipt = ReceiptV1 {
            signature: Sig64(self.key.sign(&body.digest().0).to_bytes()),
            body,
        };
        // Every receipt written passes the same rules as the offline verifier, so the log this
        // writer produces always verifies.
        let mut next = self.state.clone();
        next.push(&receipt).map_err(ReceiptLogError::Rejected)?;
        let frame = to_canonical(&receipt)
            .ok()
            .and_then(|bytes| encode_frame(&bytes))
            .ok_or(StoreError::TooLarge)?;
        if let Err(e) = durable::append_synced(&mut self.file, &frame) {
            // The end of the file is now unknown: refuse writes until a reopen repairs it.
            self.failed = true;
            return Err(io_err(e).into());
        }
        self.state = next;
        self.len = self.len.saturating_add(frame.len() as u64);
        Ok(receipt)
    }

    /// The receipt key's public half, as receipts name it.
    pub fn public_key(&self) -> Ed25519Pub {
        Ed25519Pub(self.key.verifying_key().to_bytes())
    }

    /// The last durable receipt's `seq` and digest (what an anchor records); `None` while empty.
    pub fn head(&self) -> Option<Checkpoint> {
        self.state.summary().head
    }

    /// Length of the log in bytes: an export of the first `len()` bytes ends at [`head`](Self::head).
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the log holds no receipt.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Whether `e` is a torn last frame: a write that never completed. Such a tail holds at most the
/// start of the receipt being written (`seq`), whose body begins with `key ‖ seq` (u64 LE) after
/// the 4-byte header. The key anywhere else is a later receipt behind a damaged frame: it was
/// acknowledged, so the tail is not torn.
fn is_torn(log: &[u8], e: &LogError, key: &Ed25519Pub, seq: u64) -> bool {
    let offset = usize::try_from(e.offset).unwrap_or(usize::MAX);
    let tail = log.get(offset..).unwrap_or_default();
    let own: Vec<u8> = key.0.iter().chain(&seq.to_le_bytes()).copied().collect();
    matches!(
        e.check,
        Check::Truncated | Check::Malformed | Check::Signature
    ) && match split_frame(log, offset) {
        Ok((_, next)) => next == log.len(),
        // No usable header: torn only if what is left fits in one frame.
        Err(_) => tail.len() <= MAX_FRAME_BYTES,
    } && tail.windows(key.0.len()).enumerate().all(|(at, window)| {
        // The own body may itself be cut short inside `seq`: compare what is there.
        window != key.0.as_slice()
            || (at == 4 && tail.iter().skip(4).zip(&own).all(|(a, b)| a == b))
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;

    use vaultex_types::{
        ChainId, Decision, IntentDigest, NetworkId, Refusal, RefusalCode, RequestId, TxHash,
        WalletId,
    };

    use super::*;
    use crate::receipt::verify_log;

    const NOW: u64 = 1_700_000_010_000;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vaultex-verify-receipt-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x03; 32])
    }

    fn pubkey() -> Ed25519Pub {
        Ed25519Pub(key().verifying_key().to_bytes())
    }

    fn record(n: u8, decision: Decision) -> DecisionRecord {
        DecisionRecord {
            request_id: RequestId([n; 16]),
            wallet_id: WalletId::new("wallet-1").unwrap(),
            chain: ChainId::TRON,
            network: NetworkId::new("tron:3448148188").unwrap(),
            tx_hash: TxHash([n; 32]),
            intent_digest: Some(IntentDigest([n; 32])),
            policy_version: 1,
            policy_digest: [7; 32],
            decision,
        }
    }

    fn refuse(code: RefusalCode) -> Decision {
        Decision::Refuse(Refusal {
            code,
            rule_index: None,
        })
    }

    /// A log with receipts 0..n (accept, then refusals), closed, and its path.
    fn log_with(name: &str, n: u8) -> PathBuf {
        let path = temp_dir(name).join("receipts.log");
        let mut log = ReceiptLog::open(&path, key()).unwrap();
        for i in 0..n {
            let decision = if i == 0 {
                Decision::Accept
            } else {
                refuse(RefusalCode::TX_SHAPE_NOT_ALLOWED)
            };
            log.append(&record(i, decision), NOW + u64::from(i) * 1000)
                .unwrap();
        }
        assert_eq!(log.len(), fs::metadata(&path).unwrap().len());
        path
    }

    fn summary(path: &PathBuf) -> crate::receipt::LogSummary {
        verify_log(&fs::read(path).unwrap(), Some(pubkey()), None).unwrap()
    }

    #[test]
    fn appends_a_chain_that_verifies_and_reopens() {
        let path = log_with("chain", 3);
        let s = summary(&path);
        assert_eq!((s.receipts, s.accepts), (3, 1));
        assert_eq!(
            s.refusals.get(&RefusalCode::TX_SHAPE_NOT_ALLOWED.0),
            Some(&2)
        );
        assert_eq!(s.time_s, Some((1_700_000_010, 1_700_000_012)));

        let mut log = ReceiptLog::open(&path, key()).unwrap();
        assert_eq!(log.head(), s.head);
        let r = log
            .append(&record(3, Decision::Accept), NOW + 3000)
            .unwrap();
        assert_eq!(r.body.seq, 3);
        assert_eq!(Some(r.body.prev), s.head.map(|h| h.digest));
        assert_eq!(summary(&path).receipts, 4);
    }

    #[test]
    fn a_clock_behind_the_last_receipt_keeps_its_time() {
        let path = temp_dir("clock").join("receipts.log");
        let mut log = ReceiptLog::open(&path, key()).unwrap();
        log.append(&record(0, Decision::Accept), NOW).unwrap();
        let r = log
            .append(&record(1, Decision::Accept), NOW - 60_000)
            .unwrap();
        assert_eq!(r.body.time_s, NOW / 1000);
        summary(&path);
    }

    #[test]
    fn refuses_a_second_open() {
        let path = log_with("locked", 1);
        let _held = ReceiptLog::open(&path, key()).unwrap();
        assert_eq!(
            ReceiptLog::open(&path, key()).unwrap_err(),
            ReceiptLogError::Store(StoreError::Locked)
        );
    }

    #[test]
    fn refuses_to_open_under_another_key() {
        let path = log_with("other-key", 2);
        let err = ReceiptLog::open(&path, SigningKey::from_bytes(&[0x04; 32])).unwrap_err();
        assert!(
            matches!(err, ReceiptLogError::Invalid(e) if e.index == 0 && e.check == Check::SignerKey),
            "{err:?}"
        );
    }

    /// Appends `tail` to a 2-receipt log (or replaces its last bytes), reopens, and checks that
    /// the log is back to `receipts` receipts and still appends a verifying chain.
    fn assert_reopens_with(name: &str, edit: impl FnOnce(&mut Vec<u8>), receipts: u64) {
        let path = log_with(name, 2);
        let mut bytes = fs::read(&path).unwrap();
        edit(&mut bytes);
        fs::write(&path, &bytes).unwrap();
        let mut log = ReceiptLog::open(&path, key()).unwrap();
        assert_eq!(log.head().map(|h| h.seq + 1).unwrap_or(0), receipts);
        assert_eq!(log.len(), fs::metadata(&path).unwrap().len());
        log.append(&record(9, Decision::Accept), NOW + 9000)
            .unwrap();
        assert_eq!(summary(&path).receipts, receipts + 1);
    }

    #[test]
    fn truncates_a_torn_tail() {
        // A frame cut short, a header cut short, and a zero-filled frame.
        assert_reopens_with("torn-body", |b| b.truncate(b.len() - 7), 1);
        assert_reopens_with("torn-header", |b| b.extend_from_slice(&[0x40, 0x01]), 2);
        assert_reopens_with("torn-zeros", |b| b.extend_from_slice(&[0; 300]), 2);
        // The last receipt's signature damaged: it was never acknowledged.
        assert_reopens_with(
            "torn-signature",
            |b| {
                let last = b.len() - 1;
                b[last] ^= 1;
            },
            1,
        );
    }

    #[test]
    fn refuses_to_open_on_damage_before_the_last_frame() {
        let path = log_with("corrupt", 3);
        let mut bytes = fs::read(&path).unwrap();
        let first_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        bytes[4 + first_len - 1] ^= 1; // receipt 0's signature
        fs::write(&path, &bytes).unwrap();
        let err = ReceiptLog::open(&path, key()).unwrap_err();
        assert!(
            matches!(err, ReceiptLogError::Invalid(e) if e.index == 0 && e.check == Check::Signature),
            "{err:?}"
        );
    }

    /// Edits the header of frame `frame` in a 3-receipt log and checks that the open refuses at
    /// that frame with `check` and leaves the file as it was: the receipts behind a damaged
    /// header were acknowledged, so they are never cut away as a torn tail.
    fn assert_refuses_header_edit(
        name: &str,
        frame: usize,
        edit: impl FnOnce(&mut u8),
        check: Check,
    ) {
        let path = log_with(name, 3);
        let mut bytes = fs::read(&path).unwrap();
        let mut offset = 0;
        for _ in 0..frame {
            offset +=
                4 + u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        }
        edit(&mut bytes[offset + 1]);
        fs::write(&path, &bytes).unwrap();
        let err = ReceiptLog::open(&path, key()).unwrap_err();
        assert!(
            matches!(err, ReceiptLogError::Invalid(e)
                if e.index == frame as u64 && e.offset == offset as u64 && e.check == check),
            "{err:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn refuses_to_cut_acknowledged_receipts_behind_a_damaged_header() {
        // Frame 0's length out of range: all three receipts would fit in one "torn" frame.
        assert_refuses_header_edit("header-0", 0, |b| *b = 0x05, Check::Malformed);
        // Frame 1's length raised, still in range, past the end of the log.
        assert_refuses_header_edit("header-1", 1, |b| *b ^= 0x02, Check::Truncated);
    }

    #[test]
    fn refuses_to_cut_a_damaged_last_receipt_with_a_later_seq() {
        // Receipt 1 gone and receipt 2 badly signed: 2 was written after 1 was acknowledged.
        let path = log_with("later-seq", 3);
        let bytes = fs::read(&path).unwrap();
        let end =
            |at: usize| at + 4 + u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let (one, two) = (end(0), end(end(0)));
        let mut edited = [&bytes[..one], &bytes[two..]].concat();
        *edited.last_mut().unwrap() ^= 1;
        fs::write(&path, &edited).unwrap();
        let err = ReceiptLog::open(&path, key()).unwrap_err();
        assert!(
            matches!(err, ReceiptLogError::Invalid(e) if e.index == 1 && e.check == Check::Signature),
            "{err:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), edited);
    }

    #[test]
    fn refuses_to_open_when_a_well_signed_last_receipt_breaks_the_chain() {
        // Append receipt 0 of another log under the same key: well signed, wrong seq.
        let path = log_with("spliced", 2);
        let other = fs::read(log_with("spliced-other", 1)).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&other)
            .unwrap();
        let err = ReceiptLog::open(&path, key()).unwrap_err();
        assert!(
            matches!(err, ReceiptLogError::Invalid(e) if e.index == 2 && e.check == Check::Seq),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_records_that_break_a_log_rule_and_writes_nothing() {
        let path = log_with("rejected", 2);
        let mut log = ReceiptLog::open(&path, key()).unwrap();
        let (head, len) = (log.head(), log.len());

        let mut rollback = record(5, Decision::Accept);
        rollback.policy_version = 0;
        let mut fork = record(5, Decision::Accept);
        fork.policy_digest = [8; 32];
        let mut no_intent = record(5, Decision::Accept);
        no_intent.intent_digest = None;
        let mut network = record(5, Decision::Accept);
        network.chain = ChainId::EVM;
        for (bad, check) in [
            (rollback, Check::PolicyRollback),
            (fork, Check::PolicyRollback),
            (no_intent, Check::AcceptWithoutIntent),
            (network, Check::Network),
        ] {
            assert_eq!(
                log.append(&bad, NOW + 5000).unwrap_err(),
                ReceiptLogError::Rejected(check)
            );
        }
        assert_eq!((log.head(), log.len()), (head, len));
        assert_eq!(fs::metadata(&path).unwrap().len(), len);

        // A refusal without an intent is fine.
        let mut refused = record(6, refuse(RefusalCode::TX_MALFORMED));
        refused.intent_digest = None;
        log.append(&refused, NOW + 6000).unwrap();
        assert_eq!(summary(&path).receipts, 3);
    }

    #[test]
    fn debug_shows_no_secret() {
        let path = temp_dir("debug").join("receipts.log");
        let log = ReceiptLog::open(&path, key()).unwrap();
        let shown = format!("{log:?}");
        assert!(shown.contains("ReceiptLog"), "{shown}");
        for secret in ["3, 3, 3, 3", "0303030303"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}
