//! Receipts v1 (ROADMAP M6 #6): every decision, accept or refuse, leaves a receipt signed with the
//! signer's Ed25519 receipt key and linked to the previous receipt by digest. A signer's receipt
//! log is therefore a hash chain that anyone holding the public key can verify offline
//! ([`verify_log`], and the `vaultex-receipts` binary).
//!
//! # Format
//!
//! - **Receipt:** the contracts v0 [`ReceiptV1`]: BCS([`ReceiptBodyV1`]) followed by the 64-byte
//!   Ed25519 signature over [`ReceiptBodyV1::digest`] = `tagged_digest("VAULTEX/RECEIPT/v1", body)`.
//! - **Log:** a sequence of frames `len: u32 LE ‖ BCS(ReceiptV1)`, with `1 ≤ len ≤`
//!   [`MAX_RECEIPT_BYTES`]. [`ReceiptLog`] writes it; nothing else is in the file.
//!
//! # Log rules
//!
//! Checked for each receipt in this order; the first failure is reported ([`Check`]):
//!
//! | Check | The receipt fails it when |
//! |---|---|
//! | `TRUNCATED` | its frame header or body runs past the end of the log |
//! | `MALFORMED` | the frame length is 0 or above [`MAX_RECEIPT_BYTES`], or the frame is not exactly the canonical BCS of a [`ReceiptV1`] |
//! | `SIGNER_KEY` | `signer_key` is not the pinned key or, with none pinned, the first receipt's key |
//! | `SIGNATURE` | strict Ed25519 verification fails: S must be canonical, and neither the key nor R may be a small-order point |
//! | `SEQ` | `seq` is not the next position: 0 first, or the checkpoint's `seq + 1` |
//! | `PREV` | `prev` is not the previous receipt's digest (all zeros at `seq` 0, or the checkpoint's digest) |
//! | `TIME` | `time_s` is lower than the previous receipt's (equal is allowed) |
//! | `NETWORK` | the network does not belong to the receipt's chain |
//! | `ACCEPT_WITHOUT_INTENT` | an accept carries no intent digest |
//! | `POLICY_ROLLBACK` | `policy_version` is lower than the previous receipt's, or equal with another digest |
//!
//! # What a valid log does and does not show
//!
//! - Pin the signer's published receipt key. Without a pinned key the first receipt's key is
//!   adopted, which only shows that one key signed the whole log.
//! - A log cut at a receipt boundary is a valid **prefix**: dropped receipts at the end, or a log
//!   rewritten by a host that holds the receipt key, show only against a head anchored in another
//!   failure domain (the outflow monitor compares heads). Verify a segment from an anchored
//!   [`Checkpoint`] with [`LogVerifier::new`].
//! - A receipt holds digests and the decision, not the request: the transaction bytes, statements
//!   and policy bundle live in the evidence pack.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod file;

pub use file::{ReceiptLog, ReceiptLogError};

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use vaultex_types::{
    from_canonical_strict, ChainId, Decision, Ed25519Pub, IntentDigest, NetworkId, ReceiptDigest,
    ReceiptV1, RequestId, TxHash, VerifierVersion, WalletId,
};

/// Largest encoded receipt in a log frame. A receipt is under 400 bytes.
pub const MAX_RECEIPT_BYTES: usize = 1024;
/// Largest frame: the length header and the receipt.
const MAX_FRAME_BYTES: usize = 4 + MAX_RECEIPT_BYTES;

/// This build, as recorded in every receipt it writes. A test keeps it equal to the crate version.
pub const VERIFIER_VERSION: VerifierVersion = VerifierVersion {
    major: 0,
    minor: 1,
    patch: 0,
};

/// What a decision receipt says about one request. [`ReceiptLog::append`] adds the chain fields:
/// the key, the position, the link, the time and the verifier version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecord {
    /// The request decided on.
    pub request_id: RequestId,
    /// The wallet.
    pub wallet_id: WalletId,
    /// The chain.
    pub chain: ChainId,
    /// The network; it must belong to `chain`.
    pub network: NetworkId,
    /// SHA-256 of the unsigned transaction bytes.
    pub tx_hash: TxHash,
    /// The decoded intent's digest; `None` when decoding refused. An accept must have one.
    pub intent_digest: Option<IntentDigest>,
    /// Version of the installed policy bundle. It never decreases along a log.
    pub policy_version: u64,
    /// Digest of the installed policy bundle. One version always names the same digest.
    pub policy_digest: [u8; 32],
    /// The decision.
    pub decision: Decision,
}

/// A log rule (see the module docs). The first rule a receipt breaks is the one reported.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Check {
    /// The frame runs past the end of the log.
    Truncated,
    /// A frame length out of range, or not the canonical encoding of a receipt.
    Malformed,
    /// Not the pinned key, or not the log's first key.
    SignerKey,
    /// Strict Ed25519 verification fails.
    Signature,
    /// Not the next sequence number.
    Seq,
    /// Not linked to the previous receipt.
    Prev,
    /// Earlier than the previous receipt.
    Time,
    /// The network does not belong to the chain.
    Network,
    /// An accept without an intent digest.
    AcceptWithoutIntent,
    /// The policy version went backwards, or one version named two digests.
    PolicyRollback,
}

impl Check {
    /// The stable name used by vectors and tooling, e.g. `SIGNATURE`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Truncated => "TRUNCATED",
            Self::Malformed => "MALFORMED",
            Self::SignerKey => "SIGNER_KEY",
            Self::Signature => "SIGNATURE",
            Self::Seq => "SEQ",
            Self::Prev => "PREV",
            Self::Time => "TIME",
            Self::Network => "NETWORK",
            Self::AcceptWithoutIntent => "ACCEPT_WITHOUT_INTENT",
            Self::PolicyRollback => "POLICY_ROLLBACK",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Truncated => "the frame runs past the end of the log",
            Self::Malformed => "the frame is not one canonically encoded receipt",
            Self::SignerKey => "signed by an unexpected key",
            Self::Signature => "the signature does not verify",
            Self::Seq => "out of sequence",
            Self::Prev => "not linked to the previous receipt",
            Self::Time => "dated before the previous receipt",
            Self::Network => "the network is not on the receipt's chain",
            Self::AcceptWithoutIntent => "an accept without an intent digest",
            Self::PolicyRollback => "the policy version went backwards or forked",
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.describe())
    }
}

/// Where a log breaks a rule: the receipt's position in the log (from 0, whatever its `seq`),
/// the byte offset of its frame, and the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogError {
    /// Position of the failing receipt in the log, from 0.
    pub index: u64,
    /// Byte offset of its frame.
    pub offset: u64,
    /// The rule it breaks.
    pub check: Check,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt {} (byte offset {}): {}",
            self.index, self.offset, self.check
        )
    }
}

impl std::error::Error for LogError {}

/// A verified point in a log: verification of a segment starts after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The last receipt before the segment.
    pub seq: u64,
    /// Its digest.
    pub digest: ReceiptDigest,
}

/// What a valid log holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogSummary {
    /// The key that signed every receipt; `None` for an empty log with no pinned key.
    pub key: Option<Ed25519Pub>,
    /// Whether that key was pinned by the caller rather than taken from the first receipt.
    pub key_pinned: bool,
    /// Number of receipts.
    pub receipts: u64,
    /// Number of accepts.
    pub accepts: u64,
    /// Number of refusals, by refusal code.
    pub refusals: BTreeMap<u16, u64>,
    /// The last receipt's `seq` and digest: what an anchor records.
    pub head: Option<Checkpoint>,
    /// The first and last receipt times, in seconds since the Unix epoch.
    pub time_s: Option<(u64, u64)>,
}

/// Verifies one receipt: its key is `key`, and its signature verifies strictly (RFC 8032 with
/// canonical S, and no small-order key or R). Returns the receipt's digest, which the next
/// receipt must name as `prev`.
pub fn verify(receipt: &ReceiptV1, key: &Ed25519Pub) -> Result<ReceiptDigest, Check> {
    if receipt.body.signer_key != *key {
        return Err(Check::SignerKey);
    }
    let digest = receipt.body.digest();
    VerifyingKey::from_bytes(&key.0)
        .and_then(|vk| vk.verify_strict(&digest.0, &Signature::from_bytes(&receipt.signature.0)))
        .map_err(|_| Check::Signature)?;
    Ok(digest)
}

/// Checks receipts one at a time against the log rules, in log order. The writer uses it on
/// every receipt it appends, and a monitor can use it on a stream of receipts.
#[derive(Clone, Debug)]
pub struct LogVerifier {
    key: Option<Ed25519Pub>,
    next_seq: u64,
    prev: ReceiptDigest,
    time_s: u64,
    policy: Option<(u64, [u8; 32])>,
    summary: LogSummary,
}

impl LogVerifier {
    /// A verifier for a log signed by `key` (or, if `None`, by the key of its first receipt),
    /// starting at `seq` 0, or right after `after`.
    pub fn new(key: Option<Ed25519Pub>, after: Option<Checkpoint>) -> Self {
        Self {
            key,
            // ponytail: a checkpoint at u64::MAX saturates; the next receipt then fails PREV.
            next_seq: after.map_or(0, |c| c.seq.saturating_add(1)),
            prev: after.map_or(ReceiptDigest([0; 32]), |c| c.digest),
            time_s: 0,
            policy: None,
            summary: LogSummary {
                key,
                key_pinned: key.is_some(),
                ..LogSummary::default()
            },
        }
    }

    /// Checks `receipt` as the next one in the log. On success its digest is returned and it
    /// becomes the head; on failure nothing changes.
    pub fn push(&mut self, receipt: &ReceiptV1) -> Result<ReceiptDigest, Check> {
        let body = &receipt.body;
        let key = self.key.unwrap_or(body.signer_key);
        let digest = verify(receipt, &key)?;
        if body.seq != self.next_seq {
            return Err(Check::Seq);
        }
        if body.prev != self.prev {
            return Err(Check::Prev);
        }
        if body.time_s < self.time_s {
            return Err(Check::Time);
        }
        if body.network.chain() != body.chain {
            return Err(Check::Network);
        }
        if body.decision == Decision::Accept && body.intent_digest.is_none() {
            return Err(Check::AcceptWithoutIntent);
        }
        if let Some((version, policy_digest)) = self.policy {
            if body.policy_version < version
                || (body.policy_version == version && body.policy_digest != policy_digest)
            {
                return Err(Check::PolicyRollback);
            }
        }

        self.key = Some(key);
        self.next_seq = body.seq.saturating_add(1);
        self.prev = digest;
        self.time_s = body.time_s;
        self.policy = Some((body.policy_version, body.policy_digest));
        let s = &mut self.summary;
        s.key = Some(key);
        s.receipts = s.receipts.saturating_add(1);
        match body.decision {
            Decision::Accept => s.accepts = s.accepts.saturating_add(1),
            Decision::Refuse(r) => {
                let n = s.refusals.entry(r.code.0).or_default();
                *n = n.saturating_add(1);
            }
            // A decision this version does not know does not decode, so it never gets here.
            _ => {}
        }
        s.head = Some(Checkpoint {
            seq: body.seq,
            digest,
        });
        s.time_s = Some((
            s.time_s.map_or(body.time_s, |(first, _)| first),
            body.time_s,
        ));
        Ok(digest)
    }

    /// What the receipts pushed so far add up to.
    pub fn summary(&self) -> &LogSummary {
        &self.summary
    }
}

/// Verifies a whole log (the bytes of a log file or an export) signed by `key` (or, if `None`,
/// by the key of its first receipt), from `seq` 0 or from `after`.
pub fn verify_log(
    log: &[u8],
    key: Option<Ed25519Pub>,
    after: Option<Checkpoint>,
) -> Result<LogSummary, LogError> {
    let mut verifier = LogVerifier::new(key, after);
    read_log(log, &mut verifier)?;
    Ok(verifier.summary)
}

/// Pushes every frame of `log` into `verifier`, stopping at the first failure.
fn read_log(log: &[u8], verifier: &mut LogVerifier) -> Result<(), LogError> {
    let mut offset = 0usize;
    let mut index = 0u64;
    while offset < log.len() {
        let at = |check| LogError {
            index,
            offset: offset as u64,
            check,
        };
        let (bytes, next) = split_frame(log, offset).map_err(at)?;
        let receipt =
            from_canonical_strict::<ReceiptV1>(bytes).map_err(|_| at(Check::Malformed))?;
        verifier.push(&receipt).map_err(at)?;
        offset = next;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The receipt bytes of the frame at `offset`, and the offset after the frame.
fn split_frame(log: &[u8], offset: usize) -> Result<(&[u8], usize), Check> {
    let rest = log.get(offset..).unwrap_or_default();
    let Some(header) = rest.first_chunk::<4>() else {
        return Err(Check::Truncated);
    };
    let len = u32::from_le_bytes(*header) as usize;
    if len == 0 || len > MAX_RECEIPT_BYTES {
        return Err(Check::Malformed);
    }
    let end = len.saturating_add(4);
    let bytes = rest.get(4..end).ok_or(Check::Truncated)?;
    Ok((bytes, offset.saturating_add(end)))
}

/// Encodes one log frame.
fn encode_frame(receipt_bytes: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(receipt_bytes.len())
        .ok()
        .filter(|_| (1..=MAX_RECEIPT_BYTES).contains(&receipt_bytes.len()))?;
    let mut frame = Vec::with_capacity(MAX_FRAME_BYTES);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(receipt_bytes);
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_version_is_the_crate_version() {
        let v = VERIFIER_VERSION;
        assert_eq!(
            format!("{}.{}.{}", v.major, v.minor, v.patch),
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn check_names_are_stable() {
        let all = [
            (Check::Truncated, "TRUNCATED"),
            (Check::Malformed, "MALFORMED"),
            (Check::SignerKey, "SIGNER_KEY"),
            (Check::Signature, "SIGNATURE"),
            (Check::Seq, "SEQ"),
            (Check::Prev, "PREV"),
            (Check::Time, "TIME"),
            (Check::Network, "NETWORK"),
            (Check::AcceptWithoutIntent, "ACCEPT_WITHOUT_INTENT"),
            (Check::PolicyRollback, "POLICY_ROLLBACK"),
        ];
        for (check, name) in all {
            assert_eq!(check.name(), name);
        }
    }

    #[test]
    fn frames_out_of_range_are_refused() {
        assert_eq!(split_frame(&[1, 0, 0], 0), Err(Check::Truncated));
        assert_eq!(split_frame(&[0, 0, 0, 0], 0), Err(Check::Malformed));
        let over = u32::try_from(MAX_RECEIPT_BYTES + 1).unwrap_or(u32::MAX);
        assert_eq!(split_frame(&over.to_le_bytes(), 0), Err(Check::Malformed));
        assert_eq!(split_frame(&[2, 0, 0, 0, 9], 0), Err(Check::Truncated));
        assert_eq!(split_frame(&[1, 0, 0, 0, 9], 0), Ok((&[9u8][..], 5)));
        assert_eq!(encode_frame(&[]), None);
        assert_eq!(encode_frame(&[0; MAX_RECEIPT_BYTES + 1]), None);
    }
}
