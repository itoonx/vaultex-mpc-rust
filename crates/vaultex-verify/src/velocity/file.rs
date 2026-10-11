//! [`FileStore`]: the fsync'd, append-only file implementation of [`VelocityStore`].
//!
//! # Format
//!
//! A sequence of frames, `len: u32 LE ‖ body[len] ‖ check[32]`, where
//! `check = tagged_digest("VAULTEX/VELOCITY-FRAME/v1", body)` and `body` is BCS:
//!
//! - charge: `(1u8, wallet_id, asset, intent_digest, amount, fee, at_ms)`;
//! - pause: `(2u8, cause, at_ms)`, with cause 1 refusal burst, 2 cap hit, 3 clock rollback,
//!   4 freeze.
//!
//! # Durability
//!
//! - **Append:** the frame is written and `sync_data`'d; only then is the in-memory view updated
//!   and `Ok` returned. After a failed write the store refuses further writes until reopened.
//! - **Create:** the new file and its directory entry are synced before first use.
//! - **One process:** the file is locked exclusively while open; a second open fails with
//!   [`StoreError::Locked`]. The operating system drops the lock when the process dies.
//! - **Open:** frames are replayed into memory. A damaged **last** frame is a write that never
//!   completed, so it was never acknowledged: it is truncated. Damage before the last frame, or a
//!   frame that is intact but does not decode (a record this version does not know), is
//!   [`StoreError::Corrupt`] and the store refuses to open.
//!
//! The file is crash-safe, not tamper-evident: whoever can write it can remove charges. Tamper
//! evidence comes from the signed, hash-chained receipt log, which is also meant to become the
//! source this index is rebuilt from.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

use vaultex_types::{
    from_canonical_strict, tagged_digest, to_canonical, AssetId, IntentDigest, WalletId, U256,
};

use super::{Charge, Index, Record, StoreError, Usage, VelocityKey, VelocityStore};
use crate::breaker::{Pause, PauseCause};

/// Domain tag of the per-frame check.
const FRAME_TAG: &str = "VAULTEX/VELOCITY-FRAME/v1";
/// Largest record body. A charge is under 200 bytes.
const MAX_BODY_BYTES: usize = 512;
/// Largest frame: length, body, check.
const MAX_FRAME_BYTES: usize = 4 + MAX_BODY_BYTES + 32;

const KIND_CHARGE: u8 = 1;
const KIND_PAUSE: u8 = 2;

type ChargeBody = (u8, WalletId, AssetId, IntentDigest, U256, U256, u64);
type PauseBody = (u8, u8, u64);

/// The fsync'd file implementation of [`VelocityStore`]. See the module docs for the format and
/// the durability rules.
#[derive(Debug)]
pub struct FileStore {
    file: File,
    index: Index,
    failed: bool,
}

impl FileStore {
    /// Opens the log at `path`, creating it if absent; takes its exclusive lock; truncates a torn
    /// last frame; and rebuilds the in-memory view.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let mut opts = OpenOptions::new();
        opts.read(true).append(true);
        let (mut file, created) = match opts.clone().create_new(true).open(path) {
            Ok(file) => (file, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                (opts.open(path).map_err(io_err)?, false)
            }
            Err(e) => return Err(io_err(e)),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StoreError::Locked),
            Err(TryLockError::Error(e)) => return Err(io_err(e)),
        }
        if created {
            file.sync_all().map_err(io_err)?;
            sync_parent_dir(path).map_err(io_err)?;
        }

        let mut log = Vec::new();
        file.read_to_end(&mut log).map_err(io_err)?;
        let mut index = Index::default();
        let mut offset = 0usize;
        while let Some(rest) = log.get(offset..).filter(|rest| !rest.is_empty()) {
            let torn = match parse_frame(rest) {
                Frame::Ok(record, len) => {
                    index.apply(&record);
                    offset = offset.saturating_add(len);
                    continue;
                }
                // An intact header: torn only if the frame reaches the end of the file.
                Frame::Damaged { len: Some(len) } => len >= rest.len(),
                // No usable header: torn only if what is left fits in one frame.
                Frame::Damaged { len: None } => rest.len() <= MAX_FRAME_BYTES,
                Frame::Unknown => false,
            };
            if !torn {
                return Err(StoreError::Corrupt {
                    offset: offset as u64,
                });
            }
            file.set_len(offset as u64).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
            break;
        }
        Ok(Self {
            file,
            index,
            failed: false,
        })
    }
}

impl VelocityStore for FileStore {
    fn usage(&self, key: &VelocityKey, window_ms: u64, now_ms: u64) -> Usage {
        self.index.usage(key, window_ms, now_ms)
    }

    fn is_charged(&self, intent_digest: &IntentDigest) -> bool {
        self.index.is_charged(intent_digest)
    }

    fn pause(&self) -> Option<Pause> {
        self.index.pause()
    }

    fn high_water_ms(&self) -> u64 {
        self.index.high_water_ms()
    }

    fn append(&mut self, record: &Record) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Failed);
        }
        let frame = encode_frame(record)?;
        if let Err(e) = self
            .file
            .write_all(&frame)
            .and_then(|()| self.file.sync_data())
        {
            // The end of the file is now unknown: refuse writes until a reopen repairs it.
            self.failed = true;
            return Err(io_err(e));
        }
        self.index.apply(record);
        Ok(())
    }
}

fn io_err(e: io::Error) -> StoreError {
    StoreError::Io(e.kind())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

// ponytail: signer hosts are Linux or macOS; elsewhere the directory entry is not synced.
#[cfg(not(unix))]
fn sync_parent_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

fn cause_byte(cause: PauseCause) -> u8 {
    match cause {
        PauseCause::RefusalBurst => 1,
        PauseCause::CapHit => 2,
        PauseCause::ClockRollback => 3,
        PauseCause::Freeze => 4,
    }
}

fn cause_from_byte(b: u8) -> Option<PauseCause> {
    Some(match b {
        1 => PauseCause::RefusalBurst,
        2 => PauseCause::CapHit,
        3 => PauseCause::ClockRollback,
        4 => PauseCause::Freeze,
        _ => return None,
    })
}

fn encode_frame(record: &Record) -> Result<Vec<u8>, StoreError> {
    let body = match record {
        Record::Charge(c) => to_canonical(&(
            KIND_CHARGE,
            &c.key.wallet_id,
            &c.key.asset,
            &c.intent_digest,
            &c.amount,
            &c.fee,
            c.at_ms,
        )),
        Record::Pause { cause, at_ms } => to_canonical(&(KIND_PAUSE, cause_byte(*cause), *at_ms)),
    }
    .map_err(|_| StoreError::TooLarge)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= MAX_BODY_BYTES)
        .ok_or(StoreError::TooLarge)?;
    let mut frame = Vec::with_capacity(MAX_FRAME_BYTES);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    frame.extend_from_slice(&tagged_digest(FRAME_TAG, body.as_slice()));
    Ok(frame)
}

/// What [`parse_frame`] found at the start of its input.
enum Frame {
    /// An intact frame of this many bytes.
    Ok(Record, usize),
    /// Not an intact frame. `len` is the frame length its header claims, if the header is
    /// complete and in range.
    Damaged { len: Option<usize> },
    /// An intact frame whose body does not decode.
    Unknown,
}

fn parse_frame(bytes: &[u8]) -> Frame {
    let Some(header) = bytes.get(..4) else {
        return Frame::Damaged { len: None };
    };
    let mut le = [0u8; 4];
    le.copy_from_slice(header);
    let body_len = u32::from_le_bytes(le) as usize;
    if body_len == 0 || body_len > MAX_BODY_BYTES {
        return Frame::Damaged { len: None };
    }
    let body_end = body_len.saturating_add(4);
    let frame_len = body_end.saturating_add(32);
    let (Some(body), Some(check)) = (bytes.get(4..body_end), bytes.get(body_end..frame_len)) else {
        return Frame::Damaged {
            len: Some(frame_len),
        };
    };
    if tagged_digest(FRAME_TAG, body) != check {
        return Frame::Damaged {
            len: Some(frame_len),
        };
    }
    match decode_body(body) {
        Some(record) => Frame::Ok(record, frame_len),
        None => Frame::Unknown,
    }
}

fn decode_body(body: &[u8]) -> Option<Record> {
    match *body.first()? {
        KIND_CHARGE => {
            let (_, wallet_id, asset, intent_digest, amount, fee, at_ms) =
                from_canonical_strict::<ChargeBody>(body).ok()?;
            Some(Record::Charge(Charge {
                key: VelocityKey { wallet_id, asset },
                intent_digest,
                amount,
                fee,
                at_ms,
            }))
        }
        KIND_PAUSE => {
            let (_, cause, at_ms) = from_canonical_strict::<PauseBody>(body).ok()?;
            Some(Record::Pause {
                cause: cause_from_byte(cause)?,
                at_ms,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::velocity::{reserve, Reserved, WindowLimit};

    /// A fresh, empty directory for one test.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vaultex-verify-file-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn charge(n: u8, at_ms: u64) -> Charge {
        Charge {
            key: VelocityKey {
                wallet_id: WalletId::new("wallet-1").unwrap(),
                asset: AssetId::Contract(vaultex_types::Address(vec![0x41; 21])),
            },
            intent_digest: IntentDigest([n; 32]),
            amount: U256::from(1_000_000),
            fee: U256::from(30_000_000),
            at_ms,
        }
    }

    const LIMITS: [WindowLimit; 1] = [WindowLimit {
        window_ms: 86_400_000,
        max_amount: U256([0xff; 32]),
        max_count: 100,
        max_fee: U256([0xff; 32]),
    }];

    /// A store with charges 1..=n (at times 1..=n) and the path of its log.
    fn store_with(name: &str, n: u8) -> (PathBuf, PathBuf) {
        let dir = temp_dir(name);
        let path = dir.join("velocity.log");
        let mut s = FileStore::open(&path).unwrap();
        for i in 1..=n {
            assert_eq!(
                reserve(&mut s, &charge(i, u64::from(i)), &LIMITS),
                Ok(Reserved::Charged)
            );
        }
        (dir, path)
    }

    fn count(s: &FileStore) -> u32 {
        s.usage(&charge(0, 0).key, u64::MAX, 0).count
    }

    #[test]
    fn reopen_restores_charges_pauses_and_the_high_water_mark() {
        let (dir, path) = store_with("reopen", 3);
        {
            let mut s = FileStore::open(&path).unwrap();
            assert_eq!(count(&s), 3);
            s.append(&Record::Pause {
                cause: PauseCause::CapHit,
                at_ms: 10,
            })
            .unwrap();
        }
        let s = FileStore::open(&path).unwrap();
        assert_eq!(count(&s), 3);
        assert!((1..=3).all(|i| s.is_charged(&IntentDigest([i; 32]))));
        assert!(!s.is_charged(&IntentDigest([4; 32])));
        assert_eq!(
            s.pause(),
            Some(Pause {
                seq: 1,
                cause: PauseCause::CapHit,
                since_ms: 10
            })
        );
        assert_eq!(s.high_water_ms(), 10);
        let used = s.usage(&charge(0, 0).key, u64::MAX, 0);
        assert_eq!(used.amount, U256::from(3_000_000));
        assert_eq!(used.fee, U256::from(90_000_000));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn frames_round_trip_every_record_kind() {
        let records = [
            Record::Charge(charge(7, 123)),
            Record::Charge(Charge {
                key: VelocityKey {
                    wallet_id: WalletId::new(&"a".repeat(64)).unwrap(),
                    asset: AssetId::Native,
                },
                ..charge(8, u64::MAX)
            }),
            Record::Pause {
                cause: PauseCause::RefusalBurst,
                at_ms: 1,
            },
            Record::Pause {
                cause: PauseCause::CapHit,
                at_ms: 2,
            },
            Record::Pause {
                cause: PauseCause::ClockRollback,
                at_ms: 3,
            },
            Record::Pause {
                cause: PauseCause::Freeze,
                at_ms: 4,
            },
        ];
        for record in records {
            let frame = encode_frame(&record).unwrap();
            match parse_frame(&frame) {
                Frame::Ok(back, len) => assert_eq!((back, len), (record, frame.len())),
                _ => panic!("frame does not parse"),
            }
        }
    }

    #[test]
    fn oversized_records_are_refused() {
        let huge = Record::Charge(Charge {
            key: VelocityKey {
                wallet_id: WalletId::new("w").unwrap(),
                asset: AssetId::Contract(vaultex_types::Address(vec![0; MAX_BODY_BYTES])),
            },
            ..charge(1, 1)
        });
        assert_eq!(encode_frame(&huge), Err(StoreError::TooLarge));
    }

    #[test]
    fn a_second_open_is_locked_out() {
        let (dir, path) = store_with("lock", 1);
        let first = FileStore::open(&path).unwrap();
        assert_eq!(FileStore::open(&path).unwrap_err(), StoreError::Locked);
        drop(first);
        assert_eq!(count(&FileStore::open(&path).unwrap()), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    /// Appends `tail` to the log of a 2-charge store, reopens, and checks that the tail was cut
    /// off and the store still works.
    fn assert_torn_tail_is_truncated(name: &str, tail: &[u8]) {
        let (dir, path) = store_with(name, 2);
        let good_len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(tail)
            .unwrap();
        let mut s = FileStore::open(&path).unwrap();
        assert_eq!(count(&s), 2, "{name}");
        assert_eq!(fs::metadata(&path).unwrap().len(), good_len, "{name}");
        reserve(&mut s, &charge(3, 3), &LIMITS).unwrap();
        drop(s);
        assert_eq!(count(&FileStore::open(&path).unwrap()), 3, "{name}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_torn_last_frame_is_truncated() {
        let frame = encode_frame(&Record::Charge(charge(9, 9))).unwrap();
        for cut in [1, 3, 4, 5, frame.len() / 2, frame.len() - 1] {
            assert_torn_tail_is_truncated(&format!("torn-cut-{cut}"), &frame[..cut]);
        }
        // The size grew but the data never landed.
        assert_torn_tail_is_truncated("torn-zeros", &vec![0; frame.len()]);
        // Full length, but the end of the data never landed.
        let mut bad_check = frame.clone();
        *bad_check.last_mut().unwrap() ^= 1;
        assert_torn_tail_is_truncated("torn-check", &bad_check);
        let mut half_zero = frame.clone();
        half_zero[frame.len() / 2..].fill(0);
        assert_torn_tail_is_truncated("torn-half-zero", &half_zero);
    }

    #[test]
    fn damage_before_the_last_frame_is_corrupt() {
        let (dir, path) = store_with("corrupt-middle", 3);
        let frame_len = encode_frame(&Record::Charge(charge(1, 1))).unwrap().len();
        let mut log = fs::read(&path).unwrap();
        log[frame_len + 10] ^= 0x80; // inside the second frame's body
        fs::write(&path, &log).unwrap();
        assert_eq!(
            FileStore::open(&path).unwrap_err(),
            StoreError::Corrupt {
                offset: frame_len as u64
            }
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            log,
            "a corrupt log is left untouched"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn more_than_one_frame_of_garbage_is_corrupt() {
        let (dir, path) = store_with("corrupt-garbage", 1);
        let good_len = fs::metadata(&path).unwrap().len();
        let mut log = fs::read(&path).unwrap();
        log.extend(std::iter::repeat_n(0xA5, MAX_FRAME_BYTES + 1));
        fs::write(&path, &log).unwrap();
        assert_eq!(
            FileStore::open(&path).unwrap_err(),
            StoreError::Corrupt { offset: good_len }
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_intact_frame_this_version_cannot_decode_is_corrupt_even_at_the_end() {
        let (dir, path) = store_with("corrupt-unknown", 1);
        let good_len = fs::metadata(&path).unwrap().len();
        let body = [3u8, 0, 0, 0];
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&tagged_digest(FRAME_TAG, &body[..]));
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&frame)
            .unwrap();
        assert_eq!(
            FileStore::open(&path).unwrap_err(),
            StoreError::Corrupt { offset: good_len }
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_store_refuses_further_writes() {
        let (dir, path) = store_with("failed", 0);
        let mut s = FileStore::open(&path).unwrap();
        s.failed = true;
        assert_eq!(
            reserve(&mut s, &charge(1, 1), &LIMITS),
            Err(crate::velocity::LimitRefusal::Store(StoreError::Failed))
        );
        assert!(!s.is_charged(&IntentDigest([1; 32])));
        fs::remove_dir_all(dir).unwrap();
    }
}
