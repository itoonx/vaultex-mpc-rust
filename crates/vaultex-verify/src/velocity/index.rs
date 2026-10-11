//! The in-memory view of a velocity log: what [`FileStore`](super::FileStore) rebuilds on open and
//! updates after each durable append. On its own (unit tests) it is a store without durability.

use std::collections::{HashMap, HashSet};

use vaultex_types::{IntentDigest, U256};

use super::{Record, StoreError, Usage, VelocityKey, VelocityStore};
use crate::amount::saturating_add;
use crate::breaker::Pause;

/// One charge as the index keeps it.
#[derive(Clone, Copy, Debug)]
struct Entry {
    at_ms: u64,
    amount: U256,
    fee: U256,
}

/// Charges by key, charged intents, the latest pause and the clock high-water mark.
// ponytail: charges are never pruned. At Rung 2 rates (tens a day) the log and the index stay
// small for years; compaction can come with the receipt log.
#[derive(Debug, Default)]
pub(crate) struct Index {
    charges: HashMap<VelocityKey, Vec<Entry>>,
    charged: HashSet<IntentDigest>,
    pauses: u64,
    pause: Option<Pause>,
    hwm_ms: u64,
}

impl Index {
    /// Folds one durable record into the view.
    pub(crate) fn apply(&mut self, record: &Record) {
        match record {
            Record::Charge(c) => {
                self.charges.entry(c.key.clone()).or_default().push(Entry {
                    at_ms: c.at_ms,
                    amount: c.amount,
                    fee: c.fee,
                });
                self.charged.insert(c.intent_digest);
            }
            Record::Pause { cause, at_ms } => {
                // The latest pause is the one in force, so an unpause order bound to an earlier
                // pause's `seq` cannot lift a later one.
                self.pauses = self.pauses.saturating_add(1);
                self.pause = Some(Pause {
                    seq: self.pauses,
                    cause: *cause,
                    since_ms: *at_ms,
                });
            }
        }
        self.hwm_ms = self.hwm_ms.max(record.at_ms());
    }
}

impl VelocityStore for Index {
    fn usage(&self, key: &VelocityKey, window_ms: u64, now_ms: u64) -> Usage {
        let zero = Usage {
            amount: U256::from(0),
            count: 0,
            fee: U256::from(0),
        };
        let Some(entries) = self.charges.get(key) else {
            return zero;
        };
        entries
            .iter()
            .filter(|e| e.at_ms.saturating_add(window_ms) > now_ms)
            .fold(zero, |u, e| Usage {
                amount: saturating_add(u.amount, e.amount),
                count: u.count.saturating_add(1),
                fee: saturating_add(u.fee, e.fee),
            })
    }

    fn is_charged(&self, intent_digest: &IntentDigest) -> bool {
        self.charged.contains(intent_digest)
    }

    fn pause(&self) -> Option<Pause> {
        self.pause
    }

    fn high_water_ms(&self) -> u64 {
        self.hwm_ms
    }

    fn append(&mut self, record: &Record) -> Result<(), StoreError> {
        self.apply(record);
        Ok(())
    }
}
