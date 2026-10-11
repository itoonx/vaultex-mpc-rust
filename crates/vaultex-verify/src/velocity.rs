//! Velocity caps (ROADMAP M6 #5): sliding-window limits on what one signer agrees to move, kept in
//! a durable store, plus the helper that sizes each signer's cap from the group's budget.
//!
//! # Semantics
//!
//! - A cap is counted per [`VelocityKey`]: one wallet's spending of one asset.
//! - Each window limits three sums over the charges made in the last `window_ms`: the amount, the
//!   number of charges and the fee bound ([`WindowLimit`]).
//! - A charge is made when the signer agrees to sign, **before** it signs, and is never released:
//!   a charge whose transaction is never broadcast still counts until it ages out of its window.
//! - [`reserve`] is idempotent per intent digest: a retry of an intent that is already charged is
//!   accepted without a second charge. That is harmless, because the chain deduplicates by
//!   transaction id, and the intent digest binds it.
//! - Time is the caller's `now`, in milliseconds since the Unix epoch. Charges dated after `now`
//!   (possible only after a clock rollback, which the breaker refuses) still count.
//!
//! # Storage
//!
//! [`VelocityStore`] is the storage seam. Its one write, [`VelocityStore::append`], must be durable
//! before it returns, and every record it accepts only ever restricts: a charge adds usage and a
//! pause stops signing. Nothing releases a charge, and lifting a pause waits on the M-of-N unpause
//! order (ADR-11). [`FileStore`] is the fsync'd file implementation.
//!
//! # Calibration
//!
//! In a t-of-n wallet every signature needs t signers, and each honest signer charges every
//! signature it takes part in. If each signer caps itself at `L` per window and `c` signers do not
//! enforce (`c < t`), then the honest signers' charges add up to at least `(t − c)·V` for a total
//! outflow `V`, and to at most `(n − c)·L`. So **`V ≤ (n − c)·L / (t − c)`**
//! ([`worst_case_outflow`]). With every signer enforcing and `L = ⌊t·G/n⌋`, `V ≤ G`
//! ([`per_signer_cap`]).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod file;
mod index;

pub use file::FileStore;
pub(crate) use index::Index;

use vaultex_types::{AssetId, IntentDigest, Refusal, RefusalCode, WalletId, U256};

use crate::amount::{checked_add, checked_mul_small, div_rem_small};
use crate::breaker::{Pause, PauseCause};

/// What a velocity cap is counted against: one wallet's spending of one asset.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VelocityKey {
    /// The wallet that signs.
    pub wallet_id: WalletId,
    /// The asset moved.
    pub asset: AssetId,
}

/// One reservation against a [`VelocityKey`], made for one decoded intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charge {
    /// What the charge counts against.
    pub key: VelocityKey,
    /// The intent charged; a second charge for the same digest is never made.
    pub intent_digest: IntentDigest,
    /// The amount, in the asset's base units.
    pub amount: U256,
    /// The most the transaction can burn in fees, in the chain's fee unit (TRON: sun).
    pub fee: U256,
    /// When the charge was made (the caller's clock), in milliseconds since the Unix epoch.
    pub at_ms: u64,
}

/// The limits of one sliding window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowLimit {
    /// The window length, in milliseconds.
    pub window_ms: u64,
    /// The most that may be charged in the window, in base units.
    pub max_amount: U256,
    /// The most charges the window may hold.
    pub max_count: u32,
    /// The largest fee bound the window's charges may add up to.
    pub max_fee: U256,
}

/// What a key has used in a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    /// The sum of the charged amounts.
    pub amount: U256,
    /// The number of charges.
    pub count: u32,
    /// The sum of the charged fee bounds.
    pub fee: U256,
}

/// Which limit of a window a charge would break.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    /// [`WindowLimit::max_amount`].
    Amount,
    /// [`WindowLimit::max_count`].
    Count,
    /// [`WindowLimit::max_fee`].
    Fee,
}

/// One durable entry in a [`VelocityStore`]. Every kind only ever restricts.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A velocity charge.
    Charge(Charge),
    /// The breaker paused (see [`crate::breaker`]).
    Pause {
        /// Why.
        cause: PauseCause,
        /// When, in milliseconds since the Unix epoch.
        at_ms: u64,
    },
}

impl Record {
    /// The time the record carries.
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Charge(c) => c.at_ms,
            Self::Pause { at_ms, .. } => *at_ms,
        }
    }
}

/// Why a store could not open or write. Every one fails closed: no charge, no signature.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Another process holds the store's lock.
    Locked,
    /// An I/O operation failed.
    Io(std::io::ErrorKind),
    /// A damaged or unreadable record before the end of the log, at this byte offset. The store
    /// refuses to open; it must be restored, not repaired.
    Corrupt {
        /// Byte offset of the first bad frame.
        offset: u64,
    },
    /// A record is too large to store.
    TooLarge,
    /// An earlier write failed, so the end of the log is unknown. The store accepts no more writes
    /// until it is reopened (which truncates a torn tail).
    Failed,
}

/// The durable velocity and breaker state of one signer.
///
/// Reads come from memory; [`append`](Self::append) is the one write. Callers serialise access
/// (`&mut self`), so a usage read and the charge that follows it cannot interleave with another
/// decision.
pub trait VelocityStore {
    /// What `key` has used in the window `window_ms` ending at `now_ms`: every charge with
    /// `at_ms + window_ms > now_ms`, including charges dated after `now_ms`.
    fn usage(&self, key: &VelocityKey, window_ms: u64, now_ms: u64) -> Usage;
    /// Whether a charge for this intent digest was ever recorded.
    fn is_charged(&self, intent_digest: &IntentDigest) -> bool;
    /// The latest pause, if any. (A pause cannot be lifted yet: the M-of-N unpause waits on
    /// ADR-11.)
    fn pause(&self) -> Option<Pause>;
    /// The latest time carried by any record (0 for an empty store): the clock high-water mark.
    fn high_water_ms(&self) -> u64;
    /// Records `record`. Returns `Ok` only once the record is on stable storage, and only then
    /// is it reflected in the reads.
    fn append(&mut self, record: &Record) -> Result<(), StoreError>;
}

/// The outcome of a successful [`reserve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserved {
    /// The charge is durable.
    Charged,
    /// The intent was already charged; nothing new was recorded.
    AlreadyCharged,
}

/// Why velocity or the breaker refused. The variant names the exact check;
/// [`code`](Self::code) maps it to the coarser wire registry.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitRefusal {
    /// The breaker is paused.
    Paused(Pause),
    /// `now` is behind the clock high-water mark by more than the allowed skew. The breaker has
    /// paused.
    ClockRollback,
    /// The charge would take a window over one of its limits.
    Exceeded {
        /// The window whose limit would be broken (the first, in the order given).
        window_ms: u64,
        /// Which limit.
        limit: Limit,
    },
    /// No window limits were given, so there is nothing to cap against (deny by default).
    NoLimits,
    /// The store could not make the charge or the pause durable.
    Store(StoreError),
}

impl LimitRefusal {
    /// The wire refusal code (registry in `vaultex-types`).
    pub fn code(self) -> RefusalCode {
        match self {
            Self::Paused(p) if p.cause == PauseCause::Freeze => RefusalCode::FROZEN,
            Self::Paused(_) => RefusalCode::BREAKER_TRIPPED,
            Self::ClockRollback => RefusalCode::CLOCK_UNTRUSTED,
            Self::Exceeded { .. } | Self::NoLimits => RefusalCode::VELOCITY_EXCEEDED,
            Self::Store(_) => RefusalCode::STATE_WRITE_FAILED,
        }
    }

    /// The wire refusal (no policy rule index yet; the bundle lands with T05-3).
    pub fn refusal(self) -> Refusal {
        Refusal {
            code: self.code(),
            rule_index: None,
        }
    }
}

/// Checks `charge` against every window in `limits`, in order, and makes it durable if all pass.
///
/// For each window the checks are, in order: amount, count, fee; the first failure is reported.
/// An intent that is already charged is accepted again without a check or a second charge. An
/// empty `limits` is refused. Pausing is the [`Breaker`](crate::breaker::Breaker)'s job: call this
/// through [`Breaker::reserve`](crate::breaker::Breaker::reserve) unless the caller gates requests
/// itself.
pub fn reserve(
    store: &mut dyn VelocityStore,
    charge: &Charge,
    limits: &[WindowLimit],
) -> Result<Reserved, LimitRefusal> {
    if store.is_charged(&charge.intent_digest) {
        return Ok(Reserved::AlreadyCharged);
    }
    if limits.is_empty() {
        return Err(LimitRefusal::NoLimits);
    }
    for w in limits {
        let used = store.usage(&charge.key, w.window_ms, charge.at_ms);
        let fits = |sum: Option<U256>, max: U256| sum.is_some_and(|s| s <= max);
        let broken = if !fits(checked_add(used.amount, charge.amount), w.max_amount) {
            Some(Limit::Amount)
        } else if used.count >= w.max_count {
            Some(Limit::Count)
        } else if !fits(checked_add(used.fee, charge.fee), w.max_fee) {
            Some(Limit::Fee)
        } else {
            None
        };
        if let Some(limit) = broken {
            return Err(LimitRefusal::Exceeded {
                window_ms: w.window_ms,
                limit,
            });
        }
    }
    store
        .append(&Record::Charge(charge.clone()))
        .map_err(LimitRefusal::Store)?;
    Ok(Reserved::Charged)
}

/// How [`per_signer_cap`] rounds `t·G/n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    /// `⌊t·G/n⌋`. With every signer enforcing, the group's total outflow per window is at most
    /// `G`. Use this one.
    Floor,
    /// `⌈t·G/n⌉`, the formula as ROADMAP M6 #5 writes it. The total can then exceed `G` by less
    /// than `n/t` base units: negligible, but not `≤ G`.
    Ceil,
}

/// The per-signer cap `L` for a t-of-n wallet whose group budget per window is `group_budget`
/// (`G`). `None` unless `1 ≤ t ≤ n`.
///
/// For c = 0 non-enforcing signers, [`worst_case_outflow`]`(t, n, 0, L)` is then at most `G` with
/// [`Rounding::Floor`].
pub fn per_signer_cap(t: u8, n: u8, group_budget: U256, rounding: Rounding) -> Option<U256> {
    if t == 0 || t > n {
        return None;
    }
    // t·G/n = t·⌊G/n⌋ + t·(G mod n)/n, and t·(G mod n) < 255², so nothing overflows.
    let (q, r) = div_rem_small(group_budget, u64::from(n))?;
    let tr = u64::from(t).checked_mul(r)?;
    let frac = match rounding {
        Rounding::Floor => tr.checked_div(u64::from(n))?,
        Rounding::Ceil => tr.div_ceil(u64::from(n)),
    };
    checked_add(checked_mul_small(q, u64::from(t))?, U256::from(frac))
}

/// The most a t-of-n group can move per window when every enforcing signer caps itself at
/// `per_signer` and `c` signers do not enforce: `⌊(n − c)·L / (t − c)⌋` base units.
///
/// `None` if `c ≥ t` (the non-enforcing signers can reach the threshold alone, so nothing bounds
/// the outflow), unless `1 ≤ t ≤ n`, or if the bound does not fit in 256 bits.
pub fn worst_case_outflow(t: u8, n: u8, c: u8, per_signer: U256) -> Option<U256> {
    if t == 0 || t > n || c >= t {
        return None;
    }
    let enforcing_needed = u64::from(t.checked_sub(c)?);
    let enforcing = u64::from(n.checked_sub(c)?);
    // (n−c)·L/(t−c) = (n−c)·⌊L/(t−c)⌋ + (n−c)·(L mod (t−c))/(t−c), so the product cannot overflow
    // before the division.
    let (q, r) = div_rem_small(per_signer, enforcing_needed)?;
    let frac = enforcing.checked_mul(r)?.checked_div(enforcing_needed)?;
    checked_add(checked_mul_small(q, enforcing)?, U256::from(frac))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::amount::MAX;

    fn key(asset: AssetId) -> VelocityKey {
        VelocityKey {
            wallet_id: WalletId::new("w-1").unwrap(),
            asset,
        }
    }

    fn charge(n: u8, amount: u64, fee: u64, at_ms: u64) -> Charge {
        Charge {
            key: key(AssetId::Native),
            intent_digest: IntentDigest([n; 32]),
            amount: U256::from(amount),
            fee: U256::from(fee),
            at_ms,
        }
    }

    const HOUR: u64 = 3_600_000;
    const DAY: u64 = 24 * HOUR;

    fn day_limit(amount: u64, count: u32, fee: u64) -> WindowLimit {
        WindowLimit {
            window_ms: DAY,
            max_amount: U256::from(amount),
            max_count: count,
            max_fee: U256::from(fee),
        }
    }

    fn exceeded(window_ms: u64, limit: Limit) -> Result<Reserved, LimitRefusal> {
        Err(LimitRefusal::Exceeded { window_ms, limit })
    }

    #[test]
    fn amount_cap_is_inclusive() {
        let mut s = Index::default();
        let limits = [day_limit(100, 10, 1_000)];
        assert_eq!(
            reserve(&mut s, &charge(1, 60, 1, 0), &limits),
            Ok(Reserved::Charged)
        );
        assert_eq!(
            reserve(&mut s, &charge(2, 41, 1, 1), &limits),
            exceeded(DAY, Limit::Amount)
        );
        assert_eq!(
            reserve(&mut s, &charge(3, 40, 1, 2), &limits),
            Ok(Reserved::Charged),
            "exactly the cap is allowed"
        );
        let used = s.usage(&key(AssetId::Native), DAY, 2);
        assert_eq!((used.amount, used.count), (U256::from(100), 2));
    }

    #[test]
    fn count_cap() {
        let mut s = Index::default();
        let limits = [day_limit(1_000, 2, 1_000)];
        for n in 1..=2 {
            assert_eq!(
                reserve(&mut s, &charge(n, 1, 1, 0), &limits),
                Ok(Reserved::Charged)
            );
        }
        assert_eq!(
            reserve(&mut s, &charge(3, 1, 1, 0), &limits),
            exceeded(DAY, Limit::Count)
        );
    }

    #[test]
    fn fee_cap() {
        let mut s = Index::default();
        let limits = [day_limit(1_000, 10, 50)];
        assert_eq!(
            reserve(&mut s, &charge(1, 1, 30, 0), &limits),
            Ok(Reserved::Charged)
        );
        assert_eq!(
            reserve(&mut s, &charge(2, 1, 21, 0), &limits),
            exceeded(DAY, Limit::Fee)
        );
    }

    #[test]
    fn checks_run_amount_then_count_then_fee() {
        let mut s = Index::default();
        let limits = [day_limit(10, 1, 10)];
        reserve(&mut s, &charge(1, 10, 10, 0), &limits).unwrap();
        assert_eq!(
            reserve(&mut s, &charge(2, 1, 1, 0), &limits),
            exceeded(DAY, Limit::Amount),
            "all three are broken; amount is reported"
        );
    }

    #[test]
    fn every_window_is_checked_in_order() {
        let mut s = Index::default();
        let hour = WindowLimit {
            window_ms: HOUR,
            ..day_limit(50, 10, 1_000)
        };
        let limits = [hour, day_limit(80, 10, 1_000)];
        reserve(&mut s, &charge(1, 50, 0, 0), &limits).unwrap();
        assert_eq!(
            reserve(&mut s, &charge(2, 1, 0, HOUR - 1), &limits),
            exceeded(HOUR, Limit::Amount)
        );
        // An hour later the hourly window is clear, but the daily one still holds the 50.
        reserve(&mut s, &charge(3, 30, 0, HOUR), &limits).unwrap();
        assert_eq!(
            reserve(&mut s, &charge(4, 1, 0, 2 * HOUR), &limits),
            exceeded(DAY, Limit::Amount)
        );
    }

    #[test]
    fn charges_age_out_of_a_sliding_window() {
        let mut s = Index::default();
        let limits = [day_limit(100, 10, 1_000)];
        reserve(&mut s, &charge(1, 100, 0, 1_000), &limits).unwrap();
        assert_eq!(
            reserve(&mut s, &charge(2, 1, 0, 1_000 + DAY - 1), &limits),
            exceeded(DAY, Limit::Amount)
        );
        assert_eq!(
            reserve(&mut s, &charge(3, 100, 0, 1_000 + DAY), &limits),
            Ok(Reserved::Charged)
        );
    }

    #[test]
    fn charges_dated_after_now_still_count() {
        let mut s = Index::default();
        reserve(&mut s, &charge(1, 7, 0, 5 * DAY), &[day_limit(100, 10, 0)]).unwrap();
        assert_eq!(s.usage(&key(AssetId::Native), DAY, 0).amount, U256::from(7));
    }

    #[test]
    fn keys_are_separate() {
        let mut s = Index::default();
        let limits = [day_limit(10, 10, 0)];
        reserve(&mut s, &charge(1, 10, 0, 0), &limits).unwrap();
        let token = Charge {
            key: key(AssetId::Contract(vaultex_types::Address(vec![0x41; 21]))),
            ..charge(2, 10, 0, 0)
        };
        assert_eq!(reserve(&mut s, &token, &limits), Ok(Reserved::Charged));
    }

    #[test]
    fn a_retry_is_not_charged_twice() {
        let mut s = Index::default();
        let limits = [day_limit(10, 1, 0)];
        assert_eq!(
            reserve(&mut s, &charge(1, 10, 0, 0), &limits),
            Ok(Reserved::Charged)
        );
        assert_eq!(
            reserve(&mut s, &charge(1, 10, 0, 1), &limits),
            Ok(Reserved::AlreadyCharged),
            "accepted even though the window is full"
        );
        assert_eq!(s.usage(&key(AssetId::Native), DAY, 1).count, 1);
    }

    #[test]
    fn no_limits_is_refused() {
        let mut s = Index::default();
        assert_eq!(
            reserve(&mut s, &charge(1, 1, 0, 0), &[]),
            Err(LimitRefusal::NoLimits)
        );
        assert!(!s.is_charged(&IntentDigest([1; 32])));
    }

    #[test]
    fn overflow_counts_as_over_the_cap() {
        let mut s = Index::default();
        let limits = [WindowLimit {
            max_amount: MAX,
            ..day_limit(0, 10, 0)
        }];
        let big = Charge {
            amount: MAX,
            ..charge(1, 0, 0, 0)
        };
        reserve(&mut s, &big, &limits).unwrap();
        assert_eq!(
            reserve(&mut s, &charge(2, 1, 0, 0), &limits),
            exceeded(DAY, Limit::Amount)
        );
    }

    #[test]
    fn refusal_codes() {
        assert_eq!(
            LimitRefusal::NoLimits.code(),
            RefusalCode::VELOCITY_EXCEEDED
        );
        assert_eq!(
            LimitRefusal::Store(StoreError::Failed).refusal(),
            Refusal {
                code: RefusalCode::STATE_WRITE_FAILED,
                rule_index: None
            }
        );
    }

    /// G = 10,000 USDT in base units (6 decimals).
    const G: u64 = 10_000_000_000;

    #[test]
    fn calibration_vectors() {
        // (t, n, c, ⌊tG/n⌋, ⌈tG/n⌉, worst case with the floor)
        let table: [(u8, u8, u8, u64, u64, u64); 6] = [
            (1, 1, 0, G, G, G),
            (2, 2, 0, G, G, G),
            (2, 3, 0, 6_666_666_666, 6_666_666_667, 9_999_999_999),
            (2, 3, 1, 6_666_666_666, 6_666_666_667, 13_333_333_332),
            (3, 5, 1, 6_000_000_000, 6_000_000_000, 12_000_000_000),
            (3, 5, 2, 6_000_000_000, 6_000_000_000, 18_000_000_000),
        ];
        for (t, n, c, floor, ceil, worst) in table {
            let g = U256::from(G);
            assert_eq!(
                per_signer_cap(t, n, g, Rounding::Floor),
                Some(U256::from(floor))
            );
            assert_eq!(
                per_signer_cap(t, n, g, Rounding::Ceil),
                Some(U256::from(ceil))
            );
            assert_eq!(
                worst_case_outflow(t, n, c, U256::from(floor)),
                Some(U256::from(worst)),
                "{t}-of-{n}, c = {c}"
            );
        }
    }

    #[test]
    fn floor_keeps_the_group_within_budget_and_ceil_may_not() {
        for n in 1..=9u8 {
            for t in 1..=n {
                for g in [0, 1, 2, 7, 1_000_003, G, G + 1] {
                    let budget = U256::from(g);
                    let floor = per_signer_cap(t, n, budget, Rounding::Floor).unwrap();
                    let ceil = per_signer_cap(t, n, budget, Rounding::Ceil).unwrap();
                    assert!(floor <= ceil && ceil <= budget);
                    assert!(worst_case_outflow(t, n, 0, floor).unwrap() <= budget);
                    // The ceiling overshoots by less than n/t base units.
                    let over = worst_case_outflow(t, n, 0, ceil).unwrap();
                    let slack = U256::from(g + u64::from(n.div_ceil(t)));
                    assert!(over < slack, "{t}-of-{n}, G = {g}");
                }
            }
        }
        // 2-of-3 with G = 2: each signer allows ⌈4/3⌉ = 2, so the group can move ⌊3·2/2⌋ = 3 > G.
        let ceil = per_signer_cap(2, 3, U256::from(2), Rounding::Ceil).unwrap();
        assert_eq!(ceil, U256::from(2));
        assert_eq!(worst_case_outflow(2, 3, 0, ceil), Some(U256::from(3)));
    }

    #[test]
    fn calibration_rejects_bad_parameters_and_never_overflows() {
        let g = U256::from(G);
        assert_eq!(per_signer_cap(0, 3, g, Rounding::Floor), None);
        assert_eq!(per_signer_cap(4, 3, g, Rounding::Floor), None);
        assert_eq!(worst_case_outflow(2, 3, 2, g), None, "c = t");
        assert_eq!(worst_case_outflow(2, 3, 3, g), None, "c > t");
        assert_eq!(worst_case_outflow(0, 3, 0, g), None);
        assert_eq!(per_signer_cap(255, 255, MAX, Rounding::Ceil), Some(MAX));
        assert_eq!(per_signer_cap(1, 1, MAX, Rounding::Floor), Some(MAX));
        assert_eq!(worst_case_outflow(1, 1, 0, MAX), Some(MAX));
        assert_eq!(
            worst_case_outflow(2, 255, 1, MAX),
            None,
            "254·MAX does not fit"
        );
    }
}
