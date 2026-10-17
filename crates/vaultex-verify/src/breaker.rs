//! The circuit breaker (ROADMAP M6 #5): stops a signer from agreeing to anything once something
//! looks wrong, and keeps it stopped across restarts.
//!
//! ```text
//!            T1 refusal burst | T2 cap hit (if enabled) | T3 clock rollback | T4 freeze
//! RUNNING ──────────────────────────────────────────────────────────────────────────────► PAUSED{seq, cause, since}
//! PAUSED  ── every request refused (FROZEN for a freeze, BREAKER_TRIPPED otherwise) ──────► PAUSED
//! PAUSED  ── M-of-N unpause order (nonce, expiry, bound to `seq`): waits on ADR-11 ───────► RUNNING
//! ```
//!
//! | Trigger | Fires when |
//! |---|---|
//! | T1 refusal burst | [`BreakerConfig::refusal_threshold`] refusals that count ([`trips_breaker`]) within [`BreakerConfig::refusal_window_ms`] |
//! | T2 cap hit | a velocity limit refuses a charge, if [`BreakerConfig::pause_on_cap_hit`] |
//! | T3 clock rollback | `now + max_clock_skew_ms` is behind the high-water mark (the latest time the breaker has seen) |
//! | T4 freeze | [`Breaker::freeze`]: an order the caller has authenticated, or a local operator decision |
//!
//! A pause is written to the store before anything else happens, and holds in memory even if that
//! write fails. There is no way out of PAUSED yet: the M-of-N unpause order needs the admin keys
//! of the policy bundle (ADR-11), and will be checked against the pause's `seq`, a fresh nonce and
//! an expiry.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use serde::{Deserialize, Serialize};
use vaultex_types::RefusalCode;

use crate::velocity::{self, Charge, LimitRefusal, Record, Reserved, StoreError, VelocityStore};

/// The breaker's settings, carried by the policy bundle. Its field order is part of the
/// `POLICY_BUNDLE_V1` layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakerConfig {
    /// T1: this many counted refusals within the window pause the signer (0 behaves as 1).
    pub refusal_threshold: u16,
    /// T1: the refusal window, in milliseconds.
    pub refusal_window_ms: u64,
    /// T2: pause when a velocity limit refuses a charge.
    pub pause_on_cap_hit: bool,
    /// T3: how far `now` may fall behind the high-water mark before it counts as a rollback.
    pub max_clock_skew_ms: u64,
}

/// Why the breaker paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PauseCause {
    /// T1: a burst of refusals.
    RefusalBurst,
    /// T2: a velocity cap was hit.
    CapHit,
    /// T3: the clock went backwards.
    ClockRollback,
    /// T4: a freeze order.
    Freeze,
}

/// A pause in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pause {
    /// The pause's position among all pauses of the store, from 1. An unpause order names it.
    /// 0 means the pause is only in memory, because the store could not record it.
    pub seq: u64,
    /// Why.
    pub cause: PauseCause,
    /// When, in milliseconds since the Unix epoch: the later of the caller's `now` and the
    /// high-water mark.
    pub since_ms: u64,
}

/// The breaker's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests are evaluated.
    Running,
    /// Every request is refused.
    Paused(Pause),
}

/// Whether a refusal counts towards T1.
///
/// Refusals that honest, slow or unlucky requests produce do not count: expiry and validity
/// windows, missing or late approvals, velocity (T2 handles it), a policy not yet installed or not
/// yet in force, the breaker itself, local failures, and retryable unavailability. Everything
/// else counts, including codes this version does not know.
pub fn trips_breaker(code: RefusalCode) -> bool {
    !matches!(
        code,
        RefusalCode::REQUEST_EXPIRED
            | RefusalCode::REQUEST_WINDOW_TOO_LONG
            | RefusalCode::POLICY_VERSION_MISMATCH
            | RefusalCode::TX_EXPIRY_OUT_OF_BOUNDS
            | RefusalCode::NO_POLICY
            | RefusalCode::BUNDLE_NOT_EFFECTIVE
            | RefusalCode::VALIDITY_OVER_CAP
            | RefusalCode::APPROVALS_INSUFFICIENT
            | RefusalCode::APPROVAL_EXPIRED
            | RefusalCode::VELOCITY_EXCEEDED
            | RefusalCode::FROZEN
            | RefusalCode::BREAKER_TRIPPED
            | RefusalCode::STATE_WRITE_FAILED
            | RefusalCode::KEY_UNAVAILABLE
            | RefusalCode::INTERNAL
    ) && !code.is_retryable()
}

/// Velocity reservations behind the breaker, over one durable store.
///
/// Call [`admit`](Self::admit) (or [`reserve`](Self::reserve), which admits first) for every
/// request before any other check, and [`record_refusal`](Self::record_refusal) for every refusal
/// from the other checks.
#[derive(Debug)]
pub struct Breaker<S> {
    store: S,
    cfg: BreakerConfig,
    paused: Option<Pause>,
    hwm_ms: u64,
    /// Times of recent counted refusals (at most `refusal_threshold` of them).
    // ponytail: in memory only, so a restart clears a partial burst. The receipt log (T05-6)
    // records every refusal durably; rebuild this from it then.
    recent: Vec<u64>,
}

impl<S: VelocityStore> Breaker<S> {
    /// Resumes from what `store` holds: its pause, if any, and its clock high-water mark.
    pub fn new(store: S, cfg: BreakerConfig) -> Self {
        Self {
            paused: store.pause(),
            hwm_ms: store.high_water_ms(),
            store,
            cfg,
            recent: Vec::new(),
        }
    }

    /// RUNNING or PAUSED.
    pub fn state(&self) -> BreakerState {
        self.paused
            .map_or(BreakerState::Running, BreakerState::Paused)
    }

    /// The store, for reads.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The gate in front of every request: refuses while paused, and pauses (T3) if `now_ms` is
    /// behind the high-water mark by more than the allowed skew. Otherwise moves the high-water
    /// mark up to `now_ms`.
    pub fn admit(&mut self, now_ms: u64) -> Result<(), LimitRefusal> {
        if let Some(p) = self.paused {
            return Err(LimitRefusal::Paused(p));
        }
        if now_ms.saturating_add(self.cfg.max_clock_skew_ms) < self.hwm_ms {
            self.trip(PauseCause::ClockRollback, now_ms)
                .map_err(LimitRefusal::Store)?;
            return Err(LimitRefusal::ClockRollback);
        }
        self.hwm_ms = self.hwm_ms.max(now_ms);
        Ok(())
    }

    /// Admits at `charge.at_ms`, then [`velocity::reserve`]s. A velocity refusal pauses (T2) if
    /// the config says so.
    pub fn reserve(
        &mut self,
        charge: &Charge,
        limits: &[velocity::WindowLimit],
    ) -> Result<Reserved, LimitRefusal> {
        self.admit(charge.at_ms)?;
        match velocity::reserve(&mut self.store, charge, limits) {
            Err(e @ LimitRefusal::Exceeded { .. }) if self.cfg.pause_on_cap_hit => {
                self.trip(PauseCause::CapHit, charge.at_ms)
                    .map_err(LimitRefusal::Store)?;
                Err(e)
            }
            other => other,
        }
    }

    /// Counts a refusal from another check towards T1. Returns the pause if this refusal tripped
    /// the breaker.
    pub fn record_refusal(
        &mut self,
        code: RefusalCode,
        now_ms: u64,
    ) -> Result<Option<Pause>, StoreError> {
        if self.paused.is_some() || !trips_breaker(code) {
            return Ok(None);
        }
        let window = self.cfg.refusal_window_ms;
        self.recent.retain(|&t| t.saturating_add(window) > now_ms);
        self.recent.push(now_ms);
        if self.recent.len() < usize::from(self.cfg.refusal_threshold.max(1)) {
            return Ok(None);
        }
        self.recent.clear();
        self.trip(PauseCause::RefusalBurst, now_ms).map(Some)
    }

    /// Pauses now (T4), even if already paused, so the freeze is on record and an unpause must
    /// name it. Freezing is the safe direction: authenticating a freeze order is the caller's job.
    pub fn freeze(&mut self, now_ms: u64) -> Result<Pause, StoreError> {
        self.trip(PauseCause::Freeze, now_ms)
    }

    fn trip(&mut self, cause: PauseCause, now_ms: u64) -> Result<Pause, StoreError> {
        let at_ms = now_ms.max(self.hwm_ms);
        self.hwm_ms = at_ms;
        // Fail closed: paused in memory before the write, and still paused if it fails.
        let pending = Pause {
            seq: 0,
            cause,
            since_ms: at_ms,
        };
        self.paused = Some(pending);
        self.store.append(&Record::Pause { cause, at_ms })?;
        let pause = self.store.pause().unwrap_or(pending);
        self.paused = Some(pause);
        Ok(pause)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::velocity::{Index, Limit, VelocityKey, WindowLimit};
    use vaultex_types::{AssetId, IntentDigest, WalletId, U256};

    const NOW: u64 = 1_700_000_000_000;
    const MIN: u64 = 60_000;

    fn cfg() -> BreakerConfig {
        BreakerConfig {
            refusal_threshold: 3,
            refusal_window_ms: 10 * MIN,
            pause_on_cap_hit: true,
            max_clock_skew_ms: MIN,
        }
    }

    fn breaker() -> Breaker<Index> {
        Breaker::new(Index::default(), cfg())
    }

    fn charge(n: u8, at_ms: u64) -> Charge {
        Charge {
            key: VelocityKey {
                wallet_id: WalletId::new("w-1").unwrap(),
                asset: AssetId::Native,
            },
            intent_digest: IntentDigest([n; 32]),
            amount: U256::from(10),
            fee: U256::from(0),
            at_ms,
        }
    }

    fn limits(max_count: u32) -> [WindowLimit; 1] {
        [WindowLimit {
            window_ms: 24 * 60 * MIN,
            max_amount: U256::from(1_000),
            max_count,
            max_fee: U256::from(0),
        }]
    }

    fn paused(b: &Breaker<Index>) -> Pause {
        match b.state() {
            BreakerState::Paused(p) => p,
            BreakerState::Running => panic!("breaker is running"),
        }
    }

    #[test]
    fn runs_and_charges_until_tripped() {
        let mut b = breaker();
        assert_eq!(b.state(), BreakerState::Running);
        assert_eq!(
            b.reserve(&charge(1, NOW), &limits(5)),
            Ok(Reserved::Charged)
        );
        assert_eq!(b.store().high_water_ms(), NOW);
    }

    #[test]
    fn t1_refusal_burst_within_the_window() {
        let mut b = breaker();
        let bad = RefusalCode::TX_SELECTOR_NOT_ALLOWED;
        assert_eq!(b.record_refusal(bad, NOW), Ok(None));
        assert_eq!(b.record_refusal(bad, NOW + MIN), Ok(None));
        // The first refusal ages out of the 10-minute window as the third arrives.
        assert_eq!(b.record_refusal(bad, NOW + 10 * MIN), Ok(None));
        assert_eq!(b.state(), BreakerState::Running);
        let p = b.record_refusal(bad, NOW + 10 * MIN + 1).unwrap().unwrap();
        assert_eq!(
            p,
            Pause {
                seq: 1,
                cause: PauseCause::RefusalBurst,
                since_ms: NOW + 10 * MIN + 1
            }
        );
        assert_eq!(paused(&b), p);
        assert_eq!(
            b.reserve(&charge(1, NOW + 12 * MIN), &limits(5)),
            Err(LimitRefusal::Paused(p))
        );
        assert!(!b.store().is_charged(&IntentDigest([1; 32])));
    }

    #[test]
    fn t1_ignores_refusals_that_do_not_count() {
        let mut b = breaker();
        for code in [
            RefusalCode::TX_EXPIRY_OUT_OF_BOUNDS,
            RefusalCode::APPROVALS_INSUFFICIENT,
            RefusalCode::VELOCITY_EXCEEDED,
            RefusalCode::BUSY,
        ] {
            for i in 0..5 {
                assert_eq!(b.record_refusal(code, NOW + i), Ok(None), "{code:?}");
            }
        }
        assert_eq!(b.state(), BreakerState::Running);
    }

    #[test]
    fn breaker_weights() {
        for code in [
            RefusalCode::TX_SELECTOR_NOT_ALLOWED,
            RefusalCode::TX_PERMISSION_NOT_ALLOWED,
            RefusalCode::RECIPIENT_NOT_ALLOWED,
            RefusalCode::SOD_VIOLATION,
            RefusalCode::APPROVAL_INVALID,
            RefusalCode::BUNDLE_ROLLBACK,
            RefusalCode::CLOCK_UNTRUSTED,
            RefusalCode::ADMIN_QUORUM_INSUFFICIENT,
            RefusalCode(0x0FFF),
        ] {
            assert!(trips_breaker(code), "{code:?} counts");
        }
        for code in [
            RefusalCode::REQUEST_EXPIRED,
            RefusalCode::APPROVAL_EXPIRED,
            RefusalCode::NO_POLICY,
            RefusalCode::FROZEN,
            RefusalCode::STATE_WRITE_FAILED,
            RefusalCode::TIMEOUT,
        ] {
            assert!(!trips_breaker(code), "{code:?} does not count");
        }
    }

    #[test]
    fn t2_cap_hit_pauses_when_enabled() {
        let mut b = breaker();
        b.reserve(&charge(1, NOW), &limits(1)).unwrap();
        let over = Err(LimitRefusal::Exceeded {
            window_ms: 24 * 60 * MIN,
            limit: Limit::Count,
        });
        assert_eq!(b.reserve(&charge(2, NOW + 1), &limits(1)), over);
        assert_eq!(paused(&b).cause, PauseCause::CapHit);
        assert_eq!(
            LimitRefusal::Paused(paused(&b)).code(),
            RefusalCode::BREAKER_TRIPPED
        );
        // An idempotent retry of an intent charged before the pause is refused too.
        assert!(matches!(
            b.reserve(&charge(1, NOW + 2), &limits(1)),
            Err(LimitRefusal::Paused(_))
        ));

        let mut b = Breaker::new(
            Index::default(),
            BreakerConfig {
                pause_on_cap_hit: false,
                ..cfg()
            },
        );
        b.reserve(&charge(1, NOW), &limits(1)).unwrap();
        assert_eq!(b.reserve(&charge(2, NOW + 1), &limits(1)), over);
        assert_eq!(b.state(), BreakerState::Running);
    }

    #[test]
    fn t3_clock_rollback_refuses_and_pauses() {
        let mut b = breaker();
        b.admit(NOW).unwrap();
        // Within the skew allowance: fine, and the high-water mark stays at NOW.
        assert_eq!(b.admit(NOW - MIN), Ok(()));
        assert_eq!(b.admit(NOW - MIN - 1), Err(LimitRefusal::ClockRollback));
        let p = paused(&b);
        assert_eq!((p.cause, p.since_ms), (PauseCause::ClockRollback, NOW));
        assert_eq!(
            LimitRefusal::ClockRollback.code(),
            RefusalCode::CLOCK_UNTRUSTED
        );
        assert_eq!(b.admit(NOW + MIN), Err(LimitRefusal::Paused(p)));
    }

    #[test]
    fn t3_uses_the_stored_high_water_mark_after_a_restart() {
        let mut store = Index::default();
        velocity::reserve(&mut store, &charge(1, NOW), &limits(5)).unwrap();
        let mut b = Breaker::new(store, cfg());
        assert_eq!(
            b.reserve(&charge(2, NOW - 2 * MIN), &limits(5)),
            Err(LimitRefusal::ClockRollback)
        );
    }

    #[test]
    fn t4_freeze_is_recorded_even_when_already_paused() {
        let mut b = breaker();
        let first = b.freeze(NOW).unwrap();
        assert_eq!(
            first,
            Pause {
                seq: 1,
                cause: PauseCause::Freeze,
                since_ms: NOW
            }
        );
        assert_eq!(LimitRefusal::Paused(first).code(), RefusalCode::FROZEN);
        let second = b.freeze(NOW - 5).unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(
            second.since_ms, NOW,
            "never earlier than the high-water mark"
        );
        assert_eq!(paused(&b), second);
    }

    #[test]
    fn a_stored_pause_survives_a_restart() {
        let mut b = breaker();
        b.freeze(NOW).unwrap();
        let store = b.store;
        let mut b = Breaker::new(store, cfg());
        assert_eq!(paused(&b).cause, PauseCause::Freeze);
        assert!(matches!(
            b.reserve(&charge(1, NOW + 1), &limits(5)),
            Err(LimitRefusal::Paused(_))
        ));
    }

    /// A store whose writes always fail.
    struct Broken(Index);
    impl VelocityStore for Broken {
        fn usage(&self, k: &VelocityKey, w: u64, n: u64) -> velocity::Usage {
            self.0.usage(k, w, n)
        }
        fn is_charged(&self, d: &IntentDigest) -> bool {
            self.0.is_charged(d)
        }
        fn pause(&self) -> Option<Pause> {
            self.0.pause()
        }
        fn high_water_ms(&self) -> u64 {
            self.0.high_water_ms()
        }
        fn append(&mut self, _: &Record) -> Result<(), StoreError> {
            Err(StoreError::Failed)
        }
    }

    #[test]
    fn a_pause_holds_in_memory_when_the_store_fails() {
        let mut store = Index::default();
        velocity::reserve(&mut store, &charge(1, NOW), &limits(5)).unwrap();
        let mut b = Breaker::new(Broken(store), cfg());
        assert_eq!(b.freeze(NOW), Err(StoreError::Failed));
        let p = match b.state() {
            BreakerState::Paused(p) => p,
            BreakerState::Running => panic!("must fail closed"),
        };
        assert_eq!((p.seq, p.cause), (0, PauseCause::Freeze));
        // Even an idempotent retry, which needs no write, is refused.
        assert!(matches!(
            b.reserve(&charge(1, NOW + 1), &limits(5)),
            Err(LimitRefusal::Paused(_))
        ));
    }

    #[test]
    fn a_failed_charge_write_is_refused() {
        let mut b = Breaker::new(Broken(Index::default()), cfg());
        assert_eq!(
            b.reserve(&charge(1, NOW), &limits(5)),
            Err(LimitRefusal::Store(StoreError::Failed))
        );
        assert_eq!(
            LimitRefusal::Store(StoreError::Failed).code(),
            RefusalCode::STATE_WRITE_FAILED
        );
    }
}
