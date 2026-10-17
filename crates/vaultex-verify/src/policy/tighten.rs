//! The tightening classifier: one function per row group of the table in the
//! [module docs](super#tightening). It answers "provably no looser", so every doubt is a loosening.

use crate::breaker::BreakerConfig;

use super::{AssetRuleV1, PolicyBundleV1, RecipientsV1, WalletV1};

/// Whether `new` tightens `old`: every row of the tightening table holds. Anything else is a
/// loosening, which needs M-of-N and waits out the time lock.
pub fn tightens(old: &PolicyBundleV1, new: &PolicyBundleV1) -> bool {
    new.admins == old.admins
        && new.loosen_delay_ms >= old.loosen_delay_ms
        && subset(&new.initiators, &old.initiators)
        && subset(&new.approvers, &old.approvers)
        && breaker(&old.breaker, &new.breaker)
        && new
            .wallets
            .iter()
            .all(|n| old.wallets.iter().any(|o| wallet(o, n)))
}

fn subset<T: PartialEq>(new: &[T], old: &[T]) -> bool {
    new.iter().all(|x| old.contains(x))
}

fn breaker(old: &BreakerConfig, new: &BreakerConfig) -> bool {
    new.refusal_threshold.max(1) <= old.refusal_threshold.max(1)
        && new.refusal_window_ms >= old.refusal_window_ms
        && (new.pause_on_cap_hit || !old.pause_on_cap_hit)
        && new.max_clock_skew_ms <= old.max_clock_skew_ms
}

fn wallet(old: &WalletV1, new: &WalletV1) -> bool {
    new.wallet_id == old.wallet_id
        && new.network == old.network
        && new.address == old.address
        && new.permission_id == old.permission_id
        && new.max_fee_limit_sun <= old.max_fee_limit_sun
        && new.max_validity_ms <= old.max_validity_ms
        && new
            .assets
            .iter()
            .all(|n| old.assets.iter().any(|o| asset(o, n)))
}

fn asset(old: &AssetRuleV1, new: &AssetRuleV1) -> bool {
    new.asset == old.asset
        && new.decimals == old.decimals
        && new.max_per_tx <= old.max_per_tx
        && recipients(&old.recipients, &new.recipients)
        && tiers(old, new)
        && old.windows.iter().all(|o| {
            new.windows.iter().any(|n| {
                n.window_ms == o.window_ms
                    && n.max_amount <= o.max_amount
                    && n.max_count <= o.max_count
                    && n.max_fee <= o.max_fee
            })
        })
}

fn recipients(old: &RecipientsV1, new: &RecipientsV1) -> bool {
    match (old, new) {
        (RecipientsV1::Any, _) => true,
        (RecipientsV1::Only(old), RecipientsV1::Only(new)) => subset(new, old),
        _ => false,
    }
}

/// For every amount `x ≤ m = min(new.max_per_tx, old.max_per_tx)`, `new` needs at least as many
/// approvals as `old`. With the `max_per_tx` row (`m = new.max_per_tx`) that covers every amount
/// `new` admits; larger ones it refuses (`AMOUNT_OVER_TX_CAP`).
///
/// Each tier list is a step function: `k(x)` is the approvals of the first tier with `up_to ≥ x`,
/// constant on every interval `(previous up_to, up_to]`. Sort the boundaries of both lists that
/// are `≤ m` into `c_1 < … < c_j`; `c_j = m`, since each list's last tier ends at its
/// `max_per_tx`. No boundary of either list lies strictly between two consecutive `c`, so both
/// functions are constant on `(c_{i−1}, c_i]` and equal their values at `c_i`: comparing at every
/// `c_i` compares at every `x ≤ m`. Both lists are defined there (`c_i ≤` both caps); an undefined
/// value would fail the comparison, so it never reads as tighter.
fn tiers(old: &AssetRuleV1, new: &AssetRuleV1) -> bool {
    let m = new.max_per_tx.min(old.max_per_tx);
    old.tiers
        .iter()
        .chain(&new.tiers)
        .map(|t| t.up_to)
        .filter(|x| *x <= m)
        .all(|x| {
            matches!(
                (new.approvals_for(x), old.approvals_for(x)),
                (Some(n), Some(o)) if n >= o
            )
        })
}
