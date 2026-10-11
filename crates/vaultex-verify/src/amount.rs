//! The few 256-bit operations the kernel needs on [`U256`] (little-endian bytes): checked
//! addition, and multiplication and division by a small integer.
//!
//! ponytail: a local helper instead of a big-integer crate; the kernel needs nothing more.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use vaultex_types::U256;

/// The largest value, 2^256 − 1.
pub(crate) const MAX: U256 = U256([0xff; 32]);

fn limbs(x: U256) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().zip(x.0.chunks_exact(8)) {
        let mut le = [0u8; 8];
        le.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(le);
    }
    out
}

fn from_limbs(limbs: [u64; 4]) -> U256 {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    U256(out)
}

/// `a + b`, or `None` on overflow.
pub(crate) fn checked_add(a: U256, b: U256) -> Option<U256> {
    let mut out = [0u64; 4];
    let mut carry = false;
    for ((o, x), y) in out.iter_mut().zip(limbs(a)).zip(limbs(b)) {
        let (sum, c1) = x.overflowing_add(y);
        let (sum, c2) = sum.overflowing_add(u64::from(carry));
        *o = sum;
        carry = c1 || c2;
    }
    (!carry).then(|| from_limbs(out))
}

/// `a + b`, clamped to [`MAX`].
pub(crate) fn saturating_add(a: U256, b: U256) -> U256 {
    checked_add(a, b).unwrap_or(MAX)
}

/// `a · m`, or `None` on overflow.
pub(crate) fn checked_mul_small(a: U256, m: u64) -> Option<U256> {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for (o, x) in out.iter_mut().zip(limbs(a)) {
        // (2^64 − 1)² + (2^64 − 1) < 2^128, so the checked operations never fail.
        let wide = u128::from(x)
            .checked_mul(u128::from(m))?
            .checked_add(u128::from(carry))?;
        let [lo, hi] = split(wide);
        *o = lo;
        carry = hi;
    }
    (carry == 0).then(|| from_limbs(out))
}

/// `(a / d, a % d)`, or `None` if `d` is 0.
pub(crate) fn div_rem_small(a: U256, d: u64) -> Option<(U256, u64)> {
    let d = u128::from(d);
    let mut out = [0u64; 4];
    let mut rem = 0u64;
    for (o, x) in out.iter_mut().zip(limbs(a)).rev() {
        // `rem < d`, so `cur / d < 2^64`: the quotient limb fits.
        let cur = join(rem, x);
        let [q, _] = split(cur.checked_div(d)?);
        let [r, _] = split(cur.checked_rem(d)?);
        *o = q;
        rem = r;
    }
    Some((from_limbs(out), rem))
}

/// `[low 64 bits, high 64 bits]`.
fn split(x: u128) -> [u64; 2] {
    // Truncating casts are the point here; `checked_shr(64)` on a u128 never fails.
    [x as u64, x.checked_shr(64).unwrap_or(0) as u64]
}

/// `hi · 2^64 + lo`.
fn join(hi: u64, lo: u64) -> u128 {
    u128::from(hi).checked_shl(64).unwrap_or(0) | u128::from(lo)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn u(n: u64) -> U256 {
        U256::from(n)
    }

    /// 2^(64·limb) · n.
    fn shifted(n: u64, limb: usize) -> U256 {
        let mut l = [0u64; 4];
        l[limb] = n;
        from_limbs(l)
    }

    #[test]
    fn add_carries_across_limbs_and_detects_overflow() {
        assert_eq!(checked_add(u(2), u(3)), Some(u(5)));
        assert_eq!(checked_add(u(u64::MAX), u(1)), Some(shifted(1, 1)));
        assert_eq!(
            checked_add(shifted(u64::MAX, 3), shifted(1, 3)),
            None,
            "carry out of the top limb"
        );
        assert_eq!(checked_add(MAX, u(1)), None);
        assert_eq!(checked_add(MAX, u(0)), Some(MAX));
        assert_eq!(saturating_add(MAX, u(7)), MAX);
    }

    #[test]
    fn mul_small_carries_and_detects_overflow() {
        assert_eq!(checked_mul_small(u(6), 7), Some(u(42)));
        assert_eq!(
            checked_mul_small(u(u64::MAX), 2),
            Some(from_limbs([u64::MAX - 1, 1, 0, 0]))
        );
        assert_eq!(checked_mul_small(shifted(1 << 63, 3), 2), None);
        assert_eq!(checked_mul_small(MAX, 1), Some(MAX));
        assert_eq!(checked_mul_small(MAX, 0), Some(u(0)));
    }

    #[test]
    fn div_rem_small_is_long_division() {
        assert_eq!(div_rem_small(u(43), 7), Some((u(6), 1)));
        assert_eq!(div_rem_small(u(5), 0), None);
        // (2^64 · 5 + 3) / 2 = 2^64 · 2 + 2^63 + 1, remainder 1.
        assert_eq!(
            div_rem_small(from_limbs([3, 5, 0, 0]), 2),
            Some((from_limbs([(1 << 63) + 1, 2, 0, 0]), 1))
        );
        // MAX = 3 · 5 · 17 · 257 · 641 · 65537 · … is divisible by 255.
        let (q, r) = div_rem_small(MAX, 255).unwrap();
        assert_eq!(r, 0);
        assert_eq!(checked_mul_small(q, 255), Some(MAX));
    }

    #[test]
    fn split_and_join_round_trip() {
        let x = (7u128 << 64) | 9;
        assert_eq!(split(x), [9, 7]);
        assert_eq!(join(7, 9), x);
    }
}
