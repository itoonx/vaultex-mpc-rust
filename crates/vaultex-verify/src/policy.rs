//! Policy bundle v1 (ROADMAP M6 #3): the quorum-signed file that says what a signer may agree to
//! and who may change it. Each signer installs the bundle as a file of its own (ADR-11); there is
//! no remote governance service.
//!
//! # Format
//!
//! - **Body:** [`PolicyBundleV1`], BCS with field order = declaration order. Its digest is
//!   `tagged_digest("VAULTEX/POLICY-BUNDLE/v1", body)` ([`PolicyBundleV1::digest`]). Versions are
//!   sequential from 1, and each body names the digest of the bundle it replaces (`parent`; all
//!   zeros for version 1), so a signer's policy history is a hash chain (THREAT_MODEL_V2 TH15).
//! - **Signed bundle:** [`SignedPolicyBundleV1`], the body followed by `(admin key, signature)`
//!   pairs, BCS, at most [`MAX_BUNDLE_BYTES`].
//! - **Signatures** are Ed25519 over the 32-byte digest, checked with strict verification (RFC 8032
//!   with canonical S, and no small-order key or R). A signature counts only if its key is in the
//!   judging admin set (step 4), and each such key counts once however often it appears. A
//!   signature by a judging key that does not verify refuses the bundle; one by any other key is
//!   ignored.
//! - **Amounts** are [`U256`] base units. The bundle pins each wallet's network, address and
//!   permission id, and each asset's token contract and decimals. Anything it does not list is
//!   refused. Velocity windows are this signer's own limits ([`WindowLimit`]); admin tooling sizes
//!   them from a group budget with [`per_signer_cap`](crate::velocity::per_signer_cap), rounding
//!   up (`docs/TASKS.md` §3, Kernel defaults: velocity bound rounded up).
//!
//! # Verification order
//!
//! [`PolicyState::offer`] checks a candidate in this order and reports the first failure
//! ([`PolicyRefusal`] variant, wire code in brackets):
//!
//! 1. **Decode.** At most [`MAX_BUNDLE_BYTES`], then exactly the canonical BCS of a
//!    [`SignedPolicyBundleV1`]: `Malformed` [MALFORMED].
//! 2. **Content**, in this order [BUNDLE_INVALID]:
//!    1. admins: `1 ≤ threshold ≤` number of keys (`AdminThreshold`);
//!    2. the admin, initiator and approver key lists, in that order: strictly ascending
//!       (`Unsorted`), and every key a valid point not of small order (`WeakKey`);
//!    3. `loosen_delay_ms ≥` [`MIN_LOOSEN_DELAY_MS`] (`DelayTooShort`) and `≤`
//!       [`MAX_LOOSEN_DELAY_MS`] (`DelayTooLong`);
//!    4. wallets strictly ascending by id (`Unsorted`); then each wallet in turn: its network is a
//!       TRON network (`NotTron`); its address is `0x41 ‖ 20 bytes` (`AddressShape`); every token
//!       contract is `0x41 ‖ 20 bytes` (`AddressShape`); assets strictly ascending, TRX first and
//!       tokens by contract (`Unsorted`); then each asset in turn: decimals 6 for TRX and at most
//!       77 for a token (`Decimals`); listed recipients `0x41 ‖ 20 bytes` (`AddressShape`) and
//!       strictly ascending (`Unsorted`); tiers strictly ascending by `up_to` (`Unsorted`), the
//!       last at `max_per_tx` (`LastTier`); at least one window (`NoWindows`: velocity refuses
//!       every charge without one, so the only way to block an asset is to drop its rule), windows
//!       strictly ascending by length (`Unsorted`);
//!    5. `allows_zero_approval` is true exactly when some tier needs 0 approvals
//!       (`ZeroApprovalFlag`).
//! 3. **Sequence.** Let `h` be the highest version this signer has accepted: the pending bundle's,
//!    else the effective one's, else 0. A version `≤ h` is `Rollback` [BUNDLE_ROLLBACK]; any other
//!    than `h + 1` is `VersionGap` [BUNDLE_INVALID]. The `parent` must be the digest of the bundle
//!    effective at `now` (all zeros when none): `ParentMismatch` [BUNDLE_ROLLBACK, a fork]. So a
//!    genesis is version 1 with a zero parent.
//! 4. **Judge.** The admin set of the bundle effective at `now`. With none installed it is the
//!    genesis pin configured at setup, and the candidate's own admin set must equal the pin:
//!    `GenesisAdmins` [BUNDLE_INVALID]. A candidate never judges itself.
//! 5. **Class.** A tightening if a bundle is installed and [`tightens`]`(effective, candidate)`
//!    (table below); otherwise a loosening, genesis included.
//! 6. **Signatures.** Every signature by a judging key verifies over the candidate's digest:
//!    `BadSignature` [BUNDLE_INVALID].
//! 7. **Quorum.** The distinct judging keys with a signature number at least 1 for a tightening
//!    with `allows_zero_approval` false, and at least the judge's threshold M otherwise: `Quorum`
//!    [BUNDLE_INVALID].
//! 8. **Record.** For a loosening, the end of its time lock (receipt time plus the active
//!    bundle's delay) must fit in a `u64`: `LockOverflow` [CLOCK_UNTRUSTED]. Then
//!    [`PolicyStore::offer`] replaces the installed file atomically and durably before it answers:
//!    `Store` [STATE_WRITE_FAILED]. A refusal at any step changes nothing; after a failed write
//!    the store refuses every offer until it is reopened, and the file is the truth.
//!
//! # States
//!
//! ```text
//! NONE                    ── genesis, M-of-N of the pin ───────────────────► ACTIVE(a)
//! ACTIVE(a) [+ PENDING]   ── tightening, 1-of-N of a (M if zero approval) ─► ACTIVE(b)              (pending dropped)
//! ACTIVE(a) [+ PENDING]   ── loosening, M-of-N of a ───────────────────────► ACTIVE(a) + PENDING(b, r = now)
//! ACTIVE(a) + PENDING(b, r) ── now ≥ r + a.loosen_delay_ms ───────────────► ACTIVE(b)
//! ```
//!
//! - `r` is the time this signer recorded receiving `b`: its own clock at the offer, written to the
//!   installed file together with `b`. The body carries no time at all.
//! - The delay is the active bundle's, so a loosening cannot shorten its own time lock.
//! - The last transition needs no write: the effective bundle is a function of the installed file
//!   and `now`, and the next offer writes the promoted state.
//! - A new loosening replaces the pending one and its time lock starts again. A tightening drops
//!   it, so any single admin can stop a pending loosening.
//!
//! **Using the policy.** [`PolicyState::for_version`] gives the bundle a request names: none
//! installed is `NoPolicy` [NO_POLICY]; the pending version before its lock ends is `NotEffective`
//! [BUNDLE_NOT_EFFECTIVE]; any version but the effective one is `VersionMismatch`
//! [POLICY_VERSION_MISMATCH]. On that bundle, [`VerifiedBundle::tron_ctx`] builds the decoder's
//! context and [`VerifiedBundle::check_intent`] applies the asset rules, each checking in this
//! order: the wallet is listed (`UnknownWallet` [UNKNOWN_WALLET]); the network is the wallet's
//! (`NetworkMismatch` [NETWORK_MISMATCH]); then, for an intent, the asset has a rule
//! (`AssetNotAllowed` [ASSET_NOT_ALLOWED]), `amount ≤ max_per_tx` (`AmountOverCap`
//! [AMOUNT_OVER_TX_CAP]) and the recipient is allowed (`RecipientNotAllowed`
//! [RECIPIENT_NOT_ALLOWED]).
//!
//! # Tightening
//!
//! `new` tightens `old` only if every row holds; anything not proved tighter is a loosening.
//!
//! | Field | `new` tightens `old` when |
//! |---|---|
//! | `admins` | equal. A stricter admin set is still a loosening: raising M or dropping admins lets one admin lock the quorum out |
//! | `loosen_delay_ms` | `new ≥ old` |
//! | `allows_zero_approval` | not compared (it follows the tiers); when true, the bundle needs M-of-N even as a tightening |
//! | `initiators`, `approvers` | `new ⊆ old` |
//! | `breaker.refusal_threshold` | `new ≤ old`, where 0 counts as 1 |
//! | `breaker.refusal_window_ms` | `new ≥ old` |
//! | `breaker.pause_on_cap_hit` | unchanged, or false → true |
//! | `breaker.max_clock_skew_ms` | `new ≤ old` |
//! | `wallets` | each new wallet has an old one with the same `wallet_id`, `network`, `address` and `permission_id` |
//! | `wallet.max_fee_limit_sun`, `wallet.max_validity_ms` | `new ≤ old` |
//! | `wallet.assets` | each new rule has an old rule for the same `asset` with the same `decimals` |
//! | `asset.max_per_tx` | `new ≤ old` |
//! | `asset.recipients` | old is `Any`, or both are `Only` and `new ⊆ old` |
//! | `asset.tiers` | for every amount up to both caps, new approvals `≥` old approvals |
//! | `asset.windows` | every old window length is in new, with `max_amount`, `max_count` and `max_fee` each `≤` (extra windows are allowed). No old window means nothing is allowed (step 2 refuses it): only no new window tightens that |
//! | `version`, `parent` | not compared (step 3) |
//!
//! # Limits
//!
//! - The installed file is local state, trusted like the receipt log and the velocity store. On
//!   open it is decoded strictly, both bundles pass step 2 again, and the pending bundle is
//!   checked against the active one's admins again. The active bundle's signatures were checked at
//!   install, against an admin set the file no longer holds. A deleted file reopens genesis; the
//!   receipt log's `POLICY_ROLLBACK` rule shows the rollback.
//! - The time lock is only as good as the signer's clock: a clock pushed forward shortens it, and
//!   so does a clock that is behind when a loosening arrives. A promotion is recorded only by the
//!   next offer, so a clock moved back below the end of a lock makes the earlier bundle effective
//!   again until then. The caller must pass its own clock through the breaker's rollback check.
//! - Any single admin can stop a pending loosening by installing a tightening first, including an
//!   admin-set rotation that would remove that admin (TH16). Whether cancelling an admin-set change
//!   should need M-of-N is an open governance decision (ADR-11).
//! - Versions are strictly sequential, so every signer must receive every bundle in order,
//!   including loosenings that a later tightening cancelled.
//! - The decoder clamps a fee limit or validity above its hard ceilings.
//! - No receipt records an install yet: receipts record decisions on requests only.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod file;
mod tighten;

pub use file::PolicyStore;
pub use tighten::tightens;

use std::cmp::Ordering;
use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use vaultex_types::{
    from_canonical_strict, tag, tagged_digest, Address, AssetId, ChainId, Ed25519Pub, IntentV1,
    NetworkId, Refusal, RefusalCode, Sig64, TxHash, WalletId, U256,
};

use crate::breaker::BreakerConfig;
use crate::tron::TronDecodeCtx;
use crate::velocity::{StoreError, WindowLimit};

/// Largest signed bundle [`PolicyState::offer`] reads, checked before decoding. An active and a
/// pending bundle together stay under the contracts' message cap, so the installed file decodes
/// strictly too.
pub const MAX_BUNDLE_BYTES: usize = 60 * 1024;
/// Shortest time lock a bundle may set on the loosening after it: 24 hours.
pub const MIN_LOOSEN_DELAY_MS: u64 = 86_400_000;
/// Longest time lock a bundle may set: 30 days. Without a bound one admin could tighten the delay
/// so far that no loosening, not even an admin rotation, ever takes effect.
// ponytail: provisional until the owner confirms the value.
pub const MAX_LOOSEN_DELAY_MS: u64 = 30 * 86_400_000;
/// 1 TRX = 10^6 sun.
const TRX_DECIMALS: u8 = 6;
/// 10^77 is the largest power of ten below 2^256, so every token amount has a decimal rendering.
const MAX_TOKEN_DECIMALS: u8 = 77;

/// The admin keys and the threshold M that judge the next bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSetV1 {
    /// M, the signatures a loosening needs: `1 ≤ threshold ≤ keys.len()`.
    pub threshold: u8,
    /// The N admin keys, strictly ascending.
    pub keys: Vec<Ed25519Pub>,
}

/// The body of a policy bundle: what the signer may agree to, and who may change it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundleV1 {
    /// One more than the highest version this signer accepted before; 1 for a genesis.
    pub version: u64,
    /// [`digest`](Self::digest) of the bundle in force when this one is offered; all zeros for a
    /// genesis.
    pub parent: [u8; 32],
    /// Who judges the next bundle.
    pub admins: AdminSetV1,
    /// The time lock on the next loosening, in milliseconds, from [`MIN_LOOSEN_DELAY_MS`] to
    /// [`MAX_LOOSEN_DELAY_MS`].
    pub loosen_delay_ms: u64,
    /// States that some tier needs no approval: true exactly when one does.
    pub allows_zero_approval: bool,
    /// Keys that may initiate a transfer, strictly ascending.
    pub initiators: Vec<Ed25519Pub>,
    /// Keys whose approvals count, strictly ascending.
    pub approvers: Vec<Ed25519Pub>,
    /// The circuit breaker's settings; `max_clock_skew_ms` also bounds transaction timestamps.
    pub breaker: BreakerConfig,
    /// The wallets the signer may sign for, strictly ascending by id. Any other is refused.
    pub wallets: Vec<WalletV1>,
}

/// One wallet and its network facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletV1 {
    /// The wallet (key group).
    pub wallet_id: WalletId,
    /// The one network its key is pinned to; a TRON network in v1.
    pub network: NetworkId,
    /// Its address, `0x41 ‖ 20 bytes`.
    pub address: Address,
    /// The permission it signs under: 0 (owner) or an active permission id.
    pub permission_id: u8,
    /// The largest `fee_limit`, in sun.
    pub max_fee_limit_sun: u64,
    /// The longest validity (`expiration − now`), in milliseconds.
    pub max_validity_ms: u64,
    /// The assets it may move: TRX first, then tokens ascending by contract. Any other is refused.
    pub assets: Vec<AssetRuleV1>,
}

/// What a wallet may do with one asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRuleV1 {
    /// TRX, or a TRC-20 token by its contract address (`0x41 ‖ 20 bytes`).
    pub asset: AssetId,
    /// The asset's decimals, for display: 6 for TRX, at most 77 for a token.
    pub decimals: u8,
    /// The largest amount of one transfer, in base units.
    pub max_per_tx: U256,
    /// Who may receive it.
    pub recipients: RecipientsV1,
    /// Approvals by amount, strictly ascending by `up_to`; the last ends at `max_per_tx`.
    pub tiers: Vec<TierV1>,
    /// This signer's velocity windows, strictly ascending by length.
    pub windows: Vec<WindowLimit>,
}

/// Who may receive an asset.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientsV1 {
    /// Any address.
    Any,
    /// Only these addresses (`0x41 ‖ 20 bytes`, strictly ascending).
    Only(Vec<Address>),
}

/// An approval tier: amounts above the previous tier's `up_to`, up to and including this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierV1 {
    /// The largest amount of the tier, in base units.
    pub up_to: U256,
    /// The approvals it needs; 0 only in a bundle that states [`PolicyBundleV1::allows_zero_approval`].
    pub approvals: u8,
}

/// One admin's signature on a bundle digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSignatureV1 {
    /// The admin key.
    pub key: Ed25519Pub,
    /// Ed25519 over [`PolicyBundleV1::digest`].
    pub signature: Sig64,
}

/// A bundle as distributed and installed: the body and its admin signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyBundleV1 {
    /// What was signed.
    pub body: PolicyBundleV1,
    /// The signatures, in any order.
    pub signatures: Vec<AdminSignatureV1>,
}

impl PolicyBundleV1 {
    /// `tagged_digest(POLICY_BUNDLE_V1, self)`: the 32 bytes each admin signs.
    pub fn digest(&self) -> [u8; 32] {
        tagged_digest(tag::POLICY_BUNDLE_V1, self)
    }
}

impl AssetRuleV1 {
    /// The approvals `amount` needs: those of the first tier with `up_to ≥ amount`. `None` above
    /// `max_per_tx`.
    pub fn approvals_for(&self, amount: U256) -> Option<u8> {
        self.tiers
            .iter()
            .find(|t| t.up_to >= amount)
            .map(|t| t.approvals)
    }
}

/// Why a bundle was not installed, or a request has no policy to go by: one variant per check in
/// the module docs. [`code`](Self::code) maps each to the coarser wire registry.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRefusal {
    /// Larger than [`MAX_BUNDLE_BYTES`], or not exactly the canonical encoding of a signed bundle
    /// (or of the installed file).
    Malformed,
    /// The admin threshold is 0, or above the number of admin keys.
    AdminThreshold,
    /// A list is not strictly ascending: out of order, or with a duplicate.
    Unsorted,
    /// A key is not a valid Ed25519 point, or is of small order.
    WeakKey,
    /// `loosen_delay_ms` is below [`MIN_LOOSEN_DELAY_MS`].
    DelayTooShort,
    /// `loosen_delay_ms` is above [`MAX_LOOSEN_DELAY_MS`].
    DelayTooLong,
    /// A wallet's network is not a TRON network.
    NotTron,
    /// A wallet, token or recipient address is not `0x41 ‖ 20 bytes`.
    AddressShape,
    /// TRX with decimals other than 6, or a token with more than 77.
    Decimals,
    /// The last tier does not end at `max_per_tx`, or there is no tier.
    LastTier,
    /// An asset rule without a velocity window.
    NoWindows,
    /// `allows_zero_approval` does not match the tiers.
    ZeroApprovalFlag,
    /// The version is not greater than every version accepted before.
    Rollback,
    /// The version skips ahead: it is not the highest version accepted plus 1.
    VersionGap,
    /// `parent` is not the digest of the bundle in force (a fork).
    ParentMismatch,
    /// The time lock of a loosening would end beyond the clock's range.
    LockOverflow,
    /// A first bundle whose admin set is not the genesis pin.
    GenesisAdmins,
    /// A signature by a judging admin key does not verify.
    BadSignature,
    /// Too few distinct judging admin keys signed.
    Quorum,
    /// The installed file could not be locked, read or written.
    Store(StoreError),
    /// No bundle is installed.
    NoPolicy,
    /// The request names a version other than the effective one.
    VersionMismatch,
    /// The request names the pending loosening before its time lock ends.
    NotEffective,
    /// The wallet is not in the bundle.
    UnknownWallet,
    /// The network is not the wallet's.
    NetworkMismatch,
    /// The wallet has no rule for the asset.
    AssetNotAllowed,
    /// The amount is above the asset's `max_per_tx`.
    AmountOverCap,
    /// The recipient is not on the asset's list.
    RecipientNotAllowed,
}

impl PolicyRefusal {
    /// The wire refusal code (registry in `vaultex-types`).
    pub fn code(self) -> RefusalCode {
        use PolicyRefusal as R;
        match self {
            R::Malformed => RefusalCode::MALFORMED,
            // ponytail: the registry describes BUNDLE_INVALID as "signatures or quorum"; v1 also
            // uses it for the content rules. Widening that text is a WS-03 request.
            R::AdminThreshold
            | R::Unsorted
            | R::WeakKey
            | R::DelayTooShort
            | R::DelayTooLong
            | R::NotTron
            | R::AddressShape
            | R::Decimals
            | R::LastTier
            | R::NoWindows
            | R::ZeroApprovalFlag
            | R::VersionGap
            | R::GenesisAdmins
            | R::BadSignature
            | R::Quorum => RefusalCode::BUNDLE_INVALID,
            // KAT plan KAT-12: a fork with the wrong parent digest is a rollback.
            R::Rollback | R::ParentMismatch => RefusalCode::BUNDLE_ROLLBACK,
            R::LockOverflow => RefusalCode::CLOCK_UNTRUSTED,
            R::Store(_) => RefusalCode::STATE_WRITE_FAILED,
            R::NoPolicy => RefusalCode::NO_POLICY,
            R::VersionMismatch => RefusalCode::POLICY_VERSION_MISMATCH,
            R::NotEffective => RefusalCode::BUNDLE_NOT_EFFECTIVE,
            R::UnknownWallet => RefusalCode::UNKNOWN_WALLET,
            R::NetworkMismatch => RefusalCode::NETWORK_MISMATCH,
            R::AssetNotAllowed => RefusalCode::ASSET_NOT_ALLOWED,
            R::AmountOverCap => RefusalCode::AMOUNT_OVER_TX_CAP,
            R::RecipientNotAllowed => RefusalCode::RECIPIENT_NOT_ALLOWED,
        }
    }

    /// The wire refusal.
    pub fn refusal(self) -> Refusal {
        Refusal {
            code: self.code(),
            rule_index: None,
        }
    }
}

/// A bundle that passed steps 1 and 2, with its digest and the decoder's views. Only this module
/// makes one: from an offer, or from the installed file.
#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    signed: SignedPolicyBundleV1,
    digest: [u8; 32],
    /// One per wallet, in the same order.
    views: Vec<WalletView>,
}

#[derive(Clone, Debug)]
struct WalletView {
    address: [u8; 21],
    tokens: Vec<[u8; 21]>,
}

impl VerifiedBundle {
    /// Step 2, in the order of the module docs.
    fn check(signed: SignedPolicyBundleV1) -> Result<Self, PolicyRefusal> {
        use PolicyRefusal as R;
        let b = &signed.body;
        if b.admins.threshold == 0 || usize::from(b.admins.threshold) > b.admins.keys.len() {
            return Err(R::AdminThreshold);
        }
        for keys in [&b.admins.keys, &b.initiators, &b.approvers] {
            key_list(keys)?;
        }
        if b.loosen_delay_ms < MIN_LOOSEN_DELAY_MS {
            return Err(R::DelayTooShort);
        }
        if b.loosen_delay_ms > MAX_LOOSEN_DELAY_MS {
            return Err(R::DelayTooLong);
        }
        if !ascending(&b.wallets, |x, y| {
            x.wallet_id.as_str().cmp(y.wallet_id.as_str())
        }) {
            return Err(R::Unsorted);
        }
        let views = b
            .wallets
            .iter()
            .map(wallet_view)
            .collect::<Result<_, _>>()?;
        let zero = b
            .wallets
            .iter()
            .flat_map(|w| &w.assets)
            .flat_map(|a| &a.tiers)
            .any(|t| t.approvals == 0);
        if b.allows_zero_approval != zero {
            return Err(R::ZeroApprovalFlag);
        }
        let digest = b.digest();
        Ok(Self {
            signed,
            digest,
            views,
        })
    }

    /// Steps 6 and 7: how many distinct keys of `judge` signed, each signature verified.
    fn signers(&self, judge: &AdminSetV1) -> Result<usize, PolicyRefusal> {
        let mut counted = BTreeSet::new();
        for s in &self.signed.signatures {
            if !judge.keys.contains(&s.key) {
                continue;
            }
            if !verify_strict(&s.key, &self.digest, &s.signature) {
                return Err(PolicyRefusal::BadSignature);
            }
            counted.insert(s.key.0);
        }
        Ok(counted.len())
    }

    /// The body.
    pub fn body(&self) -> &PolicyBundleV1 {
        &self.signed.body
    }

    /// The signed bundle, as installed (for evidence packs).
    pub fn signed(&self) -> &SignedPolicyBundleV1 {
        &self.signed
    }

    /// The body's version.
    pub fn version(&self) -> u64 {
        self.signed.body.version
    }

    /// [`PolicyBundleV1::digest`], as receipts name it.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The TRON decoder's context for a request on `wallet_id` and `network`: the wallet's
    /// address, permission id, token allowlist, fee and validity bounds, and the clock skew bound,
    /// all from this bundle.
    pub fn tron_ctx(
        &self,
        wallet_id: &WalletId,
        network: NetworkId,
        now_ms: u64,
        claimed_txid: Option<TxHash>,
    ) -> Result<TronDecodeCtx<'_>, PolicyRefusal> {
        let (wallet, view) = self.wallet(wallet_id)?;
        if network != wallet.network {
            return Err(PolicyRefusal::NetworkMismatch);
        }
        Ok(TronDecodeCtx {
            wallet_id: &wallet.wallet_id,
            network: wallet.network,
            wallet_address: view.address,
            permission_id: wallet.permission_id,
            trc20_allowlist: &view.tokens,
            now_ms,
            max_validity_ms: wallet.max_validity_ms,
            max_fee_limit_sun: wallet.max_fee_limit_sun,
            max_clock_skew_ms: self.body().breaker.max_clock_skew_ms,
            claimed_txid,
        })
    }

    /// Applies the asset rules to a decoded intent and returns the rule that admits it (its tiers
    /// and windows apply next).
    pub fn check_intent(&self, intent: &IntentV1) -> Result<&AssetRuleV1, PolicyRefusal> {
        use PolicyRefusal as R;
        let (wallet, _) = self.wallet(&intent.wallet_id)?;
        if intent.network != wallet.network {
            return Err(R::NetworkMismatch);
        }
        let rule = wallet
            .assets
            .iter()
            .find(|a| a.asset == intent.asset)
            .ok_or(R::AssetNotAllowed)?;
        if intent.amount > rule.max_per_tx {
            return Err(R::AmountOverCap);
        }
        let allowed = match &rule.recipients {
            RecipientsV1::Any => true,
            RecipientsV1::Only(list) => list.contains(&intent.recipient),
        };
        if !allowed {
            return Err(R::RecipientNotAllowed);
        }
        Ok(rule)
    }

    fn wallet(&self, id: &WalletId) -> Result<(&WalletV1, &WalletView), PolicyRefusal> {
        self.body()
            .wallets
            .iter()
            .zip(&self.views)
            .find(|(w, _)| w.wallet_id == *id)
            .ok_or(PolicyRefusal::UnknownWallet)
    }
}

/// Step 2 for one wallet.
fn wallet_view(wallet: &WalletV1) -> Result<WalletView, PolicyRefusal> {
    use PolicyRefusal as R;
    if wallet.network.chain() != ChainId::TRON {
        return Err(R::NotTron);
    }
    let address = tron_address(&wallet.address)?;
    let tokens = wallet
        .assets
        .iter()
        .map(|a| token(&a.asset))
        .collect::<Result<Vec<_>, _>>()?;
    if !ascending(&tokens, Ord::cmp) {
        return Err(R::Unsorted);
    }
    for rule in &wallet.assets {
        asset_rule(rule)?;
    }
    Ok(WalletView {
        address,
        tokens: tokens.into_iter().flatten().collect(),
    })
}

/// Step 2 for one asset rule (its contract was checked by [`token`]).
fn asset_rule(rule: &AssetRuleV1) -> Result<(), PolicyRefusal> {
    use PolicyRefusal as R;
    let decimals_ok = if matches!(rule.asset, AssetId::Native) {
        rule.decimals == TRX_DECIMALS
    } else {
        rule.decimals <= MAX_TOKEN_DECIMALS
    };
    if !decimals_ok {
        return Err(R::Decimals);
    }
    if let RecipientsV1::Only(list) = &rule.recipients {
        for recipient in list {
            tron_address(recipient)?;
        }
        if !ascending(list, |x, y| x.0.cmp(&y.0)) {
            return Err(R::Unsorted);
        }
    }
    if !ascending(&rule.tiers, |x, y| x.up_to.cmp(&y.up_to)) {
        return Err(R::Unsorted);
    }
    if rule.tiers.last().map(|t| t.up_to) != Some(rule.max_per_tx) {
        return Err(R::LastTier);
    }
    if rule.windows.is_empty() {
        return Err(R::NoWindows);
    }
    if !ascending(&rule.windows, |x, y| x.window_ms.cmp(&y.window_ms)) {
        return Err(R::Unsorted);
    }
    Ok(())
}

/// A key list: strictly ascending, every key a valid point not of small order.
fn key_list(keys: &[Ed25519Pub]) -> Result<(), PolicyRefusal> {
    if !ascending(keys, |x, y| x.0.cmp(&y.0)) {
        return Err(PolicyRefusal::Unsorted);
    }
    if !keys
        .iter()
        .all(|k| VerifyingKey::from_bytes(&k.0).is_ok_and(|vk| !vk.is_weak()))
    {
        return Err(PolicyRefusal::WeakKey);
    }
    Ok(())
}

/// An asset's token contract; `None` for TRX.
fn token(asset: &AssetId) -> Result<Option<[u8; 21]>, PolicyRefusal> {
    match asset {
        AssetId::Native => Ok(None),
        AssetId::Contract(address) => tron_address(address).map(Some),
        // An asset kind this version does not know does not decode; refuse it all the same.
        _ => Err(PolicyRefusal::AddressShape),
    }
}

fn tron_address(address: &Address) -> Result<[u8; 21], PolicyRefusal> {
    match <[u8; 21]>::try_from(address.0.as_slice()) {
        Ok(a @ [0x41, ..]) => Ok(a),
        _ => Err(PolicyRefusal::AddressShape),
    }
}

/// Strictly ascending under `cmp`: in order, and no two equal.
fn ascending<T>(items: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> bool {
    items
        .iter()
        .zip(items.iter().skip(1))
        .all(|(a, b)| cmp(a, b) == Ordering::Less)
}

/// Strict Ed25519 verification (RFC 8032 with canonical S, no small-order key or R): the one rule
/// for bundle signatures.
fn verify_strict(key: &Ed25519Pub, msg: &[u8], sig: &Sig64) -> bool {
    VerifyingKey::from_bytes(&key.0).is_ok_and(|vk| {
        vk.verify_strict(msg, &Signature::from_bytes(&sig.0))
            .is_ok()
    })
}

/// What a signer has installed: the active bundle and at most one pending loosening. Pure;
/// [`PolicyStore`] keeps it in a file.
#[derive(Clone, Debug, Default)]
pub struct PolicyState {
    active: Option<VerifiedBundle>,
    pending: Option<Pending>,
}

#[derive(Clone, Debug)]
struct Pending {
    bundle: VerifiedBundle,
    /// This signer's clock when it recorded the bundle.
    received_at_ms: u64,
    /// The end of the time lock.
    effective_at_ms: u64,
}

impl Pending {
    /// A loosening this signer received at `received_at_ms`, in force once `active`'s time lock
    /// has run from then. The end must fit in a `u64` (step 8).
    fn new(
        bundle: VerifiedBundle,
        received_at_ms: u64,
        active: &VerifiedBundle,
    ) -> Result<Self, PolicyRefusal> {
        let effective_at_ms = received_at_ms
            .checked_add(active.body().loosen_delay_ms)
            .ok_or(PolicyRefusal::LockOverflow)?;
        Ok(Self {
            bundle,
            received_at_ms,
            effective_at_ms,
        })
    }
}

/// How [`PolicyState::offer`] installed a bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer {
    /// In force now: a genesis or a tightening.
    Effective {
        /// Its version.
        version: u64,
        /// Its digest.
        digest: [u8; 32],
    },
    /// A loosening: recorded, and in force from `effective_at_ms`.
    Pending {
        /// Its version.
        version: u64,
        /// Its digest.
        digest: [u8; 32],
        /// When its time lock ends, in milliseconds since the Unix epoch.
        effective_at_ms: u64,
    },
}

impl PolicyState {
    /// Steps 1 to 8 (up to the write) for the signed bundle `bytes`, received at `now_ms` (this
    /// signer's clock).
    /// Returns the state to record and how the bundle was installed; `self` is unchanged.
    /// `genesis` judges the first bundle.
    pub fn offer(
        &self,
        genesis: &AdminSetV1,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<(Self, Offer), PolicyRefusal> {
        use PolicyRefusal as R;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(R::Malformed);
        }
        let signed =
            from_canonical_strict::<SignedPolicyBundleV1>(bytes).map_err(|_| R::Malformed)?;
        let candidate = VerifiedBundle::check(signed)?;

        let base = self.at(now_ms);
        let highest = base
            .pending
            .as_ref()
            .map(|p| &p.bundle)
            .or(base.active.as_ref())
            .map_or(0, VerifiedBundle::version);
        if candidate.version() <= highest {
            return Err(R::Rollback);
        }
        if Some(candidate.version()) != highest.checked_add(1) {
            return Err(R::VersionGap);
        }
        let parent = base.active.as_ref().map_or([0; 32], VerifiedBundle::digest);
        if candidate.body().parent != parent {
            return Err(R::ParentMismatch);
        }
        let (judge, tighter) = match &base.active {
            Some(active) => (
                &active.body().admins,
                tightens(active.body(), candidate.body()),
            ),
            None if candidate.body().admins == *genesis => (genesis, false),
            None => return Err(R::GenesisAdmins),
        };
        let quorum = if tighter && !candidate.body().allows_zero_approval {
            1
        } else {
            judge.threshold
        };
        if candidate.signers(judge)? < usize::from(quorum) {
            return Err(R::Quorum);
        }

        let (version, digest) = (candidate.version(), candidate.digest);
        Ok(match base.active {
            Some(active) if !tighter => {
                let pending = Pending::new(candidate, now_ms, &active)?;
                let effective_at_ms = pending.effective_at_ms;
                let next = Self {
                    active: Some(active),
                    pending: Some(pending),
                };
                let offer = Offer::Pending {
                    version,
                    digest,
                    effective_at_ms,
                };
                (next, offer)
            }
            _ => {
                let next = Self {
                    active: Some(candidate),
                    pending: None,
                };
                (next, Offer::Effective { version, digest })
            }
        })
    }

    /// The bundle in force at `now_ms`, if any.
    pub fn effective(&self, now_ms: u64) -> Option<&VerifiedBundle> {
        match (&self.active, &self.pending) {
            (Some(_), Some(p)) if now_ms >= p.effective_at_ms => Some(&p.bundle),
            (active, _) => active.as_ref(),
        }
    }

    /// The bundle a request naming `version` goes by at `now_ms`.
    pub fn for_version(&self, version: u64, now_ms: u64) -> Result<&VerifiedBundle, PolicyRefusal> {
        let effective = self.effective(now_ms).ok_or(PolicyRefusal::NoPolicy)?;
        if effective.version() == version {
            return Ok(effective);
        }
        match &self.pending {
            Some(p) if p.bundle.version() == version => Err(PolicyRefusal::NotEffective),
            _ => Err(PolicyRefusal::VersionMismatch),
        }
    }

    /// The recorded loosening and the end of its time lock, if any (for status and alerting).
    pub fn pending(&self) -> Option<(&VerifiedBundle, u64)> {
        let p = self.pending.as_ref()?;
        Some((&p.bundle, p.effective_at_ms))
    }

    /// The state at `now_ms`: a pending bundle whose time lock has ended is active.
    fn at(&self, now_ms: u64) -> Self {
        match (&self.active, &self.pending) {
            (Some(_), Some(p)) if now_ms >= p.effective_at_ms => Self {
                active: Some(p.bundle.clone()),
                pending: None,
            },
            _ => self.clone(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1 TEST 1 and TEST 2 through the entry point bundle signatures use, and a
    /// one-bit change of each that it must refuse.
    #[test]
    fn rfc8032_vectors_verify_strictly() {
        let cases = [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ];
        for (key, msg, sig) in cases {
            let key = Ed25519Pub(hex(key).try_into().unwrap());
            let (msg, sig) = (hex(msg), Sig64(hex(sig).try_into().unwrap()));
            assert!(verify_strict(&key, &msg, &sig));
            let mut bad = sig;
            bad.0[0] ^= 1;
            assert!(!verify_strict(&key, &msg, &bad));
            let mut longer = msg.clone();
            longer.push(0);
            assert!(!verify_strict(&key, &longer, &sig));
        }
    }

    /// "Taming the many EdDSAs" (Chalkias, Garillot, Nikolaenko; ed25519-speccheck `cases.txt`,
    /// test 3, index 2 in the paper): a mixed-order key and a small-order R. Cofactorless
    /// verification accepts it; the bundle signature rule must refuse it.
    #[test]
    fn speccheck_small_order_r_is_refused() {
        use ed25519_dalek::Verifier;
        let key = Ed25519Pub(
            hex("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43")
                .try_into()
                .unwrap(),
        );
        let msg = hex("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab");
        let sig = Sig64(
            hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e")
                .try_into()
                .unwrap(),
        );
        let vk = VerifyingKey::from_bytes(&key.0).unwrap();
        assert!(!vk.is_weak(), "the key alone passes step 2");
        assert!(
            vk.verify(&msg, &Signature::from_bytes(&sig.0)).is_ok(),
            "the vector is valid under cofactorless verification"
        );
        assert!(!verify_strict(&key, &msg, &sig));
    }

    #[test]
    fn refusal_codes() {
        use PolicyRefusal as R;
        let invalid = [
            R::AdminThreshold,
            R::Unsorted,
            R::WeakKey,
            R::DelayTooShort,
            R::DelayTooLong,
            R::NotTron,
            R::AddressShape,
            R::Decimals,
            R::LastTier,
            R::NoWindows,
            R::ZeroApprovalFlag,
            R::VersionGap,
            R::GenesisAdmins,
            R::BadSignature,
            R::Quorum,
        ];
        for r in invalid {
            assert_eq!(r.code(), RefusalCode::BUNDLE_INVALID, "{r:?}");
        }
        let others = [
            (R::Malformed, RefusalCode::MALFORMED),
            (R::Rollback, RefusalCode::BUNDLE_ROLLBACK),
            (R::ParentMismatch, RefusalCode::BUNDLE_ROLLBACK),
            (R::LockOverflow, RefusalCode::CLOCK_UNTRUSTED),
            (
                R::Store(StoreError::Failed),
                RefusalCode::STATE_WRITE_FAILED,
            ),
            (R::NoPolicy, RefusalCode::NO_POLICY),
            (R::VersionMismatch, RefusalCode::POLICY_VERSION_MISMATCH),
            (R::NotEffective, RefusalCode::BUNDLE_NOT_EFFECTIVE),
            (R::UnknownWallet, RefusalCode::UNKNOWN_WALLET),
            (R::NetworkMismatch, RefusalCode::NETWORK_MISMATCH),
            (R::AssetNotAllowed, RefusalCode::ASSET_NOT_ALLOWED),
            (R::AmountOverCap, RefusalCode::AMOUNT_OVER_TX_CAP),
            (R::RecipientNotAllowed, RefusalCode::RECIPIENT_NOT_ALLOWED),
        ];
        for (r, code) in others {
            assert_eq!(r.refusal().code, code, "{r:?}");
        }
    }
}
