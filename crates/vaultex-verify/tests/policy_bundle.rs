//! Policy bundle v1 (ROADMAP M6 #3): one named test per refusal, the tightening table, the
//! installed file, the decoder wiring, and the vector file
//! `vectors/POLICY_BUNDLE_V1/policy_bundle_v1.json` (KAT plan KAT-12 to KAT-14).
//!
//! **These are regression vectors (KAT plan R1), not external evidence.** [`cases`] builds them
//! with the kernel's own BCS and SHA-256 (through `vaultex-types`) and Ed25519 test keys from fixed
//! seeds; the expected outcomes and refusal codes are written by hand in [`cases`]. The
//! independent JS oracle (T05-7b, then WS-13) has not reproduced them yet. The external Ed25519
//! checks are the unit tests in `policy.rs`: RFC 8032 §7.1, and a published small-order-R case
//! (ed25519-speccheck). `R-BAD-SIGNATURE-SMALL-ORDER-R` is constructed here (see
//! [`small_order_r_signature`]) and checked against dalek's cofactorless `verify`.
//!
//! Each refusal case changes one property of a named accept case (`base`), so the refusal under
//! test is the first check that fails. The named tests and the file replay share one runner,
//! [`run`], which reads nothing but the vector's JSON. After changing a case, regenerate the file
//! with the ignored test `policy_regenerate_vector_file`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use vaultex_types::{
    from_canonical_strict, tag, tagged_digest, to_canonical, Address, AssetId, ChainId, Ed25519Pub,
    IntentV1, NetworkId, RefusalCode, Sig64, TxHash, WalletId, U256,
};
use vaultex_verify::breaker::BreakerConfig;
use vaultex_verify::policy::{
    tightens, AdminSetV1, AdminSignatureV1, AssetRuleV1, Offer, PolicyBundleV1, PolicyRefusal,
    PolicyState, PolicyStore, RecipientsV1, SignedPolicyBundleV1, TierV1, WalletV1,
    MAX_BUNDLE_BYTES, MAX_LOOSEN_DELAY_MS, MAX_VERSION_STEP, MIN_LOOSEN_DELAY_MS,
};
use vaultex_verify::tron::{decode, TronRefusal};
use vaultex_verify::velocity::{StoreError, WindowLimit};

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/POLICY_BUNDLE_V1/policy_bundle_v1.json"
);
const PREFIX: &str = "POLICY_BUNDLE_V1-";

const DAY: u64 = 86_400_000;
const T0: u64 = 1_700_000_000_000;
const T1: u64 = T0 + 1_000;
const NILE: &str = "tron:3448148188";
const SHASTA: &str = "tron:2494104990";
const WALLET: &str = "hot-payout";

/// Test-only seeds (32 × the byte), public in the vector file; they must never hold value on any
/// network. Admins 1–3 are pinned; 4 and 5 are not, until a bundle adds 5.
const ADMINS: [u8; 3] = [0x01, 0x02, 0x03];
const INITIATOR: u8 = 0x20;
const APPROVERS: [u8; 2] = [0x21, 0x22];
const EXTRA_KEY: u8 = 0x23;
/// The identity point: a valid encoding of small order.
const SMALL_ORDER: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

// ───────────────────────────── fixtures ─────────────────────────────

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(seed: u8) -> Ed25519Pub {
    Ed25519Pub(sk(seed).verifying_key().to_bytes())
}

fn keys(seeds: &[u8]) -> Vec<Ed25519Pub> {
    let mut keys: Vec<Ed25519Pub> = seeds.iter().map(|s| pk(*s)).collect();
    keys.sort_by_key(|k| k.0);
    keys
}

const fn addr(fill: u8) -> [u8; 21] {
    let mut a = [fill; 21];
    a[0] = 0x41;
    a
}

fn address(fill: u8) -> Address {
    Address(addr(fill).to_vec())
}

fn u(n: u64) -> U256 {
    U256::from(n)
}

fn nile() -> NetworkId {
    NetworkId::new(NILE).unwrap()
}

fn admins() -> AdminSetV1 {
    AdminSetV1 {
        threshold: 2,
        keys: keys(&ADMINS),
    }
}

fn tier(up_to: u64, approvals: u8) -> TierV1 {
    TierV1 {
        up_to: u(up_to),
        approvals,
    }
}

fn window(window_ms: u64, max_amount: u64, max_count: u32, max_fee: u64) -> WindowLimit {
    WindowLimit {
        window_ms,
        max_amount: u(max_amount),
        max_count,
        max_fee: u(max_fee),
    }
}

/// The genesis body (version 1): one Nile wallet under permission 2, TRX to two listed
/// recipients, and a TRC-20 to anyone.
fn base() -> PolicyBundleV1 {
    PolicyBundleV1 {
        epoch: 1,
        seq: 0,
        parent: [0; 32],
        admins: admins(),
        loosen_delay_ms: DAY,
        allows_zero_approval: false,
        initiators: keys(&[INITIATOR]),
        approvers: keys(&APPROVERS),
        breaker: BreakerConfig {
            refusal_threshold: 3,
            refusal_window_ms: 600_000,
            pause_on_cap_hit: false,
            max_clock_skew_ms: 120_000,
        },
        wallets: vec![WalletV1 {
            wallet_id: WalletId::new(WALLET).unwrap(),
            network: nile(),
            address: address(0x11),
            permission_id: 2,
            max_fee_limit_sun: 100_000_000,
            max_validity_ms: 3_600_000,
            assets: vec![
                AssetRuleV1 {
                    asset: AssetId::Native,
                    decimals: 6,
                    max_per_tx: u(1_000_000_000),
                    recipients: RecipientsV1::Only(vec![address(0x22), address(0x33)]),
                    tiers: vec![tier(100_000_000, 1), tier(1_000_000_000, 2)],
                    windows: vec![window(DAY, 5_000_000_000, 20, 0)],
                },
                AssetRuleV1 {
                    asset: AssetId::Contract(address(0x99)),
                    decimals: 6,
                    max_per_tx: u(1_000_000_000),
                    recipients: RecipientsV1::Any,
                    tiers: vec![tier(1_000_000, 1), tier(1_000_000_000, 2)],
                    windows: vec![
                        window(3_600_000, 2_000_000_000, 10, 1_000_000_000),
                        window(DAY, 10_000_000_000, 30, 3_000_000_000),
                    ],
                },
            ],
        }],
    }
}

/// A genesis with a two-day time lock and pause-on-cap-hit, so that both can be loosened.
fn strict() -> PolicyBundleV1 {
    let mut b = base();
    b.loosen_delay_ms = 2 * DAY;
    b.breaker.pause_on_cap_hit = true;
    b
}

/// A genesis whose smallest TRX tier needs no approval, as it must say.
fn zero() -> PolicyBundleV1 {
    let mut b = base();
    b.allows_zero_approval = true;
    trx(&mut b).tiers = vec![
        tier(1_000_000, 0),
        tier(100_000_000, 1),
        tier(1_000_000_000, 2),
    ];
    b
}

fn wallet(b: &mut PolicyBundleV1) -> &mut WalletV1 {
    &mut b.wallets[0]
}

fn trx(b: &mut PolicyBundleV1) -> &mut AssetRuleV1 {
    &mut b.wallets[0].assets[0]
}

fn usdt(b: &mut PolicyBundleV1) -> &mut AssetRuleV1 {
    &mut b.wallets[0].assets[1]
}

/// `from` with `edit` applied.
fn edited(from: PolicyBundleV1, edit: impl FnOnce(&mut PolicyBundleV1)) -> PolicyBundleV1 {
    let mut b = from;
    edit(&mut b);
    b
}

/// A step on `from` (in force): the same epoch, the next seq, parent `from`, then `edit`.
fn step(from: &PolicyBundleV1, edit: impl FnOnce(&mut PolicyBundleV1)) -> PolicyBundleV1 {
    let parent = from.digest();
    edited(from.clone(), |b| {
        b.seq += 1;
        b.parent = parent;
        edit(b);
    })
}

/// A quorum bundle starting `epoch`, anchored to `anchor`: `anchor`'s content, then `edit`.
fn quorum(
    anchor: &PolicyBundleV1,
    epoch: u32,
    edit: impl FnOnce(&mut PolicyBundleV1),
) -> PolicyBundleV1 {
    let parent = anchor.digest();
    edited(anchor.clone(), |b| {
        b.epoch = epoch;
        b.seq = 0;
        b.parent = parent;
        edit(b);
    })
}

/// `(epoch, seq)` as the one `u64` requests name, packed here independently of the kernel.
fn ver(epoch: u32, seq: u32) -> u64 {
    (u64::from(epoch) << 32) | u64::from(seq)
}

/// A version as the vector file writes it.
fn ver_json(version: u64) -> Value {
    json!({ "epoch": (version >> 32).to_string(), "seq": (version & 0xffff_ffff).to_string() })
}

fn body_ver(body: &PolicyBundleV1) -> Value {
    json!({ "epoch": body.epoch.to_string(), "seq": body.seq.to_string() })
}

/// TRX capped at `cap`, its top tier moved with it.
fn trx_cap(b: &mut PolicyBundleV1, cap: u64) {
    let rule = trx(b);
    rule.max_per_tx = u(cap);
    if let Some(top) = rule.tiers.last_mut() {
        top.up_to = u(cap);
    }
}

fn sign_with(body: &PolicyBundleV1, signatures: Vec<AdminSignatureV1>) -> Vec<u8> {
    to_canonical(&SignedPolicyBundleV1 {
        body: body.clone(),
        signatures,
    })
    .unwrap()
}

fn signature(seed: u8, digest: &[u8; 32]) -> AdminSignatureV1 {
    AdminSignatureV1 {
        key: pk(seed),
        signature: Sig64(sk(seed).sign(digest).to_bytes()),
    }
}

/// `body` signed by the admins with these seeds, in this order.
fn sign(body: &PolicyBundleV1, seeds: &[u8]) -> Vec<u8> {
    let digest = body.digest();
    sign_with(body, seeds.iter().map(|s| signature(*s, &digest)).collect())
}

/// L, the order of the Ed25519 base point, as little-endian 64-bit limbs.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

fn sub_l_if_ge(x: &mut [u64; 4]) {
    if x.iter().rev().cmp(L.iter().rev()) == std::cmp::Ordering::Less {
        return;
    }
    let mut borrow = false;
    for (xi, li) in x.iter_mut().zip(L) {
        let (d, b1) = xi.overflowing_sub(li);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        *xi = d;
        borrow = b1 || b2;
    }
}

/// `x ← 2x + bit mod L`, for `x < L`.
fn shift_in(x: &mut [u64; 4], bit: bool) {
    let mut carry = u64::from(bit);
    for xi in x.iter_mut() {
        let top = *xi >> 63;
        *xi = (*xi << 1) | carry;
        carry = top;
    }
    sub_l_if_ge(x);
}

/// `x ← x + y mod L`, for `x, y < L`.
fn add_l(x: &mut [u64; 4], y: &[u64; 4]) {
    let mut carry = false;
    for (xi, yi) in x.iter_mut().zip(y) {
        let (t, c1) = xi.overflowing_add(*yi);
        let (t, c2) = t.overflowing_add(u64::from(carry));
        *xi = t;
        carry = c1 || c2;
    }
    sub_l_if_ge(x);
}

/// A little-endian integer, reduced mod L.
fn reduce_l(le: &[u8]) -> [u64; 4] {
    let mut x = [0; 4];
    for byte in le.iter().rev() {
        for i in (0..8).rev() {
            shift_in(&mut x, (byte >> i) & 1 == 1);
        }
    }
    x
}

/// `x·y mod L`, for `y < L`, by double and add.
fn mul_l(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    let mut r = [0; 4];
    for limb in x.iter().rev() {
        for i in (0..64).rev() {
            shift_in(&mut r, false);
            if (limb >> i) & 1 == 1 {
                add_l(&mut r, y);
            }
        }
    }
    r
}

/// A signature by admin `seed` over `msg` whose R is the identity point (small order). With
/// `k = SHA-512(R ‖ A ‖ msg) mod L` and the admin's clamped scalar `a` (RFC 8032 §5.1.5),
/// `s = k·a mod L` gives `[s]B = [k·a]B = R + [k]A`: cofactorless verification accepts it, strict
/// verification must refuse it. Constructed here, not taken from a published set: a published
/// vector cannot sign a bundle digest (`policy.rs` runs the published one, speccheck test 3).
fn small_order_r_signature(seed: u8, msg: &[u8]) -> AdminSignatureV1 {
    let mut r = [0u8; 32];
    r[0] = 1;
    let h = Sha512::digest([seed; 32]);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let k = Sha512::new()
        .chain_update(r)
        .chain_update(pk(seed).0)
        .chain_update(msg)
        .finalize();
    let s = mul_l(&reduce_l(&k), &reduce_l(&a));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    for (chunk, limb) in sig[32..].chunks_exact_mut(8).zip(s) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    AdminSignatureV1 {
        key: pk(seed),
        signature: Sig64(sig),
    }
}

fn hx(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ───────────────────────────── expectations (written by hand) ─────────────────────────────

fn effective(body: &PolicyBundleV1) -> Value {
    json!({ "effective": { "version": body_ver(body), "digest": hx(&body.digest()) } })
}

fn pending(body: &PolicyBundleV1, effective_at_ms: u64) -> Value {
    json!({ "pending": {
        "version": body_ver(body),
        "digest": hx(&body.digest()),
        "effective_at_ms": effective_at_ms.to_string(),
    } })
}

fn in_force(body: &PolicyBundleV1) -> Value {
    json!({ "in_force": { "version": body_ver(body), "digest": hx(&body.digest()) } })
}

/// A refusal: the wire code, its registry name, and the check (the `PolicyRefusal` variant).
fn refuse(code: RefusalCode, check: &str) -> Value {
    json!({ "refuse": {
        "code": format!("0x{:04x}", code.0),
        "name": code.name().unwrap(),
        "check": check,
    } })
}

fn admitted(asset: &AssetId, approvals: u8) -> Value {
    json!({ "rule": { "asset": hx(&to_canonical(asset).unwrap()), "approvals": approvals.to_string() } })
}

// ───────────────────────────── cases ─────────────────────────────

/// One vector under construction.
struct Case {
    id: String,
    rule: &'static str,
    base: Option<String>,
    description: String,
    genesis: AdminSetV1,
    steps: Vec<Value>,
    expect: Vec<Value>,
    bundles: Vec<(String, Vec<u8>)>,
}

fn case(id: &str, rule: &'static str, base: Option<&str>, description: &str) -> Case {
    Case {
        id: format!("{PREFIX}{id}"),
        rule,
        base: base.map(|b| format!("{PREFIX}{b}")),
        description: description.to_owned(),
        genesis: admins(),
        steps: Vec::new(),
        expect: Vec::new(),
        bundles: Vec::new(),
    }
}

impl Case {
    fn pin(mut self, genesis: AdminSetV1) -> Self {
        self.genesis = genesis;
        self
    }

    /// Offers the signed bundle `bytes`, registered in the file as `name`.
    fn offer(mut self, name: &str, bytes: Vec<u8>, now_ms: u64, expect: Value) -> Self {
        self.steps
            .push(json!({ "offer": { "bundle": name, "now_ms": now_ms.to_string() } }));
        self.bundles.push((name.to_owned(), bytes));
        self.expect.push(expect);
        self
    }

    /// The genesis `body`, signed by admins 1 and 2 at `T0`, accepted.
    fn genesis(self, name: &str, body: &PolicyBundleV1) -> Self {
        self.offer(name, sign(body, &[1, 2]), T0, effective(body))
    }

    /// The tightening classifier on two bodies, given as signed bundles (signatures unused).
    fn classify(mut self, old: (&str, Vec<u8>), new: (&str, Vec<u8>), tightens: bool) -> Self {
        self.steps
            .push(json!({ "classify": { "old": old.0, "new": new.0 } }));
        self.bundles.push((old.0.to_owned(), old.1));
        self.bundles.push((new.0.to_owned(), new.1));
        self.expect.push(json!({ "tightens": tightens }));
        self
    }

    /// A request naming `version` at `now_ms`.
    fn use_version(mut self, version: u64, now_ms: u64, expect: Value) -> Self {
        self.steps.push(json!({ "use": {
            "version": ver_json(version),
            "now_ms": now_ms.to_string(),
        } }));
        self.expect.push(expect);
        self
    }

    /// The decoder view for `wallet_id` on `network`, under `version`.
    fn view(mut self, version: u64, wallet_id: &str, network: &str, expect: Value) -> Self {
        self.steps.push(json!({ "view": {
            "version": ver_json(version),
            "now_ms": T1.to_string(),
            "wallet_id": wallet_id,
            "network": network,
        } }));
        self.expect.push(expect);
        self
    }

    /// The asset rules applied to `intent`, under `version`.
    fn intent(mut self, version: u64, intent: &IntentV1, expect: Value) -> Self {
        self.steps.push(json!({ "intent": {
            "version": ver_json(version),
            "now_ms": T1.to_string(),
            "intent": hx(&to_canonical(intent).unwrap()),
        } }));
        self.expect.push(expect);
        self
    }

    fn vector(&self) -> Value {
        json!({
            "id": self.id,
            "rule": self.rule,
            "base": self.base,
            "description": self.description,
            "input": {
                "genesis": {
                    "threshold": self.genesis.threshold.to_string(),
                    "keys": self.genesis.keys.iter().map(|k| hx(&k.0)).collect::<Vec<_>>(),
                },
                "steps": self.steps,
            },
            "expect": { "steps": self.expect },
        })
    }
}

/// A genesis refused at step 2 (content): `base` edited, signed by admins 1 and 2.
fn bad_content(
    id: &str,
    description: &str,
    check: &str,
    edit: impl FnOnce(&mut PolicyBundleV1),
) -> Case {
    let body = edited(base(), edit);
    case(id, "offer step 2 (content)", Some("A-GENESIS"), description).offer(
        &format!("{id}/v1"),
        sign(&body, &[1, 2]),
        T0,
        refuse(RefusalCode::BUNDLE_INVALID, check),
    )
}

/// A transfer intent on the base wallet, as the decoder would produce it.
fn intent(asset: AssetId, recipient: u8, amount: u64) -> IntentV1 {
    IntentV1 {
        wallet_id: WalletId::new(WALLET).unwrap(),
        chain: ChainId::TRON,
        network: nile(),
        sender: address(0x11),
        recipient: address(recipient),
        asset,
        amount: u(amount),
        fee_cap: u(0),
        not_after_ms: T0 + 60_000,
        tx_hash: TxHash([7; 32]),
    }
}

fn token() -> AssetId {
    AssetId::Contract(address(0x99))
}

/// A row of the tightening table: a change to the genesis `from`, and whether it tightens.
struct Row {
    name: &'static str,
    description: &'static str,
    from: fn() -> PolicyBundleV1,
    edit: fn(&mut PolicyBundleV1),
    tightens: bool,
}

fn row(
    name: &'static str,
    description: &'static str,
    from: fn() -> PolicyBundleV1,
    edit: fn(&mut PolicyBundleV1),
    tightens: bool,
) -> Row {
    Row {
        name,
        description,
        from,
        edit,
        tightens,
    }
}

/// One case per change: version 2, signed by admin 3 alone. A tightening takes effect; anything
/// else is short of the quorum, and the same body signed by admins 1 and 2 waits out the lock.
fn table_rows() -> Vec<Row> {
    vec![
        row(
            "ADMINS-ADD",
            "admins: a fourth key",
            base,
            |b| b.admins.keys = keys(&[1, 2, 3, 4]),
            false,
        ),
        row(
            "ADMINS-DROP",
            "admins: a key dropped (a stricter set is still a loosening)",
            base,
            |b| b.admins.keys = keys(&[1, 2]),
            false,
        ),
        row(
            "ADMINS-RAISE-M",
            "admins: threshold 2 to 3 (a stricter set is still a loosening)",
            base,
            |b| b.admins.threshold = 3,
            false,
        ),
        row(
            "DELAY-DOWN",
            "loosen_delay_ms: 2 days to 1",
            strict,
            |b| b.loosen_delay_ms = DAY,
            false,
        ),
        row(
            "DELAY-UP",
            "loosen_delay_ms: 2 days to 3 (only a quorum bundle changes the time lock)",
            strict,
            |b| b.loosen_delay_ms = 3 * DAY,
            false,
        ),
        row(
            "INITIATORS-ADD",
            "initiators: a key added",
            base,
            |b| b.initiators = keys(&[INITIATOR, EXTRA_KEY]),
            false,
        ),
        row(
            "INITIATORS-DROP",
            "initiators: the only key removed",
            base,
            |b| b.initiators = Vec::new(),
            true,
        ),
        row(
            "APPROVERS-ADD",
            "approvers: a key added",
            base,
            |b| b.approvers = keys(&[0x21, 0x22, EXTRA_KEY]),
            false,
        ),
        row(
            "APPROVERS-DROP",
            "approvers: a key removed",
            base,
            |b| b.approvers = keys(&[0x21]),
            true,
        ),
        row(
            "REFUSALS-UP",
            "breaker.refusal_threshold: 3 to 4",
            base,
            |b| b.breaker.refusal_threshold = 4,
            false,
        ),
        row(
            "REFUSALS-DOWN",
            "breaker.refusal_threshold: 3 to 2",
            base,
            |b| b.breaker.refusal_threshold = 2,
            true,
        ),
        row(
            "REFUSALS-ZERO",
            "breaker.refusal_threshold: 3 to 0 (counts as 1)",
            base,
            |b| b.breaker.refusal_threshold = 0,
            true,
        ),
        row(
            "REFUSAL-WINDOW-DOWN",
            "breaker.refusal_window_ms: 10 to 5 minutes",
            base,
            |b| b.breaker.refusal_window_ms = 300_000,
            false,
        ),
        row(
            "REFUSAL-WINDOW-UP",
            "breaker.refusal_window_ms: 10 to 15 minutes",
            base,
            |b| b.breaker.refusal_window_ms = 900_000,
            true,
        ),
        row(
            "PAUSE-OFF",
            "breaker.pause_on_cap_hit: true to false",
            strict,
            |b| b.breaker.pause_on_cap_hit = false,
            false,
        ),
        row(
            "PAUSE-ON",
            "breaker.pause_on_cap_hit: false to true",
            base,
            |b| b.breaker.pause_on_cap_hit = true,
            true,
        ),
        row(
            "SKEW-UP",
            "breaker.max_clock_skew_ms: 2 to 3 minutes",
            base,
            |b| b.breaker.max_clock_skew_ms = 180_000,
            false,
        ),
        row(
            "SKEW-DOWN",
            "breaker.max_clock_skew_ms: 2 to 1 minute",
            base,
            |b| b.breaker.max_clock_skew_ms = 60_000,
            true,
        ),
        row(
            "WALLET-ADD",
            "wallets: a second wallet",
            base,
            |b| {
                let mut w = b.wallets[0].clone();
                w.wallet_id = WalletId::new("hot-two").unwrap();
                b.wallets.push(w);
            },
            false,
        ),
        row(
            "WALLET-NETWORK",
            "wallet.network: Nile to Shasta",
            base,
            |b| wallet(b).network = NetworkId::new(SHASTA).unwrap(),
            false,
        ),
        row(
            "WALLET-ADDRESS",
            "wallet.address changed",
            base,
            |b| wallet(b).address = address(0x12),
            false,
        ),
        row(
            "WALLET-PERMISSION",
            "wallet.permission_id: 2 to 3",
            base,
            |b| wallet(b).permission_id = 3,
            false,
        ),
        row(
            "WALLET-DROP",
            "wallets: the only wallet removed",
            base,
            |b| b.wallets = Vec::new(),
            true,
        ),
        row(
            "FEE-UP",
            "wallet.max_fee_limit_sun raised",
            base,
            |b| wallet(b).max_fee_limit_sun = 150_000_000,
            false,
        ),
        row(
            "FEE-DOWN",
            "wallet.max_fee_limit_sun lowered",
            base,
            |b| wallet(b).max_fee_limit_sun = 50_000_000,
            true,
        ),
        row(
            "VALIDITY-UP",
            "wallet.max_validity_ms raised",
            base,
            |b| wallet(b).max_validity_ms = 7_200_000,
            false,
        ),
        row(
            "VALIDITY-DOWN",
            "wallet.max_validity_ms lowered",
            base,
            |b| wallet(b).max_validity_ms = 600_000,
            true,
        ),
        row(
            "ASSET-ADD",
            "wallet.assets: a second token",
            base,
            |b| {
                let mut rule = b.wallets[0].assets[1].clone();
                rule.asset = AssetId::Contract(address(0x98));
                b.wallets[0].assets.insert(1, rule);
            },
            false,
        ),
        row(
            "ASSET-DECIMALS",
            "asset.decimals: the token's 6 to 18",
            base,
            |b| usdt(b).decimals = 18,
            false,
        ),
        row(
            "ASSET-DROP",
            "wallet.assets: the token removed",
            base,
            |b| {
                b.wallets[0].assets.pop();
            },
            true,
        ),
        row(
            "CAP-UP",
            "asset.max_per_tx: TRX raised",
            base,
            |b| trx_cap(b, 2_000_000_000),
            false,
        ),
        row(
            "CAP-DOWN",
            "asset.max_per_tx: TRX lowered",
            base,
            |b| trx_cap(b, 500_000_000),
            true,
        ),
        row(
            "RECIPIENTS-ANY",
            "asset.recipients: TRX list to Any",
            base,
            |b| trx(b).recipients = RecipientsV1::Any,
            false,
        ),
        row(
            "RECIPIENTS-ADD",
            "asset.recipients: a TRX recipient added",
            base,
            |b| {
                trx(b).recipients =
                    RecipientsV1::Only(vec![address(0x22), address(0x33), address(0x44)])
            },
            false,
        ),
        row(
            "RECIPIENTS-DROP",
            "asset.recipients: a TRX recipient removed",
            base,
            |b| trx(b).recipients = RecipientsV1::Only(vec![address(0x22)]),
            true,
        ),
        row(
            "RECIPIENTS-LIST",
            "asset.recipients: the token's Any to a list",
            base,
            |b| usdt(b).recipients = RecipientsV1::Only(vec![address(0x22)]),
            true,
        ),
        row(
            "TIER-FEWER",
            "asset.tiers: the top TRX tier 2 approvals to 1",
            base,
            |b| trx(b).tiers[1].approvals = 1,
            false,
        ),
        row(
            "TIER-BOUNDARY-UP",
            "asset.tiers: the 1-approval TRX tier extended upwards",
            base,
            |b| trx(b).tiers[0].up_to = u(200_000_000),
            false,
        ),
        row(
            "TIER-MORE",
            "asset.tiers: the low TRX tier 1 approval to 2",
            base,
            |b| trx(b).tiers[0].approvals = 2,
            true,
        ),
        row(
            "TIER-BOUNDARY-DOWN",
            "asset.tiers: the 1-approval TRX tier shortened",
            base,
            |b| trx(b).tiers[0].up_to = u(50_000_000),
            true,
        ),
        row(
            "TIER-SPLIT",
            "asset.tiers: a 3-approval tier added at the TRX top",
            base,
            |b| {
                trx(b).tiers = vec![
                    tier(100_000_000, 1),
                    tier(500_000_000, 2),
                    tier(1_000_000_000, 3),
                ];
            },
            true,
        ),
        row(
            "WINDOW-AMOUNT-UP",
            "asset.windows: the token's day amount raised",
            base,
            |b| usdt(b).windows[1].max_amount = u(20_000_000_000),
            false,
        ),
        row(
            "WINDOW-COUNT-UP",
            "asset.windows: the token's day count raised",
            base,
            |b| usdt(b).windows[1].max_count = 31,
            false,
        ),
        row(
            "WINDOW-FEE-UP",
            "asset.windows: the token's hour fee raised",
            base,
            |b| usdt(b).windows[0].max_fee = u(2_000_000_000),
            false,
        ),
        row(
            "WINDOW-DROP",
            "asset.windows: the token's hour window removed",
            base,
            |b| {
                usdt(b).windows.remove(0);
            },
            false,
        ),
        row(
            "WINDOW-LOWER",
            "asset.windows: every token limit lowered",
            base,
            |b| {
                usdt(b).windows = vec![
                    window(3_600_000, 1_000_000_000, 5, 500_000_000),
                    window(DAY, 5_000_000_000, 15, 1_000_000_000),
                ];
            },
            true,
        ),
        row(
            "WINDOW-ADD",
            "asset.windows: a TRX hour window added",
            base,
            |b| {
                trx(b)
                    .windows
                    .insert(0, window(3_600_000, 1_000_000_000, 5, 0));
            },
            true,
        ),
    ]
}

fn table_cases() -> Vec<Case> {
    table_rows()
        .into_iter()
        .map(|r| {
            let (name, description, tightens) = (r.name, r.description, r.tightens);
            let genesis = (r.from)();
            let as_step = step(&genesis, r.edit);
            let as_quorum = quorum(&genesis, 2, r.edit);
            let gname = if genesis == base() {
                "genesis"
            } else {
                "genesis-strict"
            };
            let delay = genesis.loosen_delay_ms;
            let (kind, rule) = if tightens {
                (
                    "TIGHTEN",
                    "offer steps 5 and 7 (a step that tightens: 1-of-N)",
                )
            } else {
                (
                    "LOOSEN",
                    "offer step 5 (not a tightening: a quorum bundle, M-of-N, time lock)",
                )
            };
            let id = format!("T-{kind}-{name}");
            let c = case(&id, rule, Some("A-GENESIS"), description).genesis(gname, &genesis);
            if tightens {
                c.offer(
                    &format!("{id}/step-1of3"),
                    sign(&as_step, &[3]),
                    T1,
                    effective(&as_step),
                )
            } else {
                c.offer(
                    &format!("{id}/step-1of3"),
                    sign(&as_step, &[3]),
                    T1,
                    refuse(RefusalCode::BUNDLE_INVALID, "StepNotTighter"),
                )
                .offer(
                    &format!("{id}/quorum-2of3"),
                    sign(&as_quorum, &[1, 2]),
                    T1,
                    pending(&as_quorum, T1 + delay),
                )
            }
        })
        .collect()
}

/// A genesis whose signed encoding is exactly `target` bytes: TRX recipients added one by one,
/// then the wallet id padded byte by byte.
fn sized(target: usize) -> PolicyBundleV1 {
    let body = |n: u64, pad: usize| {
        edited(base(), |b| {
            let mut list: Vec<Address> = (1..=n)
                .map(|i| {
                    let mut a = [0u8; 21];
                    a[0] = 0x41;
                    a[13..].copy_from_slice(&i.to_be_bytes());
                    Address(a.to_vec())
                })
                .collect();
            list.extend([address(0x22), address(0x33)]);
            trx(b).recipients = RecipientsV1::Only(list);
            wallet(b).wallet_id = WalletId::new(&format!("{WALLET}{}", "-".repeat(pad))).unwrap();
        })
    };
    let len = |n, pad| sign(&body(n, pad), &[1, 2]).len();
    let mut n = ((target - len(0, 0)) / 22) as u64;
    while len(n, 0) > target {
        n -= 1;
    }
    while len(n + 1, 0) <= target {
        n += 1;
    }
    let b = body(n, target - len(n, 0));
    assert_eq!(sign(&b, &[1, 2]).len(), target);
    b
}

fn cases() -> Vec<Case> {
    let b = base();
    // Quorum bundles anchored to the genesis: a loosening at epoch 2, a tightening at epoch 3 (it
    // supersedes `loose` while that is pending), and another loosening at epoch 3.
    let loose = quorum(&b, 2, |b| trx_cap(b, 2_000_000_000));
    let tight3 = quorum(&b, 3, |b| trx_cap(b, 500_000_000));
    let replaces = quorum(&b, 3, |b| trx_cap(b, 2_000_000_000));
    // Steps: on the genesis, and on the zero-approval genesis.
    let tight2 = step(&b, |b| trx_cap(b, 500_000_000));
    let zero_step = step(&zero(), |b| trx_cap(b, 500_000_000));
    let delay_down = quorum(&strict(), 2, |b| b.loosen_delay_ms = DAY);
    let mut out = vec![
        // ── accept sequences ──
        case("A-GENESIS", "offer steps 1 to 8 (genesis)", None, "The genesis bundle (epoch 1, seq 0, zero parent), signed 2-of-3 by the pinned admins, takes effect at once")
            .genesis("genesis", &b)
            .use_version(ver(1, 0), T0, in_force(&b)),
        case("A-GENESIS-3OF3", "offer step 7", Some("A-GENESIS"), "Signed by all three admins")
            .offer("A-GENESIS-3OF3/v1", sign(&b, &[3, 1, 2]), T0, effective(&b)),
        case("A-GENESIS-DUPLICATE", "offer step 7 (each key counts once)", Some("A-GENESIS"), "A duplicated signature next to a second admin's still reaches 2-of-3")
            .offer("A-GENESIS-DUPLICATE/v1", sign(&b, &[1, 1, 2]), T0, effective(&b)),
        case("A-GENESIS-UNPINNED-IGNORED", "offer step 6 (only judging keys are checked)", Some("A-GENESIS"), "A signature by a key outside the admin set, even a broken one, is ignored")
            .offer(
                "A-GENESIS-UNPINNED-IGNORED/v1",
                sign_with(&b, vec![signature(1, &b.digest()), AdminSignatureV1 { key: pk(4), signature: Sig64([9; 64]) }, signature(2, &b.digest())]),
                T0,
                effective(&b),
            ),
        case("A-THRESHOLD-N", "offer step 2.1 (bound)", Some("A-GENESIS"), "Threshold equal to the number of admin keys")
            .pin(AdminSetV1 { threshold: 3, keys: keys(&ADMINS) })
            .offer("A-THRESHOLD-N/v1", sign(&edited(base(), |b| b.admins.threshold = 3), &[1, 2, 3]), T0, effective(&edited(base(), |b| b.admins.threshold = 3))),
        case("A-DECIMALS-77", "offer step 2.4 (bound)", Some("A-GENESIS"), "A token with 77 decimals")
            .genesis("A-DECIMALS-77/v1", &edited(base(), |b| usdt(b).decimals = 77)),
        case("A-DELAY-MAX", "offer step 2.3 (bound)", Some("A-GENESIS"), "A time lock of exactly MAX_LOOSEN_DELAY_MS")
            .genesis("A-DELAY-MAX/v1", &edited(base(), |b| b.loosen_delay_ms = MAX_LOOSEN_DELAY_MS)),
        case("A-SIZE-MAX", "offer step 1 (bound)", Some("A-GENESIS"), "A signed bundle of exactly MAX_BUNDLE_BYTES")
            .genesis("A-SIZE-MAX/v1", &sized(MAX_BUNDLE_BYTES)),
        case("A-TIGHTEN", "offer steps 5 and 7 (a step)", Some("A-GENESIS"), "A step that tightens, signed by one admin, takes effect at once; the old version no longer serves")
            .genesis("genesis", &b)
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1, effective(&tight2))
            .use_version(ver(1, 1), T1, in_force(&tight2))
            .use_version(ver(1, 0), T1, refuse(RefusalCode::POLICY_VERSION_MISMATCH, "VersionMismatch")),
        case("A-LOOSEN", "offer step 8 and the time lock", Some("A-GENESIS"), "A quorum loosening signed 2-of-3 waits one day from this signer's receipt: refused one millisecond before, in force at the boundary")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .use_version(ver(2, 0), T1 + DAY - 1, refuse(RefusalCode::BUNDLE_NOT_EFFECTIVE, "NotEffective"))
            .use_version(ver(1, 0), T1 + DAY - 1, in_force(&b))
            .use_version(ver(2, 0), T1 + DAY, in_force(&loose))
            .use_version(ver(1, 0), T1 + DAY, refuse(RefusalCode::POLICY_VERSION_MISMATCH, "VersionMismatch")),
        case("A-LOCK-FROM-RECEIPT", "time lock (measured from this signer's receipt)", Some("A-LOOSEN"), "Received two days after genesis: still pending one day after genesis plus one day")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T0 + 2 * DAY, pending(&loose, T0 + 3 * DAY))
            .use_version(ver(2, 0), T0 + 3 * DAY - 1, refuse(RefusalCode::BUNDLE_NOT_EFFECTIVE, "NotEffective"))
            .use_version(ver(2, 0), T0 + 3 * DAY, in_force(&loose)),
        case("A-DELAY-OF-ACTIVE", "time lock (the active bundle's delay)", Some("A-LOOSEN"), "A loosening that shortens the delay to one day still waits the active two days")
            .genesis("genesis-strict", &strict())
            .offer("A-DELAY-OF-ACTIVE/q2", sign(&delay_down, &[1, 2]), T1, pending(&delay_down, T1 + 2 * DAY))
            .use_version(ver(2, 0), T1 + DAY, refuse(RefusalCode::BUNDLE_NOT_EFFECTIVE, "NotEffective"))
            .use_version(ver(2, 0), T1 + 2 * DAY, in_force(&delay_down)),
        case("A-SUPERSEDE-MOFN", "offer step 7 (superseding a pending loosening needs M-of-N)", Some("A-LOOSEN"), "A quorum tightening signed 2-of-3 while a loosening is pending takes effect at once and drops the loosening")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("SUPERSEDE/q3-2of3", sign(&tight3, &[1, 2]), T1 + 1, effective(&tight3))
            .use_version(ver(2, 0), T1 + DAY, refuse(RefusalCode::POLICY_VERSION_MISMATCH, "VersionMismatch"))
            .use_version(ver(3, 0), T1 + DAY, in_force(&tight3)),
        case("A-CANCELLED-LOOSENING-SEEN", "offer step 3 (no replay of a cancelled pending bundle)", Some("A-SUPERSEDE-MOFN"), "A signer that received the loosening and the bundle that cancelled it: the cancelled bundle cannot come back")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("SUPERSEDE/q3-2of3", sign(&tight3, &[1, 2]), T1 + 1, effective(&tight3))
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1 + 2, refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"))
            .use_version(ver(3, 0), T1 + DAY, in_force(&tight3)),
        case("A-MISSED-CANCELLED-LOOSENING", "offer step 3 (epochs that never came into force may be skipped)", Some("A-CANCELLED-LOOSENING-SEEN"), "A signer that never received the cancelled loosening installs the cancelling bundle directly and ends in the same state")
            .genesis("genesis", &b)
            .offer("SUPERSEDE/q3-2of3", sign(&tight3, &[1, 2]), T1 + 1, effective(&tight3))
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1 + 2, refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"))
            .use_version(ver(3, 0), T1 + DAY, in_force(&tight3)),
        case("A-LOOSEN-REPLACES", "states (a loosening replaces the pending one)", Some("A-LOOSEN"), "A second loosening replaces the first, and its own lock starts at its receipt; the replaced one cannot come back")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("A-LOOSEN-REPLACES/q3", sign(&replaces, &[1, 2]), T1 + 1_000, pending(&replaces, T1 + 1_000 + DAY))
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1 + 2_000, refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"))
            .use_version(ver(2, 0), T1 + DAY, refuse(RefusalCode::POLICY_VERSION_MISMATCH, "VersionMismatch"))
            .use_version(ver(3, 0), T1 + DAY, refuse(RefusalCode::BUNDLE_NOT_EFFECTIVE, "NotEffective"))
            .use_version(ver(3, 0), T1 + 1_000 + DAY, in_force(&replaces)),
        case("A-ZERO-TIGHTEN", "offer step 7 (zero approval needs M-of-N)", Some("A-GENESIS"), "A zero-approval step that tightens, signed 2-of-3, takes effect at once")
            .genesis("genesis-zero", &zero())
            .offer("A-ZERO-TIGHTEN/step-2of3", sign(&zero_step, &[1, 2]), T1, effective(&zero_step)),
    ];

    // The judge is the effective bundle: a pending one has no authority until its lock ends.
    let rotated = quorum(&b, 2, |b| b.admins.keys = keys(&[1, 2, 5]));
    let early = quorum(&b, 3, |b| {
        b.admins.keys = keys(&[1, 2, 5]);
        trx_cap(b, 500_000_000);
    });
    let after = step(&rotated, |b| trx_cap(b, 500_000_000));
    out.push(
        case("A-JUDGE-IS-EFFECTIVE", "offer step 4 (judge)", Some("A-LOOSEN"), "A rotation to admin 5 is pending: admin 5 alone cannot change anything yet, and can tighten once the rotation is in force")
            .genesis("genesis", &b)
            .offer("A-JUDGE-IS-EFFECTIVE/q2", sign(&rotated, &[1, 3]), T1, pending(&rotated, T1 + DAY))
            .offer("A-JUDGE-IS-EFFECTIVE/q3-early", sign(&early, &[5]), T1 + DAY - 1, refuse(RefusalCode::BUNDLE_INVALID, "Quorum"))
            .offer("A-JUDGE-IS-EFFECTIVE/step", sign(&after, &[5]), T1 + DAY, effective(&after)),
    );

    // ── anchors (ADR-11 follow-up of 2026-10-18) ──
    // (a) A quorum bundle signed against the anchor survives any number of steps.
    let mut churn = vec![b.clone()];
    for _ in 0..20 {
        let last = churn.last().unwrap().clone();
        churn.push(step(&last, |_| {}));
    }
    let mut churn_case = case("A-STEP-CHURN-THEN-ROTATION", "offer step 3 (a quorum bundle names the anchor)", Some("A-JUDGE-IS-EFFECTIVE"), "Twenty no-op steps by one admin neither invalidate nor delay a rotation signed 2-of-3 against the genesis, and no step lands while it is pending")
        .genesis("genesis", &b);
    for (i, s) in churn.iter().enumerate().skip(1) {
        churn_case = churn_case.offer(
            &format!("A-STEP-CHURN-THEN-ROTATION/step-{i}"),
            sign(s, &[3]),
            T1 + i as u64,
            effective(s),
        );
    }
    let late_step = step(&churn[20], |_| {});
    out.push(
        churn_case
            .offer(
                "A-JUDGE-IS-EFFECTIVE/q2",
                sign(&rotated, &[1, 3]),
                T1 + 100,
                pending(&rotated, T1 + 100 + DAY),
            )
            .offer(
                "A-STEP-CHURN-THEN-ROTATION/step-21",
                sign(&late_step, &[3]),
                T1 + 101,
                refuse(RefusalCode::BUNDLE_INVALID, "StepWhilePending"),
            )
            .use_version(ver(1, 20), T1 + 100 + DAY - 1, in_force(&churn[20]))
            .use_version(ver(2, 0), T1 + 100 + DAY, in_force(&rotated)),
    );
    // (b) It is classified against the bundle in force, steps included.
    let same = quorum(&b, 2, |_| {});
    let after_lock = quorum(&loose, 3, |b| trx_cap(b, 1_500_000_000));
    let anchor2 = quorum(&b, 2, |b| trx_cap(b, 500_000_000));
    let anchor3 = quorum(&anchor2, 3, |b| trx_cap(b, 400_000_000));
    out.extend([
        case("A-ANCHOR-CLASS", "offer step 5 (classified against the bundle in force)", Some("A-TIGHTEN"), "After a step lowered the TRX cap, a quorum bundle with the genesis content is a loosening: dropping the step waits out the lock")
            .genesis("genesis", &b)
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1, effective(&tight2))
            .offer("A-ANCHOR-CLASS/q2", sign(&same, &[1, 2]), T1 + 1, pending(&same, T1 + 1 + DAY))
            .use_version(ver(1, 1), T1 + DAY, in_force(&tight2))
            .use_version(ver(2, 0), T1 + 1 + DAY, in_force(&same)),
        case("A-ANCHOR-CLASS-LAGGING", "offer step 5 (classified against the bundle in force)", Some("A-ANCHOR-CLASS"), "A signer that missed the step classes the same quorum bundle as a tightening and installs it at once: both reach it")
            .genesis("genesis", &b)
            .offer("A-ANCHOR-CLASS/q2", sign(&same, &[1, 2]), T1 + 1, effective(&same)),
        case("A-ANCHOR-AFTER-LOCK", "offer step 3 (the anchor moves with the quorum bundle in force)", Some("A-LOOSEN"), "Once a pending quorum bundle is in force it is the anchor of the next one")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("A-ANCHOR-AFTER-LOCK/q3", sign(&after_lock, &[1, 2]), T1 + DAY, effective(&after_lock)),
        case("A-ANCHOR-AFTER-QUORUM", "offer step 3 (the anchor moves with the quorum bundle in force)", Some("A-GENESIS"), "A quorum tightening in force at once is the anchor of the next quorum bundle")
            .genesis("genesis", &b)
            .offer("A-ANCHOR-AFTER-QUORUM/q2", sign(&anchor2, &[1, 2]), T1, effective(&anchor2))
            .offer("A-ANCHOR-AFTER-QUORUM/q3", sign(&anchor3, &[1, 2]), T1 + 1, effective(&anchor3)),
    ]);

    // ── install refusals ──
    let mut trailing = sign(&b, &[1, 2]);
    trailing.push(0);
    let invalid = |check| refuse(RefusalCode::BUNDLE_INVALID, check);
    out.extend([
        case(
            "R-MALFORMED-TRAILING",
            "offer step 1",
            Some("A-GENESIS"),
            "A byte after the signed bundle",
        )
        .offer(
            "R-MALFORMED-TRAILING/v1",
            trailing,
            T0,
            refuse(RefusalCode::MALFORMED, "Malformed"),
        ),
        case(
            "R-MALFORMED-SIZE",
            "offer step 1 (bound)",
            Some("A-SIZE-MAX"),
            "A valid signed bundle one byte over MAX_BUNDLE_BYTES",
        )
        .offer(
            "R-MALFORMED-SIZE/v1",
            sign(&sized(MAX_BUNDLE_BYTES + 1), &[1, 2]),
            T0,
            refuse(RefusalCode::MALFORMED, "Malformed"),
        ),
        bad_content(
            "R-ADMIN-THRESHOLD-ZERO",
            "Admin threshold 0",
            "AdminThreshold",
            |b| b.admins.threshold = 0,
        ),
        bad_content(
            "R-ADMIN-THRESHOLD-OVER",
            "Admin threshold 4 of 3 keys",
            "AdminThreshold",
            |b| b.admins.threshold = 4,
        ),
        case(
            "R-ADMIN-THRESHOLD-ZERO-LATER",
            "offer step 2 (content)",
            Some("A-LOOSEN"),
            "A loosening, signed 2-of-3, that would let the next bundle pass with no signature",
        )
        .genesis("genesis", &b)
        .offer(
            "R-ADMIN-THRESHOLD-ZERO-LATER/v2",
            sign(&quorum(&base(), 2, |b| b.admins.threshold = 0), &[1, 2]),
            T1,
            invalid("AdminThreshold"),
        ),
        bad_content(
            "R-UNSORTED-ADMINS",
            "Admin keys out of order",
            "Unsorted",
            |b| b.admins.keys.reverse(),
        ),
        bad_content(
            "R-UNSORTED-ADMINS-DUPLICATE",
            "An admin key listed twice",
            "Unsorted",
            |b| b.admins.keys.insert(0, b.admins.keys[0]),
        ),
        bad_content(
            "R-UNSORTED-INITIATORS",
            "Initiator keys out of order",
            "Unsorted",
            |b| b.initiators = keys(&[INITIATOR, EXTRA_KEY]).into_iter().rev().collect(),
        ),
        bad_content(
            "R-UNSORTED-APPROVERS",
            "Approver keys out of order",
            "Unsorted",
            |b| b.approvers.reverse(),
        ),
        bad_content(
            "R-UNSORTED-WALLETS",
            "Wallets out of order",
            "Unsorted",
            |b| {
                let mut w = b.wallets[0].clone();
                w.wallet_id = WalletId::new("a-wallet").unwrap();
                b.wallets.push(w);
            },
        ),
        bad_content(
            "R-UNSORTED-ASSETS",
            "The token before TRX",
            "Unsorted",
            |b| b.wallets[0].assets.reverse(),
        ),
        bad_content(
            "R-UNSORTED-RECIPIENTS",
            "TRX recipients out of order",
            "Unsorted",
            |b| trx(b).recipients = RecipientsV1::Only(vec![address(0x33), address(0x22)]),
        ),
        bad_content(
            "R-UNSORTED-TIERS",
            "TRX tiers out of order",
            "Unsorted",
            |b| trx(b).tiers.reverse(),
        ),
        bad_content(
            "R-UNSORTED-WINDOWS",
            "Token windows out of order",
            "Unsorted",
            |b| usdt(b).windows.reverse(),
        ),
        bad_content(
            "R-WEAK-KEY-ADMINS",
            "A small-order admin key",
            "WeakKey",
            |b| b.admins.keys.insert(0, Ed25519Pub(SMALL_ORDER)),
        ),
        bad_content(
            "R-WEAK-KEY-INITIATORS",
            "A small-order initiator key",
            "WeakKey",
            |b| b.initiators.insert(0, Ed25519Pub(SMALL_ORDER)),
        ),
        bad_content(
            "R-WEAK-KEY-APPROVERS",
            "A small-order approver key",
            "WeakKey",
            |b| b.approvers.insert(0, Ed25519Pub(SMALL_ORDER)),
        ),
        bad_content(
            "R-DELAY-SHORT",
            "loosen_delay_ms one millisecond under MIN_LOOSEN_DELAY_MS (bound)",
            "DelayTooShort",
            |b| b.loosen_delay_ms = MIN_LOOSEN_DELAY_MS - 1,
        ),
        bad_content(
            "R-DELAY-LONG",
            "loosen_delay_ms one millisecond over MAX_LOOSEN_DELAY_MS (bound)",
            "DelayTooLong",
            |b| b.loosen_delay_ms = MAX_LOOSEN_DELAY_MS + 1,
        ),
        case(
            "R-DELAY-LONG-LATER",
            "offer step 2 (content)",
            Some("A-TIGHTEN"),
            "A tightening by one admin that would set a time lock no loosening could ever outwait",
        )
        .genesis("genesis", &b)
        .offer(
            "R-DELAY-LONG-LATER/v2",
            sign(&step(&base(), |b| b.loosen_delay_ms = u64::MAX), &[3]),
            T1,
            invalid("DelayTooLong"),
        ),
        bad_content(
            "R-NO-WINDOWS",
            "TRX with no velocity window (it would block TRX, and make any window look tighter)",
            "NoWindows",
            |b| trx(b).windows = Vec::new(),
        ),
        bad_content("R-NOT-TRON", "A wallet on an EVM network", "NotTron", |b| {
            wallet(b).network = NetworkId::new("eip155:11155111").unwrap()
        }),
        bad_content(
            "R-ADDRESS-WALLET",
            "A wallet address with prefix 0x42",
            "AddressShape",
            |b| wallet(b).address.0[0] = 0x42,
        ),
        bad_content(
            "R-ADDRESS-TOKEN",
            "A 20-byte token contract",
            "AddressShape",
            |b| usdt(b).asset = AssetId::Contract(Address(addr(0x99)[1..].to_vec())),
        ),
        bad_content(
            "R-ADDRESS-RECIPIENT",
            "A 22-byte TRX recipient",
            "AddressShape",
            |b| {
                let mut long = addr(0x22).to_vec();
                long.push(0x22);
                trx(b).recipients = RecipientsV1::Only(vec![Address(long), address(0x33)]);
            },
        ),
        bad_content("R-DECIMALS-TRX", "TRX with 18 decimals", "Decimals", |b| {
            trx(b).decimals = 18
        }),
        bad_content(
            "R-DECIMALS-TOKEN",
            "A token with 78 decimals (bound)",
            "Decimals",
            |b| usdt(b).decimals = 78,
        ),
        bad_content(
            "R-LAST-TIER-SHORT",
            "The top TRX tier ends one unit under max_per_tx",
            "LastTier",
            |b| trx(b).tiers[1].up_to = u(999_999_999),
        ),
        bad_content("R-LAST-TIER-NONE", "TRX with no tier", "LastTier", |b| {
            trx(b).tiers = Vec::new()
        }),
        bad_content(
            "R-ZERO-UNDECLARED",
            "A zero-approval tier the bundle does not declare",
            "ZeroApprovalFlag",
            |b| trx(b).tiers[0].approvals = 0,
        ),
        bad_content(
            "R-ZERO-UNUSED",
            "allows_zero_approval without a zero-approval tier",
            "ZeroApprovalFlag",
            |b| b.allows_zero_approval = true,
        ),
        case(
            "R-ROLLBACK-SAME",
            "offer step 3",
            Some("A-GENESIS"),
            "The installed bundle offered again",
        )
        .genesis("genesis", &b)
        .offer(
            "genesis",
            sign(&b, &[1, 2]),
            T1,
            refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"),
        ),
        case(
            "R-ROLLBACK-LOWER",
            "offer step 3",
            Some("A-TIGHTEN"),
            "The genesis again after a step",
        )
        .genesis("genesis", &b)
        .offer(
            "A-TIGHTEN/step-1of3",
            sign(&tight2, &[3]),
            T1,
            effective(&tight2),
        )
        .offer(
            "genesis",
            sign(&b, &[1, 2]),
            T1,
            refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"),
        ),
        case(
            "R-ROLLBACK-PENDING",
            "offer step 3 (the pending version counts)",
            Some("A-LOOSEN"),
            "A second epoch-2 bundle while epoch 2 is pending",
        )
        .genesis("genesis", &b)
        .offer(
            "A-LOOSEN/q2",
            sign(&loose, &[1, 3]),
            T1,
            pending(&loose, T1 + DAY),
        )
        .offer(
            "R-ROLLBACK-PENDING/v2",
            sign(&quorum(&base(), 2, |b| trx_cap(b, 3_000_000_000)), &[1, 2]),
            T1,
            refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"),
        ),
        case(
            "R-ROLLBACK-ZERO",
            "offer step 3",
            Some("A-GENESIS"),
            "A genesis at epoch 0",
        )
        .offer(
            "R-ROLLBACK-ZERO/v0",
            sign(&edited(base(), |b| b.epoch = 0), &[1, 2]),
            T0,
            refuse(RefusalCode::BUNDLE_ROLLBACK, "Rollback"),
        ),
        case(
            "R-GENESIS-ADMINS",
            "offer step 4",
            Some("A-THRESHOLD-N"),
            "A genesis whose admin set (3-of-3) is not the pin (2-of-3), signed by all three",
        )
        .offer(
            "A-THRESHOLD-N/v1",
            sign(&edited(base(), |b| b.admins.threshold = 3), &[1, 2, 3]),
            T0,
            invalid("GenesisAdmins"),
        ),
        case(
            "R-BAD-SIGNATURE",
            "offer step 6",
            Some("A-GENESIS"),
            "Admin 2's signature with one bit flipped",
        )
        .offer(
            "R-BAD-SIGNATURE/v1",
            {
                let mut bad = signature(2, &b.digest());
                bad.signature.0[10] ^= 0x04;
                sign_with(&b, vec![signature(1, &b.digest()), bad])
            },
            T0,
            invalid("BadSignature"),
        ),
        case(
            "R-BAD-SIGNATURE-TAG",
            "offer step 6 (domain separation)",
            Some("A-GENESIS"),
            "Admin 2 signed the body under the APPROVAL_V1 tag",
        )
        .offer(
            "R-BAD-SIGNATURE-TAG/v1",
            sign_with(
                &b,
                vec![
                    signature(1, &b.digest()),
                    signature(2, &tagged_digest(tag::APPROVAL_V1, &b)),
                ],
            ),
            T0,
            invalid("BadSignature"),
        ),
        case(
            "R-QUORUM-GENESIS",
            "offer step 7",
            Some("A-GENESIS"),
            "A genesis signed 1-of-3 (M − 1)",
        )
        .offer("R-QUORUM-GENESIS/v1", sign(&b, &[1]), T0, invalid("Quorum")),
        case(
            "R-QUORUM-UNPINNED",
            "offer step 7 (only pinned keys count)",
            Some("A-GENESIS"),
            "A genesis signed by two keys outside the admin set",
        )
        .offer(
            "R-QUORUM-UNPINNED/v1",
            sign(&b, &[4, 5]),
            T0,
            invalid("Quorum"),
        ),
        case(
            "R-QUORUM-DUPLICATE",
            "offer step 7 (each key counts once)",
            Some("A-GENESIS"),
            "A genesis signed twice by the same admin",
        )
        .offer(
            "R-QUORUM-DUPLICATE/v1",
            sign(&b, &[1, 1]),
            T0,
            invalid("Quorum"),
        ),
        case(
            "R-QUORUM-ZERO-TIGHTEN",
            "offer step 7 (zero approval needs M-of-N)",
            Some("A-ZERO-TIGHTEN"),
            "A zero-approval step that tightens, signed by one admin",
        )
        .genesis("genesis-zero", &zero())
        .offer(
            "R-QUORUM-ZERO-TIGHTEN/step-1of3",
            sign(&zero_step, &[1]),
            T1,
            invalid("Quorum"),
        ),
    ]);

    let rollback = |check| refuse(RefusalCode::BUNDLE_ROLLBACK, check);
    let seq_max = step(&b, |b| {
        trx_cap(b, 500_000_000);
        b.seq = u32::MAX;
    });
    let seq_at = |seq: u32| {
        step(&b, |b| {
            trx_cap(b, 500_000_000);
            b.seq = seq;
        })
    };
    let s2 = step(&tight2, |b| trx_cap(b, 400_000_000));
    let epoch_max = quorum(&b, u32::MAX, |b| trx_cap(b, 500_000_000));
    out.extend([
        case("R-SUPERSEDE-1OFN", "offer step 3 (a step while a loosening is pending)", Some("A-SUPERSEDE-MOFN"), "A step signed by one admin while a loosening is pending")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1 + 1, invalid("StepWhilePending"))
            .use_version(ver(2, 0), T1 + DAY, in_force(&loose)),
        case("R-QUORUM-SUPERSEDE-1OFN", "offer step 7 (a quorum bundle needs M-of-N)", Some("A-SUPERSEDE-MOFN"), "A quorum tightening signed by one admin while a loosening is pending")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("SUPERSEDE/q3-1of3", sign(&tight3, &[3]), T1 + 1, invalid("Quorum"))
            .use_version(ver(2, 0), T1 + DAY, in_force(&loose)),
        case("R-QUORUM-EPOCH-1OFN", "offer step 7 (one admin cannot start an epoch)", Some("A-ANCHOR-AFTER-QUORUM"), "A quorum tightening signed by one admin, with nothing pending")
            .genesis("genesis", &b)
            .offer("A-ANCHOR-AFTER-QUORUM/q2-1of3", sign(&anchor2, &[3]), T1, invalid("Quorum")),
        case("A-VERSION-EPOCH-AT-K", "offer step 3 (bound)", Some("A-ANCHOR-AFTER-QUORUM"), "A quorum bundle at epoch E + K (E = 1)")
            .genesis("genesis", &b)
            .offer("A-VERSION-EPOCH-AT-K/q17", sign(&quorum(&b, 1 + MAX_VERSION_STEP, |b| trx_cap(b, 500_000_000)), &[1, 2]), T1, effective(&quorum(&b, 1 + MAX_VERSION_STEP, |b| trx_cap(b, 500_000_000)))),
        case("A-VERSION-SEQ-AT-K", "offer step 3 (bound)", Some("A-TIGHTEN"), "A step at seq s + K (s = 0)")
            .genesis("genesis", &b)
            .offer("A-VERSION-SEQ-AT-K/step-16", sign(&seq_at(MAX_VERSION_STEP), &[3]), T1, effective(&seq_at(MAX_VERSION_STEP))),
        case("A-VERSION-GENESIS-AT-K", "offer step 3 (bound)", Some("A-GENESIS"), "A genesis at epoch K (E = 0)")
            .genesis("A-VERSION-GENESIS-AT-K/q16", &edited(base(), |b| b.epoch = MAX_VERSION_STEP)),
        case("A-VERSION-EPOCH-PAST-K", "offer step 3 (quorum epochs are not capped by K)", Some("A-VERSION-EPOCH-AT-K"), "A quorum bundle at epoch E + K + 1 (E = 1) takes effect")
            .genesis("genesis", &b)
            .offer("A-VERSION-EPOCH-PAST-K/q18", sign(&quorum(&b, 2 + MAX_VERSION_STEP, |b| trx_cap(b, 500_000_000)), &[1, 2]), T1, effective(&quorum(&b, 2 + MAX_VERSION_STEP, |b| trx_cap(b, 500_000_000)))),
        case("R-VERSION-SEQ-PAST-K", "offer step 3 (bound)", Some("A-VERSION-SEQ-AT-K"), "A step at seq s + K + 1 (s = 0)")
            .genesis("genesis", &b)
            .offer("R-VERSION-SEQ-PAST-K/step-17", sign(&seq_at(MAX_VERSION_STEP + 1), &[3]), T1, invalid("VersionGap")),
        case("R-VERSION-GAP-MAX", "offer step 3 (no single-admin freeze)", Some("A-TIGHTEN"), "A step by one admin at seq 2^32 − 1, which would end the step sequence")
            .genesis("genesis", &b)
            .offer("R-VERSION-GAP-MAX/step-max", sign(&seq_max, &[3]), T1, invalid("VersionGap")),
        case("A-VERSION-QUORUM-EPOCH-MAX", "offer step 3 (quorum epochs are not capped by K)", Some("A-VERSION-EPOCH-PAST-K"), "A quorum bundle at epoch 2^32 − 1 takes effect; it leaves no epoch for another quorum bundle, while steps still work")
            .genesis("genesis", &b)
            .offer("A-VERSION-QUORUM-EPOCH-MAX/q-max", sign(&epoch_max, &[1, 2]), T1, effective(&epoch_max))
            .offer("A-VERSION-QUORUM-EPOCH-MAX/q-max-again", sign(&quorum(&epoch_max, u32::MAX, |b| trx_cap(b, 400_000_000)), &[1, 2]), T1 + 1, rollback("Rollback"))
            .offer("A-VERSION-QUORUM-EPOCH-MAX/step", sign(&step(&epoch_max, |b| trx_cap(b, 400_000_000)), &[3]), T1 + 2, effective(&step(&epoch_max, |b| trx_cap(b, 400_000_000)))),
        case("R-VERSION-STEP-EPOCH", "offer step 3 (one admin cannot move the epoch)", Some("A-TIGHTEN"), "A step by one admin that names the next epoch")
            .genesis("genesis", &b)
            .offer("R-VERSION-STEP-EPOCH/step", sign(&step(&b, |b| { trx_cap(b, 500_000_000); b.epoch = 2; }), &[3]), T1, invalid("VersionGap")),
        case("R-VERSION-GENESIS-STEP", "offer step 3 (a genesis is a quorum bundle)", Some("A-GENESIS"), "A first bundle at (1, 1) with a zero parent")
            .offer("R-VERSION-GENESIS-STEP/step", sign(&edited(base(), |b| b.seq = 1), &[1, 2]), T0, invalid("VersionGap")),
        case("A-VERSION-GENESIS-PAST-K", "offer step 3 (quorum epochs are not capped by K)", Some("A-VERSION-GENESIS-AT-K"), "A genesis at epoch K + 1 (E = 0) takes effect")
            .genesis("A-VERSION-GENESIS-PAST-K/q17", &edited(base(), |b| b.epoch = MAX_VERSION_STEP + 1)),
        case("R-ROLLBACK-STEP", "offer step 3", Some("A-TIGHTEN"), "The first step again after the second")
            .genesis("genesis", &b)
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1, effective(&tight2))
            .offer("R-ROLLBACK-STEP/step-2", sign(&s2, &[3]), T1 + 1, effective(&s2))
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1 + 2, rollback("Rollback")),
        case("R-PARENT-FORK", "offer step 3 (a quorum bundle names the anchor)", Some("A-ANCHOR-AFTER-QUORUM"), "A signer whose anchor is another epoch-2 bundle cannot install an epoch-3 bundle built on the genesis")
            .genesis("genesis", &b)
            .offer("A-ANCHOR-AFTER-QUORUM/q2", sign(&anchor2, &[1, 2]), T1, effective(&anchor2))
            .offer("SUPERSEDE/q3-2of3", sign(&tight3, &[1, 2]), T1 + 1, rollback("ParentMismatch")),
        case("R-PARENT-GENESIS", "offer step 3 (genesis has a zero parent)", Some("A-GENESIS"), "A genesis that names a parent")
            .offer("R-PARENT-GENESIS/v1", sign(&edited(base(), |b| b.parent = [1; 32]), &[1, 2]), T0, rollback("ParentMismatch")),
        case("R-PARENT-ZERO", "offer step 3 (a step names the bundle in force)", Some("A-TIGHTEN"), "A step whose parent is all zeros instead of the genesis")
            .genesis("genesis", &b)
            .offer("R-PARENT-ZERO/step", sign(&step(&b, |b| { trx_cap(b, 500_000_000); b.parent = [0; 32]; }), &[3]), T1, rollback("ParentMismatch")),
        case("R-PARENT-STEP-ANCHOR", "offer step 3 (a step names the bundle in force)", Some("R-ROLLBACK-STEP"), "A second step that names the anchor instead of the step in force")
            .genesis("genesis", &b)
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1, effective(&tight2))
            .offer("R-PARENT-STEP-ANCHOR/step-2", sign(&step(&tight2, |b| { trx_cap(b, 400_000_000); b.parent = base().digest(); }), &[3]), T1 + 1, rollback("ParentMismatch")),
        case("R-PARENT-PENDING", "offer step 3 (a quorum bundle names the anchor)", Some("A-SUPERSEDE-MOFN"), "A quorum bundle that names the pending loosening, not the anchor, as its parent")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), T1, pending(&loose, T1 + DAY))
            .offer("R-PARENT-PENDING/q3", sign(&quorum(&b, 3, |b| { trx_cap(b, 500_000_000); b.parent = loose.digest(); }), &[1, 2]), T1 + 1, rollback("ParentMismatch")),
        case("R-PARENT-QUORUM-IN-FORCE", "offer step 3 (a quorum bundle names the anchor)", Some("A-ANCHOR-CLASS"), "A quorum bundle that names the step in force, not the anchor, as its parent")
            .genesis("genesis", &b)
            .offer("A-TIGHTEN/step-1of3", sign(&tight2, &[3]), T1, effective(&tight2))
            .offer("R-PARENT-QUORUM-IN-FORCE/q2", sign(&quorum(&tight2, 2, |_| {}), &[1, 2]), T1 + 1, rollback("ParentMismatch")),
        case("R-LOCK-OVERFLOW", "offer step 8 (bound)", Some("A-LOOSEN"), "A loosening received so late that its time lock would end past 2^64 − 1 ms; one millisecond earlier it ends exactly there")
            .genesis("genesis", &b)
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), u64::MAX - DAY + 1, refuse(RefusalCode::CLOCK_UNTRUSTED, "LockOverflow"))
            .offer("A-LOOSEN/q2", sign(&loose, &[1, 3]), u64::MAX - DAY, pending(&loose, u64::MAX)),
        case("R-BAD-SIGNATURE-SMALL-ORDER-R", "offer step 6 (strict verification)", Some("A-GENESIS"), "Admin 2's signature has a small-order R: cofactorless verification accepts it, strict verification refuses it")
            .offer("R-BAD-SIGNATURE-SMALL-ORDER-R/v1", sign_with(&b, vec![signature(1, &b.digest()), small_order_r_signature(2, &b.digest())]), T0, invalid("BadSignature")),
    ]);

    // ── the classifier on bodies step 2 refuses ──
    let no_windows = edited(base(), |b| trx(b).windows = Vec::new());
    out.extend([
        case(
            "T-CLASSIFY-WINDOWS-FROM-NONE",
            "tightening table (asset.windows)",
            None,
            "TRX from no window (nothing allowed) to an unbounded window: not a tightening",
        )
        .classify(
            ("T-CLASSIFY/no-windows", sign(&no_windows, &[1, 2])),
            (
                "T-CLASSIFY/any-window",
                sign(
                    &step(&no_windows, |b| {
                        trx(b).windows = vec![window(DAY, u64::MAX, u32::MAX, u64::MAX)]
                    }),
                    &[1, 2],
                ),
            ),
            false,
        ),
        case(
            "T-CLASSIFY-WINDOWS-NONE-KEPT",
            "tightening table (asset.windows)",
            Some("T-CLASSIFY-WINDOWS-FROM-NONE"),
            "TRX with no window before and after: a tightening",
        )
        .classify(
            ("T-CLASSIFY/no-windows", sign(&no_windows, &[1, 2])),
            (
                "T-CLASSIFY/no-windows-v2",
                sign(&step(&no_windows, |_| {}), &[1, 2]),
            ),
            true,
        ),
    ]);

    // ── the tightening table ──
    out.extend(table_cases());

    // ── using the policy ──
    let view = json!({ "view": {
        "wallet_id": WALLET,
        "network": NILE,
        "wallet_address": hx(&addr(0x11)),
        "permission_id": "2",
        "trc20_allowlist": [hx(&addr(0x99))],
        "max_validity_ms": "3600000",
        "max_fee_limit_sun": "100000000",
        "max_clock_skew_ms": "120000",
    } });
    let used = |id, rule, description| {
        case(id, rule, Some("A-GENESIS"), description).genesis("genesis", &base())
    };
    let mut other_wallet = intent(AssetId::Native, 0x22, 1);
    other_wallet.wallet_id = WalletId::new("hot-two").unwrap();
    let mut other_network = intent(AssetId::Native, 0x22, 1);
    other_network.network = NetworkId::new(SHASTA).unwrap();
    out.extend([
        case(
            "U-NO-POLICY",
            "use (no bundle)",
            None,
            "Nothing installed: every request is refused",
        )
        .use_version(ver(1, 0), T0, refuse(RefusalCode::NO_POLICY, "NoPolicy"))
        .view(
            ver(1, 0),
            WALLET,
            NILE,
            refuse(RefusalCode::NO_POLICY, "NoPolicy"),
        ),
        used(
            "U-VERSION-MISMATCH",
            "use (version)",
            "A request naming a version that was never installed",
        )
        .use_version(
            ver(2, 0),
            T1,
            refuse(RefusalCode::POLICY_VERSION_MISMATCH, "VersionMismatch"),
        )
        .use_version(
            ver(0, 0),
            T1,
            refuse(RefusalCode::POLICY_VERSION_MISMATCH, "VersionMismatch"),
        ),
        used(
            "U-VIEW",
            "use (decoder view)",
            "The decoder's context comes from the bundle",
        )
        .view(ver(1, 0), WALLET, NILE, view),
        used(
            "U-VIEW-UNKNOWN-WALLET",
            "use (decoder view)",
            "A wallet the bundle does not list",
        )
        .view(
            ver(1, 0),
            "hot-two",
            NILE,
            refuse(RefusalCode::UNKNOWN_WALLET, "UnknownWallet"),
        ),
        used(
            "U-VIEW-NETWORK",
            "use (decoder view)",
            "The wallet's own id on another network",
        )
        .view(
            ver(1, 0),
            WALLET,
            SHASTA,
            refuse(RefusalCode::NETWORK_MISMATCH, "NetworkMismatch"),
        ),
        used(
            "U-INTENT-TIERS",
            "use (asset rules, tier edges)",
            "TRX at each tier edge and the cap; the token to an unlisted recipient",
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Native, 0x22, 1),
            admitted(&AssetId::Native, 1),
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Native, 0x22, 100_000_000),
            admitted(&AssetId::Native, 1),
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Native, 0x33, 100_000_001),
            admitted(&AssetId::Native, 2),
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Native, 0x22, 1_000_000_000),
            admitted(&AssetId::Native, 2),
        )
        .intent(
            ver(1, 0),
            &intent(token(), 0x55, 1_000_001),
            admitted(&token(), 2),
        ),
        used(
            "U-INTENT-CAP",
            "use (asset rules)",
            "TRX one base unit over max_per_tx (bound)",
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Native, 0x22, 1_000_000_001),
            refuse(RefusalCode::AMOUNT_OVER_TX_CAP, "AmountOverCap"),
        ),
        used(
            "U-INTENT-ASSET",
            "use (asset rules, deny by default)",
            "A token the bundle does not list",
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Contract(address(0x98)), 0x22, 1),
            refuse(RefusalCode::ASSET_NOT_ALLOWED, "AssetNotAllowed"),
        ),
        used(
            "U-INTENT-RECIPIENT",
            "use (asset rules)",
            "TRX to an address not on its list",
        )
        .intent(
            ver(1, 0),
            &intent(AssetId::Native, 0x44, 1),
            refuse(RefusalCode::RECIPIENT_NOT_ALLOWED, "RecipientNotAllowed"),
        ),
        used(
            "U-INTENT-UNKNOWN-WALLET",
            "use (asset rules)",
            "An intent for a wallet the bundle does not list",
        )
        .intent(
            ver(1, 0),
            &other_wallet,
            refuse(RefusalCode::UNKNOWN_WALLET, "UnknownWallet"),
        ),
        used(
            "U-INTENT-NETWORK",
            "use (asset rules)",
            "An intent on another network",
        )
        .intent(
            ver(1, 0),
            &other_network,
            refuse(RefusalCode::NETWORK_MISMATCH, "NetworkMismatch"),
        ),
    ]);
    out
}

// ───────────────────────────── the runner (JSON only) ─────────────────────────────

fn num(v: &Value) -> u64 {
    v.as_str()
        .unwrap_or_else(|| panic!("expected a decimal string, got {v}"))
        .parse()
        .unwrap()
}

fn key_list(v: &Value) -> Vec<Ed25519Pub> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|k| Ed25519Pub(unhex(k.as_str().unwrap()).try_into().unwrap()))
        .collect()
}

fn refusal_json(r: PolicyRefusal) -> Value {
    json!({ "refuse": {
        "code": format!("0x{:04x}", r.code().0),
        "name": r.code().name(),
        "check": format!("{r:?}"),
    } })
}

fn offer_json(offer: Offer) -> Value {
    match offer {
        Offer::Effective { version, digest } => {
            json!({ "effective": { "version": ver_json(version), "digest": hx(&digest) } })
        }
        Offer::Pending {
            version,
            digest,
            effective_at_ms,
        } => json!({ "pending": {
            "version": ver_json(version),
            "digest": hx(&digest),
            "effective_at_ms": effective_at_ms.to_string(),
        } }),
    }
}

/// What the kernel answers to one step.
fn answer(state: &mut PolicyState, genesis: &AdminSetV1, bundles: &Value, step: &Value) -> Value {
    let (kind, input) = step.as_object().unwrap().iter().next().unwrap();
    if kind == "classify" {
        let body = |name: &Value| {
            let hex = bundles[name.as_str().unwrap()].as_str().unwrap();
            from_canonical_strict::<SignedPolicyBundleV1>(&unhex(hex))
                .unwrap()
                .body
        };
        return json!({ "tightens": tightens(&body(&input["old"]), &body(&input["new"])) });
    }
    let now = num(&input["now_ms"]);
    if kind == "offer" {
        let bytes = unhex(bundles[input["bundle"].as_str().unwrap()].as_str().unwrap());
        return match state.offer(genesis, &bytes, now) {
            Ok((next, offer)) => {
                *state = next;
                offer_json(offer)
            }
            Err(r) => refusal_json(r),
        };
    }
    let version = &input["version"];
    let version = ver(
        u32::try_from(num(&version["epoch"])).unwrap(),
        u32::try_from(num(&version["seq"])).unwrap(),
    );
    let bundle = match state.for_version(version, now) {
        Ok(bundle) => bundle,
        Err(r) => return refusal_json(r),
    };
    match kind.as_str() {
        "use" => json!({ "in_force": {
            "version": ver_json(bundle.version()),
            "digest": hx(&bundle.digest()),
        } }),
        "view" => {
            let wallet_id = WalletId::new(input["wallet_id"].as_str().unwrap()).unwrap();
            let network = NetworkId::new(input["network"].as_str().unwrap()).unwrap();
            match bundle.tron_ctx(&wallet_id, network, now, None) {
                Ok(ctx) => json!({ "view": {
                    "wallet_id": ctx.wallet_id.as_str(),
                    "network": ctx.network.as_str(),
                    "wallet_address": hx(&ctx.wallet_address),
                    "permission_id": ctx.permission_id.to_string(),
                    "trc20_allowlist": ctx.trc20_allowlist.iter().map(|a| hx(a)).collect::<Vec<_>>(),
                    "max_validity_ms": ctx.max_validity_ms.to_string(),
                    "max_fee_limit_sun": ctx.max_fee_limit_sun.to_string(),
                    "max_clock_skew_ms": ctx.max_clock_skew_ms.to_string(),
                } }),
                Err(r) => refusal_json(r),
            }
        }
        "intent" => {
            let intent: IntentV1 =
                from_canonical_strict(&unhex(input["intent"].as_str().unwrap())).unwrap();
            match bundle.check_intent(&intent) {
                Ok(rule) => json!({ "rule": {
                    "asset": hx(&to_canonical(&rule.asset).unwrap()),
                    "approvals": rule.approvals_for(intent.amount).map(|a| a.to_string()),
                } }),
                Err(r) => refusal_json(r),
            }
        }
        other => panic!("unknown step kind {other}"),
    }
}

/// Replays one vector against a fresh [`PolicyState`]; `Err` names the first step that differs.
fn run(vector: &Value, bundles: &Value) -> Result<(), String> {
    let mut fields: Vec<&str> = vector
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["base", "description", "expect", "id", "input", "rule"]
    );
    let input = &vector["input"];
    let genesis = AdminSetV1 {
        threshold: u8::try_from(num(&input["genesis"]["threshold"])).unwrap(),
        keys: key_list(&input["genesis"]["keys"]),
    };
    let steps = input["steps"].as_array().unwrap();
    let expect = vector["expect"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), expect.len(), "{}", vector["id"]);
    assert!(!steps.is_empty(), "no vacuous pass (KAT plan R10)");
    let mut state = PolicyState::default();
    for (i, (step, want)) in steps.iter().zip(expect).enumerate() {
        if let Some(r) = want.get("refuse") {
            // KAT plan §2: the code and its name agree with the registry.
            let code =
                u16::from_str_radix(r["code"].as_str().unwrap().trim_start_matches("0x"), 16);
            assert_eq!(
                RefusalCode(code.unwrap()).name(),
                r["name"].as_str(),
                "{}",
                vector["id"]
            );
        }
        let got = answer(&mut state, &genesis, bundles, step);
        if got != *want {
            return Err(format!("{} step {i}: got {got}, want {want}", vector["id"]));
        }
    }
    Ok(())
}

// ───────────────────────────── the vector file ─────────────────────────────

fn generate() -> Value {
    let mut bundles = BTreeMap::new();
    let mut vectors = Vec::new();
    for c in cases() {
        for (name, bytes) in &c.bundles {
            let hex = hx(bytes);
            if let Some(old) = bundles.insert(name.clone(), hex.clone()) {
                assert_eq!(old, hex, "bundle name {name} reused for other bytes");
            }
        }
        vectors.push(c.vector());
    }
    // Test-only seeds: public here, so they must never hold value on any network.
    let key = |seed: u8| json!({ "seed": hx(&[seed; 32]), "public_key": hx(&pk(seed).0) });
    json!({
        "rfc": "POLICY_BUNDLE_V1",
        "rfc_version": "DRAFT (RFC text pending, T05-7b); module docs of vaultex_verify::policy",
        "kind": "regression",
        "generated_by": [{
            "tool": "crates/vaultex-verify/tests/policy_bundle.rs (fn cases, test policy_regenerate_vector_file)",
            "version": format!("vaultex-verify {}", env!("CARGO_PKG_VERSION")),
            "note": "Written by the same author as the Rust code, and encoded with the kernel's own BCS and SHA-256: regression vectors (KAT plan R1), not external evidence. Expected outcomes and codes are written by hand. The independent oracle has not reproduced them yet.",
        }],
        "keys": {
            "note": "Test-only seeds (32 x one byte), published here: never use them for value on any network.",
            "admin1": key(1), "admin2": key(2), "admin3": key(3), "outsider4": key(4),
            "admin5": key(5), "initiator": key(INITIATOR), "approver1": key(0x21),
            "approver2": key(0x22), "extra": key(EXTRA_KEY),
        },
        "encoding": "bundles: hex of BCS(SignedPolicyBundleV1). intent: hex of BCS(IntentV1). asset: hex of BCS(AssetId). classify: the bodies of two named bundles (signatures unused). version: {epoch, seq}; requests and receipts name it as epoch * 2^32 + seq. Integers: decimal strings.",
        "bundles": bundles,
        "vectors": vectors,
    })
}

fn file() -> Value {
    let text = std::fs::read_to_string(VECTOR_PATH)
        .unwrap_or_else(|e| panic!("{VECTOR_PATH}: {e}; run policy_regenerate_vector_file"));
    serde_json::from_str(&text).unwrap()
}

fn generated() -> &'static Value {
    static GENERATED: OnceLock<Value> = OnceLock::new();
    GENERATED.get_or_init(generate)
}

/// Runs every generated case whose id starts with one of `prefixes`, and fails on the first
/// mismatch in each, listing all of them.
fn check(prefixes: &[&str]) {
    let generated = generated();
    let mut ran = 0;
    let mut failures = Vec::new();
    for v in generated["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().trim_start_matches(PREFIX);
        if prefixes.iter().any(|p| id.starts_with(p)) {
            ran += 1;
            if let Err(e) = run(v, &generated["bundles"]) {
                failures.push(e);
            }
        }
    }
    assert!(ran > 0, "no case matches {prefixes:?}");
    assert!(
        failures.is_empty(),
        "{} failing:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
#[ignore = "writes the vector file; run after changing a case"]
fn policy_regenerate_vector_file() {
    let path = PathBuf::from(VECTOR_PATH);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = serde_json::to_string_pretty(&generate()).unwrap();
    std::fs::write(&path, text + "\n").unwrap();
}

#[test]
fn policy_vector_file_matches_generator() {
    assert!(
        file() == *generated(),
        "the vector file differs from cases(); run policy_regenerate_vector_file"
    );
}

/// The kernel replays the file itself: every vector, from its JSON alone.
#[test]
fn policy_vector_file_replays_through_the_kernel() {
    let f = file();
    assert_eq!(f["rfc"], "POLICY_BUNDLE_V1");
    let vectors = f["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty(), "no vacuous pass (KAT plan R10)");
    let mut ids = std::collections::BTreeSet::new();
    let failures: Vec<String> = vectors
        .iter()
        .inspect(|v| {
            assert!(
                ids.insert(v["id"].as_str().unwrap()),
                "duplicate {}",
                v["id"]
            )
        })
        .filter_map(|v| run(v, &f["bundles"]).err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    for v in vectors {
        if let Some(base) = v["base"].as_str() {
            assert!(ids.contains(base), "{}: unknown base {base}", v["id"]);
        }
    }
}

// ───────────────────────────── one named test per check ─────────────────────────────

#[test]
fn policy_accepts_valid_sequences() {
    check(&["A-"]);
}

#[test]
fn policy_refuses_malformed() {
    check(&["R-MALFORMED"]);
}

#[test]
fn policy_refuses_admin_threshold() {
    check(&["R-ADMIN-THRESHOLD"]);
}

#[test]
fn policy_refuses_unsorted_lists() {
    check(&["R-UNSORTED"]);
}

#[test]
fn policy_refuses_weak_keys() {
    check(&["R-WEAK-KEY"]);
}

#[test]
fn policy_refuses_long_delay() {
    check(&["R-DELAY-LONG", "A-DELAY-MAX"]);
}

#[test]
fn policy_refuses_no_windows() {
    check(&["R-NO-WINDOWS"]);
}

#[test]
fn policy_refuses_version_gap() {
    check(&["R-VERSION"]);
}

#[test]
fn policy_accepts_versions_in_range() {
    check(&["A-VERSION"]);
}

/// Quorum epochs are not capped by K (owner decision, 2026-10-18): E + K + 1 and 2^32 − 1 install.
#[test]
fn policy_quorum_epoch_not_capped_by_k() {
    check(&[
        "A-VERSION-EPOCH-PAST-K",
        "A-VERSION-GENESIS-PAST-K",
        "A-VERSION-QUORUM-EPOCH-MAX",
    ]);
}

#[test]
fn policy_supersede_pending_needs_m_of_n() {
    check(&["R-SUPERSEDE", "R-QUORUM-SUPERSEDE"]);
}

/// (a) A quorum bundle signed against the anchor survives twenty no-op steps.
#[test]
fn policy_quorum_bundle_survives_step_churn() {
    check(&["A-STEP-CHURN-THEN-ROTATION"]);
}

/// (b) A quorum bundle is classified against the bundle in force, steps included.
#[test]
fn policy_quorum_bundle_classified_against_in_force() {
    check(&["A-ANCHOR-CLASS", "R-PARENT-QUORUM-IN-FORCE"]);
}

/// (c) A cancelled or replaced pending quorum bundle cannot come back.
#[test]
fn policy_no_replay_of_cancelled_or_replaced_pending() {
    check(&[
        "A-CANCELLED-LOOSENING-SEEN",
        "A-MISSED-CANCELLED-LOOSENING",
        "A-LOOSEN-REPLACES",
    ]);
}

/// (e) One admin can neither end the step sequence nor move the epoch.
#[test]
fn policy_no_single_admin_freeze() {
    check(&[
        "R-VERSION-GAP-MAX",
        "R-VERSION-STEP-EPOCH",
        "R-QUORUM-EPOCH-1OFN",
    ]);
}

/// (g) A genesis is a quorum bundle with a zero parent.
#[test]
fn policy_genesis_is_a_quorum_bundle() {
    check(&["A-GENESIS", "R-PARENT-GENESIS", "R-VERSION-GENESIS-STEP"]);
}

/// The anchor moves with the quorum bundle in force, whether it took effect at once or after its
/// lock.
#[test]
fn policy_anchor_moves_with_quorum_bundles() {
    check(&["A-ANCHOR-AFTER"]);
}

#[test]
fn policy_supersede_pending_with_m_of_n() {
    check(&["A-SUPERSEDE"]);
}

/// Two signers, one of which never received a loosening that a later bundle cancelled, end with
/// the same bundle in force, and neither can be given the cancelled one afterwards.
#[test]
fn policy_missed_cancelled_loosening_converges() {
    check(&["A-CANCELLED-LOOSENING-SEEN", "A-MISSED-CANCELLED-LOOSENING"]);
    let loose = quorum(&base(), 2, |b| trx_cap(b, 2_000_000_000));
    let cancel = quorum(&base(), 3, |b| trx_cap(b, 500_000_000));
    let genesis = PolicyState::default()
        .offer(&admins(), &sign(&base(), &[1, 2]), T0)
        .unwrap()
        .0;
    let (seen, _) = genesis
        .offer(&admins(), &sign(&loose, &[1, 3]), T1)
        .unwrap();
    let (seen, _) = seen
        .offer(&admins(), &sign(&cancel, &[1, 2]), T1 + 1)
        .unwrap();
    let (missed, _) = genesis
        .offer(&admins(), &sign(&cancel, &[1, 2]), T1 + 1)
        .unwrap();
    for now in [T1 + 1, T1 + DAY, T1 + 30 * DAY] {
        let digests = [&seen, &missed].map(|s| s.effective(now).map(|b| b.digest()));
        assert_eq!(digests, [Some(cancel.digest()); 2], "at {now}");
        assert!(seen.pending().is_none() && missed.pending().is_none());
    }
    for state in [&seen, &missed] {
        let late = state.offer(&admins(), &sign(&loose, &[1, 3]), T1 + 2);
        assert_eq!(late.map(|_| ()), Err(PolicyRefusal::Rollback));
    }
}

#[test]
fn policy_refuses_parent_mismatch() {
    check(&["R-PARENT"]);
}

#[test]
fn policy_refuses_lock_overflow() {
    check(&["R-LOCK-OVERFLOW"]);
}

/// The windows row of the tightening table, on a body step 2 now refuses.
#[test]
fn policy_classifier_no_windows_allows_nothing() {
    check(&["T-CLASSIFY"]);
}

/// The constructed vector exercises exactly the difference between the two rules.
#[test]
fn policy_small_order_r_vector_is_cofactorless_valid() {
    let digest = base().digest();
    let sig = small_order_r_signature(2, &digest);
    let vk = VerifyingKey::from_bytes(&pk(2).0).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig.signature.0);
    assert!(vk.verify(&digest, &sig).is_ok());
    assert!(vk.verify_strict(&digest, &sig).is_err());
}

#[test]
fn policy_refuses_short_delay() {
    check(&["R-DELAY"]);
}

#[test]
fn policy_refuses_non_tron_network() {
    check(&["R-NOT-TRON"]);
}

#[test]
fn policy_refuses_address_shape() {
    check(&["R-ADDRESS"]);
}

#[test]
fn policy_refuses_decimals() {
    check(&["R-DECIMALS"]);
}

#[test]
fn policy_refuses_last_tier() {
    check(&["R-LAST-TIER"]);
}

#[test]
fn policy_refuses_zero_approval_flag() {
    check(&["R-ZERO"]);
}

#[test]
fn policy_refuses_rollback() {
    check(&["R-ROLLBACK"]);
}

#[test]
fn policy_refuses_genesis_admins() {
    check(&["R-GENESIS-ADMINS"]);
}

#[test]
fn policy_refuses_bad_signature() {
    check(&["R-BAD-SIGNATURE"]);
}

#[test]
fn policy_refuses_short_quorum() {
    check(&["R-QUORUM", "A-JUDGE-IS-EFFECTIVE"]);
}

#[test]
fn policy_loosening_needs_quorum_and_time_lock() {
    check(&["T-LOOSEN"]);
}

#[test]
fn policy_tightening_needs_one_admin() {
    check(&["T-TIGHTEN"]);
}

#[test]
fn policy_refuses_until_time_lock_ends() {
    check(&["A-LOOSEN", "A-LOCK-FROM-RECEIPT", "A-DELAY-OF-ACTIVE"]);
}

#[test]
fn policy_refuses_no_policy() {
    check(&["U-NO-POLICY"]);
}

#[test]
fn policy_refuses_version_mismatch() {
    check(&["U-VERSION-MISMATCH", "A-TIGHTEN"]);
}

#[test]
fn policy_refuses_unknown_wallet() {
    check(&["U-VIEW-UNKNOWN-WALLET", "U-INTENT-UNKNOWN-WALLET"]);
}

#[test]
fn policy_refuses_network_mismatch() {
    check(&["U-VIEW-NETWORK", "U-INTENT-NETWORK"]);
}

#[test]
fn policy_refuses_asset_not_allowed() {
    check(&["U-INTENT-ASSET"]);
}

#[test]
fn policy_refuses_amount_over_cap() {
    check(&["U-INTENT-CAP"]);
}

#[test]
fn policy_refuses_recipient_not_allowed() {
    check(&["U-INTENT-RECIPIENT"]);
}

#[test]
fn policy_decoder_view_and_tiers() {
    check(&["U-VIEW", "U-INTENT-TIERS"]);
}

/// Every row of the tightening table has a case that loosens it, or (where only equality
/// tightens) a case that changes it.
#[test]
fn policy_table_rows_have_cases() {
    let rows = table_rows();
    for field in [
        "ADMINS",
        "DELAY",
        "INITIATORS",
        "APPROVERS",
        "REFUSALS",
        "REFUSAL-WINDOW",
        "PAUSE",
        "SKEW",
        "WALLET",
        "FEE",
        "VALIDITY",
        "ASSET",
        "CAP",
        "RECIPIENTS",
        "TIER",
        "WINDOW",
    ] {
        assert!(
            rows.iter()
                .any(|r| r.name.starts_with(field) && !r.tightens),
            "no loosening case for {field}"
        );
    }
}

// ───────────────────────────── the decoder, wired from the bundle ─────────────────────────────

/// The TRC-20 `transfer` vector under `Permission_id = 2` from `tron_decode.rs`: 1,000,000 base
/// units of token 0x41 99… from 0x41 11… to 0x41 22…, `fee_limit` 100 TRX.
const TRC20_PERM2_HEX: &str = "0a0200012208010203040506070840e0a499ffbc315ab001081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541111111111111111111111111111111111111111112154199999999999999999999999999999999999999992244a9059cbb000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000f424028027080d095ffbc31900180c2d72f";
/// Inside the vector's validity window.
const DECODE_NOW: u64 = 1_700_000_010_000;

fn installed(body: &PolicyBundleV1) -> PolicyState {
    PolicyState::default()
        .offer(&admins(), &sign(body, &[1, 2]), T0)
        .unwrap()
        .0
}

#[test]
fn policy_tron_ctx_decodes_with_bundle_facts() {
    let state = installed(&base());
    let bundle = state.for_version(ver(1, 0), DECODE_NOW).unwrap();
    let wallet_id = WalletId::new(WALLET).unwrap();
    let ctx = bundle
        .tron_ctx(&wallet_id, nile(), DECODE_NOW, None)
        .unwrap();
    let (intent, _) = decode(&unhex(TRC20_PERM2_HEX), &ctx).unwrap();
    assert_eq!(intent.asset, token());
    assert_eq!(intent.amount, u(1_000_000));
    let rule = bundle.check_intent(&intent).unwrap();
    assert_eq!(rule.approvals_for(intent.amount), Some(1));
}

#[test]
fn policy_tron_ctx_denies_by_default() {
    // Without the token's rule, the decoder's allowlist no longer holds it.
    let state = installed(&edited(base(), |b| {
        b.wallets[0].assets.pop();
    }));
    let bundle = state.for_version(ver(1, 0), DECODE_NOW).unwrap();
    let wallet_id = WalletId::new(WALLET).unwrap();
    let ctx = bundle
        .tron_ctx(&wallet_id, nile(), DECODE_NOW, None)
        .unwrap();
    assert_eq!(
        decode(&unhex(TRC20_PERM2_HEX), &ctx).map(|_| ()),
        Err(TronRefusal::TokenNotAllowlisted)
    );
    // A bundle that pins permission 0 refuses the permission-2 transaction.
    let state = installed(&edited(base(), |b| wallet(b).permission_id = 0));
    let bundle = state.for_version(ver(1, 0), DECODE_NOW).unwrap();
    let ctx = bundle
        .tron_ctx(&wallet_id, nile(), DECODE_NOW, None)
        .unwrap();
    assert_eq!(
        decode(&unhex(TRC20_PERM2_HEX), &ctx).map(|_| ()),
        Err(TronRefusal::PermissionIdMismatch)
    );
}

// ───────────────────────────── the installed file ─────────────────────────────

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vaultex-policy-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn loosened() -> PolicyBundleV1 {
    quorum(&base(), 2, |b| trx_cap(b, 2_000_000_000))
}

#[test]
fn policy_store_records_and_reloads() {
    let path = temp_dir("reload").join("policy.bcs");
    let mut store = PolicyStore::open(&path, admins()).unwrap();
    assert_eq!(
        store.state().for_version(ver(1, 0), T0).map(|_| ()),
        Err(PolicyRefusal::NoPolicy)
    );
    assert!(!path.exists());

    store.offer(&sign(&base(), &[1, 2]), T0).unwrap();
    let pending = store.offer(&sign(&loosened(), &[1, 3]), T1).unwrap();
    assert!(
        matches!(pending, Offer::Pending { effective_at_ms, .. } if effective_at_ms == T1 + DAY)
    );
    drop(store);

    // The pending bundle and this signer's receipt time survive a restart.
    let mut store = PolicyStore::open(&path, admins()).unwrap();
    let state = store.state();
    assert_eq!(
        state.for_version(ver(2, 0), T1 + DAY - 1).map(|_| ()),
        Err(PolicyRefusal::NotEffective)
    );
    assert_eq!(
        state.for_version(ver(2, 0), T1 + DAY).unwrap().digest(),
        loosened().digest()
    );
    assert_eq!(
        state.pending().map(|(b, at)| (b.version(), at)),
        Some((ver(2, 0), T1 + DAY))
    );

    // After the lock, the promoted bundle judges: admin 3 alone may tighten it.
    let tighter = step(&loosened(), |b| trx_cap(b, 1_500_000_000));
    store.offer(&sign(&tighter, &[3]), T1 + DAY).unwrap();
    drop(store);
    let store = PolicyStore::open(&path, admins()).unwrap();
    assert_eq!(store.state().effective(T0).unwrap().version(), ver(2, 1));
    assert!(store.state().pending().is_none());
}

#[test]
fn policy_store_is_locked_while_open() {
    let path = temp_dir("lock").join("policy.bcs");
    let _store = PolicyStore::open(&path, admins()).unwrap();
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::Store(StoreError::Locked))
    );
}

#[test]
fn policy_store_failed_write_changes_nothing() {
    let path = temp_dir("write").join("policy.bcs");
    let mut store = PolicyStore::open(&path, admins()).unwrap();
    // The temporary file cannot be created: a directory holds its name.
    std::fs::create_dir(path.with_extension("bcs.tmp")).unwrap();
    let result = store.offer(&sign(&base(), &[1, 2]), T0);
    assert!(
        matches!(result, Err(PolicyRefusal::Store(StoreError::Io(_)))),
        "{result:?}"
    );
    assert_eq!(
        store.state().for_version(ver(1, 0), T0).map(|_| ()),
        Err(PolicyRefusal::NoPolicy)
    );
    assert!(!path.exists());
    // The store is poisoned until reopened, even once the obstacle is gone.
    std::fs::remove_dir(path.with_extension("bcs.tmp")).unwrap();
    assert_eq!(
        store.offer(&sign(&base(), &[1, 2]), T0),
        Err(PolicyRefusal::Store(StoreError::Failed))
    );
    drop(store);
    let mut store = PolicyStore::open(&path, admins()).unwrap();
    assert!(store.offer(&sign(&base(), &[1, 2]), T0).is_ok());
}

/// The installed file's layout: the active signed bundle, the anchor, then the pending one with
/// its receipt time. Written here by hand to tamper with it. The anchor is the active bundle's own
/// digest (an active quorum bundle) unless given.
fn write_installed_with(
    path: &Path,
    active: Vec<u8>,
    anchor: Option<[u8; 32]>,
    pending: Option<(Vec<u8>, u64)>,
) {
    let decode = |bytes: Vec<u8>| from_canonical_strict::<SignedPolicyBundleV1>(&bytes).unwrap();
    let active = decode(active);
    let anchor = anchor.unwrap_or_else(|| active.body.digest());
    let file = (
        active,
        anchor,
        pending.map(|(bytes, at)| (decode(bytes), at)),
    );
    std::fs::write(path, to_canonical(&file).unwrap()).unwrap();
}

fn write_installed(path: &Path, active: Vec<u8>, pending: Option<(Vec<u8>, u64)>) {
    write_installed_with(path, active, None, pending);
}

/// (h) The anchor survives restarts: a quorum bundle signed against the genesis installs after a
/// step and a restart; a step while it is pending is still refused after another restart; once in
/// force it anchors the next quorum bundle, across a restart that follows a step on it.
#[test]
fn policy_store_keeps_the_anchor_across_restarts() {
    let path = temp_dir("anchor").join("policy.bcs");
    let open = || PolicyStore::open(&path, admins()).unwrap();
    let rotation = quorum(&base(), 2, |b| b.admins.keys = keys(&[1, 2, 5]));
    let s1 = step(&base(), |b| trx_cap(b, 500_000_000));
    let mut store = open();
    store.offer(&sign(&base(), &[1, 2]), T0).unwrap();
    store.offer(&sign(&s1, &[3]), T1).unwrap();
    drop(store);

    let mut store = open();
    let offered = store.offer(&sign(&rotation, &[1, 2]), T1 + 1);
    assert!(matches!(offered, Ok(Offer::Pending { .. })), "{offered:?}");
    drop(store);

    let mut store = open();
    let late = step(&s1, |b| trx_cap(b, 400_000_000));
    assert_eq!(
        store.offer(&sign(&late, &[3]), T1 + 2),
        Err(PolicyRefusal::StepWhilePending)
    );
    let on_rotation = step(&rotation, |b| trx_cap(b, 500_000_000));
    store
        .offer(&sign(&on_rotation, &[5]), T1 + 1 + DAY)
        .unwrap();
    drop(store);

    let mut store = open();
    let next_epoch = quorum(&rotation, 3, |b| trx_cap(b, 400_000_000));
    let offered = store.offer(&sign(&next_epoch, &[1, 5]), T1 + 2 + DAY);
    assert!(
        matches!(offered, Ok(Offer::Effective { .. })),
        "{offered:?}"
    );
}

#[test]
fn policy_store_rechecks_the_anchor() {
    let path = temp_dir("anchor-check").join("policy.bcs");
    // An active quorum bundle is its own anchor.
    write_installed_with(&path, sign(&base(), &[1, 2]), Some([7; 32]), None);
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::ParentMismatch)
    );
}

#[test]
fn policy_store_refuses_a_damaged_file() {
    let path = temp_dir("damaged").join("policy.bcs");
    let mut store = PolicyStore::open(&path, admins()).unwrap();
    store.offer(&sign(&base(), &[1, 2]), T0).unwrap();
    drop(store);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::Malformed)
    );

    // Content rules are checked again on load.
    write_installed(
        &path,
        sign(&edited(base(), |b| trx(b).decimals = 18), &[1, 2]),
        None,
    );
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::Decimals)
    );
}

#[test]
fn policy_store_rechecks_the_pending_bundle() {
    let path = temp_dir("pending").join("policy.bcs");
    // A loosening recorded with one signature: short of the active admins' quorum.
    write_installed(
        &path,
        sign(&base(), &[1, 2]),
        Some((sign(&loosened(), &[1]), T1)),
    );
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::Quorum)
    );
    // A pending version that is not above the active one.
    write_installed(
        &path,
        sign(&loosened(), &[1, 2]),
        Some((sign(&base(), &[1, 2]), T1)),
    );
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::Rollback)
    );
    // A forged signature on the pending bundle.
    let mut forged =
        from_canonical_strict::<SignedPolicyBundleV1>(&sign(&loosened(), &[1, 2])).unwrap();
    forged.signatures[1].signature.0[0] ^= 1;
    write_installed(
        &path,
        sign(&base(), &[1, 2]),
        Some((to_canonical(&forged).unwrap(), T1)),
    );
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::BadSignature)
    );
    // The untampered file opens.
    write_installed(
        &path,
        sign(&base(), &[1, 2]),
        Some((sign(&loosened(), &[1, 2]), T1)),
    );
    assert!(PolicyStore::open(&path, admins()).is_ok());
    // So does a pending bundle that replaced an earlier one (two versions above the active one).
    let replaced = quorum(&base(), 3, |b| trx_cap(b, 2_000_000_000));
    write_installed(
        &path,
        sign(&base(), &[1, 2]),
        Some((sign(&replaced, &[1, 2]), T1)),
    );
    assert!(PolicyStore::open(&path, admins()).is_ok());
}

#[test]
fn policy_store_rechecks_the_pending_parent() {
    let path = temp_dir("pending-parent").join("policy.bcs");
    let orphan = quorum(&base(), 2, |b| {
        trx_cap(b, 2_000_000_000);
        b.parent = [0; 32];
    });
    write_installed(
        &path,
        sign(&base(), &[1, 2]),
        Some((sign(&orphan, &[1, 2]), T1)),
    );
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::ParentMismatch)
    );
}

#[test]
fn policy_store_rechecks_the_pending_lock() {
    let path = temp_dir("pending-lock").join("policy.bcs");
    write_installed(
        &path,
        sign(&base(), &[1, 2]),
        Some((sign(&loosened(), &[1, 2]), u64::MAX)),
    );
    assert_eq!(
        PolicyStore::open(&path, admins()).map(|_| ()),
        Err(PolicyRefusal::LockOverflow)
    );
}
