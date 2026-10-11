//! Differential test of the strict TRON decoder against tronweb (ROADMAP M6 #8).
//!
//! A deterministic generator mutates the reference transactions into [`MUTANTS`] inputs: 30%
//! valid-preserving (amounts, recipients, in-bound times, reference block, fee), 40%
//! structure-aware (field drop, duplicate and reorder, wire-type and varint tricks, unknown
//! fields, type and `type_url` swaps, calldata, address, permission, time, fee and integer edges,
//! size), 30% byte-level. The kernel decodes each one under an owner-permission and an
//! active-permission wallet.
//!
//! - [`corpus_is_large_varied_and_not_vacuous`] runs in every `cargo test`: the corpus size, the
//!   kernel's acceptance count and that every refusal reachable from the bytes fires.
//! - [`tronweb_agrees_with_every_kernel_accept`] is the differential itself. It needs Node.js and
//!   `npm ci --ignore-scripts` in `differential/` (tronweb pinned to the version `scripts/` uses),
//!   so it is ignored by default; run it with
//!   `cargo test --workspace --features local-transport tronweb_agrees -- --ignored --nocapture`.
//!
//! **Accept-disagreement:** the kernel accepts an input and tronweb does not read the same
//! transaction from it: it fails to parse it, its re-serialisation or txid differs from the input's,
//! it sees more than one contract, a memo, scripts, auths or a reference-block number, or any of
//! type, `type_url`, `Permission_id`, owner, recipient, token, amount, `fee_limit` or expiration
//! differs from the kernel's intent. The target is 0. Inputs the kernel refuses are counted, not
//! judged: the kernel is meant to be stricter than tronweb.
//!
//! **Known class, open:** the kernel accepts native amounts up to `2^63 − 1` sun, and tronweb
//! reports any amount above `2^53 − 1` rounded to a JS number. Those inputs are counted and printed
//! separately ([`js_rounded_native_amount`]) until the kernel either refuses such amounts or the
//! limit is documented as tronweb's.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;
use vaultex_types::{Address, AssetId, IntentV1, NetworkId, WalletId, U256};
use vaultex_verify::tron::{
    decode, TronDecodeCtx, TronRefusal, MAX_FEE_LIMIT_SUN, MAX_RAW_BYTES, MAX_VALIDITY_MS,
};

/// PRNG seed; printed in the report so a run can be reproduced.
const SEED: u64 = 0x7472_6f6e_6469_6666;
/// Number of mutants (M6 #8 asks for at least 10,000).
const MUTANTS: usize = 12_000;

const WALLET: [u8; 21] = addr(0x11);
const RECIPIENT: [u8; 21] = addr(0x22);
const TOKEN: [u8; 21] = addr(0x99);
/// The kernel's clock: inside the reference vectors' validity window.
const NOW: u64 = 1_700_000_010_000;
const SKEW_MS: u64 = 120_000;
const TRANSFER_URL: &[u8] = b"type.googleapis.com/protocol.TransferContract";
const TRIGGER_URL: &[u8] = b"type.googleapis.com/protocol.TriggerSmartContract";
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

const fn addr(fill: u8) -> [u8; 21] {
    let mut a = [fill; 21];
    a[0] = 0x41;
    a
}

// ───────────────────────────── deterministic PRNG (SplitMix64) ─────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<T: Clone>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())].clone()
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }

    /// Log-uniform in `1..=2^bits − 1`: every bit length is equally likely.
    fn log_uniform(&mut self, bits: u32) -> u64 {
        let len = 1 + self.below(bits as usize) as u32;
        let top = 1u64 << (len - 1);
        top | (self.next() & (top - 1))
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

// ───────────────────────────── transactions as field trees ─────────────────────────────

/// An encoding trick applied to one field.
#[derive(Clone, Copy, PartialEq)]
enum Quirk {
    None,
    /// The tag varint in a non-minimal form.
    OverlongTag,
    /// The value (varint) or length varint in a non-minimal form.
    OverlongValue,
    /// A varint sent length-delimited, or a length-delimited field sent as a varint (its length).
    WireSwap,
    /// Wire type 1 (8 bytes) for a varint, 5 (4 bytes) for a length-delimited field.
    Fixed,
    /// The length prefix one more, or one less, than the payload.
    LenPlus,
    LenMinus,
}

#[derive(Clone)]
enum Val {
    Int(u64),
    Bytes(Vec<u8>),
    Msg(Vec<Field>),
}

#[derive(Clone)]
struct Field {
    num: u64,
    val: Val,
    quirk: Quirk,
}

fn field(num: u64, val: Val) -> Field {
    Field {
        num,
        val,
        quirk: Quirk::None,
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64, overlong: bool) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    if overlong {
        out.push(v as u8 | 0x80);
        out.push(0);
    } else {
        out.push(v as u8);
    }
}

/// An independent protobuf writer (it shares nothing with the kernel's encoder).
fn encode(msg: &[Field]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in msg {
        let tag = |out: &mut Vec<u8>, wire: u64| {
            put_varint(out, (f.num << 3) | wire, f.quirk == Quirk::OverlongTag)
        };
        let payload = match &f.val {
            Val::Int(n) => {
                match f.quirk {
                    Quirk::WireSwap => {
                        tag(&mut out, 2);
                        let mut v = Vec::new();
                        put_varint(&mut v, *n, false);
                        put_varint(&mut out, v.len() as u64, false);
                        out.extend(v);
                    }
                    Quirk::Fixed => {
                        tag(&mut out, 1);
                        out.extend(n.to_le_bytes());
                    }
                    q => {
                        tag(&mut out, 0);
                        put_varint(&mut out, *n, q == Quirk::OverlongValue);
                    }
                }
                continue;
            }
            Val::Bytes(b) => b.clone(),
            Val::Msg(m) => encode(m),
        };
        match f.quirk {
            Quirk::WireSwap => {
                tag(&mut out, 0);
                put_varint(&mut out, payload.len() as u64, false);
            }
            Quirk::Fixed => {
                tag(&mut out, 5);
                out.extend(payload.iter().chain([0; 4].iter()).take(4));
            }
            q => {
                tag(&mut out, 2);
                let len = match q {
                    Quirk::LenPlus => payload.len() + 1,
                    Quirk::LenMinus => payload.len().saturating_sub(1),
                    _ => payload.len(),
                };
                put_varint(&mut out, len as u64, q == Quirk::OverlongValue);
                out.extend(payload);
            }
        }
    }
    out
}

/// The transaction fields the valid-preserving and semantic mutations edit.
#[derive(Clone)]
struct Base {
    ref_block_bytes: Vec<u8>,
    ref_block_hash: Vec<u8>,
    expiration: u64,
    timestamp: u64,
    fee_limit: Option<u64>,
    contract_type: u64,
    /// `None` leaves the field out (the owner permission).
    permission: Option<u64>,
    type_url: Vec<u8>,
    owner: Vec<u8>,
    /// Native: `to_address`. TRC-20: `contract_address`.
    to: Vec<u8>,
    /// Native `amount` (field 3).
    amount: Option<u64>,
    /// TRC-20 calldata (field 4).
    data: Option<Vec<u8>>,
}

impl Base {
    fn tree(&self) -> Vec<Field> {
        let mut value = vec![
            field(1, Val::Bytes(self.owner.clone())),
            field(2, Val::Bytes(self.to.clone())),
        ];
        value.extend(self.amount.map(|a| field(3, Val::Int(a))));
        value.extend(self.data.clone().map(|d| field(4, Val::Bytes(d))));
        let any = vec![
            field(1, Val::Bytes(self.type_url.clone())),
            field(2, Val::Msg(value)),
        ];
        let mut contract = vec![
            field(1, Val::Int(self.contract_type)),
            field(2, Val::Msg(any)),
        ];
        contract.extend(self.permission.map(|p| field(5, Val::Int(p))));
        let mut raw = vec![
            field(1, Val::Bytes(self.ref_block_bytes.clone())),
            field(4, Val::Bytes(self.ref_block_hash.clone())),
            field(8, Val::Int(self.expiration)),
            field(11, Val::Msg(contract)),
            field(14, Val::Int(self.timestamp)),
        ];
        raw.extend(self.fee_limit.map(|f| field(18, Val::Int(f))));
        raw
    }

    fn is_trc20(&self) -> bool {
        self.data.is_some()
    }
}

fn calldata(to: &[u8; 21], amount_be: [u8; 32]) -> Vec<u8> {
    let mut d = SEL_TRANSFER.to_vec();
    d.extend([0; 12]);
    d.extend(&to[1..]);
    d.extend(amount_be);
    d
}

fn word(n: u64) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn native(permission: Option<u64>) -> Base {
    Base {
        ref_block_bytes: vec![0x00, 0x01],
        ref_block_hash: vec![1, 2, 3, 4, 5, 6, 7, 8],
        expiration: 1_700_000_060_000,
        timestamp: 1_700_000_000_000,
        fee_limit: None,
        contract_type: 1,
        permission,
        type_url: TRANSFER_URL.to_vec(),
        owner: WALLET.to_vec(),
        to: RECIPIENT.to_vec(),
        amount: Some(1_000_000),
        data: None,
    }
}

fn trc20(permission: Option<u64>) -> Base {
    Base {
        fee_limit: Some(100_000_000),
        contract_type: 31,
        type_url: TRIGGER_URL.to_vec(),
        to: TOKEN.to_vec(),
        amount: None,
        data: Some(calldata(&RECIPIENT, word(1_000_000))),
        ..native(permission)
    }
}

/// The four seeds: native and TRC-20, under the owner permission and active permission 2.
fn seeds() -> [Base; 4] {
    [native(None), trc20(None), native(Some(2)), trc20(Some(2))]
}

// ───────────────────────────── mutations ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Valid,
    Structure,
    Byte,
}

/// One valid-preserving edit: the result stays inside the accepted grammar and bounds.
fn vary(b: &mut Base, rng: &mut Rng) {
    match rng.below(5) {
        0 => {
            if let Some(data) = &mut b.data {
                // A non-zero uint256 of 1 to 32 significant bytes.
                let len = 1 + rng.below(256);
                let mut amount = [0u8; 32];
                for (i, byte) in amount.iter_mut().enumerate().skip(32 - len.div_ceil(8)) {
                    *byte = rng.next() as u8;
                    if i == 32 - len.div_ceil(8) {
                        *byte |= 1;
                    }
                }
                data[36..].copy_from_slice(&amount);
            } else {
                b.amount = Some(rng.log_uniform(63));
            }
        }
        1 => {
            let mut to = [0x41; 21];
            to[1..].copy_from_slice(&rng.bytes(20));
            match &mut b.data {
                Some(data) => data[16..36].copy_from_slice(&to[1..]),
                None => b.to = to.to_vec(),
            }
        }
        2 => {
            b.expiration = rng.range(NOW + 1, NOW + MAX_VALIDITY_MS);
            b.timestamp = rng.range(NOW - MAX_VALIDITY_MS, b.expiration.min(NOW + SKEW_MS));
        }
        3 => {
            b.ref_block_bytes = rng.bytes(2);
            b.ref_block_hash = rng.bytes(8);
        }
        _ => {
            if b.is_trc20() {
                b.fee_limit = Some(rng.range(1, MAX_FEE_LIMIT_SUN));
            }
        }
    }
}

/// A path from `raw` to each nested message: raw, Contract, Any, value.
const LEVELS: [&[u64]; 4] = [&[], &[11], &[11, 2], &[11, 2, 2]];

fn level<'a>(msg: &'a mut Vec<Field>, path: &[u64]) -> &'a mut Vec<Field> {
    let Some((num, rest)) = path.split_first() else {
        return msg;
    };
    let Some(i) = msg
        .iter()
        .position(|f| f.num == *num && matches!(f.val, Val::Msg(_)))
    else {
        return msg;
    };
    match &mut msg[i].val {
        Val::Msg(m) => level(m, rest),
        _ => unreachable!(),
    }
}

/// Paths to every varint in the tree.
fn int_paths(msg: &[Field], prefix: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
    for (i, f) in msg.iter().enumerate() {
        prefix.push(i);
        match &f.val {
            Val::Int(_) => out.push(prefix.clone()),
            Val::Msg(m) => int_paths(m, prefix, out),
            Val::Bytes(_) => {}
        }
        prefix.pop();
    }
}

fn int_at<'a>(msg: &'a mut [Field], path: &[usize]) -> &'a mut Val {
    let (first, rest) = path.split_first().unwrap();
    let f = &mut msg[*first];
    match (&mut f.val, rest.is_empty()) {
        (v, true) => v,
        (Val::Msg(m), false) => int_at(m, rest),
        _ => unreachable!(),
    }
}

const INT_EDGES: [u64; 15] = [
    0,
    1,
    2,
    127,
    128,
    (1 << 31) - 1,
    1 << 32,
    (1 << 53) - 1,
    1 << 53,
    (1 << 53) + 1,
    (1 << 63) - 1,
    1 << 63,
    u64::MAX,
    NOW,
    NOW + MAX_VALIDITY_MS,
];

/// Unknown or refused field numbers per level (raw, Contract, Any, value).
const FOREIGN: [&[u64]; 4] = [&[2, 3, 9, 10, 12, 99], &[3, 4, 6], &[3], &[3, 5, 6, 7]];

/// Inserts `f` after every field numbered `<= f.num`.
fn insert_sorted(msg: &mut Vec<Field>, f: Field) {
    let at = msg.iter().position(|g| g.num > f.num).unwrap_or(msg.len());
    msg.insert(at, f);
}

/// One structure-aware mutation of the encoded tree.
fn structure(b: &mut Base, rng: &mut Rng) -> Vec<u8> {
    match rng.below(17) {
        // Semantic edges, on the typed fields.
        0 | 1 => {
            if rng.chance(50) {
                b.expiration = rng.pick(&[
                    NOW - 1,
                    NOW,
                    NOW + 1,
                    NOW + MAX_VALIDITY_MS - 1,
                    NOW + MAX_VALIDITY_MS,
                    NOW + MAX_VALIDITY_MS + 1,
                    b.timestamp - 1,
                ]);
            } else {
                b.timestamp = rng.pick(&[
                    b.expiration,
                    b.expiration + 1,
                    NOW + SKEW_MS,
                    NOW + SKEW_MS + 1,
                    NOW - MAX_VALIDITY_MS,
                    NOW - MAX_VALIDITY_MS - 1,
                ]);
            }
        }
        2 => {
            b.fee_limit = rng.pick(&[
                None,
                Some(0),
                Some(1),
                Some(MAX_FEE_LIMIT_SUN),
                Some(MAX_FEE_LIMIT_SUN + 1),
                Some((1 << 63) - 1),
            ]);
        }
        3 | 4 => {
            let Some(data) = &mut b.data else {
                b.amount = Some(rng.pick(&INT_EDGES));
                return encode(&b.tree());
            };
            match rng.below(8) {
                0 => {
                    let selector = rng.pick(&[
                        [0x09, 0x5e, 0xa7, 0xb3], // approve
                        [0x23, 0xb8, 0x72, 0xdd], // transferFrom
                        [0x39, 0x50, 0x93, 0x51], // increaseAllowance
                        [0xa9, 0x05, 0x9c, 0xbc],
                    ]);
                    data[..4].copy_from_slice(&selector);
                }
                1 => data[4 + rng.below(12)] = 1 + rng.below(255) as u8,
                2 => {
                    let len = rng.pick(&[0, 3, 4, 36, 67, 69, 100]);
                    data.resize(len, rng.next() as u8);
                }
                3 => {
                    let mut top = [0; 32];
                    top[0] = 0x80;
                    let edge = rng.pick(&[[0; 32], word(1), word((1 << 53) + 1), top, [0xff; 32]]);
                    data[36..].copy_from_slice(&edge);
                }
                4 => data[16..36].fill(0),
                5 => data[36..].fill(0),
                6 => {
                    // Value attached to the call: `call_value`, `call_token_value` or `token_id`.
                    let mut tree = b.tree();
                    let num = rng.pick(&[3, 5, 6]);
                    let extra = field(num, Val::Int(rng.pick(&[1, 1_000_000])));
                    insert_sorted(level(&mut tree, LEVELS[3]), extra);
                    return encode(&tree);
                }
                _ => {
                    let to = rng.pick(&[WALLET, TOKEN, RECIPIENT]);
                    data[16..36].copy_from_slice(&to[1..]);
                }
            }
        }
        5 | 6 if !b.is_trc20() && rng.chance(25) => b.to = b.owner.clone(), // self-transfer
        5 | 6 => {
            let mut a = rng
                .pick(&[WALLET, RECIPIENT, TOKEN, addr(0x33), addr(0)])
                .to_vec();
            match rng.below(4) {
                0 => {
                    a.remove(0);
                }
                1 => a.push(0x41),
                2 => a[0] = rng.pick(&[0x00, 0xa0]),
                _ => {}
            }
            if rng.chance(50) {
                b.owner = a;
            } else {
                b.to = a;
            }
        }
        7 => b.permission = rng.pick(&[None, Some(0), Some(1), Some(2), Some(3), Some(256)]),
        8 => {
            b.contract_type = rng.pick(&[0, 1, 2, 4, 11, 30, 31, 33, 46, 54, 57, 99, 1 << 32]);
        }
        9 => {
            let urls: [&[u8]; 6] = [
                TRANSFER_URL,
                TRIGGER_URL,
                b"type.googleapis.com/protocol.AccountPermissionUpdateContract",
                b"type.googleapis.com/protocol.TriggerSmartContractX",
                b"TriggerSmartContract",
                b"",
            ];
            b.type_url = rng.pick(&urls).to_vec();
        }
        10 => match rng.below(4) {
            0 => b.ref_block_bytes = rng.bytes(1),
            1 => b.ref_block_bytes = rng.bytes(3),
            2 => b.ref_block_hash = rng.bytes(7),
            _ => b.ref_block_hash = rng.bytes(32),
        },
        // Framing, on the tree.
        n => {
            let mut tree = b.tree();
            if n == 11 {
                let mut paths = Vec::new();
                int_paths(&tree, &mut Vec::new(), &mut paths);
                let path = rng.pick(&paths);
                *int_at(&mut tree, &path) = Val::Int(rng.pick(&INT_EDGES));
                return encode(&tree);
            }
            if n == 12 && rng.chance(20) {
                return Vec::new(); // empty input
            }
            let depth = rng.below(LEVELS.len());
            let msg = level(&mut tree, LEVELS[depth]);
            let i = rng.below(msg.len());
            match n {
                12 => {
                    // Oversized: a large unknown field, so the input passes the size cap or not.
                    let len = rng.range(300, 700) as usize;
                    msg.push(field(99, Val::Bytes(vec![0x5a; len])));
                }
                13 => {
                    if rng.chance(50) {
                        msg.remove(i);
                    } else {
                        let copy = msg[i].clone();
                        msg.insert(i + 1, copy);
                    }
                }
                14 => {
                    if msg.len() > 1 {
                        let j = (i + 1) % msg.len();
                        msg.swap(i, j);
                    }
                }
                15 => {
                    msg[i].quirk = rng.pick(&[
                        Quirk::OverlongTag,
                        Quirk::OverlongValue,
                        Quirk::WireSwap,
                        Quirk::Fixed,
                        Quirk::LenPlus,
                        Quirk::LenMinus,
                    ]);
                }
                _ => {
                    let num = rng.pick(FOREIGN[depth]);
                    let len = rng.below(9);
                    let val = if rng.chance(50) {
                        Val::Int(rng.pick(&[0, 1, 1_000_001]))
                    } else {
                        Val::Bytes(rng.bytes(len))
                    };
                    insert_sorted(msg, field(num, val));
                }
            }
            return encode(&tree);
        }
    }
    encode(&b.tree())
}

/// One byte-level edit.
fn byte_op(input: &mut Vec<u8>, rng: &mut Rng) {
    if input.is_empty() {
        input.push(rng.next() as u8);
        return;
    }
    let i = rng.below(input.len());
    match rng.below(6) {
        0 => input[i] ^= rng.pick(&[0x01, 0x02, 0x04, 0x40, 0x80, 0xff]),
        1 => input[i] = rng.next() as u8,
        2 => input.insert(i, rng.next() as u8),
        3 => {
            input.remove(i);
        }
        4 => input.truncate(i),
        _ => {
            let end = (i + 1 + rng.below(16)).min(input.len());
            let slice = input[i..end].to_vec();
            let at = rng.below(input.len() + 1);
            input.splice(at..at, slice);
        }
    }
}

fn corpus() -> Vec<(Kind, Vec<u8>)> {
    let mut rng = Rng(SEED);
    (0..MUTANTS)
        .map(|i| {
            let kind = match i % 10 {
                0..=2 => Kind::Valid,
                3..=6 => Kind::Structure,
                _ => Kind::Byte,
            };
            let mut base = rng.pick(&seeds());
            let edits = match kind {
                Kind::Valid => 1 + rng.below(4),
                _ => rng.below(3),
            };
            for _ in 0..edits {
                vary(&mut base, &mut rng);
            }
            let input = match kind {
                Kind::Valid => encode(&base.tree()),
                Kind::Structure => structure(&mut base, &mut rng),
                Kind::Byte => {
                    let mut input = encode(&base.tree());
                    for _ in 0..1 + rng.below(3) {
                        byte_op(&mut input, &mut rng);
                    }
                    input
                }
            };
            (kind, input)
        })
        .collect()
}

// ───────────────────────────── the kernel side ─────────────────────────────

/// The kernel's verdict: the intent and the permission it was accepted under, or the refusal
/// under the owner permission (the first context).
fn kernel(input: &[u8]) -> Result<(IntentV1, u8), TronRefusal> {
    let wallet_id = WalletId::new("differential").unwrap();
    let allowlist = [TOKEN];
    let mut first = None;
    for permission_id in [0, 2] {
        let ctx = TronDecodeCtx {
            wallet_id: &wallet_id,
            network: NetworkId::new("tron:3448148188").unwrap(),
            wallet_address: WALLET,
            permission_id,
            trc20_allowlist: &allowlist,
            now_ms: NOW,
            max_validity_ms: MAX_VALIDITY_MS,
            max_fee_limit_sun: MAX_FEE_LIMIT_SUN,
            max_clock_skew_ms: SKEW_MS,
            claimed_txid: None,
        };
        match decode(input, &ctx) {
            Ok((intent, _)) => return Ok((intent, permission_id)),
            Err(r) => {
                first.get_or_insert(r);
            }
        }
    }
    Err(first.unwrap())
}

/// Every refusal the bytes alone can trigger. Not reachable from the bytes: `NetworkNotTron` and
/// `DigestMismatch` (the context), and `NonCanonicalEncoding` (the reader refuses first; see its
/// unit test).
const REACHABLE: [&str; 33] = [
    "Empty",
    "TooLarge",
    "PbMalformed",
    "PbNonCanonicalVarint",
    "PbWireType",
    "PbDuplicateField",
    "PbFieldOrder",
    "PbDefaultValue",
    "FieldNotAllowed",
    "MemoPresent",
    "CallValuePresent",
    "Trc10FieldsPresent",
    "MissingField",
    "IntRange",
    "ContractTypeNotAllowed",
    "AccountPermissionUpdate",
    "TypeUrlMismatch",
    "RefBlockShape",
    "PermissionIdMismatch",
    "AddressShape",
    "OwnerNotWallet",
    "SelfTransfer",
    "AmountZero",
    "CalldataLength",
    "SelectorNotTransfer",
    "CalldataAddressPadding",
    "RecipientZero",
    "TokenNotAllowlisted",
    "FeeLimitMissing",
    "FeeLimitOnNative",
    "FeeLimitOverBound",
    "ExpirationWindow",
    "TimestampInvalid",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Big-endian hex of a little-endian `U256`.
fn hex_be(n: &U256) -> String {
    let mut be = n.0;
    be.reverse();
    hex(&be)
}

fn lower(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_ascii_lowercase()
}

#[test]
fn seeds_reproduce_the_reference_vectors() {
    let [native, trc20, native_perm2, trc20_perm2] = seeds().map(|b| encode(&b.tree()));
    let corpus = |name| std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap();
    assert_eq!(native, corpus("fuzz/corpus/tron_decode/native_transfer"));
    assert_eq!(trc20, corpus("fuzz/corpus/tron_decode/trc20_transfer"));
    assert_eq!(
        trc20_perm2,
        corpus("fuzz/corpus/tron_decode/trc20_transfer_permission2")
    );
    // The native active-permission seed adds exactly `Permission_id = 2` to the contract.
    assert_eq!(native_perm2.len(), native.len() + 2);
    assert_eq!(kernel(&native_perm2).map(|(_, p)| p), Ok(2));
}

#[test]
fn corpus_is_large_varied_and_not_vacuous() {
    let corpus = corpus();
    assert!(corpus.len() >= 10_000);
    assert!(
        corpus == self::corpus(),
        "the generator is not deterministic"
    );
    let share = |k| corpus.iter().filter(|(kind, _)| *kind == k).count() * 100 / corpus.len();
    assert!(share(Kind::Structure) >= 40 && share(Kind::Valid) >= 30 && share(Kind::Byte) <= 30);

    let mut accepted = 0;
    let mut hits: Vec<(String, usize)> = REACHABLE.iter().map(|r| (r.to_string(), 0)).collect();
    for (_, input) in &corpus {
        match kernel(input) {
            Ok(_) => accepted += 1,
            Err(r) => {
                let name = format!("{r:?}");
                match hits.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, n)) => *n += 1,
                    None => panic!("refusal {name} is not in REACHABLE"),
                }
            }
        }
    }
    println!(
        "{} mutants, {accepted} accepted by the kernel",
        corpus.len()
    );
    for (name, n) in &hits {
        println!("  {name}: {n}");
    }
    assert!(accepted >= 1_000, "only {accepted} mutants accepted");
    let rare: Vec<_> = hits.iter().filter(|(_, n)| *n < 10).collect();
    assert!(
        rare.is_empty(),
        "refusals hit fewer than 10 times: {rare:?}"
    );
    assert!(corpus.iter().all(|(_, i)| i.len() <= 2 * MAX_RAW_BYTES));
}

// ───────────────────────────── the tronweb side ─────────────────────────────

/// Runs every input through `differential/tron-decode.mjs`: the version header, then one reading
/// per input.
fn tronweb(inputs: &[&[u8]]) -> (Value, Vec<Value>) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("differential");
    assert!(
        dir.join("node_modules/tronweb").is_dir(),
        "tronweb is not installed: run `npm ci --ignore-scripts` in {}",
        dir.display()
    );
    let mut child = Command::new("node")
        .arg(dir.join("tron-decode.mjs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("`node` on PATH");
    let lines: String = inputs.iter().map(|i| hex(i) + "\n").collect();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(lines.as_bytes()));
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert!(output.status.success(), "tron-decode.mjs failed");
    let mut readings = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice::<Value>(l).unwrap());
    let header = readings.next().unwrap();
    let readings: Vec<Value> = readings.collect();
    assert_eq!(readings.len(), inputs.len(), "one reading per input");
    (header, readings)
}

/// What tronweb reads differently from the kernel's accepted intent (empty when they agree).
fn disagreements(input: &[u8], intent: &IntentV1, permission: u8, o: &Value) -> Vec<&'static str> {
    let tx = &o["tx"];
    let contract = &tx["contract"][0];
    let value = &contract["parameter"]["value"];
    let url = |u: &[u8]| contract["parameter"]["type_url"] == std::str::from_utf8(u).unwrap();
    let mut checks = vec![
        ("parsed", o["parsed"] == true && o.get("tx_error").is_none()),
        ("re-serialisation", o["reserialized"] == hex(input)),
        ("txid", o["txid"] == hex(&intent.tx_hash.0)),
        ("one contract", o["contracts"] == 1),
        ("no ref_block_num", o["ref_block_num"] == 0),
        ("no auths", o["auths"] == 0),
        ("no scripts", o["scripts"] == ""),
        ("no memo", o["memo"] == ""),
        ("Permission_id", contract["Permission_id"] == permission),
        ("expiration", tx["expiration"] == intent.not_after_ms),
        (
            "owner",
            lower(&value["owner_address"]) == hex(&intent.sender.0),
        ),
    ];
    match &intent.asset {
        AssetId::Native => checks.extend([
            ("type", contract["type"] == "TransferContract"),
            ("type_url", url(TRANSFER_URL)),
            (
                "to",
                lower(&value["to_address"]) == hex(&intent.recipient.0),
            ),
            (
                "amount",
                value["amount"].as_u64().map(U256::from) == Some(intent.amount),
            ),
            (
                "no fee_limit",
                tx["fee_limit"] == 0 && intent.fee_cap == U256::from(0),
            ),
        ]),
        AssetId::Contract(token) => checks.extend([
            ("type", contract["type"] == "TriggerSmartContract"),
            ("type_url", url(TRIGGER_URL)),
            ("token", lower(&value["contract_address"]) == hex(&token.0)),
            ("no call_value", value["call_value"] == 0),
            (
                "no TRC-10 value",
                value["call_token_value"] == 0 && value["token_id"] == 0,
            ),
            ("selector", lower(&o["selector"]) == hex(&SEL_TRANSFER)),
            (
                "recipient",
                lower(&o["call"]["to"]) == hex(&intent.recipient.0),
            ),
            ("amount", o["call"]["amount"] == hex_be(&intent.amount)),
            (
                "fee_limit",
                tx["fee_limit"].as_u64().map(U256::from) == Some(intent.fee_cap),
            ),
        ]),
        _ => checks.push(("asset", false)),
    }
    checks
        .into_iter()
        .filter_map(|(what, ok)| (!ok).then_some(what))
        .collect()
}

/// The one known class of accept-disagreement: a native amount above 2^53 − 1 sun. tronweb reads
/// `int64` fields as JS numbers, so it reports the amount rounded to the nearest double, while the
/// kernel and the chain read it exactly. Everything else agrees, including the txid and the
/// re-serialisation (the amount sits in the parameter's opaque bytes). True only when "amount" is
/// the sole disagreement and tronweb's value is exactly the kernel's amount rounded to an `f64`.
fn js_rounded_native_amount(intent: &IntentV1, o: &Value, d: &[&str]) -> bool {
    let (low, high) = intent.amount.0.split_at(8);
    let amount = u64::from_le_bytes(low.try_into().unwrap());
    let tronweb = &o["tx"]["contract"][0]["parameter"]["value"]["amount"];
    intent.asset == AssetId::Native
        && d == ["amount"]
        && high.iter().all(|b| *b == 0)
        && amount > (1 << 53) - 1
        && tronweb.as_f64() == Some(amount as f64)
}

#[test]
#[ignore = "needs Node.js and `npm ci --ignore-scripts` in differential/"]
fn tronweb_agrees_with_every_kernel_accept() {
    let corpus = corpus();
    let inputs: Vec<&[u8]> = corpus.iter().map(|(_, i)| i.as_slice()).collect();
    let (versions, readings) = tronweb(&inputs);

    let (mut accepted, mut stricter, mut both_refuse) = (0, 0, 0);
    let (mut disagreeing, mut rounded) = (Vec::new(), 0);
    for (input, reading) in inputs.iter().zip(&readings) {
        match kernel(input) {
            Ok((intent, permission)) => {
                accepted += 1;
                if accepted == 1 {
                    // Not vacuous: the comparison notices a wrong recipient, amount or permission.
                    let mut wrong = intent.clone();
                    wrong.recipient = Address(addr(0x77).to_vec());
                    assert!(!disagreements(input, &wrong, permission, reading).is_empty());
                    let mut wrong = intent.clone();
                    wrong.amount = U256::from(7u64);
                    assert!(!disagreements(input, &wrong, permission, reading).is_empty());
                    assert!(!disagreements(input, &intent, permission ^ 2, reading).is_empty());
                }
                let d = disagreements(input, &intent, permission, reading);
                if d.is_empty() {
                    continue;
                }
                // ponytail: the known class stays counted and printed, but is kept out of the
                // assertion until R3/R1 decide whether the kernel refuses native amounts above
                // 2^53 − 1 (then this branch never fires) or documents the tronweb limit.
                if js_rounded_native_amount(&intent, reading, &d) {
                    rounded += 1;
                } else {
                    disagreeing.push((hex(input), d));
                }
            }
            Err(_) if reading["parsed"] == true => stricter += 1,
            Err(_) => both_refuse += 1,
        }
    }
    println!(
        "tronweb differential: seed {SEED:#x}, {} inputs",
        inputs.len()
    );
    println!("  oracle: {versions}");
    println!("  kernel: vaultex-verify {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  kernel accepts: {accepted}; accept-disagreements: {} (+ {rounded} known: native amount \
         above 2^53 - 1, which tronweb rounds to a JS number)",
        disagreeing.len()
    );
    println!("  kernel refuses, tronweb parses (kernel stricter): {stricter}");
    println!("  kernel refuses, tronweb fails to parse: {both_refuse}");
    for (input, d) in disagreeing.iter().take(10) {
        println!("  DISAGREE {d:?}: {input}");
    }
    assert!(accepted >= 1_000, "only {accepted} kernel accepts");
    assert!(
        disagreeing.is_empty(),
        "{} accept-disagreements",
        disagreeing.len()
    );
}
