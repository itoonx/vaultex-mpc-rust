//! TRON incident cases: the test world, the fixture writer, the controls and the cases.
//!
//! Transaction layout (upstream `Tron.proto` and `smart_contract.proto`): `raw` has
//! `ref_block_bytes` 1, `ref_block_num` 3, `ref_block_hash` 4, `expiration` 8, `auths` 9, `data`
//! (memo) 10, `contract` 11, `scripts` 12, `timestamp` 14 and `fee_limit` 18; `Contract` has
//! `type` 1, `parameter` 2 (an `Any` of `type_url` 1 and `value` 2), `provider` 3, `ContractName`
//! 4 and `Permission_id` 5; `TriggerSmartContract` has `owner_address` 1, `contract_address` 2,
//! `call_value` 3, `data` 4, `call_token_value` 5 and `token_id` 6; `TransferContract` has
//! `owner_address` 1, `to_address` 2 and `amount` 3.

use vaultex_types::{RefusalCode as R, Role};

use crate::{
    Case, Control, Evidence, Governance, IncidentClass as C, Key, Over, Scenario, Statement,
};

/// The test world every TRON case assumes. The kernel-side adapter builds the policy bundle and
/// the request from these facts; a case changes exactly one thing relative to them.
pub mod world {
    /// The wallet's network (Nile testnet, CAIP-2).
    pub const NETWORK: &str = "tron:3448148188";
    /// The wallet's account (`0x41` ‖ 20 bytes).
    pub const WALLET: [u8; 21] = addr(0x11);
    /// The active permission the wallet signs under. Any other id, including the owner
    /// permission (id absent), is refused.
    pub const PERMISSION_ID: u64 = 2;
    /// The one allowlisted TRC-20 token contract.
    pub const TOKEN: [u8; 21] = addr(0x99);
    /// Allowlisted recipient (both assets).
    pub const RECIPIENT: [u8; 21] = addr(0x22);
    /// A second allowlisted recipient (both assets).
    pub const RECIPIENT_2: [u8; 21] = addr(0x44);
    /// An account that is allowlisted for nothing.
    pub const OUTSIDER: [u8; 21] = addr(0x33);
    /// Per-transaction cap for the token, in base units.
    pub const TOKEN_TX_CAP: u128 = 1_000_000_000;
    /// Per-transaction cap for TRX, in sun.
    pub const NATIVE_TX_CAP_SUN: u64 = 100_000_000;
    /// Policy cap on `fee_limit`, in sun (150 TRX).
    pub const FEE_CAP_SUN: u64 = 150_000_000;
    /// Network fact: the largest `fee_limit` the network accepts, in sun (15,000 TRX).
    pub const NETWORK_MAX_FEE_LIMIT_SUN: u64 = 15_000_000_000;
    /// Network fact: the longest expiry the network accepts after "now" (24 h).
    pub const CHAIN_MAX_EXPIRATION_MS: u64 = 24 * HOUR_MS;
    /// Policy cap on the transaction's remaining validity (4 h).
    pub const MAX_VALIDITY_MS: u64 = 4 * HOUR_MS;
    /// Longest request freshness window the verifier accepts (10 min).
    pub const MAX_REQUEST_WINDOW_S: u64 = 600;
    /// Pinned approver keys: `Key::Approver(0..APPROVERS)`.
    pub const APPROVERS: u8 = 3;
    /// Approvals required for every amount.
    pub const QUORUM: usize = 2;
    /// The installed policy bundle's version.
    pub const BUNDLE_VERSION: u64 = 2;
    /// Valid statements expire this long after `NOW_S`.
    pub const STATEMENT_TTL_S: u64 = 3_600;
    /// The verifier's clock, unless a case says otherwise (one second after the build time).
    pub const NOW_MS: u64 = 1_700_000_001_000;
    /// [`NOW_MS`] in seconds.
    pub const NOW_S: u64 = NOW_MS / 1_000;

    const HOUR_MS: u64 = 3_600_000;

    const fn addr(fill: u8) -> [u8; 21] {
        let mut a = [fill; 21];
        a[0] = 0x41;
        a
    }
}

use world::*;

// ── Minimal protobuf writer (independent of the kernel's encoder) ───────────────────────────────

/// One field value: a varint (wire type 0) or length-delimited bytes (wire type 2).
#[derive(Clone)]
enum V {
    Int(u64),
    Bytes(Vec<u8>),
}

fn bytes(b: &[u8]) -> V {
    V::Bytes(b.to_vec())
}

/// A message as an ordered field list, so a fixture can hold what a canonical encoder never
/// emits (duplicates, explicit defaults).
#[derive(Clone, Default)]
struct Msg(Vec<(u32, V)>);

impl Msg {
    /// Inserts after every field numbered `<= field`, keeping ascending order.
    fn add(&mut self, field: u32, v: V) {
        let at = self.0.iter().position(|(f, _)| *f > field);
        self.0.insert(at.unwrap_or(self.0.len()), (field, v));
    }

    fn remove(&mut self, field: u32) {
        self.0.retain(|(f, _)| *f != field);
    }

    fn set(&mut self, field: u32, v: V) {
        self.remove(field);
        self.add(field, v);
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (field, v) in &self.0 {
            match v {
                V::Int(n) => {
                    put_varint(&mut out, u64::from(*field) << 3);
                    put_varint(&mut out, *n);
                }
                V::Bytes(b) => {
                    put_varint(&mut out, (u64::from(*field) << 3) | 2);
                    put_varint(&mut out, b.len() as u64);
                    out.extend_from_slice(b);
                }
            }
        }
        out
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

// ── Transactions ────────────────────────────────────────────────────────────────────────────────

const TRANSFER_URL: &str = "type.googleapis.com/protocol.TransferContract";
const TRIGGER_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
const SEL_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
const SEL_INCREASE_ALLOWANCE: [u8; 4] = [0x39, 0x50, 0x93, 0x51]; // increaseAllowance(address,uint256)
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256)

// Build-time fields of every baseline: those of the tronweb reference vectors.
const TIMESTAMP_MS: u64 = 1_700_000_000_000;
const EXPIRATION_MS: u64 = TIMESTAMP_MS + 60_000;
const FEE_LIMIT_SUN: u64 = 100_000_000;
const AMOUNT: u64 = 1_000_000;

/// A transaction taken apart at the layers the cases mutate.
#[derive(Clone)]
struct Tx {
    /// `Transaction.raw` without its contract (field 11).
    raw: Msg,
    /// The contract without its parameter (field 2).
    contract: Msg,
    /// The parameter's `Any.type_url`.
    type_url: String,
    /// The parameter's value.
    value: Msg,
    /// Further encoded `Contract` entries, after the first.
    extra_contracts: Vec<Vec<u8>>,
}

impl Tx {
    fn contract_bytes(&self) -> Vec<u8> {
        let any = Msg(vec![
            (1, bytes(self.type_url.as_bytes())),
            (2, V::Bytes(self.value.encode())),
        ]);
        let mut contract = self.contract.clone();
        contract.add(2, V::Bytes(any.encode()));
        contract.encode()
    }

    fn encode(&self) -> Vec<u8> {
        let mut raw = self.raw.clone();
        raw.add(11, V::Bytes(self.contract_bytes()));
        for c in &self.extra_contracts {
            raw.add(11, V::Bytes(c.clone()));
        }
        raw.encode()
    }

    /// The same transaction after `f`.
    fn with(&self, f: impl FnOnce(&mut Tx)) -> Tx {
        let mut t = self.clone();
        f(&mut t);
        t
    }
}

fn raw_head() -> Msg {
    Msg(vec![
        (1, bytes(&[0x00, 0x01])),
        (4, bytes(&[1, 2, 3, 4, 5, 6, 7, 8])),
        (8, V::Int(EXPIRATION_MS)),
        (14, V::Int(TIMESTAMP_MS)),
    ])
}

fn contract_head(contract_type: u64) -> Msg {
    Msg(vec![(1, V::Int(contract_type)), (5, V::Int(PERMISSION_ID))])
}

fn addr_word(a: &[u8; 21]) -> [u8; 32] {
    let mut w = [0; 32];
    w[12..].copy_from_slice(&a[1..]);
    w
}

fn amount_word(n: u128) -> [u8; 32] {
    let mut w = [0; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn call(selector: [u8; 4], words: &[[u8; 32]]) -> V {
    V::Bytes(selector.into_iter().chain(words.concat()).collect())
}

/// A TRC-20 `transfer(to, amount)` on the allowlisted token, under the wallet's permission.
fn token_to(to: &[u8; 21], amount: u128) -> Tx {
    let mut raw = raw_head();
    raw.add(18, V::Int(FEE_LIMIT_SUN));
    Tx {
        raw,
        contract: contract_head(31),
        type_url: TRIGGER_URL.into(),
        value: Msg(vec![
            (1, bytes(&WALLET)),
            (2, bytes(&TOKEN)),
            (4, call(SEL_TRANSFER, &[addr_word(to), amount_word(amount)])),
        ]),
        extra_contracts: vec![],
    }
}

/// A native TRX transfer, under the wallet's permission.
fn native_to(to: &[u8; 21], amount: u64) -> Tx {
    Tx {
        raw: raw_head(),
        contract: contract_head(1),
        type_url: TRANSFER_URL.into(),
        value: Msg(vec![
            (1, bytes(&WALLET)),
            (2, bytes(to)),
            (3, V::Int(amount)),
        ]),
        extra_contracts: vec![],
    }
}

fn token() -> Tx {
    token_to(&RECIPIENT, AMOUNT.into())
}

fn native() -> Tx {
    native_to(&RECIPIENT, AMOUNT)
}

/// A contract of `contract_type` that carries only the owner address: the shape, not a working
/// operation.
fn other_contract(contract_type: u64, name: &str) -> Tx {
    native().with(|t| {
        t.contract = contract_head(contract_type);
        if contract_type == 0 {
            t.contract.remove(1); // proto3 omits a zero enum
        }
        t.type_url = format!("type.googleapis.com/protocol.{name}");
        t.value = Msg(vec![(1, bytes(&WALLET))]);
    })
}

/// Every `ContractType` upstream defines except the two allowlisted shapes (1, 31) and the
/// permission update (46, its own case).
const OTHER_CONTRACT_TYPES: [(u64, &str); 38] = [
    (0, "AccountCreateContract"),
    (2, "TransferAssetContract"),
    (3, "VoteAssetContract"),
    (4, "VoteWitnessContract"),
    (5, "WitnessCreateContract"),
    (6, "AssetIssueContract"),
    (8, "WitnessUpdateContract"),
    (9, "ParticipateAssetIssueContract"),
    (10, "AccountUpdateContract"),
    (11, "FreezeBalanceContract"),
    (12, "UnfreezeBalanceContract"),
    (13, "WithdrawBalanceContract"),
    (14, "UnfreezeAssetContract"),
    (15, "UpdateAssetContract"),
    (16, "ProposalCreateContract"),
    (17, "ProposalApproveContract"),
    (18, "ProposalDeleteContract"),
    (19, "SetAccountIdContract"),
    (20, "CustomContract"),
    (30, "CreateSmartContract"),
    (32, "GetContract"),
    (33, "UpdateSettingContract"),
    (41, "ExchangeCreateContract"),
    (42, "ExchangeInjectContract"),
    (43, "ExchangeWithdrawContract"),
    (44, "ExchangeTransactionContract"),
    (45, "UpdateEnergyLimitContract"),
    (48, "ClearABIContract"),
    (49, "UpdateBrokerageContract"),
    (51, "ShieldedTransferContract"),
    (52, "MarketSellAssetContract"),
    (53, "MarketCancelOrderContract"),
    (54, "FreezeBalanceV2Contract"),
    (55, "UnfreezeBalanceV2Contract"),
    (56, "WithdrawExpireUnfreezeContract"),
    (57, "DelegateResourceContract"),
    (58, "UnDelegateResourceContract"),
    (59, "CancelAllUnfreezeV2Contract"),
];

// ── Scenarios ───────────────────────────────────────────────────────────────────────────────────

fn statement(key: Key, role: Role) -> Statement {
    Statement {
        key,
        role,
        over: Over::ThisTx,
        not_after_s: NOW_S + STATEMENT_TTL_S,
        corrupt_signature: false,
    }
}

fn approver(n: u8) -> Statement {
    statement(Key::Approver(n), Role::Approver)
}

/// A control-shaped scenario around `tx`: valid initiator, a quorum of approvals, fresh request,
/// installed bundle.
fn scenario(tx: &Tx) -> Scenario {
    Scenario {
        raw_tx: tx.encode(),
        now_ms: NOW_MS,
        request_not_after_s: NOW_S + 60,
        policy_version: BUNDLE_VERSION,
        evidence: Evidence {
            initiator: statement(Key::Initiator, Role::Initiator),
            approvals: vec![approver(0), approver(1)],
        },
        governance: Governance::Installed,
    }
}

/// The same scenario after `f`.
fn edit(mut s: Scenario, f: impl FnOnce(&mut Scenario)) -> Scenario {
    f(&mut s);
    s
}

/// Well-formed scenarios the kernel must accept. Without them, a kernel that refuses everything
/// would pass the replay.
pub fn controls() -> Vec<Control> {
    vec![
        Control {
            id: "CTRL-1",
            summary: "TRC-20 transfer of the allowlisted token to an allowlisted recipient",
            scenario: scenario(&token()),
        },
        Control {
            id: "CTRL-2",
            summary: "Native transfer to an allowlisted recipient",
            scenario: scenario(&native()),
        },
        Control {
            id: "CTRL-3",
            summary: "Initiated by the dual-role key and approved by two other approvers",
            scenario: edit(scenario(&token()), |s| {
                s.evidence.initiator = statement(Key::Approver(2), Role::Initiator);
            }),
        },
    ]
}

/// The incident cases, every one of which the kernel must refuse with an expected code.
pub fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut add =
        |id: String, class: C, summary: &'static str, expect: &'static [R], scenario: Scenario| {
            out.push(Case {
                id,
                class,
                summary,
                expect,
                scenario,
            });
        };
    let tx = |t: Tx| scenario(&t);

    // Approve-to-attacker: allowance grants are never a transfer.
    let approve = |spender: &[u8; 21], words: [u8; 32]| {
        token().with(|t| {
            t.value
                .set(4, call(SEL_APPROVE, &[addr_word(spender), words]))
        })
    };
    add(
        "IR-APPROVE-1".into(),
        C::ApproveToAttacker,
        "Unlimited allowance granted to a third party instead of a transfer",
        &[R::TX_SELECTOR_NOT_ALLOWED],
        tx(approve(&OUTSIDER, [0xff; 32])),
    );
    add(
        "IR-APPROVE-2".into(),
        C::ApproveToAttacker,
        "Bounded allowance granted to an allowlisted recipient (a standing allowance is still refused)",
        &[R::TX_SELECTOR_NOT_ALLOWED],
        tx(approve(&RECIPIENT, amount_word(AMOUNT.into()))),
    );
    add(
        "IR-APPROVE-3".into(),
        C::ApproveToAttacker,
        "Allowance raised through an increase-style call",
        &[R::TX_SELECTOR_NOT_ALLOWED],
        tx(token().with(|t| {
            let words = [addr_word(&OUTSIDER), amount_word(AMOUNT.into())];
            t.value.set(4, call(SEL_INCREASE_ALLOWANCE, &words));
        })),
    );
    add(
        "IR-APPROVE-4".into(),
        C::ApproveToAttacker,
        "Allowance spent through a delegated-transfer call",
        &[R::TX_SELECTOR_NOT_ALLOWED, R::TX_MALFORMED],
        tx(token().with(|t| {
            let words = [
                addr_word(&OUTSIDER),
                addr_word(&RECIPIENT),
                amount_word(AMOUNT.into()),
            ];
            t.value.set(4, call(SEL_TRANSFER_FROM, &words));
        })),
    );

    // Destination swap.
    let original = token().encode();
    add(
        "IR-DEST-1".into(),
        C::DestinationSwap,
        "Token recipient changed after approval to another allowlisted address",
        &[R::APPROVAL_INTENT_MISMATCH],
        edit(tx(token_to(&RECIPIENT_2, AMOUNT.into())), |s| {
            for a in &mut s.evidence.approvals {
                a.over = Over::OtherTx(original.clone());
            }
        }),
    );
    add(
        "IR-DEST-2".into(),
        C::DestinationSwap,
        "Token recipient changed in transit after initiation and approval",
        &[R::APPROVAL_INTENT_MISMATCH, R::INITIATOR_INVALID],
        edit(tx(token_to(&RECIPIENT_2, AMOUNT.into())), |s| {
            s.evidence.initiator.over = Over::OtherTx(original.clone());
            for a in &mut s.evidence.approvals {
                a.over = Over::OtherTx(original.clone());
            }
        }),
    );
    let original_native = native().encode();
    add(
        "IR-DEST-3".into(),
        C::DestinationSwap,
        "Native recipient changed after approval to another allowlisted address",
        &[R::APPROVAL_INTENT_MISMATCH],
        edit(tx(native_to(&RECIPIENT_2, AMOUNT)), |s| {
            for a in &mut s.evidence.approvals {
                a.over = Over::OtherTx(original_native.clone());
            }
        }),
    );
    add(
        "IR-DEST-4".into(),
        C::DestinationSwap,
        "Recipient outside the allowlist, with every statement signed over the swapped transfer",
        &[R::RECIPIENT_NOT_ALLOWED],
        tx(token_to(&OUTSIDER, AMOUNT.into())),
    );
    add(
        "IR-DEST-5".into(),
        C::DestinationSwap,
        "Recipient field encoded twice, so first-wins and last-wins decoders disagree",
        &[R::TX_DUPLICATE_FIELD],
        tx(native().with(|t| t.value.add(2, bytes(&OUTSIDER)))),
    );
    add(
        "IR-DEST-6".into(),
        C::DestinationSwap,
        "Token recipient word with non-zero padding, so truncating and strict decoders disagree",
        &[R::TX_NON_CANONICAL, R::TX_MALFORMED],
        tx(token().with(|t| {
            let mut to = addr_word(&RECIPIENT);
            to[0] = 0x01;
            let words = [to, amount_word(AMOUNT.into())];
            t.value.set(4, call(SEL_TRANSFER, &words));
        })),
    );

    // Permission takeover.
    add(
        "IR-PERM-1".into(),
        C::PermissionTakeover,
        "Account permission update (changes who controls the account)",
        &[R::TX_SHAPE_NOT_ALLOWED],
        tx(other_contract(46, "AccountPermissionUpdateContract")),
    );
    add(
        "IR-PERM-2".into(),
        C::PermissionTakeover,
        "Signed under the owner permission (id omitted) on a wallet configured for an active permission",
        &[R::TX_PERMISSION_NOT_ALLOWED],
        tx(token().with(|t| t.contract.remove(5))),
    );
    add(
        "IR-PERM-3".into(),
        C::PermissionTakeover,
        "Owner permission named explicitly (an encoded default)",
        &[R::TX_PERMISSION_NOT_ALLOWED, R::TX_NON_CANONICAL],
        tx(token().with(|t| t.contract.set(5, V::Int(0)))),
    );
    add(
        "IR-PERM-4".into(),
        C::PermissionTakeover,
        "Signed under another active permission the wallet does not use",
        &[R::TX_PERMISSION_NOT_ALLOWED],
        tx(token().with(|t| t.contract.set(5, V::Int(PERMISSION_ID + 1)))),
    );
    add(
        "IR-PERM-5".into(),
        C::PermissionTakeover,
        "Signed under the witness permission",
        &[R::TX_PERMISSION_NOT_ALLOWED],
        tx(token().with(|t| t.contract.set(5, V::Int(1)))),
    );
    add(
        "IR-PERM-6".into(),
        C::PermissionTakeover,
        "Spends from another account on which the same key may also hold a permission",
        &[R::TX_SENDER_MISMATCH],
        tx(token().with(|t| t.value.set(1, bytes(&OUTSIDER)))),
    );
    for (contract_type, name) in OTHER_CONTRACT_TYPES {
        // Type 0 is encoded by omission, so a decoder may also call it a missing field.
        let expect: &'static [R] = if contract_type == 0 {
            &[R::TX_SHAPE_NOT_ALLOWED, R::TX_MALFORMED]
        } else {
            &[R::TX_SHAPE_NOT_ALLOWED]
        };
        add(
            format!("IR-PERM-T{contract_type:02}"),
            C::PermissionTakeover,
            "Contract type outside the transfer allowlist (privileged, governance, resource or asset operation)",
            expect,
            tx(other_contract(contract_type, name)),
        );
    }
    add(
        "IR-PERM-T99".into(),
        C::PermissionTakeover,
        "Contract type no decoder knows",
        &[R::TX_SHAPE_NOT_ALLOWED],
        tx(other_contract(99, "UnknownContract")),
    );

    // Memo or second-contract smuggling.
    add(
        "IR-SMUGGLE-1".into(),
        C::MemoOrSecondContractSmuggling,
        "Memo attached to a token transfer",
        &[R::TX_SHAPE_NOT_ALLOWED],
        tx(token().with(|t| t.raw.add(10, bytes(b"note")))),
    );
    add(
        "IR-SMUGGLE-2".into(),
        C::MemoOrSecondContractSmuggling,
        "Memo attached to a native transfer",
        &[R::TX_SHAPE_NOT_ALLOWED],
        tx(native().with(|t| t.raw.add(10, bytes(b"note")))),
    );
    let second_token = token_to(&OUTSIDER, AMOUNT.into()).contract_bytes();
    add(
        "IR-SMUGGLE-3".into(),
        C::MemoOrSecondContractSmuggling,
        "Second token transfer to an unlisted account behind the approved one",
        &[R::TX_SHAPE_NOT_ALLOWED, R::TX_DUPLICATE_FIELD],
        tx(token().with(|t| t.extra_contracts.push(second_token))),
    );
    let second_native = native_to(&OUTSIDER, AMOUNT).contract_bytes();
    add(
        "IR-SMUGGLE-4".into(),
        C::MemoOrSecondContractSmuggling,
        "Second native transfer to an unlisted account behind the approved one",
        &[R::TX_SHAPE_NOT_ALLOWED, R::TX_DUPLICATE_FIELD],
        tx(native().with(|t| t.extra_contracts.push(second_native))),
    );
    let authority = Msg(vec![(2, bytes(b"active"))]).encode();
    add(
        "IR-SMUGGLE-5".into(),
        C::MemoOrSecondContractSmuggling,
        "Hidden authority list in the transaction body",
        &[R::TX_UNKNOWN_FIELD],
        tx(token().with(|t| t.raw.add(9, V::Bytes(authority)))),
    );
    add(
        "IR-SMUGGLE-6".into(),
        C::MemoOrSecondContractSmuggling,
        "Hidden script bytes in the transaction body",
        &[R::TX_UNKNOWN_FIELD],
        tx(token().with(|t| t.raw.add(12, bytes(b"script")))),
    );
    add(
        "IR-SMUGGLE-7".into(),
        C::MemoOrSecondContractSmuggling,
        "Deprecated reference-block number in the transaction body",
        &[R::TX_UNKNOWN_FIELD],
        tx(token().with(|t| t.raw.add(3, V::Int(1)))),
    );
    add(
        "IR-SMUGGLE-8".into(),
        C::MemoOrSecondContractSmuggling,
        "Provider bytes on the contract",
        &[R::TX_UNKNOWN_FIELD],
        tx(token().with(|t| t.contract.add(3, bytes(b"provider")))),
    );
    add(
        "IR-SMUGGLE-9".into(),
        C::MemoOrSecondContractSmuggling,
        "Contract name on the contract",
        &[R::TX_UNKNOWN_FIELD],
        tx(token().with(|t| t.contract.add(4, bytes(b"name")))),
    );
    add(
        "IR-SMUGGLE-10".into(),
        C::MemoOrSecondContractSmuggling,
        "Parameter type URL that disagrees with the declared contract type",
        &[R::TX_SHAPE_NOT_ALLOWED, R::TX_MALFORMED],
        tx(token().with(|t| t.type_url = TRANSFER_URL.into())),
    );
    add(
        "IR-SMUGGLE-11".into(),
        C::MemoOrSecondContractSmuggling,
        "Native value attached to a token call",
        &[R::TX_VALUE_NOT_ALLOWED],
        tx(token().with(|t| t.value.add(3, V::Int(1)))),
    );
    add(
        "IR-SMUGGLE-12".into(),
        C::MemoOrSecondContractSmuggling,
        "Legacy-token value attached to a token call",
        &[R::TX_VALUE_NOT_ALLOWED],
        tx(token().with(|t| {
            t.value.add(5, V::Int(1));
            t.value.add(6, V::Int(1_000_001));
        })),
    );

    // Fee-limit abuse.
    add(
        "IR-FEE-1".into(),
        C::FeeLimitAbuse,
        "Fee limit above the network maximum",
        &[R::TX_FEE_OVER_BOUND],
        tx(token().with(|t| t.raw.set(18, V::Int(NETWORK_MAX_FEE_LIMIT_SUN + 1)))),
    );
    add(
        "IR-FEE-2".into(),
        C::FeeLimitAbuse,
        "Fee limit within the network maximum but above the policy cap",
        &[R::FEE_OVER_CAP],
        tx(token().with(|t| t.raw.set(18, V::Int(1_000_000_000)))),
    );
    add(
        "IR-FEE-3".into(),
        C::FeeLimitAbuse,
        "Negative fee limit (signed and unsigned readings disagree)",
        &[R::TX_FEE_OVER_BOUND, R::TX_MALFORMED],
        tx(token().with(|t| t.raw.set(18, V::Int(u64::MAX)))),
    );
    add(
        "IR-FEE-4".into(),
        C::FeeLimitAbuse,
        "Fee limit on a native transfer, which carries none",
        &[R::TX_SHAPE_NOT_ALLOWED, R::TX_NON_CANONICAL],
        tx(native().with(|t| t.raw.add(18, V::Int(FEE_CAP_SUN)))),
    );

    // Expired or overlong validity.
    let expiring = |expiration_ms: u64| token().with(|t| t.raw.set(8, V::Int(expiration_ms)));
    add(
        "IR-VALID-1".into(),
        C::ExpiredOrOverlongValidity,
        "Transaction whose expiry is now (already invalid on chain)",
        &[R::TX_EXPIRY_OUT_OF_BOUNDS],
        edit(tx(token()), |s| s.now_ms = EXPIRATION_MS),
    );
    add(
        "IR-VALID-2".into(),
        C::ExpiredOrOverlongValidity,
        "Transaction valid for just over the network maximum",
        &[R::TX_EXPIRY_OUT_OF_BOUNDS],
        tx(expiring(NOW_MS + CHAIN_MAX_EXPIRATION_MS + 1)),
    );
    add(
        "IR-VALID-3".into(),
        C::ExpiredOrOverlongValidity,
        "Long-lived pre-signed transaction (valid for a year)",
        &[R::TX_EXPIRY_OUT_OF_BOUNDS],
        tx(expiring(NOW_MS + 365 * 24 * 3_600_000)),
    );
    add(
        "IR-VALID-4".into(),
        C::ExpiredOrOverlongValidity,
        "Transaction validity within the network maximum but above the policy cap",
        &[R::VALIDITY_OVER_CAP],
        tx(expiring(NOW_MS + MAX_VALIDITY_MS + 2 * 3_600_000)),
    );
    add(
        "IR-VALID-5".into(),
        C::ExpiredOrOverlongValidity,
        "Request past its freshness bound",
        &[R::REQUEST_EXPIRED],
        edit(tx(token()), |s| s.request_not_after_s = NOW_S - 1),
    );
    add(
        "IR-VALID-6".into(),
        C::ExpiredOrOverlongValidity,
        "Request freshness window longer than the maximum",
        &[R::REQUEST_WINDOW_TOO_LONG],
        edit(tx(token()), |s| s.request_not_after_s = NOW_S + 24 * 3_600),
    );
    add(
        "IR-VALID-7".into(),
        C::ExpiredOrOverlongValidity,
        "Approval used after its expiry",
        &[R::APPROVAL_EXPIRED],
        edit(tx(token()), |s| {
            s.evidence.approvals[1].not_after_s = NOW_S - 1
        }),
    );

    // Rolled-back bundle.
    add(
        "IR-ROLLBACK-1".into(),
        C::RolledBackBundle,
        "Older, looser bundle re-offered with its original valid signatures",
        &[R::BUNDLE_ROLLBACK],
        edit(tx(token()), |s| {
            s.governance = Governance::Offered {
                version: BUNDLE_VERSION - 1,
            }
        }),
    );
    add(
        "IR-ROLLBACK-2".into(),
        C::RolledBackBundle,
        "Different, looser bundle offered at the installed version",
        &[R::BUNDLE_ROLLBACK],
        edit(tx(token()), |s| {
            s.governance = Governance::Offered {
                version: BUNDLE_VERSION,
            }
        }),
    );
    add(
        "IR-ROLLBACK-3".into(),
        C::RolledBackBundle,
        "Request evaluated against an older policy version",
        &[R::POLICY_VERSION_MISMATCH],
        edit(tx(token()), |s| s.policy_version = BUNDLE_VERSION - 1),
    );
    add(
        "IR-ROLLBACK-4".into(),
        C::RolledBackBundle,
        "Signer whose policy state was lost or wiped",
        &[R::NO_POLICY],
        edit(tx(token()), |s| s.governance = Governance::Missing),
    );

    // Forged or duplicate approvals.
    add(
        "IR-APPROVAL-1".into(),
        C::ForgedOrDuplicateApprovals,
        "Approval whose signature does not verify",
        &[R::APPROVAL_INVALID],
        edit(tx(token()), |s| {
            s.evidence.approvals[1].corrupt_signature = true
        }),
    );
    add(
        "IR-APPROVAL-2".into(),
        C::ForgedOrDuplicateApprovals,
        "Approval by a key pinned for no role",
        &[R::APPROVER_UNKNOWN],
        edit(tx(token()), |s| {
            s.evidence.approvals[1] = statement(Key::Outsider, Role::Approver)
        }),
    );
    add(
        "IR-APPROVAL-3".into(),
        C::ForgedOrDuplicateApprovals,
        "Same approver counted twice",
        &[R::APPROVER_DUPLICATE],
        edit(tx(token()), |s| s.evidence.approvals[1] = approver(0)),
    );
    add(
        "IR-APPROVAL-4".into(),
        C::ForgedOrDuplicateApprovals,
        "Quorum short by one approval",
        &[R::APPROVALS_INSUFFICIENT],
        edit(tx(token()), |s| s.evidence.approvals.truncate(QUORUM - 1)),
    );
    add(
        "IR-APPROVAL-5".into(),
        C::ForgedOrDuplicateApprovals,
        "Approvals collected for a smaller transfer reused for a larger one",
        &[R::APPROVAL_INTENT_MISMATCH],
        edit(tx(token_to(&RECIPIENT, 900_000_000)), |s| {
            for a in &mut s.evidence.approvals {
                a.over = Over::OtherTx(original.clone());
            }
        }),
    );
    add(
        "IR-APPROVAL-6".into(),
        C::ForgedOrDuplicateApprovals,
        "Approver's statement signed in the initiator role and counted as an approval",
        &[R::APPROVAL_INVALID, R::APPROVER_UNKNOWN],
        edit(tx(token()), |s| {
            s.evidence.approvals[1].role = Role::Initiator
        }),
    );
    add(
        "IR-APPROVAL-7".into(),
        C::ForgedOrDuplicateApprovals,
        "Initiator statement whose signature does not verify",
        &[R::INITIATOR_INVALID],
        edit(tx(token()), |s| {
            s.evidence.initiator.corrupt_signature = true
        }),
    );
    add(
        "IR-APPROVAL-8".into(),
        C::ForgedOrDuplicateApprovals,
        "Initiator statement by a key pinned for no role",
        &[R::INITIATOR_INVALID],
        edit(tx(token()), |s| {
            s.evidence.initiator = statement(Key::Outsider, Role::Initiator)
        }),
    );
    add(
        "IR-APPROVAL-9".into(),
        C::ForgedOrDuplicateApprovals,
        "Initiator statement signed in the approver role",
        &[R::INITIATOR_INVALID],
        edit(tx(token()), |s| s.evidence.initiator.role = Role::Approver),
    );

    // Initiator self-approval.
    add(
        "IR-SOD-1".into(),
        C::InitiatorSelfApproval,
        "Dual-role key initiates and supplies one of the quorum approvals",
        &[R::SOD_VIOLATION],
        edit(tx(token()), |s| {
            s.evidence.initiator = statement(Key::Approver(2), Role::Initiator);
            s.evidence.approvals = vec![approver(2), approver(0)];
        }),
    );
    add(
        "IR-SOD-2".into(),
        C::InitiatorSelfApproval,
        "Dual-role key initiates and adds a self-approval beyond a quorum met by others",
        &[R::SOD_VIOLATION],
        edit(tx(token()), |s| {
            s.evidence.initiator = statement(Key::Approver(2), Role::Initiator);
            s.evidence.approvals = vec![approver(0), approver(1), approver(2)];
        }),
    );
    add(
        "IR-SOD-3".into(),
        C::InitiatorSelfApproval,
        "Initiator-only key signs an approval for its own request",
        &[R::SOD_VIOLATION, R::APPROVER_UNKNOWN],
        edit(tx(token()), |s| {
            s.evidence.approvals[1] = statement(Key::Initiator, Role::Approver)
        }),
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The fixture writer reproduces both tronweb reference vectors byte for byte (the same
    /// vectors the chains crate and `vaultex-types` pin), so the baselines are real TRON bytes.
    #[test]
    fn baselines_reproduce_tronweb_reference_vectors() {
        let native_ref = concat!(
            "0a0200012208010203040506070840e0a499ffbc315a67080112630a2d747970652e676f6f676c656170",
            "69732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15411111111111",
            "111111111111111111111111111111121541222222222222222222222222222222222222222218c0843d",
            "7080d095ffbc31",
        );
        let token_ref = concat!(
            "0a0200012208010203040506070840e0a499ffbc315aae01081f12a9010a31747970652e676f6f676c65",
            "617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15",
            "411111111111111111111111111111111111111111121541999999999999999999999999999999999999",
            "99992244a9059cbb00000000000000000000000022222222222222222222222222222222222222220000",
            "0000000000000000000000000000000000000000000000000000000f42407080d095ffbc31900180c2d7",
            "2f",
        );
        // The references are signed under the owner permission (no Permission_id).
        let owner = |t: Tx| t.with(|t| t.contract.remove(5)).encode();
        assert_eq!(hex(&owner(native())), native_ref);
        assert_eq!(hex(&owner(token())), token_ref);
        // The world's baselines add exactly `Permission_id = 2` (field 5, after the parameter).
        for t in [native(), token()] {
            let owner_contract = t.with(|t| t.contract.remove(5)).contract_bytes();
            assert_eq!(
                t.contract_bytes(),
                [owner_contract, vec![0x28, 0x02]].concat()
            );
        }
    }
}
