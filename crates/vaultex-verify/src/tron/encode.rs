//! Canonical TRON encoder for the two accepted shapes, written apart from the reader (`pb.rs`) and
//! sharing no tables with it, so that "re-encoding is byte-equal" is an independent cross-check of
//! the reader.
//!
//! Output order: raw `1, 4, 8, 11, 14, [18]`; Contract `1, 2, [5]`; Any `1, 2`; transfer value
//! `1, 2, 3`; trigger value `1, 2, 4`. `Permission_id` is emitted only when non-zero, `fee_limit`
//! only when present. This is the order tronweb produces for both shapes (pinned vectors in the
//! tests).

/// `ContractType.TransferContract`.
pub(super) const TRANSFER_TYPE: u64 = 1;
/// `ContractType.TriggerSmartContract`.
pub(super) const TRIGGER_TYPE: u64 = 31;
pub(super) const TRANSFER_URL: &str = "type.googleapis.com/protocol.TransferContract";
pub(super) const TRIGGER_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// The contract call, with its fields as they appear in the transaction.
#[derive(Clone, Copy)]
pub(super) enum Call<'a> {
    /// A native TRX transfer.
    Transfer {
        owner: &'a [u8],
        to: &'a [u8],
        amount: u64,
    },
    /// A smart-contract call with no call value and no TRC-10 fields.
    Trigger {
        owner: &'a [u8],
        contract: &'a [u8],
        data: &'a [u8],
    },
}

/// The fields of `Transaction.raw` that the accepted shapes carry.
pub(super) struct Tx<'a> {
    pub ref_block_bytes: &'a [u8],
    pub ref_block_hash: &'a [u8],
    pub expiration: u64,
    pub call: Call<'a>,
    /// 0 (owner) is not emitted.
    pub permission_id: u64,
    pub timestamp: u64,
    pub fee_limit: Option<u64>,
}

/// Encodes `tx` as `Transaction.raw`.
pub(super) fn encode(tx: &Tx<'_>) -> Vec<u8> {
    let mut value = Vec::new();
    let (contract_type, type_url) = match tx.call {
        Call::Transfer { owner, to, amount } => {
            put_bytes(&mut value, 1, owner);
            put_bytes(&mut value, 2, to);
            put_int(&mut value, 3, amount);
            (TRANSFER_TYPE, TRANSFER_URL)
        }
        Call::Trigger {
            owner,
            contract,
            data,
        } => {
            put_bytes(&mut value, 1, owner);
            put_bytes(&mut value, 2, contract);
            put_bytes(&mut value, 4, data);
            (TRIGGER_TYPE, TRIGGER_URL)
        }
    };

    let mut any = Vec::new();
    put_bytes(&mut any, 1, type_url.as_bytes());
    put_bytes(&mut any, 2, &value);

    let mut contract = Vec::new();
    put_int(&mut contract, 1, contract_type);
    put_bytes(&mut contract, 2, &any);
    if tx.permission_id != 0 {
        put_int(&mut contract, 5, tx.permission_id);
    }

    let mut raw = Vec::new();
    put_bytes(&mut raw, 1, tx.ref_block_bytes);
    put_bytes(&mut raw, 4, tx.ref_block_hash);
    put_int(&mut raw, 8, tx.expiration);
    put_bytes(&mut raw, 11, &contract);
    put_int(&mut raw, 14, tx.timestamp);
    if let Some(fee_limit) = tx.fee_limit {
        put_int(&mut raw, 18, fee_limit);
    }
    raw
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v = v.wrapping_shr(7);
    }
    out.push(v as u8);
}

fn put_int(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, field.wrapping_shl(3)); // wire type 0
    put_varint(out, v);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, field.wrapping_shl(3) | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
