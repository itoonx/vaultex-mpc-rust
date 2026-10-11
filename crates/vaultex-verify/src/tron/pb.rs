//! Strict protobuf reader for the TRON grammar. It only reads; the encoder lives apart, in
//! `encode.rs`, and shares no tables with it.
//!
//! Profile, applied to every nested message:
//! - wire types 0 (varint) and 2 (length-delimited) only, and only the one the schema names;
//! - varints (tags, values and lengths) minimal and at most 10 bytes, with a 10th byte ≤ 1;
//! - lengths within the input, and no bytes left over;
//! - only the fields in the message's allowlist, each at most once (so a `repeated` field occurs
//!   once), in strictly ascending field order;
//! - proto3 default values (0, empty bytes) are never encoded.

use super::TronRefusal;

/// What a message schema says about one field number.
#[derive(Clone, Copy)]
pub(super) enum Rule {
    /// Allowed, as a varint.
    Varint,
    /// Allowed, as length-delimited bytes.
    Bytes,
    /// Refused with this specific refusal (so the class shows up as its own refusal), whatever its
    /// wire type or value.
    Refuse(TronRefusal),
}

/// A field value, borrowed from the input.
#[derive(Clone, Copy)]
pub(super) enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// Reads one message under `schema`. Slot `i` of the result holds the value of `schema[i]`'s field
/// if it was present (a `Refuse` slot is always `None`). Field numbers not in `schema` are refused.
pub(super) fn read<'a, const N: usize>(
    mut buf: &'a [u8],
    schema: &[(u64, Rule); N],
) -> Result<[Option<Value<'a>>; N], TronRefusal> {
    let mut out = [None; N];
    let mut last_field = 0;
    while !buf.is_empty() {
        let key = varint(&mut buf)?;
        let field = key.wrapping_shr(3);
        let wire = key & 7;
        if field == 0 {
            return Err(TronRefusal::PbMalformed);
        }
        let Some((rule, slot)) = schema
            .iter()
            .zip(out.iter_mut())
            .find_map(|((f, rule), slot)| (*f == field).then_some((*rule, slot)))
        else {
            return Err(TronRefusal::FieldNotAllowed);
        };
        let is_varint = match rule {
            Rule::Refuse(refusal) => return Err(refusal),
            Rule::Varint => true,
            Rule::Bytes => false,
        };
        if wire != if is_varint { 0 } else { 2 } {
            return Err(TronRefusal::PbWireType);
        }
        if slot.is_some() {
            return Err(TronRefusal::PbDuplicateField);
        }
        if field < last_field {
            return Err(TronRefusal::PbFieldOrder);
        }
        last_field = field;
        let value = if is_varint {
            Value::Varint(varint(&mut buf)?)
        } else {
            Value::Bytes(len_delimited(&mut buf)?)
        };
        if matches!(value, Value::Varint(0)) || matches!(value, Value::Bytes(b) if b.is_empty()) {
            return Err(TronRefusal::PbDefaultValue);
        }
        *slot = Some(value);
    }
    Ok(out)
}

/// Reads a minimal varint of at most 10 bytes (64 bits).
fn varint(buf: &mut &[u8]) -> Result<u64, TronRefusal> {
    let mut value = 0u64;
    for (i, shift) in (0..64u32).step_by(7).enumerate() {
        let (&byte, rest) = buf.split_first().ok_or(TronRefusal::PbMalformed)?;
        *buf = rest;
        if i == 9 && byte > 1 {
            return Err(TronRefusal::PbMalformed); // more than 64 bits
        }
        value |= u64::from(byte & 0x7f).wrapping_shl(shift);
        if byte & 0x80 == 0 {
            // A minimal varint never ends in a zero byte, except the one-byte encoding of 0.
            if i > 0 && byte == 0 {
                return Err(TronRefusal::PbNonCanonicalVarint);
            }
            return Ok(value);
        }
    }
    // The 10th byte is ≤ 1, so it always ends the varint above.
    Err(TronRefusal::PbMalformed)
}

fn len_delimited<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], TronRefusal> {
    let len = usize::try_from(varint(buf)?).map_err(|_| TronRefusal::PbMalformed)?;
    let (head, tail) = buf.split_at_checked(len).ok_or(TronRefusal::PbMalformed)?;
    *buf = tail;
    Ok(head)
}
