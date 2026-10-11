// Shared pieces of the independent vector oracle (T13-2).
// Written from specs/INTENT_V1.md and specs/RECEIPT_V1.md only. Node stdlib only.
import { createHash } from 'node:crypto';

// ---------- bytes and hashes ----------

export function fromHex(s, what = 'hex') {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) {
    throw new OracleError(`${what}: not lower-case hex: ${JSON.stringify(s)}`);
  }
  return Uint8Array.from(Buffer.from(s, 'hex'));
}
export const toHex = (b) => Buffer.from(b).toString('hex');
export const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
export const bytesEqual = (a, b) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
export const sha256 = (b) => Uint8Array.from(createHash('sha256').update(b).digest());
export const sha512 = (b) => Uint8Array.from(createHash('sha512').update(b).digest());

// A harness error: the vector file or the oracle itself is wrong, not the input under test.
export class OracleError extends Error {}

// Decimal strings in the vector files ("Integers in the vector file are decimal strings").
export function dec(s, what) {
  if (typeof s !== 'string' || !/^(0|[1-9][0-9]*)$/.test(s)) {
    throw new OracleError(`${what}: not a decimal string: ${JSON.stringify(s)}`);
  }
  return BigInt(s);
}

// ---------- BCS (INTENT_V1 §5.1, RECEIPT_V1 §5.1) ----------

export function uleb128(n) {
  n = BigInt(n);
  const out = [];
  do {
    let b = Number(n & 0x7fn);
    n >>= 7n;
    if (n > 0n) b |= 0x80;
    out.push(b);
  } while (n > 0n);
  return Uint8Array.from(out);
}
export function uintLE(n, width) {
  n = BigInt(n);
  if (n < 0n || n >= 1n << BigInt(8 * width)) throw new OracleError(`u${8 * width} out of range: ${n}`);
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
export const u16 = (n) => uintLE(n, 2);
export const u32 = (n) => uintLE(n, 4);
export const u64 = (n) => uintLE(n, 8);
export const u256 = (n) => uintLE(n, 32); // U256 is 32 bytes little-endian (INTENT_V1 §5.1)
export const bcsBytes = (b) => concat(uleb128(b.length), b);
export const bcsStr = (s) => bcsBytes(Buffer.from(s, 'ascii'));
export const leToBig = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
export const beToBig = (b) => { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; };

// Strict BCS reader: any failure throws BcsError (RECEIPT_V1 §5.4 -> MALFORMED).
export class BcsError extends Error {}
export class BcsReader {
  constructor(buf) { this.b = buf; this.p = 0; }
  take(n) {
    if (n > this.b.length - this.p) throw new BcsError('runs past the end');
    const out = this.b.subarray(this.p, this.p + n);
    this.p += n;
    return out;
  }
  uint(width) { return leToBig(this.take(width)); }
  uleb() {
    // Shortest form only; BCS lengths and variant indexes fit in u32.
    let n = 0n;
    for (let i = 0; i < 5; i++) {
      const byte = this.take(1)[0];
      n |= BigInt(byte & 0x7f) << BigInt(7 * i);
      if ((byte & 0x80) === 0) {
        if (i > 0 && byte === 0) throw new BcsError('non-minimal ULEB128');
        if (n > 0xffffffffn) throw new BcsError('ULEB128 above u32');
        return n;
      }
    }
    throw new BcsError('ULEB128 too long');
  }
  bytes() {
    const len = this.uleb();
    if (len > BigInt(this.b.length - this.p)) throw new BcsError('length runs past the end');
    return this.take(Number(len));
  }
  option(readValue) {
    const tag = this.take(1)[0];
    if (tag === 0) return null;
    if (tag === 1) return readValue();
    throw new BcsError(`option tag ${tag}`);
  }
  done() { if (this.p !== this.b.length) throw new BcsError('trailing bytes'); }
}

// ---------- identifiers (INTENT_V1 §4.2) ----------

export const WALLET_ID_RE = /^[a-z0-9-]{1,64}$/;

// NetworkId allowlist -> ChainId. Unknown networks fail closed.
export const NETWORKS = new Map([
  ['tron:728126428', 1],
  ['tron:2494104990', 1],
  ['tron:3448148188', 1],
  ['eip155:1', 2],
  ['eip155:11155111', 2],
]);
export const CHAIN_TRON = 1;

// ---------- refusal-code registry (RECEIPT_V1 Appendix A) ----------

export const REGISTRY = new Map([
  [0x0101, 'MALFORMED'], [0x0102, 'UNSUPPORTED_VERSION'], [0x0103, 'REQUEST_EXPIRED'],
  [0x0104, 'REQUEST_WINDOW_TOO_LONG'], [0x0105, 'REPLAY'], [0x0106, 'UNKNOWN_WALLET'],
  [0x0107, 'NETWORK_MISMATCH'], [0x0108, 'POLICY_VERSION_MISMATCH'], [0x0109, 'PAYLOAD_TOO_LARGE'],
  [0x010a, 'PAYLOAD_MISSING'], [0x010b, 'SIGNER_SET_INVALID'], [0x010c, 'ISSUER_NOT_AUTHORIZED'],
  [0x010d, 'SUBJECT_MISMATCH'],
  [0x0201, 'TX_MALFORMED'], [0x0202, 'TX_TRAILING_BYTES'], [0x0203, 'TX_UNKNOWN_FIELD'],
  [0x0204, 'TX_DUPLICATE_FIELD'], [0x0205, 'TX_NON_CANONICAL'], [0x0206, 'TX_SHAPE_NOT_ALLOWED'],
  [0x0207, 'TX_SELECTOR_NOT_ALLOWED'], [0x0208, 'TX_VALUE_NOT_ALLOWED'], [0x0209, 'TX_PERMISSION_NOT_ALLOWED'],
  [0x020a, 'TX_SENDER_MISMATCH'], [0x020b, 'TX_EXPIRY_OUT_OF_BOUNDS'], [0x020c, 'TX_FEE_OVER_BOUND'],
  [0x020d, 'TX_DIGEST_MISMATCH'], [0x020e, 'TX_CHAIN_ID_MISMATCH'],
  [0x0301, 'NO_POLICY'], [0x0302, 'BUNDLE_INVALID'], [0x0303, 'BUNDLE_ROLLBACK'],
  [0x0304, 'BUNDLE_NOT_EFFECTIVE'], [0x0305, 'ASSET_NOT_ALLOWED'], [0x0306, 'RECIPIENT_NOT_ALLOWED'],
  [0x0307, 'AMOUNT_OVER_TX_CAP'], [0x0308, 'FEE_OVER_CAP'], [0x0309, 'VALIDITY_OVER_CAP'],
  [0x0401, 'INITIATOR_INVALID'], [0x0402, 'APPROVALS_INSUFFICIENT'], [0x0403, 'APPROVAL_INVALID'],
  [0x0404, 'APPROVER_UNKNOWN'], [0x0405, 'APPROVER_DUPLICATE'], [0x0406, 'SOD_VIOLATION'],
  [0x0407, 'APPROVAL_EXPIRED'], [0x0408, 'APPROVAL_INTENT_MISMATCH'],
  [0x0501, 'VELOCITY_EXCEEDED'], [0x0502, 'FROZEN'], [0x0503, 'BREAKER_TRIPPED'], [0x0504, 'CLOCK_UNTRUSTED'],
  [0x0601, 'STATE_WRITE_FAILED'], [0x0602, 'KEY_UNAVAILABLE'], [0x0603, 'INTERNAL'],
  [0x0701, 'GROUP_EXISTS'], [0x0702, 'KEYGEN_INTENT_INVALID'], [0x0703, 'AUX_EPOCH_UNKNOWN'],
  [0x0704, 'ADMIN_QUORUM_INSUFFICIENT'],
  [0xf001, 'BUSY'], [0xf002, 'TIMEOUT'], [0xf003, 'PEER_UNREACHABLE'], [0xf004, 'ENGINE_ABORT'],
]);
export const codeHex = (c) => '0x' + c.toString(16).padStart(4, '0');
export function parseCode(s, what) {
  if (typeof s !== 'string' || !/^0x[0-9a-f]{4}$/.test(s)) throw new OracleError(`${what}: bad code ${JSON.stringify(s)}`);
  return parseInt(s.slice(2), 16);
}
// KAT plan R10: an expected code must be in the registry, under its registered name.
export function requireRegistered(codeStr, name, what) {
  const code = parseCode(codeStr, what);
  if (REGISTRY.get(code) !== name) {
    throw new OracleError(`${what}: code ${codeStr} is ${REGISTRY.get(code) ?? 'not registered'}, vector says ${name}`);
  }
  return code;
}

// ---------- strict JSON shape checks (KAT plan R10: unknown keys fail) ----------

export function requireKeys(obj, keys, what) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new OracleError(`${what}: not an object`);
  const have = Object.keys(obj).sort();
  const want = [...keys].sort();
  if (have.join(',') !== want.join(',')) {
    throw new OracleError(`${what}: keys [${have}] != expected [${want}]`);
  }
}
