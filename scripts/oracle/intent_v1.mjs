// INTENT_V1 oracle: the strict TRON decoder of INTENT_V1 §7, the intent BCS of §5.1,
// the digest of §6.1 and SignInput of §5.3, plus a runner for the RFC's vector file (§9).
// Written from specs/INTENT_V1.md only (and RECEIPT_V1 Appendix A for the code registry).
import {
  CHAIN_TRON, NETWORKS, OracleError, REGISTRY, WALLET_ID_RE, bcsBytes, bcsStr, beToBig, bytesEqual,
  codeHex, concat, dec, fromHex, parseCode, requireKeys, requireRegistered, sha256, toHex, u16, u256, u64,
  uleb128,
} from './lib.mjs';

// ---------- constants (§4.4, §5.2, §6.1) ----------

export const MAX_RAW_BYTES = 512;
export const MAX_VALIDITY_MS = 86_400_000n;
export const MAX_FEE_LIMIT_SUN = 15_000_000_000n;
export const INTENT_TAG = 'VAULTEX/INTENT/v1';
const INT64_MAX = 2n ** 63n - 1n;
const TRANSFER_URL = Buffer.from('type.googleapis.com/protocol.TransferContract', 'ascii');
const TRIGGER_URL = Buffer.from('type.googleapis.com/protocol.TriggerSmartContract', 'ascii');
const TRANSFER_SELECTOR = Buffer.from('a9059cbb', 'hex');

// ---------- checks and codes (§7.4, in table order) ----------

export const CHECKS = [
  ['NETWORK_NOT_TRON', 0x0107], ['EMPTY', 0x010a], ['TOO_LARGE', 0x0109],
  ['PB_MALFORMED', 0x0201], ['PB_NON_CANONICAL_VARINT', 0x0205], ['FIELD_NOT_ALLOWED', 0x0203],
  ['MEMO_PRESENT', 0x0206], ['CALL_VALUE_PRESENT', 0x0208], ['TRC10_FIELDS_PRESENT', 0x0208],
  ['PB_WIRE_TYPE', 0x0201], ['PB_DUPLICATE_FIELD', 0x0204], ['PB_FIELD_ORDER', 0x0205],
  ['PB_DEFAULT_VALUE', 0x0205], ['MISSING_FIELD', 0x0201], ['INT_RANGE', 0x0201],
  ['TYPE_URL_MISMATCH', 0x0206], ['ACCOUNT_PERMISSION_UPDATE', 0x0206], ['CONTRACT_TYPE_NOT_ALLOWED', 0x0206],
  ['DIGEST_MISMATCH', 0x020d], ['REF_BLOCK_SHAPE', 0x0201], ['PERMISSION_ID_MISMATCH', 0x0209],
  ['ADDRESS_SHAPE', 0x0201], ['OWNER_NOT_WALLET', 0x020a], ['SELF_TRANSFER', 0x0206],
  ['FEE_LIMIT_ON_NATIVE', 0x0206], ['CALLDATA_LENGTH', 0x0207], ['SELECTOR_NOT_TRANSFER', 0x0207],
  ['CALLDATA_ADDRESS_PADDING', 0x0205], ['RECIPIENT_ZERO', 0x0206], ['AMOUNT_ZERO', 0x0208],
  ['TOKEN_NOT_ALLOWLISTED', 0x0305], ['FEE_LIMIT_MISSING', 0x0206], ['FEE_LIMIT_OVER_BOUND', 0x020c],
  ['EXPIRATION_WINDOW', 0x020b], ['TIMESTAMP_INVALID', 0x020b], ['NON_CANONICAL_ENCODING', 0x0205],
];
const CODE_OF = new Map(CHECKS);

class Refusal extends Error {
  constructor(check) { super(check); this.check = check; }
}
const refuse = (check) => { throw new Refusal(check); };

// ---------- protobuf reading (§7.2) ----------

const VARINT = 0, BYTES = 2;
// Schemas (§7.1): field number -> wire type, or the name of the check that refuses the field.
const RAW = { 1: BYTES, 4: BYTES, 8: VARINT, 10: 'MEMO_PRESENT', 11: BYTES, 14: VARINT, 18: VARINT };
const CONTRACT = { 1: VARINT, 2: BYTES, 5: VARINT };
const ANY = { 1: BYTES, 2: BYTES };
const TRANSFER = { 1: BYTES, 2: BYTES, 3: VARINT };
const TRIGGER = { 1: BYTES, 2: BYTES, 3: 'CALL_VALUE_PRESENT', 4: BYTES, 5: 'TRC10_FIELDS_PRESENT', 6: 'TRC10_FIELDS_PRESENT' };

function readVarint(buf, pos) {
  let value = 0n;
  for (let i = 0; i < 10; i++) {
    if (pos + i >= buf.length) refuse('PB_MALFORMED'); // V1
    const b = buf[pos + i];
    if (i === 9 && b > 1) refuse('PB_MALFORMED'); // V2
    value |= BigInt(b & 0x7f) << BigInt(7 * i);
    if ((b & 0x80) === 0) {
      if (i >= 1 && b === 0) refuse('PB_NON_CANONICAL_VARINT'); // V3
      return [value, pos + i + 1];
    }
  }
  throw new OracleError('unreachable: V2 bounds a varint to 10 bytes');
}

// Reads one message under its schema. Returns Map(fieldNumber -> BigInt | Uint8Array).
function readMessage(buf, schema) {
  const fields = new Map();
  let pos = 0, prev = 0n;
  while (pos < buf.length) {
    let key;
    [key, pos] = readVarint(buf, pos); // R1
    const num = key >> 3n, wire = Number(key & 7n); // R2
    if (num === 0n) refuse('PB_MALFORMED');
    const rule = schema[num.toString()];
    if (rule === undefined) refuse('FIELD_NOT_ALLOWED'); // R3
    if (typeof rule === 'string') refuse(rule); // R4
    if (wire !== rule) refuse('PB_WIRE_TYPE'); // R5
    if (fields.has(num.toString())) refuse('PB_DUPLICATE_FIELD'); // R6
    if (num < prev) refuse('PB_FIELD_ORDER'); // R7
    let value;
    if (rule === VARINT) { // R8
      [value, pos] = readVarint(buf, pos);
      if (value === 0n) refuse('PB_DEFAULT_VALUE'); // R9
    } else {
      let len;
      [len, pos] = readVarint(buf, pos);
      if (len > BigInt(buf.length - pos)) refuse('PB_MALFORMED');
      value = buf.subarray(pos, pos + Number(len));
      pos += Number(len);
      if (value.length === 0) refuse('PB_DEFAULT_VALUE'); // R9
    }
    fields.set(num.toString(), value);
    prev = num;
  }
  return fields;
}

// ---------- canonical protobuf writing (§5.2) ----------

const pbVarint = (n) => uleb128(n); // protobuf varints are the same 7-bit little-endian groups
const pbField = (num, wire, value) => concat(
  pbVarint((BigInt(num) << 3n) | BigInt(wire)),
  wire === VARINT ? pbVarint(value) : concat(pbVarint(value.length), value),
);
function encodeRaw(d) {
  const valueMsg = d.type === 1n
    ? concat(pbField(1, BYTES, d.owner), pbField(2, BYTES, d.counterparty), pbField(3, VARINT, d.amount))
    : concat(pbField(1, BYTES, d.owner), pbField(2, BYTES, d.counterparty), pbField(4, BYTES, d.data));
  const any = concat(pbField(1, BYTES, d.typeUrl), pbField(2, BYTES, valueMsg));
  const contract = concat(
    pbField(1, VARINT, d.type), pbField(2, BYTES, any),
    d.permissionId !== 0n ? pbField(5, VARINT, d.permissionId) : new Uint8Array(0),
  );
  return concat(
    pbField(1, BYTES, d.refBlockBytes), pbField(4, BYTES, d.refBlockHash), pbField(8, VARINT, d.expiration),
    pbField(11, BYTES, contract), pbField(14, VARINT, d.timestamp),
    d.feeLimit !== undefined ? pbField(18, VARINT, d.feeLimit) : new Uint8Array(0),
  );
}

// ---------- intent BCS, digest, SignInput (§5.1, §5.3, §6.1) ----------

export function intentBcs(it) {
  return concat(
    bcsStr(it.wallet_id), u16(it.chain), bcsStr(it.network), bcsBytes(it.sender), bcsBytes(it.recipient),
    it.asset.kind === 'native' ? Uint8Array.of(0) : concat(Uint8Array.of(1), bcsBytes(it.asset.address)),
    u256(it.amount), u256(it.fee_cap), u64(it.not_after_ms), it.tx_hash,
  );
}
export const intentDigest = (bcs) => sha256(concat(bcsStr(INTENT_TAG), bcs));
export const signInputBcs = (raw) => concat(Uint8Array.of(0, 0), bcsBytes(raw)); // EcdsaPreimage{Sha256, raw}

// ---------- the decoder (§7.3) ----------

// ctx: { wallet_id, network, wallet_address: Uint8Array, permission_id: BigInt,
//        trc20_allowlist: Uint8Array[], now_ms, max_validity_ms, max_fee_limit_sun,
//        max_clock_skew_ms: BigInt, claimed_txid: Uint8Array | null }
// Returns { accept: { intent, intentBcs, digest, signInput } } or { refuse: checkName }.
export function decodeTronV1(raw, ctx) {
  try {
    return { accept: decode(raw, ctx) };
  } catch (e) {
    if (e instanceof Refusal) return { refuse: e.check };
    throw e;
  }
}

function decode(raw, ctx) {
  // 1. Context and size. ponytail: a network off the allowlist has no chain, so it is not TRON.
  if (NETWORKS.get(ctx.network) !== CHAIN_TRON) refuse('NETWORK_NOT_TRON');
  if (raw.length === 0) refuse('EMPTY');
  if (raw.length > MAX_RAW_BYTES) refuse('TOO_LARGE');

  // 2. raw.
  const r = readMessage(raw, RAW);
  for (const f of ['1', '4', '8', '11', '14']) if (!r.has(f)) refuse('MISSING_FIELD');
  const expiration = r.get('8'), timestamp = r.get('14'), feeLimit = r.get('18');
  if (expiration > INT64_MAX) refuse('INT_RANGE');
  if (timestamp > INT64_MAX) refuse('INT_RANGE');
  if (feeLimit !== undefined && feeLimit > INT64_MAX) refuse('INT_RANGE');

  // 3. Contract, then Any.
  const c = readMessage(r.get('11'), CONTRACT);
  if (!c.has('1') || !c.has('2')) refuse('MISSING_FIELD');
  const type = c.get('1');
  const permissionId = c.get('5') ?? 0n;
  const any = readMessage(c.get('2'), ANY);
  if (!any.has('1') || !any.has('2')) refuse('MISSING_FIELD');
  const typeUrl = any.get('1');

  // 4. Contract type.
  let v, owner, counterparty, amount, data;
  if (type === 1n) {
    if (!bytesEqual(typeUrl, TRANSFER_URL)) refuse('TYPE_URL_MISMATCH');
    v = readMessage(any.get('2'), TRANSFER);
    if (!v.has('1') || !v.has('2') || !v.has('3')) refuse('MISSING_FIELD');
    [owner, counterparty, amount] = [v.get('1'), v.get('2'), v.get('3')];
    if (amount > INT64_MAX) refuse('INT_RANGE');
  } else if (type === 31n) {
    if (!bytesEqual(typeUrl, TRIGGER_URL)) refuse('TYPE_URL_MISMATCH');
    v = readMessage(any.get('2'), TRIGGER);
    if (!v.has('1') || !v.has('2') || !v.has('4')) refuse('MISSING_FIELD');
    [owner, counterparty, data] = [v.get('1'), v.get('2'), v.get('4')];
  } else if (type === 46n) {
    refuse('ACCOUNT_PERMISSION_UPDATE');
  } else {
    refuse('CONTRACT_TYPE_NOT_ALLOWED');
  }

  // 5. Transaction facts.
  const txHash = sha256(raw);
  if (ctx.claimed_txid !== null && !bytesEqual(ctx.claimed_txid, txHash)) refuse('DIGEST_MISMATCH');
  if (r.get('1').length !== 2 || r.get('4').length !== 8) refuse('REF_BLOCK_SHAPE');
  if (permissionId === 1n || permissionId !== ctx.permission_id) refuse('PERMISSION_ID_MISMATCH');
  const tronAddr = (a) => a.length === 21 && a[0] === 0x41;
  if (!tronAddr(owner)) refuse('ADDRESS_SHAPE');
  if (!tronAddr(counterparty)) refuse('ADDRESS_SHAPE');
  if (!bytesEqual(owner, ctx.wallet_address)) refuse('OWNER_NOT_WALLET');

  // 6. Shape.
  let intentFields;
  if (type === 1n) {
    if (bytesEqual(counterparty, owner)) refuse('SELF_TRANSFER');
    if (feeLimit !== undefined) refuse('FEE_LIMIT_ON_NATIVE');
    intentFields = { recipient: counterparty, asset: { kind: 'native' }, amount, fee_cap: 0n };
  } else {
    const isZero = (b) => b.every((x) => x === 0);
    if (data.length < 4) refuse('CALLDATA_LENGTH');
    if (!bytesEqual(data.subarray(0, 4), TRANSFER_SELECTOR)) refuse('SELECTOR_NOT_TRANSFER');
    if (data.length !== 68) refuse('CALLDATA_LENGTH');
    if (!isZero(data.subarray(4, 16))) refuse('CALLDATA_ADDRESS_PADDING');
    if (isZero(data.subarray(16, 36))) refuse('RECIPIENT_ZERO');
    if (isZero(data.subarray(36, 68))) refuse('AMOUNT_ZERO');
    if (!ctx.trc20_allowlist.some((a) => bytesEqual(a, counterparty))) refuse('TOKEN_NOT_ALLOWLISTED');
    if (feeLimit === undefined) refuse('FEE_LIMIT_MISSING');
    const feeBound = ctx.max_fee_limit_sun < MAX_FEE_LIMIT_SUN ? ctx.max_fee_limit_sun : MAX_FEE_LIMIT_SUN;
    if (feeLimit > feeBound) refuse('FEE_LIMIT_OVER_BOUND');
    intentFields = {
      recipient: concat(Uint8Array.of(0x41), data.subarray(16, 36)),
      asset: { kind: 'contract', address: counterparty },
      amount: beToBig(data.subarray(36, 68)),
      fee_cap: feeLimit,
    };
  }
  const V = ctx.max_validity_ms < MAX_VALIDITY_MS ? ctx.max_validity_ms : MAX_VALIDITY_MS;
  const now = ctx.now_ms;
  if (expiration <= now || expiration > now + V) refuse('EXPIRATION_WINDOW');
  const oldest = now - V < 0n ? 0n : now - V;
  if (timestamp > expiration || timestamp > now + ctx.max_clock_skew_ms || timestamp < oldest) refuse('TIMESTAMP_INVALID');

  // 7. Canonical form.
  const reencoded = encodeRaw({
    refBlockBytes: r.get('1'), refBlockHash: r.get('4'), expiration, timestamp, feeLimit,
    type, permissionId, typeUrl, owner, counterparty, amount, data,
  });
  if (!bytesEqual(reencoded, raw)) refuse('NON_CANONICAL_ENCODING');

  // Accept (§7.5).
  const intent = {
    wallet_id: ctx.wallet_id, chain: BigInt(CHAIN_TRON), network: ctx.network, sender: owner,
    ...intentFields, not_after_ms: expiration, tx_hash: txHash,
  };
  const bcs = intentBcs(intent);
  return { intent, intentBcs: bcs, digest: intentDigest(bcs), signInput: signInputBcs(raw) };
}

// ---------- vector file runner (§9) ----------

const TOP_KEYS = ['rfc', 'rfc_version', 'kind', 'generated_by', 'constants', 'checks', 'untested_checks', 'vectors'];
const VECTOR_KEYS = ['id', 'rule', 'base', 'description', 'input', 'expect'];
const CTX_KEYS = ['wallet_id', 'network', 'wallet_address', 'permission_id', 'trc20_allowlist', 'now_ms',
  'max_validity_ms', 'max_fee_limit_sun', 'max_clock_skew_ms', 'claimed_txid'];
const ACCEPT_KEYS = ['tx_hash', 'intent', 'intent_bcs', 'intent_digest', 'sign_input_bcs'];
const INTENT_KEYS = ['wallet_id', 'chain', 'network', 'sender', 'recipient', 'asset', 'amount', 'fee_cap',
  'not_after_ms', 'tx_hash'];

export function parseCtx(c, what) {
  requireKeys(c, CTX_KEYS, what);
  if (!WALLET_ID_RE.test(c.wallet_id)) throw new OracleError(`${what}: wallet_id outside [a-z0-9-]{1,64}`);
  if (typeof c.network !== 'string') throw new OracleError(`${what}: network`);
  if (!Array.isArray(c.trc20_allowlist)) throw new OracleError(`${what}: trc20_allowlist`);
  const permission = dec(c.permission_id, `${what}.permission_id`);
  if (permission > 255n) throw new OracleError(`${what}: permission_id is a u8`);
  return {
    wallet_id: c.wallet_id,
    network: c.network,
    wallet_address: fromHex(c.wallet_address, `${what}.wallet_address`),
    permission_id: permission,
    trc20_allowlist: c.trc20_allowlist.map((a, i) => fromHex(a, `${what}.trc20_allowlist[${i}]`)),
    now_ms: dec(c.now_ms, `${what}.now_ms`),
    max_validity_ms: dec(c.max_validity_ms, `${what}.max_validity_ms`),
    max_fee_limit_sun: dec(c.max_fee_limit_sun, `${what}.max_fee_limit_sun`),
    max_clock_skew_ms: dec(c.max_clock_skew_ms, `${what}.max_clock_skew_ms`),
    claimed_txid: c.claimed_txid === null ? null : fromHex(c.claimed_txid, `${what}.claimed_txid`),
  };
}

// The decoded intent in the vector file's JSON form (§9).
export function intentJson(it) {
  return {
    wallet_id: it.wallet_id, chain: it.chain.toString(), network: it.network,
    sender: toHex(it.sender), recipient: toHex(it.recipient),
    asset: it.asset.kind === 'native' ? { kind: 'native' } : { kind: 'contract', address: toHex(it.asset.address) },
    amount: it.amount.toString(), fee_cap: it.fee_cap.toString(), not_after_ms: it.not_after_ms.toString(),
    tx_hash: toHex(it.tx_hash),
  };
}

// Runs every vector of a parsed intent_v1.json. Throws OracleError on a malformed file;
// returns { results: [{ id, rule, ok, detail }], coverage: Map(check -> ids) }.
export function runIntentVectors(file) {
  requireKeys(file, TOP_KEYS, 'INTENT_V1 file');
  if (file.rfc !== 'INTENT_V1') throw new OracleError(`rfc is ${file.rfc}`);
  requireKeys(file.constants, ['max_raw_bytes', 'max_validity_ms', 'max_fee_limit_sun', 'intent_tag'], 'constants');
  if (file.constants.max_raw_bytes !== String(MAX_RAW_BYTES) || file.constants.max_validity_ms !== String(MAX_VALIDITY_MS)
    || file.constants.max_fee_limit_sun !== String(MAX_FEE_LIMIT_SUN) || file.constants.intent_tag !== INTENT_TAG) {
    throw new OracleError(`constants differ from INTENT_V1 §4.4/§6.1: ${JSON.stringify(file.constants)}`);
  }
  // The file's check table must be §7.4, in order, with registry-consistent codes.
  if (!Array.isArray(file.checks) || file.checks.length !== CHECKS.length) throw new OracleError('checks: not the §7.4 table');
  file.checks.forEach((c, i) => {
    requireKeys(c, ['check', 'code', 'name'], `checks[${i}]`);
    const code = requireRegistered(c.code, c.name, `checks[${i}]`);
    if (c.check !== CHECKS[i][0] || code !== CHECKS[i][1]) throw new OracleError(`checks[${i}]: ${c.check} ${c.code} != §7.4 ${CHECKS[i][0]} ${codeHex(CHECKS[i][1])}`);
  });
  requireKeys(file.untested_checks, ['NON_CANONICAL_ENCODING'], 'untested_checks');
  if (!Array.isArray(file.vectors) || file.vectors.length === 0) throw new OracleError('no vectors (KAT plan R10)');

  const ids = new Set(file.vectors.map((v) => v.id));
  if (ids.size !== file.vectors.length) throw new OracleError('duplicate vector ids');
  const coverage = new Map(CHECKS.map(([c]) => [c, []]));
  const results = file.vectors.map((v, i) => {
    const what = `vectors[${i}] ${v.id}`;
    requireKeys(v, VECTOR_KEYS, what);
    if (!/^INTENT_V1-[AR]-\d{3}$/.test(v.id)) throw new OracleError(`${what}: bad id`);
    if (v.base !== null && !ids.has(v.base)) throw new OracleError(`${what}: unknown base ${v.base}`);
    requireKeys(v.input, ['raw_tx', 'ctx'], `${what}.input`);
    const raw = fromHex(v.input.raw_tx, `${what}.raw_tx`);
    const ctx = parseCtx(v.input.ctx, `${what}.ctx`);
    const got = decodeTronV1(raw, ctx);
    const exp = v.expect;
    if (v.id.includes('-A-')) {
      requireKeys(exp, ['accept'], `${what}.expect`);
      if (v.rule !== 'ACCEPT_NATIVE' && v.rule !== 'ACCEPT_TRC20') throw new OracleError(`${what}: rule ${v.rule}`);
      requireKeys(exp.accept, ACCEPT_KEYS, `${what}.expect.accept`);
      requireKeys(exp.accept.intent, INTENT_KEYS, `${what}.expect.accept.intent`);
      if (!got.accept) return { id: v.id, rule: v.rule, ok: false, detail: `refused ${got.refuse}, expected accept` };
      const a = got.accept;
      const mine = {
        tx_hash: toHex(a.intent.tx_hash), intent: intentJson(a.intent), intent_bcs: toHex(a.intentBcs),
        intent_digest: toHex(a.digest), sign_input_bcs: toHex(a.signInput),
      };
      const shape = a.intent.asset.kind === 'native' ? 'ACCEPT_NATIVE' : 'ACCEPT_TRC20';
      const diffs = Object.keys(mine).filter((k) => JSON.stringify(mine[k]) !== JSON.stringify(exp.accept[k]));
      if (shape !== v.rule) diffs.push(`rule (decoded ${shape})`);
      return { id: v.id, rule: v.rule, ok: diffs.length === 0, detail: diffs.length ? `differs in ${diffs.join(', ')}` : 'accept' };
    }
    requireKeys(exp, ['refuse'], `${what}.expect`);
    requireKeys(exp.refuse, ['check', 'code', 'name'], `${what}.expect.refuse`);
    const code = requireRegistered(exp.refuse.code, exp.refuse.name, `${what}.expect.refuse`);
    if (CODE_OF.get(exp.refuse.check) !== code) throw new OracleError(`${what}: ${exp.refuse.check} is not ${exp.refuse.code} in §7.4`);
    if (v.rule !== exp.refuse.check) throw new OracleError(`${what}: rule ${v.rule} != expected check ${exp.refuse.check}`);
    coverage.get(exp.refuse.check).push(v.id);
    if (!got.refuse) return { id: v.id, rule: v.rule, ok: false, detail: `accepted, expected ${exp.refuse.check}` };
    const myCode = codeHex(CODE_OF.get(got.refuse));
    const ok = got.refuse === exp.refuse.check && myCode === exp.refuse.code && REGISTRY.get(parseCode(myCode)) === exp.refuse.name;
    return { id: v.id, rule: v.rule, ok, detail: `${got.refuse} ${myCode}${ok ? '' : `, expected ${exp.refuse.check} ${exp.refuse.code}`}` };
  });
  // RFC §9 coverage: every check except the untested one has a refuse vector.
  for (const [check, vids] of coverage) {
    const untested = check in file.untested_checks;
    if (untested === (vids.length > 0)) throw new OracleError(`coverage: ${check} has ${vids.length} vectors, untested=${untested}`);
  }
  return { results, coverage };
}
