// RECEIPT_V1 oracle: body/receipt BCS (§5), digest and signature (§6), the writer rules W4/W5
// (§7.1) and the offline log verifier (§7.2), plus a runner for the RFC's vector file (§9).
// Written from specs/RECEIPT_V1.md only.
import {
  BcsError, BcsReader, NETWORKS, OracleError, WALLET_ID_RE, bcsStr, bytesEqual, codeHex, concat, dec, fromHex,
  requireKeys, requireRegistered, sha256, toHex, u16, u32, u64,
} from './lib.mjs';
import { keyFromSeed, signWith, verifyStrict } from './ed25519.mjs';

export const RECEIPT_TAG = 'VAULTEX/RECEIPT/v1';
export const MAX_FRAME = 1024;
export const CHECKS = ['TRUNCATED', 'MALFORMED', 'SIGNER_KEY', 'SIGNATURE', 'SEQ', 'PREV', 'TIME', 'NETWORK',
  'ACCEPT_WITHOUT_INTENT', 'POLICY_ROLLBACK'];
const ZERO32 = new Uint8Array(32);

// ---------- encoding (§5.1, §5.2) ----------

// body: { signer_key, seq, prev, time_s, request_id, wallet_id, chain, network, tx_hash,
//         intent_digest (Uint8Array|null), policy_version, policy_digest, verifier_version [3],
//         decision: { kind: 'accept' } | { kind: 'refuse', code, rule_index (BigInt|null) } }
export function bodyBcs(b) {
  const decision = b.decision.kind === 'accept'
    ? Uint8Array.of(0)
    : concat(Uint8Array.of(1), u16(b.decision.code),
      b.decision.rule_index === null ? Uint8Array.of(0) : concat(Uint8Array.of(1), u32(b.decision.rule_index)));
  return concat(
    fixed(b.signer_key, 32), u64(b.seq), fixed(b.prev, 32), u64(b.time_s), fixed(b.request_id, 16),
    bcsStr(b.wallet_id), u16(b.chain), bcsStr(b.network), fixed(b.tx_hash, 32),
    b.intent_digest === null ? Uint8Array.of(0) : concat(Uint8Array.of(1), fixed(b.intent_digest, 32)),
    u64(b.policy_version), fixed(b.policy_digest, 32), ...b.verifier_version.map(u16), decision,
  );
}
function fixed(bytes, n) {
  if (bytes.length !== n) throw new OracleError(`expected ${n} bytes, got ${bytes.length}`);
  return bytes;
}
export const receiptDigest = (bodyBytes) => sha256(concat(bcsStr(RECEIPT_TAG), bodyBytes));
export const frame = (receiptBytes) => concat(u32(receiptBytes.length), receiptBytes);

// Strict decode of one frame's receipt bytes (§5.4). Throws BcsError on any failure.
export function decodeReceipt(bytes) {
  const r = new BcsReader(bytes);
  const ascii = (b) => Buffer.from(b).toString('latin1');
  const body = {
    signer_key: r.take(32), seq: r.uint(8), prev: r.take(32), time_s: r.uint(8), request_id: r.take(16),
    wallet_id: ascii(r.bytes()), chain: Number(r.uint(2)), network: ascii(r.bytes()), tx_hash: r.take(32),
    intent_digest: r.option(() => r.take(32)), policy_version: r.uint(8), policy_digest: r.take(32),
    verifier_version: [r.uint(2), r.uint(2), r.uint(2)],
  };
  const variant = r.uleb();
  if (variant === 0n) body.decision = { kind: 'accept' };
  else if (variant === 1n) body.decision = { kind: 'refuse', code: Number(r.uint(2)), rule_index: r.option(() => r.uint(4)) };
  else throw new BcsError(`decision variant ${variant}`);
  const signature = r.take(64);
  r.done();
  if (!WALLET_ID_RE.test(body.wallet_id)) throw new BcsError('wallet_id');
  if (!NETWORKS.has(body.network)) throw new BcsError('network not on the allowlist');
  const bodyBytes = bodyBcs(body);
  if (!bytesEqual(concat(bodyBytes, signature), bytes)) throw new BcsError('re-encoding differs');
  return { body, bodyBytes, signature };
}

// ---------- verifier (§7.2) ----------

// log: Uint8Array; key: Uint8Array|null (pinned); after: { seq: BigInt, digest: Uint8Array }|null.
export function verifyLog(log, key = null, after = null) {
  let expectedKey = key;
  let nextSeq = after ? after.seq + 1n : 0n;
  let prevDigest = after ? after.digest : ZERO32;
  let prevTime = 0n, prevPolicy = null, head = null, firstTime = null;
  let pos = 0, index = 0, accepts = 0;
  const refusals = {};
  const fail = (check) => ({ invalid: { check, index, offset: pos } });
  while (pos < log.length) {
    if (log.length - pos < 4) return fail('TRUNCATED');
    const len = Buffer.from(log).readUInt32LE(pos);
    if (len === 0 || len > MAX_FRAME) return fail('MALFORMED');
    if (len > log.length - pos - 4) return fail('TRUNCATED');
    let rc;
    try { rc = decodeReceipt(log.subarray(pos + 4, pos + 4 + len)); } catch (e) {
      if (e instanceof BcsError) return fail('MALFORMED');
      throw e;
    }
    const { body, bodyBytes, signature } = rc;
    if (expectedKey === null) expectedKey = body.signer_key;
    if (!bytesEqual(body.signer_key, expectedKey)) return fail('SIGNER_KEY');
    const digest = receiptDigest(bodyBytes);
    if (!verifyStrict(body.signer_key, signature, digest)) return fail('SIGNATURE');
    if (body.seq !== nextSeq) return fail('SEQ');
    if (!bytesEqual(body.prev, prevDigest)) return fail('PREV');
    if (body.time_s < prevTime) return fail('TIME');
    if (NETWORKS.get(body.network) !== body.chain) return fail('NETWORK');
    if (body.decision.kind === 'accept' && body.intent_digest === null) return fail('ACCEPT_WITHOUT_INTENT');
    if (prevPolicy && (body.policy_version < prevPolicy.version
      || (body.policy_version === prevPolicy.version && !bytesEqual(body.policy_digest, prevPolicy.digest)))) {
      return fail('POLICY_ROLLBACK');
    }
    nextSeq = body.seq + 1n;
    prevDigest = digest;
    prevTime = body.time_s;
    prevPolicy = { version: body.policy_version, digest: body.policy_digest };
    head = { seq: body.seq, digest };
    firstTime ??= body.time_s;
    if (body.decision.kind === 'accept') accepts++;
    else refusals[codeHex(body.decision.code)] = (refusals[codeHex(body.decision.code)] ?? 0) + 1;
    pos += 4 + len;
    index++;
  }
  return {
    valid: {
      key: expectedKey, key_pinned: key !== null, receipts: index, accepts, refusals, head,
      first_time_s: firstTime, last_time_s: head ? prevTime : null,
    },
  };
}

// ---------- writer (§7.1 W4, W5) ----------

// steps: [{ now_ms: BigInt, record }]; record holds the caller-supplied fields of §4.1.
export function writeLog(seed, verifierVersion, steps) {
  const { priv, pub } = keyFromSeed(seed);
  const receipts = [];
  let prev = null;
  for (const { now_ms, record } of steps) {
    const nowS = now_ms / 1000n; // floor: now_ms is non-negative
    const body = {
      ...record,
      signer_key: pub,
      seq: prev ? prev.body.seq + 1n : 0n,
      prev: prev ? prev.digest : ZERO32,
      time_s: prev && prev.body.time_s > nowS ? prev.body.time_s : nowS,
      verifier_version: verifierVersion,
    };
    const bodyBytes = bodyBcs(body);
    const digest = receiptDigest(bodyBytes);
    const signature = signWith(priv, digest);
    prev = { body, bodyBytes, digest, signature, receiptBytes: concat(bodyBytes, signature) };
    receipts.push(prev);
  }
  const log = concat(...receipts.map((x) => frame(x.receiptBytes)));
  // W5: a conforming writer only produces logs that verify.
  const check = verifyLog(log, pub, null);
  if (!check.valid) throw new OracleError(`writer produced an invalid log: ${JSON.stringify(check.invalid)}`);
  return { pub, receipts, log, head: prev ? { seq: prev.body.seq, digest: prev.digest } : null };
}

// ---------- vector file runner (§9) ----------

const TOP_KEYS = ['rfc', 'rfc_version', 'kind', 'generated_by', 'keys', 'frame', 'checks', 'vectors'];
const VECTOR_KEYS = ['id', 'rule', 'base', 'description', 'input', 'expect'];
const RECORD_KEYS = ['request_id', 'wallet_id', 'chain', 'network', 'tx_hash', 'intent_digest', 'policy_version',
  'policy_digest', 'decision'];
const BODY_KEYS = [...RECORD_KEYS, 'signer_key', 'seq', 'prev', 'time_s', 'verifier_version'];
const VALID_KEYS = ['receipts', 'accepts', 'refusals', 'head', 'key', 'key_pinned'];

function parseVersion(s, what) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(s ?? '');
  if (!m) throw new OracleError(`${what}: verifier_version ${JSON.stringify(s)}`);
  return m.slice(1).map((x) => dec(x, what));
}
const versionJson = (v) => v.join('.');

function parseRecord(rec, what) {
  requireKeys(rec, RECORD_KEYS, what);
  const d = rec.decision;
  let decision;
  if (d?.kind === 'accept') {
    requireKeys(d, ['kind'], `${what}.decision`);
    decision = { kind: 'accept' };
  } else if (d?.kind === 'refuse') {
    requireKeys(d, ['kind', 'code', 'name', 'rule_index'], `${what}.decision`);
    decision = {
      kind: 'refuse', code: requireRegistered(d.code, d.name, `${what}.decision`),
      rule_index: d.rule_index === null ? null : dec(d.rule_index, `${what}.rule_index`),
    };
  } else throw new OracleError(`${what}: decision kind ${JSON.stringify(d?.kind)}`);
  return {
    request_id: fromHex(rec.request_id, `${what}.request_id`), wallet_id: rec.wallet_id,
    chain: Number(dec(rec.chain, `${what}.chain`)), network: rec.network,
    tx_hash: fromHex(rec.tx_hash, `${what}.tx_hash`),
    intent_digest: rec.intent_digest === null ? null : fromHex(rec.intent_digest, `${what}.intent_digest`),
    policy_version: dec(rec.policy_version, `${what}.policy_version`),
    policy_digest: fromHex(rec.policy_digest, `${what}.policy_digest`), decision,
  };
}
function bodyJson(b, recordDecision) {
  return {
    request_id: toHex(b.request_id), wallet_id: b.wallet_id, chain: String(b.chain), network: b.network,
    tx_hash: toHex(b.tx_hash), intent_digest: b.intent_digest === null ? null : toHex(b.intent_digest),
    policy_version: b.policy_version.toString(), policy_digest: toHex(b.policy_digest), decision: recordDecision,
    signer_key: toHex(b.signer_key), seq: b.seq.toString(), prev: toHex(b.prev), time_s: b.time_s.toString(),
    verifier_version: versionJson(b.verifier_version),
  };
}
const headJson = (h) => (h ? { seq: h.seq.toString(), digest: toHex(h.digest) } : null);
// Order-insensitive deep equality for the JSON objects the vector file holds.
const canon = (o) => (o === null || typeof o !== 'object' ? JSON.stringify(o)
  : Array.isArray(o) ? `[${o.map(canon).join(',')}]`
    : `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`);
const same = (a, b) => canon(a) === canon(b);

function runWriter(v, what) {
  requireKeys(v.input, ['signer_seed', 'verifier_version', 'steps'], `${what}.input`);
  requireKeys(v.expect, ['receipts', 'log', 'head'], `${what}.expect`);
  if (!Array.isArray(v.input.steps) || v.input.steps.length === 0) throw new OracleError(`${what}: no steps`);
  const steps = v.input.steps.map((s, i) => {
    requireKeys(s, ['now_ms', 'record', 'note'], `${what}.steps[${i}]`);
    return { now_ms: dec(s.now_ms, `${what}.steps[${i}].now_ms`), record: parseRecord(s.record, `${what}.steps[${i}].record`) };
  });
  const out = writeLog(fromHex(v.input.signer_seed, `${what}.signer_seed`), parseVersion(v.input.verifier_version, what), steps);
  const exp = v.expect.receipts;
  if (!Array.isArray(exp) || exp.length !== steps.length) throw new OracleError(`${what}: one expected receipt per step`);
  const diffs = [];
  out.receipts.forEach((rc, i) => {
    const e = exp[i];
    requireKeys(e, ['body', 'body_bcs', 'digest', 'signature', 'receipt_bcs'], `${what}.expect.receipts[${i}]`);
    requireKeys(e.body, BODY_KEYS, `${what}.expect.receipts[${i}].body`);
    if (!same(bodyJson(rc.body, v.input.steps[i].record.decision), e.body)) diffs.push(`receipt ${i} body`);
    if (toHex(rc.bodyBytes) !== e.body_bcs) diffs.push(`receipt ${i} body_bcs`);
    if (toHex(rc.digest) !== e.digest) diffs.push(`receipt ${i} digest`);
    if (toHex(rc.signature) !== e.signature) diffs.push(`receipt ${i} signature`);
    if (toHex(rc.receiptBytes) !== e.receipt_bcs) diffs.push(`receipt ${i} receipt_bcs`);
  });
  if (toHex(out.log) !== v.expect.log) diffs.push('log');
  if (!same(headJson(out.head), v.expect.head)) diffs.push('head');
  return { ok: diffs.length === 0, detail: diffs.length ? `differs in ${diffs.join(', ')}` : `${out.receipts.length} receipts written` };
}

function runVerify(v, what) {
  requireKeys(v.input, ['log', 'key', 'after'], `${what}.input`);
  const key = v.input.key === null ? null : fromHex(v.input.key, `${what}.key`);
  let after = null;
  if (v.input.after !== null) {
    requireKeys(v.input.after, ['seq', 'digest'], `${what}.after`);
    after = { seq: dec(v.input.after.seq, `${what}.after.seq`), digest: fromHex(v.input.after.digest, `${what}.after.digest`) };
  }
  const got = verifyLog(fromHex(v.input.log, `${what}.log`), key, after);
  if (v.rule === 'VALID_LOG') {
    requireKeys(v.expect, ['valid'], `${what}.expect`);
    requireKeys(v.expect.valid, VALID_KEYS, `${what}.expect.valid`);
    if (!got.valid) return { ok: false, detail: `invalid ${got.invalid.check} at ${got.invalid.index}, expected valid` };
    const g = got.valid;
    const mine = {
      receipts: String(g.receipts), accepts: String(g.accepts),
      refusals: Object.fromEntries(Object.entries(g.refusals).map(([k, n]) => [k, String(n)])),
      head: headJson(g.head), key: g.key === null ? null : toHex(g.key), key_pinned: g.key_pinned,
    };
    const diffs = VALID_KEYS.filter((k) => !same(mine[k], v.expect.valid[k]));
    return { ok: diffs.length === 0, detail: diffs.length ? `differs in ${diffs.join(', ')}` : `valid, ${g.receipts} receipts` };
  }
  requireKeys(v.expect, ['invalid'], `${what}.expect`);
  requireKeys(v.expect.invalid, ['check', 'index'], `${what}.expect.invalid`);
  if (v.expect.invalid.check !== v.rule) throw new OracleError(`${what}: rule ${v.rule} != expected check`);
  if (!got.invalid) return { ok: false, detail: `valid, expected ${v.rule}` };
  const ok = got.invalid.check === v.expect.invalid.check && String(got.invalid.index) === v.expect.invalid.index;
  return { ok, detail: `${got.invalid.check} at index ${got.invalid.index} (offset ${got.invalid.offset})${ok ? '' : `, expected ${v.expect.invalid.check} at ${v.expect.invalid.index}`}` };
}

export function runReceiptVectors(file) {
  requireKeys(file, TOP_KEYS, 'RECEIPT_V1 file');
  if (file.rfc !== 'RECEIPT_V1') throw new OracleError(`rfc is ${file.rfc}`);
  requireKeys(file.keys, ['receipt', 'other'], 'keys');
  for (const k of ['receipt', 'other']) {
    requireKeys(file.keys[k], ['seed', 'public_key'], `keys.${k}`);
    const pub = keyFromSeed(fromHex(file.keys[k].seed, `keys.${k}.seed`)).pub;
    if (toHex(pub) !== file.keys[k].public_key) throw new OracleError(`keys.${k}: public key does not match its seed`);
  }
  if (typeof file.frame !== 'string') throw new OracleError('frame');
  if (!Array.isArray(file.checks) || file.checks.map((c) => c?.check).join() !== CHECKS.join()) {
    throw new OracleError('checks: not the ten checks of §7.2 in order');
  }
  file.checks.forEach((c, i) => requireKeys(c, ['check', 'rule'], `checks[${i}]`));
  if (!Array.isArray(file.vectors) || file.vectors.length === 0) throw new OracleError('no vectors (KAT plan R10)');
  const ids = new Set(file.vectors.map((v) => v.id));
  if (ids.size !== file.vectors.length) throw new OracleError('duplicate vector ids');
  const coverage = new Map(CHECKS.map((c) => [c, []]));
  const results = file.vectors.map((v, i) => {
    const what = `vectors[${i}] ${v.id}`;
    requireKeys(v, VECTOR_KEYS, what);
    if (!/^RECEIPT_V1-[AR]-\d{3}$/.test(v.id)) throw new OracleError(`${what}: bad id`);
    if (v.base !== null && !ids.has(v.base)) throw new OracleError(`${what}: unknown base ${v.base}`);
    const isAccept = v.id.includes('-A-');
    if (isAccept !== (v.rule === 'WRITER' || v.rule === 'VALID_LOG')) throw new OracleError(`${what}: rule ${v.rule} vs id`);
    if (!isAccept && !coverage.has(v.rule)) throw new OracleError(`${what}: unknown check ${v.rule}`);
    if (!isAccept) coverage.get(v.rule).push(v.id);
    const r = v.rule === 'WRITER' ? runWriter(v, what) : runVerify(v, what);
    return { id: v.id, rule: v.rule, ...r };
  });
  // RFC §9: every check of §7.2 has at least one invalid-log vector.
  for (const [check, vids] of coverage) if (vids.length === 0) throw new OracleError(`coverage: no vector for ${check}`);
  return { results, coverage };
}
