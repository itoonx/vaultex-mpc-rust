// Self-tests of the oracle: RFC 8032 and RFC worked examples, the strict Ed25519 rule,
// and proof that the harness cannot pass vacuously (KAT plan R10).
// Run: node --test scripts/oracle/
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { L, decodePoint, keyFromSeed, signWith, verifyStrict } from './ed25519.mjs';
import { OracleError, bcsStr, concat, fromHex, leToBig, toHex, u256, u64 } from './lib.mjs';
import { INTENT_TAG, decodeTronV1, parseCtx, runIntentVectors } from './intent_v1.mjs';
import { RECEIPT_TAG, bodyBcs, decodeReceipt, receiptDigest, runReceiptVectors } from './receipt_v1.mjs';

const VECTORS = fileURLToPath(new URL('../../crates/vaultex-verify/vectors/', import.meta.url));
const load = (p) => JSON.parse(readFileSync(join(VECTORS, p), 'utf8'));
const intentFile = () => load('INTENT_V1/intent_v1.json');
const receiptFile = () => load('RECEIPT_V1/receipt_v1.json');
const vec = (file, id) => file.vectors.find((v) => v.id === id);
const allOk = ({ results }) => results.every((r) => r.ok);

// ---------- Ed25519 ----------

test('RFC 8032 §7.1 TEST 1 and TEST 2: node:crypto signs, the strict verifier accepts', () => {
  for (const [seed, pub, msg, sig] of [
    ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
    ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
  ]) {
    const k = keyFromSeed(fromHex(seed));
    assert.equal(toHex(k.pub), pub);
    assert.equal(toHex(signWith(k.priv, fromHex(msg))), sig);
    assert.ok(verifyStrict(k.pub, fromHex(sig), fromHex(msg)));
    const flipped = fromHex(sig);
    flipped[10] ^= 1;
    assert.ok(!verifyStrict(k.pub, flipped, fromHex(msg)));
  }
});

test('RECEIPT_V1 §6.3: S + L, a small-order R or A, and an unreduced y are refused', () => {
  const k = keyFromSeed(new Uint8Array(32).fill(3));
  const msg = fromHex('00'.repeat(32));
  const sig = signWith(k.priv, msg);
  assert.ok(verifyStrict(k.pub, sig, msg));
  // Step 1: S + L is the same scalar mod L, but not canonical.
  const highS = concat(sig.subarray(0, 32), u256(leToBig(sig.subarray(32)) + L));
  assert.ok(!verifyStrict(k.pub, highS, msg));
  // Step 3: identity key with R = identity, S = 0 satisfies the cofactorless equation.
  const identity = fromHex('01' + '00'.repeat(31));
  assert.ok(!verifyStrict(identity, concat(identity, new Uint8Array(32)), msg));
  // Step 2: y = p (unreduced encoding of y = 0) does not decode (RFC 8032 §5.1.3).
  assert.equal(decodePoint(fromHex('ed' + 'ff'.repeat(30) + '7f')), null);
});

test('the explicit small-order check is load-bearing: OpenSSL alone accepts R-010 and R-011', () => {
  const f = receiptFile();
  for (const id of ['RECEIPT_V1-R-010', 'RECEIPT_V1-R-011']) {
    const v = vec(f, id);
    const log = Buffer.from(v.input.log, 'hex');
    let pos = 0;
    for (let i = 0; i < Number(v.expect.invalid.index); i++) pos += 4 + log.readUInt32LE(pos);
    const rc = decodeReceipt(Uint8Array.from(log.subarray(pos + 4, pos + 4 + log.readUInt32LE(pos))));
    const msg = receiptDigest(rc.bodyBytes);
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rc.body.signer_key).toString('base64url') }, format: 'jwk' });
    assert.equal(nodeVerify(null, Buffer.from(msg), key, Buffer.from(rc.signature)), true, `${id}: cofactorless equation holds`);
    assert.equal(verifyStrict(rc.body.signer_key, rc.signature, msg), false, `${id}: strict rule refuses`);
  }
});

// ---------- RFC worked examples ----------

test('INTENT_V1 §5.1, §5.3, §6.1 worked examples', () => {
  assert.equal(toHex(bcsStr(INTENT_TAG)), '11' + '5641554c5445582f494e54454e542f7631');
  const v = vec(intentFile(), 'INTENT_V1-A-002');
  const raw = fromHex(v.input.raw_tx);
  assert.equal(raw.length, 211);
  const { accept } = decodeTronV1(raw, parseCtx(v.input.ctx, v.id));
  const b = toHex(accept.intentBcs);
  assert.equal(accept.intentBcs.length, 226);
  const at = (off, hex) => assert.equal(b.slice(2 * off, 2 * off + hex.length), hex, `offset ${off}`);
  at(0, '24' + '3030303030303030');
  at(37, '0100');
  at(39, '0f74726f6e3a32343934313034393930');
  at(55, '1541' + '11'.repeat(20));
  at(77, '1541' + '22'.repeat(20));
  at(99, '011541' + '99'.repeat(20));
  at(122, '40420f00' + '00'.repeat(28));
  at(154, '00e1f505' + '00'.repeat(28));
  at(186, '6052e6cf8b010000');
  at(194, '4145dae0');
  assert.ok(b.endsWith('8ecbf99e'));
  assert.equal(toHex(accept.signInput).slice(0, 8), '0000d301');
});

test('RECEIPT_V1 §5.1 and §6.1 worked examples', () => {
  assert.equal(toHex(bcsStr(RECEIPT_TAG)), '12' + '5641554c5445582f524543454950542f7631');
  const base = {
    signer_key: new Uint8Array(32), seq: 0n, prev: new Uint8Array(32), time_s: 0n, request_id: new Uint8Array(16),
    wallet_id: 'w', chain: 1, network: 'tron:2494104990', tx_hash: new Uint8Array(32), intent_digest: null,
    policy_version: 0n, policy_digest: new Uint8Array(32), verifier_version: [0n, 1n, 0n],
  };
  const decisionHex = (decision, bytes) => toHex(bodyBcs({ ...base, decision })).slice(-2 * bytes);
  assert.equal(decisionHex({ kind: 'refuse', code: 0x0207, rule_index: null }, 4), '01070200');
  assert.equal(decisionHex({ kind: 'refuse', code: 0x0501, rule_index: 3n }, 8), '0101050103000000');
  const w = vec(receiptFile(), 'RECEIPT_V1-A-001');
  const body = w.expect.receipts[0].body_bcs;
  assert.equal(body.length / 2, 263);
  const at = (off, hex) => assert.equal(body.slice(2 * off, 2 * off + hex.length), hex, `offset ${off}`);
  at(0, 'ed4928c6');
  at(32, '00'.repeat(8) + '00'.repeat(32));
  at(72, toHex(u64(1_700_000_010n)));
  at(80, '000102030405060708090a0b0c0d0e0f');
  at(96, '24');
  at(133, '0100');
  at(135, '0f');
  at(151, '4145dae0');
  at(183, '0171eda63f');
  at(216, '0100000000000000');
  at(224, '3d400d56');
  at(256, '000001000000');
  at(262, '00');
});

// ---------- decoder robustness (INTENT_V1 §7.3 step 7, §10 resource use) ----------

test('mutants of the accept vectors: always a result, never NON_CANONICAL_ENCODING', () => {
  let seed = 0x9e3779b9; // deterministic xorshift32
  const rnd = (n) => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed % n; };
  for (const v of intentFile().vectors.filter((x) => x.id.includes('-A-'))) {
    const base = Array.from(fromHex(v.input.raw_tx));
    const ctx = parseCtx(v.input.ctx, v.id);
    for (let i = 0; i < 2000; i++) {
      const b = base.slice();
      for (let k = 1 + rnd(3); k > 0; k--) {
        const op = rnd(4), at = rnd(b.length);
        if (op === 0) b[at] = rnd(256);
        else if (op === 1) b[at] ^= 1 << rnd(8);
        else if (op === 2) b.splice(at, 0, rnd(256));
        else b.splice(at, 1);
      }
      const r = decodeTronV1(Uint8Array.from(b), ctx); // throws only on an oracle bug
      assert.ok(r.accept || r.refuse, v.id);
      assert.notEqual(r.refuse, 'NON_CANONICAL_ENCODING', `${v.id} mutant ${toHex(Uint8Array.from(b))}`);
    }
  }
});

// ---------- the harness cannot pass vacuously (KAT plan R10) ----------

test('both vector files reproduce in full', () => {
  assert.ok(allOk(runIntentVectors(intentFile())));
  assert.ok(allOk(runReceiptVectors(receiptFile())));
});

test('a malformed vector file is a harness error, not a pass', () => {
  const cases = [
    (f) => { f.vectors = []; },
    (f) => { f.vectors[0].extra = 1; },
    (f) => { f.vectors[0].input.ctx.extra = 1; },
    (f) => { delete f.untested_checks; },
    (f) => { f.checks[0].name = 'MALFORMED'; },
    (f) => { const r = f.vectors.find((v) => v.expect.refuse); r.expect.refuse.name = 'TX_MALFORMED'; },
    (f) => { const r = f.vectors.find((v) => v.expect.refuse); r.expect.refuse.code = '0x0999'; },
    (f) => { f.vectors = f.vectors.filter((v) => v.rule !== 'AMOUNT_ZERO'); },
  ];
  for (const mutate of cases) {
    const f = intentFile();
    mutate(f);
    assert.throws(() => runIntentVectors(f), OracleError);
  }
  for (const mutate of [(f) => { f.vectors = []; }, (f) => { f.vectors[1].input.extra = 1; },
    (f) => { f.vectors = f.vectors.filter((v) => v.rule !== 'TIME'); },
    (f) => { f.vectors[0].input.steps[1].record.decision.name = 'TX_MALFORMED'; }]) {
    const f = receiptFile();
    mutate(f);
    assert.throws(() => runReceiptVectors(f), OracleError);
  }
});

test('a wrong expected value is a disagreement', () => {
  const flip = (hex) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);
  const intentCases = [
    (f) => { const a = vec(f, 'INTENT_V1-A-001').expect.accept; a.intent_digest = flip(a.intent_digest); },
    (f) => { const a = vec(f, 'INTENT_V1-A-002').expect.accept; a.intent.amount = '1000001'; },
    (f) => { const a = vec(f, 'INTENT_V1-A-002').expect.accept; a.sign_input_bcs = flip(a.sign_input_bcs); },
    // Same wire code, different check: the oracle compares check names, not only codes.
    (f) => { const r = vec(f, 'INTENT_V1-R-001'); r.rule = 'EMPTY'; r.expect.refuse = { check: 'EMPTY', code: '0x010a', name: 'PAYLOAD_MISSING' }; },
    (f) => { const r = f.vectors.find((v) => v.rule === 'PB_WIRE_TYPE'); r.rule = 'MISSING_FIELD'; r.expect.refuse.check = 'MISSING_FIELD'; },
  ];
  for (const mutate of intentCases) {
    const f = intentFile();
    mutate(f);
    assert.ok(!allOk(runIntentVectors(f)));
  }
  const receiptCases = [
    (f) => { const r = vec(f, 'RECEIPT_V1-A-001').expect.receipts[2]; r.signature = flip(r.signature); },
    (f) => { const r = vec(f, 'RECEIPT_V1-A-001').expect.receipts[2].body; r.time_s = '1700000010'; },
    (f) => { vec(f, 'RECEIPT_V1-A-002').expect.valid.key_pinned = false; },
    (f) => { vec(f, 'RECEIPT_V1-R-012').expect.invalid.index = '1'; },
  ];
  for (const mutate of receiptCases) {
    const f = receiptFile();
    mutate(f);
    assert.ok(!allOk(runReceiptVectors(f)));
  }
});

test('the CLI exits 0 on the real files and 2 on an empty one', () => {
  const run = fileURLToPath(new URL('./run.mjs', import.meta.url));
  assert.equal(spawnSync(process.execPath, [run]).status, 0);
  const dir = mkdtempSync(join(tmpdir(), 'oracle-'));
  try {
    const f = intentFile();
    f.vectors = [];
    writeFileSync(join(dir, 'empty.json'), JSON.stringify(f));
    assert.equal(spawnSync(process.execPath, [run, '--intent', join(dir, 'empty.json')]).status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
