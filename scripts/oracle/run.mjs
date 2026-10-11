#!/usr/bin/env node
// Independent vector oracle (T13-2): reproduces the INTENT_V1 and RECEIPT_V1 vector files.
// Usage: node scripts/oracle/run.mjs [--intent FILE] [--receipt FILE] [--verbose]
// Exit 0 only when every vector and every cross-file link agrees; 1 on a disagreement; 2 on a bad file.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { OracleError, fromHex, sha256, toHex } from './lib.mjs';
import { CHECKS as INTENT_CHECKS, decodeTronV1, parseCtx, runIntentVectors } from './intent_v1.mjs';
import { runReceiptVectors } from './receipt_v1.mjs';

const VECTORS = fileURLToPath(new URL('../../crates/vaultex-verify/vectors/', import.meta.url));
const DEFAULTS = { intent: `${VECTORS}INTENT_V1/intent_v1.json`, receipt: `${VECTORS}RECEIPT_V1/receipt_v1.json` };

// INTENT_V1 §9 and RECEIPT_V1 §9, "Links to other vectors".
export function crossLinks(intentFile, receiptFile) {
  const iv = (id) => intentFile.vectors.find((v) => v.id === id) ?? fail(`${id} missing`);
  const writer = receiptFile.vectors.find((v) => v.id === 'RECEIPT_V1-A-001') ?? fail('RECEIPT_V1-A-001 missing');
  const step = (i) => writer.input.steps[i]?.record ?? fail(`RECEIPT_V1-A-001 step ${i} missing`);
  const out = [];
  const link = (name, ok) => out.push({ id: name, ok });
  for (const [i, id] of [[0, 'INTENT_V1-A-002'], [2, 'INTENT_V1-A-001']]) {
    const a = iv(id).expect.accept;
    link(`receipt ${i} names ${id}`, step(i).intent_digest === a.intent_digest && step(i).tx_hash === a.tx_hash);
  }
  // Receipt 1 records the decoder's refusal of INTENT_V1-A-002 "with a memo added". Neither RFC gives
  // those bytes. ponytail: take the memo field of R-039 (A-002 with a memo appended) and put it in
  // field order, i.e. right after the expiration varint (§5.2 fixes the 15 bytes before it).
  const a2 = fromHex(iv('INTENT_V1-A-002').input.raw_tx);
  const r39 = fromHex(iv('INTENT_V1-R-039').input.raw_tx);
  if (toHex(r39.subarray(0, a2.length)) !== toHex(a2)) fail('INTENT_V1-R-039 is not A-002 with a field appended');
  let at = 15;
  while (a2[at] & 0x80) at++;
  at++;
  const withMemo = Uint8Array.from([...a2.subarray(0, at), ...r39.subarray(a2.length), ...a2.subarray(at)]);
  const got = decodeTronV1(withMemo, parseCtx(iv('INTENT_V1-A-002').input.ctx, 'INTENT_V1-A-002'));
  const code = INTENT_CHECKS.find(([c]) => c === got.refuse)?.[1];
  link('receipt 1 records the memo refusal of INTENT_V1-A-002', got.refuse === 'MEMO_PRESENT'
    && toHex(sha256(withMemo)) === step(1).tx_hash && step(1).intent_digest === null
    && step(1).decision.code === `0x${code.toString(16).padStart(4, '0')}`);
  return out;
}
function fail(msg) { throw new OracleError(msg); }

function report(name, results, verbose) {
  const bad = results.filter((r) => !r.ok);
  for (const r of results) if (verbose || !r.ok) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.id}${r.rule ? ` ${r.rule}` : ''}${r.detail ? `: ${r.detail}` : ''}`);
  console.log(`${name}: ${results.length - bad.length}/${results.length} agree`);
  return bad.length;
}

function main(argv) {
  const opts = { ...DEFAULTS, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--verbose') opts.verbose = true;
    else if (argv[i] === '--intent' || argv[i] === '--receipt') opts[argv[i].slice(2)] = argv[++i];
    else { console.error(`unknown argument ${argv[i]}`); return 2; }
  }
  try {
    const intent = JSON.parse(readFileSync(opts.intent, 'utf8'));
    const receipt = JSON.parse(readFileSync(opts.receipt, 'utf8'));
    const i = runIntentVectors(intent);
    const r = runReceiptVectors(receipt);
    const accepts = i.results.filter((x) => x.id.includes('-A-')).length;
    const covered = [...i.coverage.values()].filter((v) => v.length).length;
    console.log(`INTENT_V1 ${intent.rfc_version}: ${i.results.length} vectors (${accepts} accept, ${i.results.length - accepts} refuse); `
      + `${covered}/${i.coverage.size} checks have a refuse vector (untested: ${Object.keys(intent.untested_checks).join(', ')})`);
    let failures = report('INTENT_V1', i.results, opts.verbose);
    console.log(`RECEIPT_V1 ${receipt.rfc_version}: ${r.results.length} vectors; ${r.coverage.size}/10 checks have an invalid-log vector`);
    failures += report('RECEIPT_V1', r.results, opts.verbose);
    failures += report('cross-links', crossLinks(intent, receipt), opts.verbose);
    console.log(failures ? `ORACLE DISAGREES: ${failures} failure(s)` : 'ORACLE AGREES with every vector');
    return failures ? 1 : 0;
  } catch (e) {
    if (!(e instanceof OracleError) && !(e instanceof SyntaxError) && e.code !== 'ENOENT') throw e;
    console.error(`bad vector file: ${e.message}`);
    return 2;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
