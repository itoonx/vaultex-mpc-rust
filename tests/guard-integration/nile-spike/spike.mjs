#!/usr/bin/env node
// Nile spike (ROADMAP M6 #11): can a 2-of-2 active permission {operator (tronweb key),
// verifier (Rust k256 key)} co-sign TRON payouts, while a 2-of-3 cold owner keeps the
// only right to change permissions? T06-2 ships this script; T06-3 runs it. TESTNET ONLY.
//
//   node spike.mjs keygen            new testnet keys in $SPIKE_KEYS_DIR + funding list (offline)
//   node spike.mjs selftest          local build, co-sign and cross-recover with throwaway keys (offline)
//   node spike.mjs run               read-only preflight against Nile: genesis, fees, token, funding
//   node spike.mjs run --broadcast   the spike: broadcasts on Nile, and only on Nile
//
// Private keys are never printed and never written inside the repository.

import { TronWeb } from "tronweb";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const env = process.env;
const SIGNER_BIN = env.SPIKE_SIGN_BIN ?? path.join(REPO, "target/debug/spike-sign");
const NILE_RPC = env.NILE_RPC ?? "https://nile.trongrid.io";
const MAINNET_RPC = env.MAINNET_RPC ?? "https://api.trongrid.io"; // read-only: S0 params, S15 ref block
const TOKEN = env.SPIKE_TOKEN ?? "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"; // Nile USDT (secondary sources); S0 checks it
const OUT = env.SPIKE_OUT ?? path.join(HERE, "out/spike-results.json");

// A CAIP-2 TRON chain id is the last 4 bytes of the genesis block id.
const NILE_GENESIS_SUFFIX = "cd8690dc"; // tron:3448148188
const MAINNET_GENESIS_SUFFIX = "2b6653dc"; // tron:728126428

const OPS_IDS = [1, 31]; // TransferContract, TriggerSmartContract
const OPS = "0200008000000000000000000000000000000000000000000000000000000000";
const PERMISSION_UPDATE = 46; // AccountPermissionUpdateContract: must stay out of the bitmap
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const FEE_LIMIT = 50_000_000; // 50 TRX cap per TRC-20 call
const FUND_TRX = 400;
const FUND_TOKENS = 20;
const ACCOUNTS = ["F", "O1", "O2", "O3", "KOP", "R"]; // tronweb keys; KG and KG2 are Rust keys

// ---------- helpers ----------

const die = (msg) => {
  console.error(`spike: ${msg}`);
  process.exit(1);
};
const check = (cond, msg) => {
  if (!cond) throw new Error(msg);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256hex = (hex) => createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const json = (v) => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x), 2);
const signer = (...args) => execFileSync(SIGNER_BIN, args, { encoding: "utf8", stdio: "pipe" }).trim();

const bitmap = (ids) => {
  const b = Buffer.alloc(32);
  for (const n of ids) b[n >> 3] |= 1 << (n & 7); // little-endian, as in the TRON docs
  return b.toString("hex");
};

// Top-level fields of a protobuf message. raw_data only uses varints and length-delimited fields.
function pbFields(buf) {
  const out = [];
  let i = 0;
  const varint = () => {
    let x = 0n;
    for (let s = 0n; ; s += 7n) {
      const b = buf[i++];
      check(b !== undefined, "truncated varint");
      x |= BigInt(b & 0x7f) << s;
      if (b < 0x80) return x;
    }
  };
  while (i < buf.length) {
    const key = varint();
    const [field, wire] = [Number(key >> 3n), Number(key & 7n)];
    if (wire === 0) out.push([field, varint()]);
    else if (wire === 2) {
      const n = Number(varint());
      out.push([field, buf.subarray(i, i + n)]);
      i += n;
    } else throw new Error(`unexpected wire type ${wire}`);
  }
  return out;
}

// What the signed bytes say: Contract.Permission_id (field 5), the contract's fields, raw length.
function rawFacts(rawHex) {
  const contracts = pbFields(Buffer.from(rawHex, "hex")).filter(([f]) => f === 11);
  check(contracts.length === 1, "expected exactly one contract");
  const fields = pbFields(contracts[0][1]);
  const pid = fields.find(([f]) => f === 5);
  return {
    permissionId: pid ? Number(pid[1]) : 0,
    contractFields: fields.map(([f]) => f),
    rawBytes: rawHex.length / 2,
  };
}

// Who signed, per k256 (spike-sign) and per tronweb (ethers); a refusal is recorded, not thrown.
function sigFacts(tw, txid, sig) {
  const tryOr = (f) => {
    try {
      return f();
    } catch (e) {
      return `error: ${String(e.shortMessage ?? e.stderr ?? e.message).trim()}`;
    }
  };
  return {
    lowS: BigInt("0x" + sig.slice(64, 128)) <= SECP_N / 2n,
    v: parseInt(sig.slice(128), 16),
    k256: tryOr(() => signer("recover", txid, sig)),
    tronweb: tryOr(() => tw.address.fromHex(tw.utils.crypto.ecRecover(txid, sig))),
  };
}

// No network: any request goes to the discard port and fails.
const offline = () => new TronWeb({ fullHost: "http://127.0.0.1:9" });

function keysDir() {
  const d = env.SPIKE_KEYS_DIR;
  if (!d) die("set SPIKE_KEYS_DIR to a private directory outside the repository");
  const real = (p) => {
    try {
      return fs.realpathSync(p);
    } catch {
      return path.resolve(p);
    }
  };
  if ((real(d) + path.sep).startsWith(real(REPO) + path.sep)) die("SPIKE_KEYS_DIR is inside the repository");
  return path.resolve(d);
}

// A Rust key: spike-sign creates it (0600, never overwrites); S1 cross-derives its address in tronweb.
function rustKey(tw, name, keyfile) {
  const address = signer("keygen", keyfile);
  const hex = fs.readFileSync(keyfile, "utf8").trim();
  check(tw.address.fromPrivateKey(hex) === address, `S1: k256 and tronweb derive different addresses for ${name}`);
  return { name, address, keyfile };
}

// ---------- transaction builders (all local: txLocal / blockHeader, so tronweb never asks a node) ----------

async function refBlock(client, ttlMs = 120_000) {
  const p = await client.trx.getCurrentRefBlockParams();
  const now = Date.now();
  return { ...p, timestamp: now, expiration: now + ttlMs };
}

async function trc20(tw, { from, to, amount, permissionId, blockHeader }) {
  const { transaction } = await tw.transactionBuilder.triggerSmartContract(
    TOKEN,
    "transfer(address,uint256)",
    { feeLimit: FEE_LIMIT, callValue: 0, txLocal: true, permissionId, blockHeader },
    [
      { type: "address", value: to },
      { type: "uint256", value: amount.toString() },
    ],
    from,
  );
  return transaction;
}

const trx = (tw, { from, to, amountSun, permissionId, blockHeader }) =>
  tw.transactionBuilder.sendTrx(to, amountSun, from, { permissionId, blockHeader });

// AccountPermissionUpdate replaces the whole set, so the owner is always resubmitted.
function permissionUpdate(tw, a, activeKeys, { permissionId, blockHeader }) {
  const keys = (list) => list.map((address) => ({ address, weight: 1 }));
  return tw.transactionBuilder.updateAccountPermissions(
    a.F,
    { type: 0, permission_name: "owner", threshold: 2, keys: keys([a.O1, a.O2, a.O3]) },
    null,
    [{ type: 2, permission_name: "payouts", threshold: 2, operations: OPS, keys: keys(activeKeys) }],
    { permissionId, blockHeader },
  );
}

// tronweb keys sign through multiSign's direct path: Permission_id is taken from the bytes, so
// multiSign never swaps in a node-built transaction. Rust keys sign the locally checked txid.
async function coSign(tw, tx, signers) {
  check(sha256hex(tx.raw_data_hex) === tx.txID, "txID is not sha256(raw_data_hex)");
  const { permissionId } = rawFacts(tx.raw_data_hex);
  check((tx.raw_data.contract[0].Permission_id ?? 0) === permissionId, "JSON and bytes disagree on Permission_id");
  for (const s of signers) {
    if (s.keyfile) tx.signature = [...(tx.signature ?? []), signer("sign", s.keyfile, tx.txID)];
    else tx = await tw.trx.multiSign(tx, s.privateKey, permissionId);
  }
  return tx;
}

// ---------- keygen ----------

async function keygen() {
  const dir = keysDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  for (const f of ["keys.json", "kg.key", "kg2.key", "addresses.json"])
    if (fs.existsSync(path.join(dir, f))) die(`${f} already exists in SPIKE_KEYS_DIR; refusing to overwrite keys`);
  const tw = offline();
  const accounts = {};
  for (const n of ACCOUNTS) {
    const a = tw.utils.accounts.generateAccount();
    accounts[n] = { address: a.address.base58, privateKey: a.privateKey };
  }
  const KG = rustKey(tw, "KG", path.join(dir, "kg.key"));
  const KG2 = rustKey(tw, "KG2", path.join(dir, "kg2.key"));
  const created = new Date().toISOString();
  const write = (f, v) => fs.writeFileSync(path.join(dir, f), json(v) + "\n", { mode: 0o600, flag: "wx" });
  write("keys.json", { purpose: "vaultex nile spike, TESTNET ONLY", network: "tron:3448148188", created, accounts });
  const addresses = Object.fromEntries(ACCOUNTS.map((n) => [n, accounts[n].address]));
  Object.assign(addresses, { KG: KG.address, KG2: KG2.address });
  write("addresses.json", { network: "tron:3448148188", created, addresses });
  console.log(json({ fund: { F: addresses.F, trx: `>= ${FUND_TRX}`, token: `>= ${FUND_TOKENS} whole tokens of ${TOKEN}` }, addresses }));
  console.log("Only F needs funds. The S1 address cross-check passed for KG and KG2.");
}

// ---------- selftest (offline) ----------

async function selftest() {
  const tw = offline();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nile-spike-selftest-"));
  const ok = (msg) => console.log(`ok  ${msg}`);
  try {
    check(bitmap(OPS_IDS) === OPS, "operations bitmap for {1, 31}");
    check(bitmap([1, 4, 54]).startsWith("1200000000004000"), "bitmap encoder vs the TRON docs' {1, 4, 54} example");
    check(!(Buffer.from(OPS, "hex")[PERMISSION_UPDATE >> 3] & (1 << (PERMISSION_UPDATE & 7))), "bit 46 clear");
    ok(`bitmap {1, 31} = ${OPS}; AccountPermissionUpdate (46) not allowed`);

    const k = Object.fromEntries(
      ACCOUNTS.map((n) => {
        const a = tw.utils.accounts.generateAccount();
        return [n, { name: n, address: a.address.base58, privateKey: a.privateKey }];
      }),
    );
    const KG = rustKey(tw, "KG", path.join(tmp, "kg.key"));
    ok("S1 k256 and tronweb derive the same address");
    const a = Object.fromEntries(Object.entries(k).map(([n, v]) => [n, v.address]));
    const now = Date.now();
    const blockHeader = { ref_block_bytes: "0001", ref_block_hash: "0102030405060708", timestamp: now, expiration: now + 120_000 };

    let upd = await permissionUpdate(tw, a, [a.KOP, KG.address], { blockHeader });
    const value = upd.raw_data.contract[0].parameter.value;
    check(rawFacts(upd.raw_data_hex).permissionId === 0, "S3 is an owner (id 0) transaction");
    check(value.owner.threshold === 2 && value.owner.keys.length === 3, "S3 owner 2-of-3");
    check(value.actives[0].operations === OPS && value.actives[0].threshold === 2, "S3 active 2-of-2 with {1, 31}");
    upd = await coSign(tw, upd, [k.F]);
    check(tw.trx.ecRecover(upd) === a.F, "S3 signed by F's original key");
    ok("S3 shape: owner 2-of-3, active 2-of-2, operations {1, 31}, signed by F");

    const check2of2 = (tx, label) => {
      const facts = rawFacts(tx.raw_data_hex);
      check(facts.permissionId === 2, `${label}: Permission_id 2 is in the signed bytes`);
      check(isDeepStrictEqual(tw.trx.ecRecover(tx), [a.KOP, KG.address]), `${label}: tronweb recovers KOP, KG`);
      for (const [i, who] of [a.KOP, KG.address].entries()) {
        const f = sigFacts(tw, tx.txID, tx.signature[i]);
        check(f.lowS && (f.v === 27 || f.v === 28) && f.k256 === who && f.tronweb === who, `${label}: signature ${i}`);
      }
      return facts;
    };
    let t4 = await trc20(tw, { from: a.F, to: a.R, amount: 1_000_000n, permissionId: 2, blockHeader });
    t4 = await coSign(tw, t4, [k.KOP, KG]);
    const f4 = check2of2(t4, "S4");
    ok(`S4 shape: TRC-20 under Permission_id 2 co-signed by tronweb + k256 (contract fields ${f4.contractFields}, ${f4.rawBytes} raw bytes)`);

    let t5 = await trx(tw, { from: a.F, to: a.R, amountSun: 1_000_000, permissionId: 2, blockHeader });
    check2of2(await coSign(tw, t5, [k.KOP, KG]), "S5");
    ok("S5 shape: TRX transfer under Permission_id 2 co-signed");

    let t10 = await permissionUpdate(tw, a, [a.KOP, KG.address, a.R], { permissionId: 2, blockHeader });
    check(t10.raw_data.contract[0].type === "AccountPermissionUpdateContract", "S10 type");
    check2of2(await coSign(tw, t10, [k.KOP, KG]), "S10");
    ok("S10 shape: AccountPermissionUpdate under Permission_id 2 (the chain must refuse it in T06-3)");

    for (let i = 0; i < 20; i++) {
      const txid = randomBytes(32).toString("hex");
      const sigs = [
        [a.KOP, tw.utils.crypto.ECKeySign(Buffer.from(txid, "hex"), Buffer.from(k.KOP.privateKey, "hex"))],
        [KG.address, signer("sign", KG.keyfile, txid)],
      ];
      for (const [who, sig] of sigs) {
        const f = sigFacts(tw, txid, sig);
        check(f.lowS && f.k256 === who && f.tronweb === who, `S14 signature ${i} by ${who}`);
      }
    }
    ok("S14 20 tronweb + 20 k256 signatures: all low-S, each recovers in both libraries");

    // The high-S twin (n - s, flipped parity) of a valid signature: k256 recovery refuses it, so a
    // verifier must normalise a copy before recovering (WS-05 change request); the chain's view is S14's broadcast.
    const txid = randomBytes(32).toString("hex");
    const sig = signer("sign", KG.keyfile, txid);
    const highS = (SECP_N - BigInt("0x" + sig.slice(64, 128))).toString(16).padStart(64, "0");
    const twin = sig.slice(0, 64) + highS + (sig.slice(128) === "1b" ? "1c" : "1b");
    const f = sigFacts(tw, txid, twin);
    check(!f.lowS && f.k256.startsWith("error"), "k256 refuses to recover from a high-S signature");
    ok(`S14 high-S twin: k256 refuses (${f.k256}); tronweb: ${f.tronweb === KG.address ? "recovers the signer" : f.tronweb}`);
    console.log("selftest: PASS (no network used)");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true }); // throwaway selftest key only
  }
}

// ---------- run (T06-3) ----------

let BROADCAST = false;
let nile;
let A; // public addresses
let S; // signers
let activeId = 2;
const results = { spike: "vaultex-nile-spike", rpc: NILE_RPC, token: TOKEN, steps: [] };

function record(step, data) {
  results.steps.push({ step, at: new Date().toISOString(), ...data });
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, json(results) + "\n");
  const b = data.broadcast;
  const verdict = data.met === undefined ? "recorded" : data.met ? "as expected" : "UNEXPECTED";
  console.log(`${step}: ${verdict}${b ? ` (${b.code}${b.message ? `: ${b.message}` : ""})` : ""}`);
}

function loadKeys() {
  const dir = keysDir();
  for (const f of ["keys.json", "kg.key", "kg2.key"])
    if (fs.statSync(path.join(dir, f)).mode & 0o077) die(`${f} must be mode 0600`);
  const { accounts } = JSON.parse(fs.readFileSync(path.join(dir, "keys.json"), "utf8"));
  const { addresses } = JSON.parse(fs.readFileSync(path.join(dir, "addresses.json"), "utf8"));
  A = addresses;
  S = Object.fromEntries(ACCOUNTS.map((n) => [n, { name: n, privateKey: accounts[n].privateKey }]));
  S.KG = { name: "KG", keyfile: path.join(dir, "kg.key") };
  S.KG2 = { name: "KG2", keyfile: path.join(dir, "kg2.key") };
}

async function send(tx) {
  check(BROADCAST, "refusing to broadcast without --broadcast");
  const res = await nile.trx.sendRawTransaction(tx);
  const m = res.message ?? "";
  return {
    ok: res.result === true,
    code: res.code ?? (res.result === true ? "SUCCESS" : "UNKNOWN"),
    message: /^[0-9a-f]+$/i.test(m) ? Buffer.from(m, "hex").toString("utf8") : m,
  };
}

async function waitInfo(txid) {
  for (let i = 0; i < 30; i++) {
    const info = await nile.trx.getUnconfirmedTransactionInfo(txid);
    if (info?.id) return info;
    await sleep(3_000); // one Nile block
  }
  throw new Error(`${txid} not included after 30 blocks`);
}

// Co-sign, read the node's sign weight, broadcast, and for accepted ones wait for the receipt.
// expect: "accept" or a RegExp the refusal's code + message should match.
async function attempt(step, tx, signers, expect, extraSigs = []) {
  tx = await coSign(nile, tx, signers);
  tx.signature.push(...extraSigs.map((i) => tx.signature[i]));
  const weight = await nile.trx.getSignWeight(structuredClone(tx)); // mutates its argument
  const before = await nile.trx.getBalance(A.F);
  const broadcast = await send(tx);
  const entry = {
    txid: tx.txID,
    expect: String(expect),
    raw: { ...rawFacts(tx.raw_data_hex), raw_data_hex: tx.raw_data_hex },
    weight: { code: weight.result?.code ?? "ENOUGH_PERMISSION", current: weight.current_weight ?? 0 },
    broadcast,
    signatures: tx.signature.map((s) => sigFacts(nile, tx.txID, s)),
  };
  if (broadcast.ok) {
    const info = await waitInfo(tx.txID);
    entry.info = { block: info.blockNumber, fee: info.fee ?? 0, result: info.result ?? "SUCCESS", receipt: info.receipt };
  }
  entry.balanceDeltaSun = before - (await nile.trx.getBalance(A.F));
  entry.met =
    expect === "accept"
      ? broadcast.ok && entry.info.result === "SUCCESS" && (entry.info.receipt?.result ?? "SUCCESS") === "SUCCESS"
      : !broadcast.ok && expect.test(`${broadcast.code} ${broadcast.message}`);
  entry.refused = !broadcast.ok;
  record(step, entry);
  return entry;
}

const hexAddr = (b58) => nile.address.toHex(b58).toLowerCase();
const keySet = (p) => (p?.keys ?? []).map((k) => k.address.toLowerCase()).sort();
const sameSet = (keys, b58s) => isDeepStrictEqual(keys, b58s.map(hexAddr).sort());

async function permissions() {
  const acc = await nile.trx.getAccount(A.F);
  return {
    owner: { threshold: acc.owner_permission?.threshold, keys: keySet(acc.owner_permission) },
    active: (acc.active_permission ?? []).map((p) => ({ id: p.id ?? 0, threshold: p.threshold, operations: p.operations, keys: keySet(p) })),
  };
}

async function chainParams(client) {
  const want = [
    "getUpdateAccountPermissionFee", // #22
    "getMultiSignFee", // #23
    "getEnergyFee",
    "getTransactionFee",
    "getCreateAccountFee",
    "getCreateNewAccountFeeInSystemContract",
  ];
  const all = await client.trx.getChainParameters();
  return Object.fromEntries(want.map((k) => [k, all.find((p) => p.key === k)?.value ?? null]));
}

async function constant(selector, params = []) {
  const r = await nile.transactionBuilder.triggerConstantContract(TOKEN, selector, {}, params, A.F);
  check(r.constant_result?.[0], `${selector} on ${TOKEN} returned nothing`);
  return "0x" + r.constant_result[0];
}
const tokenBalance = async (who) => BigInt(await constant("balanceOf(address)", [{ type: "address", value: who }]));

async function run() {
  BROADCAST = process.argv.includes("--broadcast");
  loadKeys();
  nile = new TronWeb({ fullHost: NILE_RPC });
  const mainnet = new TronWeb({ fullHost: MAINNET_RPC }); // never passed to send()
  const genesis = async (c) => (await c.trx.getBlockByNumber(0)).blockID;
  if (!(await genesis(nile)).endsWith(NILE_GENESIS_SUFFIX)) die(`${NILE_RPC} is not Nile; nothing sent`);
  if (!(await genesis(mainnet)).endsWith(MAINNET_GENESIS_SUFFIX)) die(`${MAINNET_RPC} is not mainnet`);

  // S0
  const symbol = nile.utils.abi.decodeParams([], ["string"], await constant("symbol()"))[0];
  const decimals = Number(BigInt(await constant("decimals()")));
  const unit = 10n ** BigInt(decimals);
  const funds = { trxSun: await nile.trx.getBalance(A.F), tokens: await tokenBalance(A.F) };
  const perms = await permissions();
  const state =
    perms.owner.keys.length <= 1 && !perms.active.some((p) => p.keys.includes(hexAddr(A.KOP)))
      ? "fresh"
      : sameSet(perms.owner.keys, [A.O1, A.O2, A.O3]) && sameSet(perms.active[0]?.keys ?? [], [A.KOP, A.KG])
        ? "configured"
        : "other";
  const s0 = {
    nile: await chainParams(nile),
    mainnet: await chainParams(mainnet),
    token: { address: TOKEN, symbol, decimals },
    float: { address: A.F, ...funds, state, permissions: perms },
  };
  const funded = funds.trxSun >= FUND_TRX * 1e6 && funds.tokens >= BigInt(FUND_TOKENS) * unit;
  if (!BROADCAST) {
    console.log(json(s0));
    console.log(
      funded
        ? "preflight: funded. Nothing was sent; rerun with --broadcast to run the spike."
        : `preflight: fund ${A.F} with >= ${FUND_TRX} TRX and >= ${FUND_TOKENS} ${symbol} first. Nothing was sent.`,
    );
    return;
  }
  if (!funded) die(`fund ${A.F} with >= ${FUND_TRX} TRX and >= ${FUND_TOKENS} ${symbol} first; nothing sent`);
  if (state === "other") die("the float's permissions are neither fresh nor the S3 set (already rotated?); nothing sent");
  results.started = new Date().toISOString();
  record("S0", s0);

  // S3: set permissions, signed by F's original key.
  if (state === "fresh") {
    await attempt("S3", await permissionUpdate(nile, A, [A.KOP, A.KG], { blockHeader: await refBlock(nile) }), [S.F], "accept");
  }
  const p3 = await permissions();
  activeId = p3.active[0]?.id ?? activeId; // ROADMAP: a different id is not a NO-GO, use it
  const fHex = hexAddr(A.F);
  record("S3.read", {
    permissions: p3,
    met:
      p3.owner.threshold === 2 &&
      sameSet(p3.owner.keys, [A.O1, A.O2, A.O3]) &&
      p3.active.length === 1 &&
      p3.active[0].threshold === 2 &&
      p3.active[0].operations === OPS &&
      sameSet(p3.active[0].keys, [A.KOP, A.KG]) &&
      ![...p3.owner.keys, ...p3.active[0].keys].includes(fHex),
  });

  const pay = async (opts = {}) =>
    trc20(nile, { from: A.F, to: A.R, amount: unit, permissionId: activeId, blockHeader: await refBlock(nile), ...opts });
  const rBefore = await tokenBalance(A.R);
  const s4 = await attempt("S4", await pay(), [S.KOP, S.KG], "accept");
  const rDelta = (await tokenBalance(A.R)) - rBefore;
  record("S4.recipient", { tokenDelta: rDelta, met: rDelta === unit });
  const s5 = await attempt(
    "S5",
    await trx(nile, { from: A.F, to: A.R, amountSun: 1_000_000, permissionId: activeId, blockHeader: await refBlock(nile) }),
    [S.KOP, S.KG],
    "accept",
  );
  await attempt("S6", await pay(), [S.KOP], /sig error/i);
  await attempt("S7", await pay(), [S.KG], /sig error/i);
  await attempt("S8", await pay(), [S.KOP], /signed twice/i, [0]);
  await attempt("S9", await pay({ permissionId: 0 }), [S.KOP, S.KG], /not contained of permission/i);
  await attempt(
    "S10",
    await permissionUpdate(nile, A, [A.KOP, A.KG, A.R], { permissionId: activeId, blockHeader: await refBlock(nile) }),
    [S.KOP, S.KG],
    /permission denied/i,
  );
  await attempt("S12.late", await pay({ blockHeader: await refBlock(nile, 25 * 3600_000) }), [S.KOP, S.KG], /expir/i);
  await attempt("S12.past", await pay({ blockHeader: await refBlock(nile, -60_000) }), [S.KOP, S.KG], /expir/i);
  await attempt("S15", await pay({ blockHeader: await refBlock(mainnet) }), [S.KOP, S.KG], /tapos/i);

  // S13: rotate KG -> KG2 under the owner permission (O1 + O2), then old KG must fail and KG2 must work.
  await attempt("S13", await permissionUpdate(nile, A, [A.KOP, A.KG2], { blockHeader: await refBlock(nile) }), [S.O1, S.O2], "accept");
  const p13 = await permissions();
  record("S13.read", { permissions: p13, met: sameSet(p13.active[0]?.keys ?? [], [A.KOP, A.KG2]) && p13.active[0].operations === OPS });
  await attempt("S13.oldKG", await pay(), [S.KOP, S.KG], /not contained of permission/i);
  const s13 = await attempt("S13.newKG", await pay(), [S.KOP, S.KG2], "accept");

  // S14: every signature of the run, both libraries.
  const sigs = results.steps.flatMap((s) => s.signatures ?? []);
  record("S14", {
    signatures: sigs.length,
    highS: sigs.filter((f) => !f.lowS).length,
    k256Disagrees: sigs.filter((f) => f.k256 !== f.tronweb).length,
    met: sigs.every((f) => f.lowS && f.k256 === f.tronweb),
  });

  // S16: isolate the multisig surcharge (#23) from energy and bandwidth fees.
  const multisigFee = Number(s0.nile.getMultiSignFee);
  const fees = Object.fromEntries(
    [["S4", s4], ["S5", s5], ["S13.newKG", s13]].map(([n, e]) => {
      const r = e.info?.receipt ?? {};
      const rest = (e.info?.fee ?? 0) - (r.energy_fee ?? 0) - (r.net_fee ?? 0);
      return [n, { fee: e.info?.fee, energy_fee: r.energy_fee ?? 0, net_fee: r.net_fee ?? 0, rest, balanceDeltaSun: e.balanceDeltaSun }];
    }),
  );
  // S5 is R's first TRX, so its `rest` may also hold the account-creation fee.
  record("S16", { multisigFeeParam: multisigFee, fees, met: fees.S4.rest === multisigFee && fees["S13.newKG"].rest === multisigFee });

  const mustAccept = ["S3", "S4", "S5", "S13", "S13.newKG"];
  const mustRefuse = ["S6", "S7", "S8", "S9", "S10", "S13.oldKG"];
  const by = Object.fromEntries(results.steps.map((s) => [s.step, s]));
  const go =
    mustAccept.every((s) => by[s]?.broadcast?.ok || (s === "S3" && state === "configured")) &&
    mustRefuse.every((s) => by[s]?.refused);
  results.verdict = {
    reading: go ? "GO" : by.S10?.refused === false ? "NO-GO (active permission can rewrite permissions)" : "NO-GO or tooling: read the steps",
    unexpected: results.steps.filter((s) => s.met === false).map((s) => s.step),
  };
  record("verdict", results.verdict);
  console.log(`results: ${OUT}`);
}

const cmd = process.argv[2];
const commands = { keygen, selftest, run };
if (!commands[cmd]) die("usage: node spike.mjs keygen | selftest | run [--broadcast]");
try {
  await commands[cmd]();
} catch (e) {
  die(e.message);
}
