// tronweb side of the strict TRON decoder's differential test, driven by
// ../tests/tron_differential.rs. Setup: `npm ci --ignore-scripts` in this directory.
//
// Reads one hex `Transaction.raw` per stdin line and writes one JSON line per input with what
// tronweb reads from it: its bundled google-protobuf `Transaction.raw` class, its public
// `deserializeTransaction`, its ABI decoder and its txid helper. It judges nothing; the Rust side
// compares. The first output line names the versions.
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { utils } from 'tronweb';

// Registered by tronweb's protocol modules when `tronweb` is imported.
const { Transaction } = globalThis.TronWebProto;
const TYPES = { 1: 'TransferContract', 31: 'TriggerSmartContract' };
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const message = (e) => String(e?.message ?? e).slice(0, 120);

function read(line) {
  let raw;
  try {
    raw = Transaction.raw.deserializeBinary(Buffer.from(line, 'hex'));
  } catch (e) {
    return { parsed: false, error: message(e) };
  }
  const out = { parsed: true };
  try {
    out.reserialized = hex(raw.serializeBinary());
    const tx = new Transaction();
    tx.setRawData(raw);
    out.txid = utils.transaction.txPbToTxID(tx).replace(/^0x/, '');
  } catch (e) {
    // google-protobuf can parse what it cannot write back (e.g. a wire type the schema does not name).
    out.reserialize_error = message(e);
  }
  const contracts = raw.getContractList();
  Object.assign(out, {
    contracts: contracts.length,
    ref_block_num: raw.getRefBlockNum(),
    auths: raw.getAuthsList().length,
    scripts: hex(raw.getScripts_asU8()),
    memo: hex(raw.getData_asU8()),
  });
  let name;
  try {
    name = contracts.length ? TYPES[contracts[0].getType()] : undefined;
  } catch (e) {
    out.contract_error = message(e);
  }
  if (!name) return out;
  try {
    out.tx = utils.deserializeTx.deserializeTransaction(name, line);
  } catch (e) {
    out.tx_error = message(e);
    return out;
  }
  const value = out.tx.contract[0].parameter.value;
  if (name === 'TriggerSmartContract') {
    out.selector = value.data.slice(0, 8);
    try {
      const [to, amount] = utils.abi.decodeParams([], ['address', 'uint256'], value.data, true);
      out.call = { to, amount: amount.toString(16).padStart(64, '0') };
    } catch (e) {
      out.call_error = message(e);
    }
  }
  return out;
}

const pkg = (name) =>
  JSON.parse(readFileSync(new URL(`./node_modules/${name}/package.json`, import.meta.url))).version;
console.log(
  JSON.stringify({ tronweb: pkg('tronweb'), google_protobuf: pkg('google-protobuf'), node: process.version }),
);
// Strings decoded from mutated bytes can hold lone surrogates, which are not valid JSON text.
const wellFormed = (_key, v) => (typeof v === 'string' ? v.toWellFormed() : v);
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  console.log(JSON.stringify(read(line.trim()), wellFormed));
}
