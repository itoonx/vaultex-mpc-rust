// Ed25519 for the receipt oracle (RECEIPT_V1 §6.2-§6.3).
// Signing and key derivation use node:crypto (pure Ed25519, deterministic).
// Verification follows the strict rule of RECEIPT_V1 §6.3 step by step, with the curve
// arithmetic of RFC 8032 §5.1 written out in BigInt, so the oracle does not inherit any
// library's edge-case behaviour.
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { concat, leToBig, sha512 } from './lib.mjs';

const P = 2n ** 255n - 19n;
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;
function pow(b, e, m = P) {
  let r = 1n;
  b = mod(b, m);
  for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
}
const inv = (a) => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

// Points in extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z (RFC 8032 §5.1.4).
const IDENTITY = [0n, 1n, 1n, 0n];
function add([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) {
  const A = mod((Y1 - X1) * (Y2 - X2));
  const B = mod((Y1 + X1) * (Y2 + X2));
  const C = mod(T1 * 2n * D * T2);
  const Dd = mod(Z1 * 2n * Z2);
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}
function mul(s, Pt) {
  let Q = IDENTITY;
  for (let i = BigInt(s.toString(2).length) - 1n; i >= 0n; i--) {
    Q = add(Q, Q);
    if ((s >> i) & 1n) Q = add(Q, Pt);
  }
  return Q;
}
const neg = ([X, Y, Z, T]) => [mod(-X), Y, Z, mod(-T)];
const isIdentity = ([X, Y, Z]) => mod(X) === 0n && mod(Y - Z) === 0n;

// RFC 8032 §5.1.2.
function encode([X, Y, Z]) {
  const zi = inv(Z);
  const x = mod(X * zi), y = mod(Y * zi);
  const out = new Uint8Array(32);
  let n = y | ((x & 1n) << 255n);
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

// RFC 8032 §5.1.3. Returns null when decoding fails.
// ponytail: an unreduced y (y >= p) is refused for both R and A, as RFC 8032 says. RECEIPT_V1 §6.3
// leaves this open for A (§11 Q3); for R it changes nothing, since step 5 compares encodings.
export function decodePoint(bytes) {
  if (bytes.length !== 32) return null;
  const n = leToBig(bytes);
  const x0 = n >> 255n;
  const y = n & ((1n << 255n) - 1n);
  if (y >= P) return null;
  const u = mod(y * y - 1n), v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === u) { /* root found */ } else if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else return null;
  if (x === 0n && x0 === 1n) return null;
  if ((x & 1n) !== x0) x = P - x;
  return [x, y, 1n, mod(x * y)];
}

const BASE = decodePoint(Uint8Array.from(Buffer.from('58' + '66'.repeat(31), 'hex')));
const dbl = (Pt) => add(Pt, Pt);
const smallOrder = (Pt) => isIdentity(dbl(dbl(dbl(Pt)))); // its order divides 8 iff [8]P is the identity

// RECEIPT_V1 §6.3, steps 1-5, over the bytes as received. Returns true only on accept.
export function verifyStrict(pub, sig, msg) {
  if (pub.length !== 32 || sig.length !== 64) return false;
  const Rb = sig.subarray(0, 32), Sb = sig.subarray(32);
  const S = leToBig(Sb);
  if (S >= L) return false; // step 1
  const R = decodePoint(Rb), A = decodePoint(pub);
  if (!R || !A) return false; // step 2
  if (smallOrder(R) || smallOrder(A)) return false; // step 3
  const k = mod(leToBig(sha512(concat(Rb, pub, msg))), L); // step 4
  const check = add(mul(S, BASE), neg(mul(k, A))); // step 5: [S]B - [k]A
  return Buffer.from(encode(check)).equals(Buffer.from(Rb));
}

// node:crypto key from a 32-byte RFC 8032 seed (PKCS#8 wrapping of the raw seed).
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
export function keyFromSeed(seed) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return { priv, pub: Uint8Array.from(spki.subarray(spki.length - 32)) };
}
export const signWith = (priv, msg) => Uint8Array.from(nodeSign(null, Buffer.from(msg), priv));
