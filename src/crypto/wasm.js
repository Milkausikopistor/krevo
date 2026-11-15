// Wallet cryptographic core in Rust, compiled to WebAssembly (rust/krevo-wasm).
//
// Everything that touches SECRETS goes through here when the module is available — in Node and
// in the browser: multiplications by keys and masks, Schnorr signatures, range proofs,
// FCMP proofs and AES-GCM. The core is constant-time (no branches or memory accesses that
// depend on secrets), uses "hedged" nonces and checks every signature/proof before returning
// it. It is the SAME code as the Rust node (rust/krevod/src), checked against this JavaScript
// node by the test vectors.
//
// If the module does not load (or with KREVO_NO_WASM=1), the JavaScript code keeps working on
// its own, as before — correct, but without the constant-time guarantee.

const WASM_URL = new URL('./krevo_core.wasm', import.meta.url);
const IS_NODE = typeof process !== 'undefined' && !!process.versions?.node;
const disabled = IS_NODE && !!process.env.KREVO_NO_WASM;

const OP = {
  MUL: 1, MUL_G: 2, MUL_H: 3, SCHNORR: 4, RANGE: 5, FCMP_HALF: 6, AES_ENC: 7, AES_DEC: 8, SELFTEST: 9,
  GSP: 10, FCMP_HEAD: 11, FCMP_PREP: 12, MLDSA_KEY: 13, MLDSA_SIGN: 14, MLDSA_VERIFY: 15,
};

function fillRandom(view) {
  // crypto.getRandomValues accepts at most 65536 bytes per call
  for (let o = 0; o < view.length; o += 65536) globalThis.crypto.getRandomValues(view.subarray(o, Math.min(view.length, o + 65536)));
}

let module = null; // compiled WebAssembly.Module (reused if the instance has to be rebuilt)
let inst = null;
export let loadError = null;

function instantiate() {
  const imports = {
    env: {
      krevo_random: (ptr, len) => fillRandom(new Uint8Array(inst.exports.memory.buffer, ptr, len)),
    },
  };
  inst = new WebAssembly.Instance(module, imports);
}

async function load() {
  if (disabled) return;
  try {
    if (!globalThis.crypto?.getRandomValues) throw new Error('crypto.getRandomValues unavailable');
    if (IS_NODE) {
      // getBuiltinModule: the real fs, even when "node:fs" is swapped (tests that emulate the browser)
      const fs = process.getBuiltinModule?.('node:fs') ?? (await import('node:fs'));
      module = new WebAssembly.Module(fs.readFileSync(WASM_URL));
    } else {
      const r = await fetch(WASM_URL);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      module = await WebAssembly.compile(await r.arrayBuffer());
    }
    instantiate();
    const st = callRaw(OP.SELFTEST, new Uint8Array(0));
    if (new TextDecoder().decode(st) !== 'ok') throw new Error('self-test failed');
  } catch (e) {
    module = null; inst = null; loadError = e;
  }
}

function callRaw(op, input) {
  const ex = inst.exports;
  const len = input.length;
  const ptr = ex.krevo_alloc(len);
  try {
    new Uint8Array(ex.memory.buffer, ptr, len).set(input);
    const status = ex.krevo_call(op, ptr, len);
    const out = new Uint8Array(ex.memory.buffer, ex.krevo_out_ptr(), ex.krevo_out_len()).slice();
    if (status !== 0) throw new Error(new TextDecoder().decode(out));
    return out;
  } catch (e) {
    // A WebAssembly trap leaves the instance in an undefined state: rebuild it.
    if (e instanceof WebAssembly.RuntimeError) { instantiate(); throw new Error(`crypto core: ${e.message}`); }
    throw e;
  } finally {
    try { inst.exports.krevo_free(ptr, len); } catch { /* instance rebuilt */ }
  }
}

await load();

/** Raw call to the core (bytes → bytes), for tests and measurements (rust/krevo-wasm/ct-timing.mjs). */
export const rawCall = (op, input) => callRaw(op, input);
export { OP };

/** Is the Rust (WebAssembly) core active? */
export const available = () => inst !== null;

// ---------------------------------------------------------------- conversions
function be32(n) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
function big(b, o = 0, len = 32) {
  let n = 0n;
  for (let i = o; i < o + len; i++) n = (n << 8n) | BigInt(b[i]);
  return n;
}
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const xy = (out) => (out.length === 0 ? null : [big(out, 0), big(out, 32)]);
const toBuf = (u8) => (typeof Buffer !== 'undefined' ? Buffer.from(u8) : u8);

// ---------------------------------------------------------------- operations
/** k·P (affine P [x, y]; k already reduced mod n). Returns [x, y] or null (infinity). */
export const mul = (x, y, k) => xy(callRaw(OP.MUL, concat(be32(x), be32(y), be32(k))));
/** k·G. */
export const mulG = (k) => xy(callRaw(OP.MUL_G, be32(k)));
/** k·H (value generator of the Pedersen commitments). */
export const mulH = (k) => xy(callRaw(OP.MUL_H, be32(k)));

/** Schnorr signature (e, s) with a hedged nonce, checked before it leaves. */
export function schnorrSign(x, msg, domain) {
  const d = new TextEncoder().encode(domain);
  if (d.length > 255) throw new Error('domain too long');
  return toBuf(callRaw(OP.SCHNORR, concat(be32(x), Uint8Array.of(d.length), d, msg)));
}

/** Aggregated range proof. Returns { V: [33 bytes], proof }. */
export function proveRange(values, gammas) {
  if (values.length < 1 || values.length > 16 || gammas.length !== values.length) throw new Error('bp: invalid number of values');
  const parts = [Uint8Array.of(values.length)];
  for (let j = 0; j < values.length; j++) {
    const v = new Uint8Array(8);
    let t = values[j];
    for (let i = 0; i < 8; i++) { v[i] = Number(t & 0xffn); t >>= 8n; }
    parts.push(v, be32(gammas[j]));
  }
  const out = callRaw(OP.RANGE, concat(...parts));
  const V = [];
  for (let j = 0; j < values.length; j++) V.push(toBuf(out.slice(33 * j, 33 * j + 33)));
  return { V, proof: toBuf(out.slice(33 * values.length)) };
}

/** AES-256-GCM: returns { ct, tag }. */
export function aesGcmEncrypt(key, iv, data) {
  const out = callRaw(OP.AES_ENC, concat(key, iv, data));
  return { ct: out.slice(0, out.length - 16), tag: out.slice(out.length - 16) };
}
/** AES-256-GCM: returns the plaintext or throws if the tag does not match. */
export const aesGcmDecrypt = (key, iv, ct, tag) => callRaw(OP.AES_DEC, concat(key, iv, ct, tag));

// ---------------------------------------------------------------- FCMP (membership proofs)
const hex64 = (x) => x.toString(16).padStart(64, '0');
const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
/** Job in the native prover's format (P, C: 33 bytes; r1, r2: BigInt; path with BigInt). */
export function fcmpJob(a, blinds) {
  return {
    branch: a.branch, N: a.N, leafPos: a.leafPos, P: hexOf(a.P), C: hexOf(a.C), r1: hex64(blinds.r1), r2: hex64(blinds.r2),
    path: a.path.map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map(hex64) })),
  };
}
const json = (o) => new TextEncoder().encode(JSON.stringify(o));
/** One half (E1 or E2) of an input's circuit proofs. */
export const fcmpHalf = (job, half) => toBuf(callRaw(OP.FCMP_HALF, json({ ...job, half })));
/** Statement header (P̂, Î, Ĉ, L̂, blinded nodes), with the blinding applied in constant time. */
export const fcmpHead = (job) => toBuf(callRaw(OP.FCMP_HEAD, json(job)));
/** Header + both halves, self-verified. */
export function fcmpPrepare(job) {
  const out = callRaw(OP.FCMP_PREP, json(job));
  const dv = new DataView(out.buffer, out.byteOffset, out.length);
  const hl = dv.getUint32(0, true);
  const head = out.slice(4, 4 + hl);
  const e1l = dv.getUint32(4 + hl, true);
  return { head: toBuf(head), bps: toBuf(out.slice(8 + hl)), e1Len: e1l };
}
/** Ownership proof (generalized Schnorr) of the FCMP: ctx 32 bytes, 33-byte points, w = [p, t, q, y, a, b]. */
export const gspProve = (ctx, Phat, Ihat, D, w) => toBuf(callRaw(OP.GSP, concat(ctx, Phat, Ihat, D, ...w.map(be32))));

// ---------------------------------------------------------------- ML-DSA-44 (post-quantum)
/** ML-DSA-44 public key from the 32-byte seed (the same as OpenSSL's). */
export const mldsaPub = (seed) => toBuf(callRaw(OP.MLDSA_KEY, seed));
/** Hedged ML-DSA-44 signature, checked before it leaves. */
export const mldsaSign = (seed, msg) => toBuf(callRaw(OP.MLDSA_SIGN, concat(seed, msg)));
export const mldsaVerify = (pub, msg, sig) => callRaw(OP.MLDSA_VERIFY, concat(pub, sig, msg))[0] === 1;
