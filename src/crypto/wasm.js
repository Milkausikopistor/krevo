// Núcleo criptográfico das carteiras em Rust, compilado para WebAssembly (rust/krevo-wasm).
//
// Tudo o que toca SEGREDOS passa por aqui quando o módulo está disponível — no Node e no
// navegador: multiplicações por chaves e máscaras, assinaturas Schnorr, provas de intervalo,
// provas FCMP e AES-GCM. O núcleo é de tempo constante (sem desvios nem acessos à memória
// que dependam de segredos), usa nonces "hedged" e confere cada assinatura/prova antes de
// devolvê-la. É o MESMO código do nó em Rust (rust/krevod/src), conferido contra este nó
// JavaScript pelos vetores de teste.
//
// Se o módulo não carregar (ou com KREVO_NO_WASM=1), o código JavaScript continua funcionando
// sozinho, como antes — correto, mas sem a garantia de tempo constante.

const WASM_URL = new URL('./krevo_core.wasm', import.meta.url);
const IS_NODE = typeof process !== 'undefined' && !!process.versions?.node;
const disabled = IS_NODE && !!process.env.KREVO_NO_WASM;

const OP = {
  MUL: 1, MUL_G: 2, MUL_H: 3, SCHNORR: 4, RANGE: 5, FCMP_HALF: 6, AES_ENC: 7, AES_DEC: 8, SELFTEST: 9,
  GSP: 10, FCMP_HEAD: 11, FCMP_PREP: 12, MLDSA_KEY: 13, MLDSA_SIGN: 14, MLDSA_VERIFY: 15,
};

function fillRandom(view) {
  // crypto.getRandomValues aceita no máximo 65536 bytes por chamada
  for (let o = 0; o < view.length; o += 65536) globalThis.crypto.getRandomValues(view.subarray(o, Math.min(view.length, o + 65536)));
}

let module = null; // WebAssembly.Module compilado (reaproveitado se a instância precisar ser refeita)
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
    if (!globalThis.crypto?.getRandomValues) throw new Error('crypto.getRandomValues indisponível');
    if (IS_NODE) {
      // getBuiltinModule: o fs de verdade, mesmo quando "node:fs" é trocado (testes que imitam o navegador)
      const fs = process.getBuiltinModule?.('node:fs') ?? (await import('node:fs'));
      module = new WebAssembly.Module(fs.readFileSync(WASM_URL));
    } else {
      const r = await fetch(WASM_URL);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      module = await WebAssembly.compile(await r.arrayBuffer());
    }
    instantiate();
    const st = callRaw(OP.SELFTEST, new Uint8Array(0));
    if (new TextDecoder().decode(st) !== 'ok') throw new Error('autoteste falhou');
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
    // Uma armadilha (trap) do WebAssembly deixa a instância num estado indefinido: refaz.
    if (e instanceof WebAssembly.RuntimeError) { instantiate(); throw new Error(`núcleo criptográfico: ${e.message}`); }
    throw e;
  } finally {
    try { inst.exports.krevo_free(ptr, len); } catch { /* instância refeita */ }
  }
}

await load();

/** Chamada crua ao núcleo (bytes → bytes), para testes e medições (rust/krevo-wasm/ct-timing.mjs). */
export const rawCall = (op, input) => callRaw(op, input);
export { OP };

/** O núcleo em Rust (WebAssembly) está ativo? */
export const available = () => inst !== null;

// ---------------------------------------------------------------- conversões
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

// ---------------------------------------------------------------- operações
/** k·P (P afim [x, y]; k já reduzido mod n). Devolve [x, y] ou null (infinito). */
export const mul = (x, y, k) => xy(callRaw(OP.MUL, concat(be32(x), be32(y), be32(k))));
/** k·G. */
export const mulG = (k) => xy(callRaw(OP.MUL_G, be32(k)));
/** k·H (gerador de valor dos compromissos de Pedersen). */
export const mulH = (k) => xy(callRaw(OP.MUL_H, be32(k)));

/** Assinatura Schnorr (e, s) com nonce hedged, conferida antes de sair. */
export function schnorrSign(x, msg, domain) {
  const d = new TextEncoder().encode(domain);
  if (d.length > 255) throw new Error('domínio longo demais');
  return toBuf(callRaw(OP.SCHNORR, concat(be32(x), Uint8Array.of(d.length), d, msg)));
}

/** Prova de intervalo agregada. Devolve { V: [33 bytes], proof }. */
export function proveRange(values, gammas) {
  if (values.length < 1 || values.length > 16 || gammas.length !== values.length) throw new Error('bp: número de valores inválido');
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

/** AES-256-GCM: devolve { ct, tag }. */
export function aesGcmEncrypt(key, iv, data) {
  const out = callRaw(OP.AES_ENC, concat(key, iv, data));
  return { ct: out.slice(0, out.length - 16), tag: out.slice(out.length - 16) };
}
/** AES-256-GCM: devolve o texto ou lança erro se a etiqueta não confere. */
export const aesGcmDecrypt = (key, iv, ct, tag) => callRaw(OP.AES_DEC, concat(key, iv, ct, tag));

// ---------------------------------------------------------------- FCMP (provas de pertencimento)
const hex64 = (x) => x.toString(16).padStart(64, '0');
const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
/** Tarefa no formato do provador nativo (P, C: 33 bytes; r1, r2: BigInt; path com BigInt). */
export function fcmpJob(a, blinds) {
  return {
    branch: a.branch, N: a.N, leafPos: a.leafPos, P: hexOf(a.P), C: hexOf(a.C), r1: hex64(blinds.r1), r2: hex64(blinds.r2),
    path: a.path.map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map(hex64) })),
  };
}
const json = (o) => new TextEncoder().encode(JSON.stringify(o));
/** Uma metade (E1 ou E2) das provas de circuito de uma entrada. */
export const fcmpHalf = (job, half) => toBuf(callRaw(OP.FCMP_HALF, json({ ...job, half })));
/** Cabeçalho do enunciado (P̂, Î, Ĉ, L̂, nós cegados), com os cegamentos aplicados em tempo constante. */
export const fcmpHead = (job) => toBuf(callRaw(OP.FCMP_HEAD, json(job)));
/** Cabeçalho + as duas metades, autoverificadas. */
export function fcmpPrepare(job) {
  const out = callRaw(OP.FCMP_PREP, json(job));
  const dv = new DataView(out.buffer, out.byteOffset, out.length);
  const hl = dv.getUint32(0, true);
  const head = out.slice(4, 4 + hl);
  const e1l = dv.getUint32(4 + hl, true);
  return { head: toBuf(head), bps: toBuf(out.slice(8 + hl)), e1Len: e1l };
}
/** Prova de posse (Schnorr generalizada) da FCMP: ctx 32 bytes, pontos de 33 bytes, w = [p, t, q, y, a, b]. */
export const gspProve = (ctx, Phat, Ihat, D, w) => toBuf(callRaw(OP.GSP, concat(ctx, Phat, Ihat, D, ...w.map(be32))));

// ---------------------------------------------------------------- ML-DSA-44 (pós-quântica)
/** Chave pública ML-DSA-44 a partir da semente de 32 bytes (a mesma do OpenSSL). */
export const mldsaPub = (seed) => toBuf(callRaw(OP.MLDSA_KEY, seed));
/** Assinatura ML-DSA-44 hedged, conferida antes de sair. */
export const mldsaSign = (seed, msg) => toBuf(callRaw(OP.MLDSA_SIGN, concat(seed, msg)));
export const mldsaVerify = (pub, msg, sig) => callRaw(OP.MLDSA_VERIFY, concat(pub, sig, msg))[0] === 1;
