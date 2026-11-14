// Medição estatística de tempo constante (método "dudect") no núcleo WebAssembly — o código que
// as carteiras realmente executam, no motor V8. Ver rust/krevod/src/ct_timing_test.rs (nativo).
//   node rust/krevo-wasm/ct-timing.mjs [amostras]
// Classe 0: segredo fixo (k = 1, valor 0, chave fixa); classe 1: segredo aleatório novo a cada
// medida. Teste t de Welch, também com cortes nos percentis; |t| > 4,5 = vazamento.
// O CONTROLE (multiplicação em BigInt do JavaScript, de tempo variável) precisa acusar vazamento.
import crypto from 'node:crypto';
import * as core from '../../src/crypto/wasm.js';
import { G, multiexp, mulG } from '../../src/crypto/secp256k1.js';

const N = Number(process.argv[2] ?? 6000);
if (!core.available()) { console.error('núcleo WebAssembly indisponível'); process.exit(1); }
const { OP, rawCall } = core;

function welch(samples) {
  const n = [0, 0], mean = [0, 0], m2 = [0, 0];
  for (const [c, x] of samples) { n[c]++; const d = x - mean[c]; mean[c] += d / n[c]; m2[c] += d * (x - mean[c]); }
  if (n[0] < 2 || n[1] < 2) return { t: 0, mean };
  const v0 = m2[0] / (n[0] - 1), v1 = m2[1] / (n[1] - 1);
  return { t: (mean[0] - mean[1]) / Math.sqrt(v0 / n[0] + v1 / n[1]), mean };
}
function dudect(n, prep, run) {
  for (let i = 0; i < n / 20; i++) run(prep(i & 1)); // aquecimento
  const samples = [];
  for (let i = 0; i < n; i++) {
    const c = crypto.randomInt(2);
    const x = prep(c);
    const t0 = process.hrtime.bigint();
    run(x);
    samples.push([c, Number(process.hrtime.bigint() - t0)]);
  }
  const sorted = samples.map((s) => s[1]).sort((a, b) => a - b);
  let best = 0, all = welch(samples);
  for (const pct of [100, 99, 95, 90, 75, 50]) {
    const cut = sorted[Math.floor((sorted.length - 1) * pct / 100)];
    best = Math.max(best, Math.abs(welch(samples.filter((s) => s[1] <= cut)).t));
  }
  return { t: best, mean: all.mean };
}

const be32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
const rnd32 = () => { for (;;) { const b = crypto.randomBytes(32); if (b[0] < 0xff) return b; } }; // < n
const ONE = be32(1n), FIXED = rnd32();
const [px, py] = mulG(0x12345678n).affine();
const P = Buffer.concat([be32(px), be32(py)]);
const pick = (fixed) => (c) => { const r = rnd32(); return c === 0 ? fixed : r; }; // mesmo preparo nas duas classes

const results = [];
const run = (name, n, prep, fn, control = false) => {
  const r = dudect(n, prep, fn);
  const leak = r.t > 4.5;
  results.push({ name, t: r.t, ok: leak === control, note: control ? (leak ? 'vazamento detectado (esperado: controle)' : 'CONTROLE NÃO DETECTOU') : (leak ? 'VAZAMENTO' : 'ok'), means: r.mean.map((m) => Math.round(m / 1000)) });
};
run('k·G (k = 1 × aleatório)', N, pick(ONE), (k) => rawCall(OP.MUL_G, k));
run('k·G (k fixo aleatório × aleatório)', N, pick(FIXED), (k) => rawCall(OP.MUL_G, k));
run('k·P (k = 1 × aleatório)', N / 2, pick(ONE), (k) => rawCall(OP.MUL, Buffer.concat([P, k])));
run('k·H (k = 1 × aleatório)', N, pick(ONE), (k) => rawCall(OP.MUL_H, k));
const sig = (x) => Buffer.concat([x, Buffer.from([3]), Buffer.from('sig'), Buffer.from('m')]);
run('Schnorr (chave fixa × aleatória)', N / 2, (c) => sig(pick(FIXED)(c)), (i) => rawCall(OP.SCHNORR, i));
const aes = (k) => Buffer.concat([k, Buffer.alloc(12, 1), Buffer.alloc(256, 2)]);
run('AES-256-GCM (chave fixa × aleatória)', N, (c) => aes(pick(Buffer.alloc(32))(c)), (i) => rawCall(OP.AES_ENC, i));
const range = (v) => Buffer.concat([Buffer.from([1]), v, be32(5n)]);
run('prova de intervalo (valor 0 × aleatório)', 300, (c) => { const r = crypto.randomBytes(8); return range(c === 0 ? Buffer.alloc(8) : r); }, (i) => rawCall(OP.RANGE, i));
const Pp = mulG(0x12345678n);
run('CONTROLE: k·P em BigInt do JavaScript', N / 2, (c) => { const r = BigInt('0x' + rnd32().toString('hex')); return c === 0 ? 1n : r; }, (k) => multiexp([k], [Pp]), true);

for (const r of results) console.log(`${r.name.padEnd(42)} |t| = ${r.t.toFixed(2).padStart(7)}  ${r.note}   (médias ${r.means[0]} × ${r.means[1]} µs)`);
if (results.some((r) => !r.ok)) { console.error('resultado inesperado'); process.exit(1); }
