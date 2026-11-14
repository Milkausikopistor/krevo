// Provas FCMP: a parte cara são as duas provas Bulletproofs de cada entrada (uma sobre cada
// curva). Ordem de preferência:
//   1. provador NATIVO em Rust (`krevod provar`), se existir — ~10–20× mais rápido;
//      KREVO_PROVER=/caminho/krevod, ou o binário compilado em rust/krevod/target/{release,debug}
//   2. o núcleo em Rust compilado para WebAssembly (src/crypto/wasm.js) — no Node, uma thread por
//      metade de cada entrada; no navegador, em sequência. Tempo constante nos segredos (r1, r2).
//   3. JavaScript puro: threads (Node) ou em sequência (KREVO_NO_WASM / sem WebAssembly).
// Todos produzem provas no mesmo formato, verificadas pelas mesmas regras. A prova de posse
// final (com a chave de gasto) é feita neste processo — pelo núcleo WebAssembly quando
// disponível: a chave de gasto nunca sai daqui.

import { fcmpPrepare, newBlinds, setupFor, finishPrep } from './fcmp.js';
import { exportGens } from './bp.js';
import { E1, E2 } from './curve.js';
import { Point } from '../crypto/secp256k1.js';
import { hashPointForKeyImage } from '../crypto/clsag.js';
import * as core from '../crypto/wasm.js';

const isNode = () => !!globalThis.process?.versions?.node;

let wt;
async function threads() {
  if (wt === undefined) {
    wt = null;
    if (isNode() && !globalThis.process.env?.KREVO_NO_THREADS) {
      try { wt = await import('node:worker_threads'); } catch { wt = null; }
    }
  }
  return wt;
}

// ------------------------------------------------------------------ provador nativo
let native;
/** Caminho do provador nativo, ou null. */
export async function nativeProver() {
  if (native !== undefined) return native;
  native = null;
  if (!isNode() || globalThis.process.env?.KREVO_NO_NATIVE) return native;
  try {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const exe = globalThis.process.platform === 'win32' ? 'krevod.exe' : 'krevod';
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../rust/krevod/target');
    const cands = [globalThis.process.env.KREVO_PROVER, path.join(root, 'release', exe), path.join(root, 'debug', exe)].filter(Boolean);
    native = cands.find((c) => fs.existsSync(c)) ?? null;
  } catch { native = null; }
  return native;
}

const hex64 = (x) => x.toString(16).padStart(64, '0');

async function proveNative(bin, jobs) {
  const { spawn } = await import('node:child_process');
  const req = JSON.stringify({
    jobs: jobs.map(({ a, blinds }) => ({
      branch: a.branch, N: a.N, leafPos: a.leafPos, P: bytes(a.P).toString('hex'), C: bytes(a.C).toString('hex'),
      r1: hex64(blinds.r1), r2: hex64(blinds.r2),
      path: a.path.map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map(hex64) })),
    })),
  });
  return new Promise((ok, fail) => {
    const p = spawn(bin, ['provar'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', fail);
    p.on('close', () => {
      try {
        const r = JSON.parse(out);
        if (r.error) return fail(new Error('provador nativo: ' + r.error));
        ok(r.proofs.map((x) => ({ head: Buffer.from(x.head, 'hex'), bps: Buffer.concat([Buffer.from(x.E1, 'hex'), Buffer.from(x.E2, 'hex')]) })));
      } catch { fail(new Error('provador nativo: resposta inválida ' + (err || out).slice(0, 200))); }
    });
    p.stdin.end(req);
  });
}

// ------------------------------------------------------------------ threads JavaScript
const MAX_THREADS = 8;
let running = 0;
const waiting = [];
async function slot() {
  if (running < MAX_THREADS) { running++; return; }
  await new Promise((ok) => waiting.push(ok));
  running++;
}
function release() { running--; const next = waiting.shift(); if (next) next(); }

async function runHalf(w, job, half, gens, wasmJob) {
  await slot();
  try {
    return await new Promise((ok, fail) => {
      const worker = new w.Worker(new URL('./worker.js', import.meta.url), { workerData: { job, half, gens, wasmJob } });
      worker.once('message', (m) => (m.error ? fail(new Error(m.error)) : ok(Buffer.from(m.proof))));
      worker.once('error', fail);
      worker.once('exit', (code) => { if (code !== 0) fail(new Error(`thread de prova saiu com código ${code}`)); });
    });
  } finally { release(); }
}

const bytes = (p) => (Buffer.isBuffer(p) || p instanceof Uint8Array ? Buffer.from(p) : p.toBytes());

/** Qual provador foi usado na última preparação ('nativo' | 'wasm-threads' | 'wasm' | 'threads' | 'sequencial'). */
export let lastProver = null;

/** Monta o "preparo" a partir do cabeçalho calculado em Rust (nativo ou WebAssembly). */
function fromHead(a, blinds, head, bps) {
  const st = { Phat: E1.fromBytes(head.subarray(0, 33)), Ihat: E1.fromBytes(head.subarray(33, 66)), Chat: E1.fromBytes(head.subarray(66, 99)) };
  const P = a.P instanceof Point ? a.P : Point.fromBytes(a.P);
  return { st, leaf: { I: hashPointForKeyImage(P) }, r1: blinds.r1, head, bps };
}

/**
 * Parte cara das provas de várias entradas. argsList: [{ branch, N, path, leafPos, P, C }].
 * Devolve os "preparos" para fcmpFinish (que prende cada prova à transação).
 */
export async function fcmpPrepareMany(argsList) {
  const jobs = argsList.map((a) => ({ a, blinds: newBlinds() }));
  const bin = await nativeProver();
  if (bin) {
    try {
      // o Rust devolve também o cabeçalho (P̂, Î, Ĉ, L̂, nós cegados): nada a recalcular aqui
      const res = await proveNative(bin, jobs);
      lastProver = 'nativo';
      return jobs.map(({ a, blinds }, i) => fromHead(a, blinds, res[i].head, res[i].bps));
    } catch { /* segue para o WebAssembly ou o JavaScript */ }
  }
  const w = await threads();
  if (core.available()) {
    const cj = jobs.map(({ a, blinds }) => core.fcmpJob({ ...a, P: bytes(a.P), C: bytes(a.C) }, blinds));
    if (w) {
      const heads = cj.map((j) => core.fcmpHead(j)); // valida o caminho antes de gastar CPU
      const halves = await Promise.all(cj.map((j) => Promise.all([runHalf(w, null, 'E1', null, j), runHalf(w, null, 'E2', null, j)])));
      lastProver = 'wasm-threads';
      return jobs.map(({ a, blinds }, i) => fromHead(a, blinds, heads[i], Buffer.concat(halves[i])));
    }
    lastProver = 'wasm';
    return jobs.map(({ a, blinds }, i) => { const r = core.fcmpPrepare(cj[i]); return fromHead(a, blinds, r.head, r.bps); });
  }
  if (!w) { lastProver = 'sequencial'; return argsList.map((a, i) => fcmpPrepare(a, jobs[i].blinds)); }
  const setups = jobs.map(({ a, blinds }) => setupFor(a, blinds)); // valida o caminho antes de gastar CPU
  const gens = { E1: exportGens(E1), E2: exportGens(E2) };         // o que já estiver calculado vai junto
  const halves = await Promise.all(jobs.map(({ a, blinds }) => {
    const job = { branch: a.branch, N: a.N, path: a.path, leafPos: a.leafPos, P: bytes(a.P), C: bytes(a.C), r1: blinds.r1, r2: blinds.r2 };
    return Promise.all([runHalf(w, job, 'E1', gens), runHalf(w, job, 'E2', gens)]);
  }));
  lastProver = 'threads';
  return setups.map((s, i) => finishPrep(s, halves[i][0], halves[i][1]));
}
