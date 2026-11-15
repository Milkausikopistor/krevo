// FCMP proofs: the expensive part is each input's two Bulletproofs (one over each
// curve). Order of preference:
//   1. the NATIVE Rust prover (`krevod prove`), if present — ~10–20× faster;
//      KREVO_PROVER=/path/krevod, or the binary built in rust/krevod/target/{release,debug}
//   2. the Rust core compiled to WebAssembly (src/crypto/wasm.js) — in Node, one thread per
//      half of each input; in the browser, sequentially. Constant time on the secrets (r1, r2).
//   3. pure JavaScript: threads (Node) or sequentially (KREVO_NO_WASM / no WebAssembly).
// All produce proofs in the same format, verified by the same rules. The final ownership
// proof (with the spend key) is made in this process — by the WebAssembly core when
// available: the spend key never leaves here.

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

// ------------------------------------------------------------------ native prover
let native;
/** Path of the native prover, or null. */
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
    const p = spawn(bin, ['prove'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', fail);
    p.on('close', () => {
      try {
        const r = JSON.parse(out);
        if (r.error) return fail(new Error('provador nativo: ' + r.error));
        ok(r.proofs.map((x) => ({ head: Buffer.from(x.head, 'hex'), bps: Buffer.concat([Buffer.from(x.E1, 'hex'), Buffer.from(x.E2, 'hex')]) })));
      } catch { fail(new Error('native prover: invalid response ' + (err || out).slice(0, 200))); }
    });
    p.stdin.end(req);
  });
}

// ------------------------------------------------------------------ JavaScript threads
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
      worker.once('exit', (code) => { if (code !== 0) fail(new Error(`proving thread exited with code ${code}`)); });
    });
  } finally { release(); }
}

const bytes = (p) => (Buffer.isBuffer(p) || p instanceof Uint8Array ? Buffer.from(p) : p.toBytes());

/** Which prover was used in the last preparation ('native' | 'wasm-threads' | 'wasm' | 'threads' | 'sequential'). */
export let lastProver = null;

/** Builds the "preparation" from the header computed in Rust (native or WebAssembly). */
function fromHead(a, blinds, head, bps) {
  const st = { Phat: E1.fromBytes(head.subarray(0, 33)), Ihat: E1.fromBytes(head.subarray(33, 66)), Chat: E1.fromBytes(head.subarray(66, 99)) };
  const P = a.P instanceof Point ? a.P : Point.fromBytes(a.P);
  return { st, leaf: { I: hashPointForKeyImage(P) }, r1: blinds.r1, head, bps };
}

/**
 * Expensive part of the proofs of several inputs. argsList: [{ branch, N, path, leafPos, P, C }].
 * Returns the "preparations" for fcmpFinish (which binds each proof to the transaction).
 */
export async function fcmpPrepareMany(argsList) {
  const jobs = argsList.map((a) => ({ a, blinds: newBlinds() }));
  const bin = await nativeProver();
  if (bin) {
    try {
      // Rust also returns the header (P̂, Î, Ĉ, L̂, blinded nodes): nothing to recompute here
      const res = await proveNative(bin, jobs);
      lastProver = 'native';
      return jobs.map(({ a, blinds }, i) => fromHead(a, blinds, res[i].head, res[i].bps));
    } catch { /* fall through to WebAssembly or JavaScript */ }
  }
  const w = await threads();
  if (core.available()) {
    const cj = jobs.map(({ a, blinds }) => core.fcmpJob({ ...a, P: bytes(a.P), C: bytes(a.C) }, blinds));
    if (w) {
      const heads = cj.map((j) => core.fcmpHead(j)); // validates the path before spending CPU
      const halves = await Promise.all(cj.map((j) => Promise.all([runHalf(w, null, 'E1', null, j), runHalf(w, null, 'E2', null, j)])));
      lastProver = 'wasm-threads';
      return jobs.map(({ a, blinds }, i) => fromHead(a, blinds, heads[i], Buffer.concat(halves[i])));
    }
    lastProver = 'wasm';
    return jobs.map(({ a, blinds }, i) => { const r = core.fcmpPrepare(cj[i]); return fromHead(a, blinds, r.head, r.bps); });
  }
  if (!w) { lastProver = 'sequential'; return argsList.map((a, i) => fcmpPrepare(a, jobs[i].blinds)); }
  const setups = jobs.map(({ a, blinds }) => setupFor(a, blinds)); // validates the path before spending CPU
  const gens = { E1: exportGens(E1), E2: exportGens(E2) };         // whatever is already computed goes along
  const halves = await Promise.all(jobs.map(({ a, blinds }) => {
    const job = { branch: a.branch, N: a.N, path: a.path, leafPos: a.leafPos, P: bytes(a.P), C: bytes(a.C), r1: blinds.r1, r2: blinds.r2 };
    return Promise.all([runHalf(w, job, 'E1', gens), runHalf(w, job, 'E2', gens)]);
  }));
  lastProver = 'threads';
  return setups.map((s, i) => finishPrep(s, halves[i][0], halves[i][1]));
}
