// Proving thread: computes ONE of an input's two Bulletproofs (E1 or E2) —
// in the Rust/WebAssembly core (wasmJob) or in JavaScript.
import { parentPort, workerData } from 'node:worker_threads';
import * as core from '../crypto/wasm.js';
import { installGens } from './bp.js';
import { E1, E2 } from './curve.js';
import { proveHalf } from './fcmp.js';

try {
  const { job, half, gens, wasmJob } = workerData;
  if (wasmJob) {
    if (!core.available()) throw new Error('WebAssembly core unavailable in the thread');
    parentPort.postMessage({ proof: core.fcmpHalf(wasmJob, half) });
  } else {
    if (gens) { installGens(E1, gens.E1); installGens(E2, gens.E2); }
    parentPort.postMessage({ proof: proveHalf(job, half) });
  }
} catch (e) {
  parentPort.postMessage({ error: e.message });
}
