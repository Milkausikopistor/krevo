// Thread de prova: calcula UMA das duas provas Bulletproofs de uma entrada (E1 ou E2) —
// no núcleo em Rust/WebAssembly (wasmJob) ou em JavaScript.
import { parentPort, workerData } from 'node:worker_threads';
import * as core from '../crypto/wasm.js';
import { installGens } from './bp.js';
import { E1, E2 } from './curve.js';
import { proveHalf } from './fcmp.js';

try {
  const { job, half, gens, wasmJob } = workerData;
  if (wasmJob) {
    if (!core.available()) throw new Error('núcleo WebAssembly indisponível na thread');
    parentPort.postMessage({ proof: core.fcmpHalf(wasmJob, half) });
  } else {
    if (gens) { installGens(E1, gens.E1); installGens(E2, gens.E2); }
    parentPort.postMessage({ proof: proveHalf(job, half) });
  }
} catch (e) {
  parentPort.postMessage({ error: e.message });
}
