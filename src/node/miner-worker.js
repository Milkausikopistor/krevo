// Thread de mineração: procura nonces cujo hash fica abaixo do alvo do trabalho.
// O mesmo código serve à mineração solo (alvo = alvo do bloco) e ao pool
// (alvo = alvo de "share", mais fácil: mede o esforço de cada minerador).
//
//   recebe: { type:'job', jobId, prePowHash, timestamp, target (32 bytes LE, hex) } | { type:'pause' } | { type:'stop' }
//   envia:  { type:'share', jobId, nonce, timestamp } | { type:'hashes', n }
import { parentPort } from 'node:worker_threads';
import { randomBytes } from 'node:crypto';
import { PowState, hashMeetsTarget } from '../consensus/pow.js';

let job = null, seq = 0, cur = null, hashes = 0, lastReport = Date.now();

parentPort.on('message', (m) => {
  if (m.type === 'job') { job = m; seq++; }
  else if (m.type === 'pause') job = null;
  else if (m.type === 'stop') process.exit(0);
});

function loop() {
  if (!job) { setTimeout(loop, 20); return; }
  if (!cur || cur.seq !== seq) {
    const samePow = cur && cur.prePowHash === job.prePowHash; // só mudou o alvo (vardiff): reaproveita a matriz
    cur = {
      seq, jobId: job.jobId, prePowHash: job.prePowHash, minTs: job.timestamp,
      pow: samePow ? cur.pow : new PowState(Buffer.from(job.prePowHash, 'hex')),
      target: Buffer.from(job.target, 'hex'),
      nonce: samePow ? cur.nonce : randomBytes(8).readBigUInt64LE(0) >> 1n,
    };
  }
  const ts = Math.max(cur.minTs, Date.now());
  for (let i = 0; i < 3000; i++) {
    hashes++;
    if (hashMeetsTarget(cur.pow.hash(ts, cur.nonce), cur.target)) {
      parentPort.postMessage({ type: 'share', jobId: cur.jobId, nonce: cur.nonce.toString(), timestamp: ts });
    }
    cur.nonce++;
  }
  const now = Date.now();
  if (now - lastReport > 1000) { parentPort.postMessage({ type: 'hashes', n: hashes }); hashes = 0; lastReport = now; }
  setImmediate(loop);
}
loop();
