// CPU miners.
//   runMiner      — solo: asks its own node for templates (getblocktemplate with long polling) and submits blocks.
//   runPoolMiner  — connects to a pool through the share protocol (one JSON per line, Stratum-style).
import net from 'node:net';
import { Worker } from 'node:worker_threads';
import { rpc } from './rpcclient.js';
import { Block } from '../consensus/block.js';
import { compactToTarget, targetToLE } from '../consensus/pow.js';
import { toHex, fromHex } from '../util/bytes.js';

const spawnWorkers = (n) => Array.from({ length: n }, () => new Worker(new URL('./miner-worker.js', import.meta.url)));

export async function runMiner({ rpcUrl, address, threads = 1, log = console.log, signal }) {
  const workers = spawnWorkers(threads);
  const st = { hashes: 0, found: 0, accepted: 0, since: Date.now() };
  const jobs = new Map();
  let current = null;
  for (const w of workers) {
    w.on('message', async (m) => {
      if (m.type === 'hashes') st.hashes += m.n;
      if (m.type !== 'share') return;
      const hex = jobs.get(m.jobId);
      if (!hex || m.jobId !== current) return;
      for (const x of workers) x.postMessage({ type: 'pause' }); // one block per template; the next one arrives right after
      current = null;
      const b = Block.deserialize(fromHex(hex));
      b.header.nonce = BigInt(m.nonce);
      b.header.timestamp = m.timestamp;
      b._hash = null;
      st.found++;
      try {
        const r = await rpc(rpcUrl, 'submitblock', { block: toHex(b.serialize()) });
        if (r.status === 'accepted') st.accepted++;
        else log(`block not accepted: ${r.status} ${r.reason ?? ''}`);
      } catch (e) { log('error submitting block: ' + e.message); }
    });
  }
  const report = setInterval(() => {
    const s = (Date.now() - st.since) / 1000;
    log(`hashrate ${(st.hashes / s / 1000).toFixed(1)} kH/s | blocks found ${st.found} | accepted ${st.accepted}`);
    st.hashes = 0; st.since = Date.now();
  }, 10_000);

  let longpollid = null;
  while (!signal?.aborted) {
    try {
      const t = await rpc(rpcUrl, 'getblocktemplate', { address, longpollid });
      if (t.longpollid !== longpollid || current === null) {
        longpollid = t.longpollid;
        const header = Block.deserialize(fromHex(t.block)).header;
        jobs.set(t.longpollid, t.block);
        if (jobs.size > 16) jobs.delete(jobs.keys().next().value);
        current = t.longpollid;
        const job = { type: 'job', jobId: t.longpollid, prePowHash: t.prePowHash, timestamp: header.timestamp, target: toHex(targetToLE(compactToTarget(t.bits))) };
        for (const w of workers) w.postMessage(job);
      }
    } catch (e) {
      log('node unavailable: ' + e.message);
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  clearInterval(report);
  for (const w of workers) w.postMessage({ type: 'stop' });
  return st;
}

/** Pool miner: the pool sends jobs with a share target; the miner returns shares. */
export async function runPoolMiner({ pool, address, worker = 'cpu', threads = 1, log = console.log, signal }) {
  const [host, port] = pool.split(':');
  const workers = spawnWorkers(threads);
  const st = { hashes: 0, sent: 0, accepted: 0, rejected: 0, blocks: 0, since: Date.now() };
  let sock = null, id = 0;
  const send = (o) => { if (sock && !sock.destroyed) sock.write(JSON.stringify(o) + '\n'); };
  for (const w of workers) {
    w.on('message', (m) => {
      if (m.type === 'hashes') st.hashes += m.n;
      if (m.type === 'share') { st.sent++; send({ id: ++id, method: 'submit', params: { jobId: m.jobId, nonce: m.nonce, timestamp: m.timestamp } }); }
    });
  }
  const report = setInterval(() => {
    const s = (Date.now() - st.since) / 1000;
    log(`hashrate ${(st.hashes / s / 1000).toFixed(1)} kH/s | shares accepted ${st.accepted} | rejected ${st.rejected} | pool blocks found by you ${st.blocks}`);
    st.hashes = 0; st.since = Date.now();
  }, 10_000);

  while (!signal?.aborted) {
    await new Promise((resolve) => {
      let buf = '';
      sock = net.connect(Number(port), host);
      sock.setNoDelay(true);
      sock.on('connect', () => send({ id: ++id, method: 'login', params: { address, worker } }));
      sock.on('data', (d) => {
        buf += d;
        if (buf.length > 1_000_000) { sock.destroy(); return; }
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1);
          let msg;
          try { msg = JSON.parse(line); } catch { continue; }
          if (msg.method === 'job') {
            for (const w of workers) w.postMessage({ type: 'job', ...msg.params });
          } else if (msg.result?.login) {
            log(`connected to pool ${pool} as ${address.slice(0, 20)}… (${worker})`);
          } else if (msg.result?.accepted) {
            st.accepted++;
            if (msg.result.block) { st.blocks++; log('🎉 your share became a pool BLOCK'); }
          } else if (msg.error) {
            st.rejected++;
            if (msg.error.startsWith('login')) { log('pool recusou o login: ' + msg.error); signal?.abort?.(); }
          }
        }
      });
      sock.on('error', () => {});
      sock.on('close', () => { for (const w of workers) w.postMessage({ type: 'pause' }); resolve(); });
      signal?.addEventListener?.('abort', () => sock.destroy(), { once: true });
    });
    if (!signal?.aborted) { log('connection to the pool lost; retrying in 2 s'); await new Promise((r) => setTimeout(r, 2000)); }
  }
  clearInterval(report);
  for (const w of workers) w.postMessage({ type: 'stop' });
  return st;
}
