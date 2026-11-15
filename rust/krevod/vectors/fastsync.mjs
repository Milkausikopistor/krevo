// Fast sync with real processes over TCP (simnet: trivial proof of work, so a long chain is quick):
//  1. an archival Rust node A + a JavaScript miner until the chain is long enough for a sync point
//  2. a NEW Rust node B with --fast-sync, connected only to A: headers first, then the state at the
//     sync point, then the blocks after it — it must end with exactly A's state
//  3. for comparison, a new Rust node C syncing normally (every block validated)
//  4. B mines through the JavaScript miner and A follows (B's blocks are valid for A)
//   node rust/krevod/vectors/fastsync.mjs <krevod.exe>
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const krevod = process.argv[2];
const cli = path.join(root, 'src', 'cli.js');
const { rpc } = await import(pathToFileURL(path.join(root, 'src/node/rpcclient.js')).href);
const { Keys } = await import(pathToFileURL(path.join(root, 'src/wallet/keys.js')).href);
const { getParams } = await import(pathToFileURL(path.join(root, 'src/params.js')).href);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-fastsync-'));
const BASE = 25000 + Math.floor(Math.random() * 200) * 10;
const url = (i) => `http://127.0.0.1:${BASE + 2 * i + 1}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const procs = [];
const logs = {};
function startNode(name, i, extra = []) {
  const args = ['node', '--network', 'simnet', '--datadir', path.join(tmp, name), '--port', String(BASE + 2 * i), '--rpcport', String(BASE + 2 * i + 1), '--no-seeds', ...extra];
  const p = spawn(krevod, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  logs[name] = '';
  p.stderr.on('data', (d) => { logs[name] += d; });
  procs.push(p);
  return p;
}
const startMiner = (rpcUrl, address) => { const p = spawn(process.execPath, [cli, 'mine', '--address', address, '--rpc', rpcUrl, '--network', 'simnet', '--threads', '2'], { stdio: 'ignore' }); procs.push(p); return p; };
async function waitFor(fn, what, timeout = 120_000) {
  const t = Date.now();
  for (;;) { try { const v = await fn(); if (v) return v; } catch {} if (Date.now() - t > timeout) throw new Error('timed out: ' + what); await sleep(300); }
}
const fields = (x) => ({ bs: x.virtual.blueScore, sp: x.virtual.selectedParent, minted: x.minted, feePool: x.feePool, shielded: x.shieldedSupply, outputs: x.shieldedOutputs });
const same = (a, b) => JSON.stringify(fields(a)) === JSON.stringify(fields(b));
let ok = true;
try {
  const params = getParams('simnet');
  const k = Keys.random();
  // 1. a chain longer than two sync depths (devnet/simnet merge depth: 1,200)
  startNode('a', 0);
  await waitFor(() => rpc(url(0), 'getinfo'), 'node A');
  let miner = startMiner(url(0), k.sAddress(params));
  const t0 = Date.now();
  await waitFor(async () => (await rpc(url(0), 'getinfo')).virtual.blueScore > 2700, 'a chain of 2,700 blue score on A', 600_000);
  miner.kill();
  await sleep(2000);
  const a = await rpc(url(0), 'getinfo');
  console.log(`A: ${a.blocks} blocks, blue score ${a.virtual.blueScore} (mined in ${((Date.now() - t0) / 1000).toFixed(0)} s)`);

  // 2. fast sync
  let t = Date.now();
  startNode('b', 1, ['--fast-sync', '--peer', `127.0.0.1:${BASE}`]);
  const b = await waitFor(async () => { const x = await rpc(url(1), 'getinfo'); return !x.fastSync && x.pruned && same(x, a) && x; }, 'B fast-synced to A');
  const fastMs = Date.now() - t;
  const verified = /fast sync: state at \w+ verified/.test(logs.b);
  console.log(`B (--fast-sync): ${b.blocks} blocks known, pruning point ${b.pruningPoint.slice(0, 12)}, same state as A in ${(fastMs / 1000).toFixed(1)} s — ${verified ? 'started from the verified state' : 'did NOT use fast sync'}`);
  ok &&= verified;

  // 3. normal sync, for comparison
  t = Date.now();
  startNode('c', 2, ['--peer', `127.0.0.1:${BASE}`]);
  await waitFor(async () => { const x = await rpc(url(2), 'getinfo'); return same(x, a) && x; }, 'C synced normally');
  console.log(`C (normal sync): same state as A in ${((Date.now() - t) / 1000).toFixed(1)} s`);

  // 4. B mines; A (and C) follow
  miner = startMiner(url(1), k.tAddress(params));
  await waitFor(async () => (await rpc(url(1), 'getinfo')).virtual.blueScore > a.virtual.blueScore + 40, 'B mining');
  miner.kill();
  await sleep(3000);
  const [a2, b2, c2] = await Promise.all([0, 1, 2].map((i) => rpc(url(i), 'getinfo')));
  const agree = same(a2, b2) && same(a2, c2);
  console.log(`after B mined ${b2.virtual.blueScore - a.virtual.blueScore} blue score: ${agree ? 'A, B and C agree' : 'DIFFERENT'} (blue score ${a2.virtual.blueScore})`);
  ok &&= agree;
  const bad = Object.entries(logs).flatMap(([n, l]) => l.split('\n').filter((x) => /invalid|disqualified|abandoned/.test(x)).map((x) => `${n}: ${x}`));
  if (bad.length) { console.log('unexpected log lines:\n' + bad.join('\n')); ok = false; }
} catch (e) { console.error('FAILED: ' + e.stack); ok = false; }
for (const p of procs) { try { p.kill(); } catch {} }
if (!ok) { console.log('--- log of B ---\n' + (logs.b ?? '').split('\n').slice(-30).join('\n')); process.exitCode = 1; }
