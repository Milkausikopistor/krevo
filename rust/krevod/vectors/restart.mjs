// Persistence and the explorer on top of the Rust node:
//  1. the Rust node alone + a JavaScript miner for a few seconds
//  2. the block explorer (JavaScript) reading the Rust node's RPC
//  3. restarting the Rust node: it reloads its own block file
//  4. the reference node (JavaScript) reprocesses the file WRITTEN BY RUST and reaches the same state
//   node rust/krevod/vectors/restart.mjs <krevod.exe>
import { spawn, execFileSync } from 'node:child_process';
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
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-restart-'));
const BASE = 23000 + Math.floor(Math.random() * 200) * 10;
const B = `http://127.0.0.1:${BASE + 1}`, E = `http://127.0.0.1:${BASE + 2}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const procs = [];
const start = (bin, args) => { const p = spawn(bin, args, { stdio: 'ignore' }); procs.push(p); return p; };
process.on('exit', () => { for (const p of procs) { try { p.kill(); } catch {} } });
async function waitFor(fn, what, timeout = 60_000) {
  const t = Date.now();
  for (;;) { try { const v = await fn(); if (v) return v; } catch {} if (Date.now() - t > timeout) throw new Error('timed out: ' + what); await sleep(300); }
}
const nodeArgs = ['node', '--network', 'devnet', '--datadir', path.join(tmp, 'b'), '--port', String(BASE), '--rpcport', String(BASE + 1)];
try {
  let node = start(krevod, nodeArgs);
  await waitFor(() => rpc(B, 'getinfo'), 'Rust node');
  const k = Keys.random(), params = getParams('devnet');
  const miner = start(process.execPath, [cli, 'mine', '--address', k.sAddress(params), '--rpc', B, '--network', 'devnet']);
  await waitFor(async () => (await rpc(B, 'getinfo')).blocks > 150, 'blocks mined on the Rust node', 120_000);
  miner.kill();
  await sleep(1500);

  start(process.execPath, [cli, 'explorer', '--rpc', B, '--port', String(BASE + 2), '--network', 'devnet']);
  await waitFor(() => fetch(E + '/api/info').then((r) => r.ok), 'explorer');
  const info = await (await fetch(E + '/api/info')).json();
  const dag = await (await fetch(E + '/api/dag')).json();
  const h = dag.blocks.at(-1).hash;
  const page = await fetch(`${E}/block/${h}`);
  const html = await page.text();
  console.log(`explorer on top of the Rust node: /api/info ok (blocks ${info.blocks ?? info.node?.blocks ?? '?'}), /api/dag with ${dag.blocks.length} blocks, block page ${page.status} (${html.includes(h.slice(0, 16)) ? 'shows the hash' : 'without the hash!'})`);

  const before = await rpc(B, 'getinfo');
  node.kill();
  await sleep(1000);
  node = start(krevod, nodeArgs);
  const after = await waitFor(() => rpc(B, 'getinfo'), 'Rust node restarted');
  const same = ['blocks', 'minted', 'shieldedSupply', 'shieldedOutputs'].every((x) => before[x] === after[x]) && before.virtual.selectedParent === after.virtual.selectedParent;
  console.log(`restart: ${before.blocks} blocks before, ${after.blocks} after — ${same ? 'same state' : 'DIFFERENT'}`);

  const file = path.join(tmp, 'b', 'devnet', 'blocks.dat');
  const js = JSON.parse(execFileSync(process.execPath, [path.join(here, 'replay.mjs'), 'devnet', file], { stdio: ['ignore', 'pipe', 'ignore'] }).toString());
  const ok = js.virtual.selectedParent === after.virtual.selectedParent && js.minted === after.minted && js.chain === js.blocks;
  console.log(`JavaScript node reading the file written by Rust: ${js.blocks} blocks, ${js.disq} disqualified — ${ok ? 'same state as the Rust node' : 'DIFFERENT'}`);
  if (!same || !ok) process.exitCode = 1;
} catch (e) { console.error('FAILED: ' + e.stack); process.exitCode = 1; }
