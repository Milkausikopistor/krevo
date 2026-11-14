// Persistência e explorador sobre o nó Rust:
//  1. nó Rust sozinho + minerador JavaScript por alguns segundos
//  2. explorador de blocos (JavaScript) lendo o RPC do nó Rust
//  3. reinício do nó Rust: recarrega o próprio arquivo de blocos
//  4. o nó de referência (JavaScript) reprocessa o arquivo GRAVADO PELO RUST e chega ao mesmo estado
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
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-reinicio-'));
const BASE = 23000 + Math.floor(Math.random() * 200) * 10;
const B = `http://127.0.0.1:${BASE + 1}`, E = `http://127.0.0.1:${BASE + 2}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const procs = [];
const start = (bin, args) => { const p = spawn(bin, args, { stdio: 'ignore' }); procs.push(p); return p; };
process.on('exit', () => { for (const p of procs) { try { p.kill(); } catch {} } });
async function waitFor(fn, what, timeout = 60_000) {
  const t = Date.now();
  for (;;) { try { const v = await fn(); if (v) return v; } catch {} if (Date.now() - t > timeout) throw new Error('tempo esgotado: ' + what); await sleep(300); }
}
const nodeArgs = ['no', '--rede', 'devnet', '--dados', path.join(tmp, 'b'), '--porta', String(BASE), '--rpcporta', String(BASE + 1)];
try {
  let node = start(krevod, nodeArgs);
  await waitFor(() => rpc(B, 'getinfo'), 'nó Rust');
  const k = Keys.random(), params = getParams('devnet');
  const miner = start(process.execPath, [cli, 'minerar', '--endereco', k.sAddress(params), '--rpc', B, '--rede', 'devnet']);
  await waitFor(async () => (await rpc(B, 'getinfo')).blocks > 150, 'blocos minerados no nó Rust', 120_000);
  miner.kill();
  await sleep(1500);

  start(process.execPath, [cli, 'explorador', '--rpc', B, '--porta', String(BASE + 2), '--rede', 'devnet']);
  await waitFor(() => fetch(E + '/api/info').then((r) => r.ok), 'explorador');
  const info = await (await fetch(E + '/api/info')).json();
  const dag = await (await fetch(E + '/api/dag')).json();
  const h = dag.blocks.at(-1).hash;
  const page = await fetch(`${E}/bloco/${h}`);
  const html = await page.text();
  console.log(`explorador sobre o nó Rust: /api/info ok (blocos ${info.blocks ?? info.node?.blocks ?? '?'}), /api/dag com ${dag.blocks.length} blocos, página do bloco ${page.status} (${html.includes(h.slice(0, 16)) ? 'mostra o hash' : 'sem o hash!'})`);

  const before = await rpc(B, 'getinfo');
  node.kill();
  await sleep(1000);
  node = start(krevod, nodeArgs);
  const after = await waitFor(() => rpc(B, 'getinfo'), 'nó Rust reiniciado');
  const same = ['blocks', 'minted', 'shieldedSupply', 'shieldedOutputs'].every((x) => before[x] === after[x]) && before.virtual.selectedParent === after.virtual.selectedParent;
  console.log(`reinício: ${before.blocks} blocos antes, ${after.blocks} depois — ${same ? 'mesmo estado' : 'DIFERENTE'}`);

  const file = path.join(tmp, 'b', 'devnet', 'blocos.dat');
  const js = JSON.parse(execFileSync(process.execPath, [path.join(here, 'replay.mjs'), 'devnet', file], { stdio: ['ignore', 'pipe', 'ignore'] }).toString());
  const ok = js.virtual.selectedParent === after.virtual.selectedParent && js.minted === after.minted && js.chain === js.blocks;
  console.log(`nó JavaScript lendo o arquivo gravado pelo Rust: ${js.blocks} blocos, ${js.disq} desqualificados — ${ok ? 'mesmo estado do nó Rust' : 'DIFERENTE'}`);
  if (!same || !ok) process.exitCode = 1;
} catch (e) { console.error('FALHOU: ' + e.stack); process.exitCode = 1; }
