// MIXED network with real processes: a JavaScript node (A) and a Rust node (B) connected over P2P.
//  • a JavaScript miner on each node (Rust's templates must be valid for JS and vice versa)
//  • CLI wallets using the RUST node's RPC: transparent, shielding and a private payment (FCMP)
//  • a light wallet through a light server pointed at the Rust node
//  • at the end, both nodes must have exactly the same state
//   node rust/krevod/vectors/mixed.mjs <krevod.exe>
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const krevod = process.argv[2];
const cli = path.join(root, 'src', 'cli.js');
const imp = (p) => import(pathToFileURL(path.join(root, 'src', p)).href);
const { getParams, COIN } = await imp('params.js');
const { Wallet } = await imp('wallet/wallet.js');
const { rpc } = await imp('node/rpcclient.js');
const params = getParams('devnet');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-misto-'));
const BASE = 21000 + Math.floor(Math.random() * 200) * 20;
const A = `http://127.0.0.1:${BASE + 1}`, B = `http://127.0.0.1:${BASE + 11}`, L = `http://127.0.0.1:${BASE + 12}`;
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (m) => console.log(m);
const out = (name) => fs.openSync(path.join(tmp, name + '.log'), 'w');
const start = (bin, args, name) => { const p = spawn(bin, args, { stdio: ['ignore', out(name), out(name + '.err')] }); procs.push(p); return p; };
const js = (args, name) => start(process.execPath, [cli, ...args, '--network', 'devnet'], name);
const run = (args) => new Promise((resolve, reject) => {
  const p = spawn(process.execPath, [cli, ...args, '--network', 'devnet', '--rpc', B], { stdio: ['ignore', 'pipe', 'pipe'], cwd: tmp });
  let o = '', e = '';
  p.stdout.on('data', (d) => { o += d; }); p.stderr.on('data', (d) => { e += d; });
  p.on('close', (code) => (code === 0 ? resolve(o) : reject(new Error((e || o).trim()))));
});
const show = (cmd, o) => { say(`$ krevo ${cmd}`); say(o.trim().split('\n').map((l) => '    ' + l).join('\n')); };
const cleanup = () => { for (const p of procs) { try { p.kill(); } catch {} } };
process.on('exit', cleanup);
async function waitFor(fn, what, timeout = 240_000) {
  const t = Date.now();
  for (;;) { try { const v = await fn(); if (v) return v; } catch {} if (Date.now() - t > timeout) throw new Error('timed out: ' + what); await sleep(500); }
}

try {
  js(['node', '--datadir', path.join(tmp, 'a'), '--port', String(BASE), '--rpcport', String(BASE + 1)], 'node-js');
  await waitFor(() => rpc(A, 'getinfo'), 'JavaScript node');
  start(krevod, ['node', '--network', 'devnet', '--datadir', path.join(tmp, 'b'), '--port', String(BASE + 10), '--rpcport', String(BASE + 11), '--peer', `127.0.0.1:${BASE}`], 'node-rust');
  await waitFor(async () => (await rpc(B, 'getinfo')).peers === 1, 'Rust node connected to the JavaScript one');
  const ib = await rpc(B, 'getinfo');
  say(`Rust node up: ${ib.implementation}, genesis ${ib.genesis.slice(0, 16)}… (same as JS: ${ib.genesis === (await rpc(A, 'getinfo')).genesis})`);

  for (const n of ['alice', 'bob']) await run(['wallet', 'create', '--file', `${n}.json`]);
  const alice = Wallet.load(path.join(tmp, 'alice.json'), params, B);
  const bob = Wallet.load(path.join(tmp, 'bob.json'), params, B);
  // miner 1 on the JS node (pays Alice, transparent); miner 2 on the RUST node (pays Bob at a PRIVATE address)
  js(['mine', '--address', alice.tAddress, '--rpc', A], 'miner-js');
  js(['mine', '--address', bob.sAddress, '--rpc', B], 'miner-on-rust-node');
  await waitFor(async () => { await alice.sync(); return alice.balance().transparent > 8n * COIN; }, 'Alice\'s balance (through the Rust node)');
  const ia = await rpc(A, 'getinfo'), ib2 = await rpc(B, 'getinfo');
  say(`blocks: JS ${ia.blocks}, Rust ${ib2.blocks} — blue score ${ia.virtual.blueScore} / ${ib2.virtual.blueScore}`);

  show('wallet send --to <Bob krv…> --amount 1 (Rust node RPC)', await run(['wallet', 'send', '--file', 'alice.json', '--to', bob.tAddress, '--amount', '1']));
  show('wallet send --to <Alice krs…> --amount 5 --from transparent (shield)', await run(['wallet', 'send', '--file', 'alice.json', '--to', alice.sAddress, '--amount', '5', '--from', 'transparent']));
  await waitFor(async () => { await alice.sync(); return alice.balance().shielded >= 5n * COIN; }, 'mature private coin');
  show('wallet send --to <Bob krs…> --amount 2 --from private --memo "via Rust" (FCMP)', await run(['wallet', 'send', '--file', 'alice.json', '--to', bob.sAddress, '--amount', '2', '--from', 'private', '--memo', 'via Rust']));
  await sleep(1500);
  show('wallet history (Bob, through the Rust node)', (await run(['wallet', 'history', '--file', 'bob.json'])).split('\n').filter((l) => l.includes('via Rust') || l.startsWith('RECEIVED')).join('\n'));

  // light server on top of the Rust node + Bob's light wallet
  js(['light-server', '--port', String(BASE + 12), '--rpc', B], 'light-server');
  await waitFor(() => fetch(L + '/v1/info').then((r) => r.ok), 'light server');
  show(`wallet balance --light ${L} (Bob, light server on top of the Rust node)`, await run(['wallet', 'balance', '--file', 'bob.json', '--light', L]));

  // stops everything and compares the two nodes
  for (const p of procs.filter((x) => x.spawnargs.some((a) => a === 'mine'))) p.kill();
  await sleep(3000);
  const [fa, fb] = [await rpc(A, 'getinfo'), await rpc(B, 'getinfo')];
  const keys = ['blocks', 'minted', 'feePool', 'shieldedSupply', 'shieldedOutputs', 'names'];
  const same = keys.every((k) => fa[k] === fb[k]) && fa.virtual.blueScore === fb.virtual.blueScore && fa.virtual.selectedParent === fb.virtual.selectedParent;
  say(`\nfinal state — JS: ${keys.map((k) => `${k}=${fa[k]}`).join(' ')} blueScore=${fa.virtual.blueScore}`);
  say(`final state — Rust: ${keys.map((k) => `${k}=${fb[k]}`).join(' ')} blueScore=${fb.virtual.blueScore}`);
  say(same ? 'BOTH NODES AGREE' : 'DIVERGENCE!');
  const errs = fs.readFileSync(path.join(tmp, 'node-rust.err.log'), 'utf8').split('\n').filter((l) => /invalid|disqualified/.test(l));
  const errsJs = fs.readFileSync(path.join(tmp, 'node-js.log'), 'utf8').split('\n').filter((l) => /invalid|disqualified/.test(l));
  say(`blocks rejected/disqualified — Rust: ${errs.length}, JS: ${errsJs.length}`);
  for (const l of [...errs, ...errsJs].slice(0, 5)) say('   ' + l);
  if (!same) process.exitCode = 1;
} catch (e) {
  console.error('FAILED: ' + e.stack);
  console.error('logs in ' + tmp);
  process.exitCode = 1;
} finally { cleanup(); }
