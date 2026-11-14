// Rede MISTA com processos reais: um nó JavaScript (A) e um nó Rust (B) conectados por P2P.
//  • um minerador JavaScript em cada nó (modelos do Rust precisam valer para o JS e vice-versa)
//  • carteiras da CLI usando o RPC do nó RUST: transparente, blindagem e pagamento privado (FCMP)
//  • carteira leve via servidor leve apontado para o nó Rust
//  • no fim, os dois nós precisam ter exatamente o mesmo estado
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
const js = (args, name) => start(process.execPath, [cli, ...args, '--rede', 'devnet'], name);
const run = (args) => new Promise((resolve, reject) => {
  const p = spawn(process.execPath, [cli, ...args, '--rede', 'devnet', '--rpc', B], { stdio: ['ignore', 'pipe', 'pipe'], cwd: tmp });
  let o = '', e = '';
  p.stdout.on('data', (d) => { o += d; }); p.stderr.on('data', (d) => { e += d; });
  p.on('close', (code) => (code === 0 ? resolve(o) : reject(new Error((e || o).trim()))));
});
const show = (cmd, o) => { say(`$ krevo ${cmd}`); say(o.trim().split('\n').map((l) => '    ' + l).join('\n')); };
const cleanup = () => { for (const p of procs) { try { p.kill(); } catch {} } };
process.on('exit', cleanup);
async function waitFor(fn, what, timeout = 240_000) {
  const t = Date.now();
  for (;;) { try { const v = await fn(); if (v) return v; } catch {} if (Date.now() - t > timeout) throw new Error('tempo esgotado: ' + what); await sleep(500); }
}

try {
  js(['no', '--dados', path.join(tmp, 'a'), '--porta', String(BASE), '--rpcporta', String(BASE + 1)], 'no-js');
  await waitFor(() => rpc(A, 'getinfo'), 'nó JavaScript');
  start(krevod, ['no', '--rede', 'devnet', '--dados', path.join(tmp, 'b'), '--porta', String(BASE + 10), '--rpcporta', String(BASE + 11), '--par', `127.0.0.1:${BASE}`], 'no-rust');
  await waitFor(async () => (await rpc(B, 'getinfo')).peers === 1, 'nó Rust conectado ao JavaScript');
  const ib = await rpc(B, 'getinfo');
  say(`nó Rust no ar: ${ib.implementation}, gênesis ${ib.genesis.slice(0, 16)}… (mesmo do JS: ${ib.genesis === (await rpc(A, 'getinfo')).genesis})`);

  for (const n of ['alice', 'bob']) await run(['carteira', 'criar', '--arquivo', `${n}.json`]);
  const alice = Wallet.load(path.join(tmp, 'alice.json'), params, B);
  const bob = Wallet.load(path.join(tmp, 'bob.json'), params, B);
  // minerador 1 no nó JS (paga Alice, transparente); minerador 2 no nó RUST (paga Bob em endereço PRIVADO)
  js(['minerar', '--endereco', alice.tAddress, '--rpc', A], 'minerador-js');
  js(['minerar', '--endereco', bob.sAddress, '--rpc', B], 'minerador-no-rust');
  await waitFor(async () => { await alice.sync(); return alice.balance().transparent > 8n * COIN; }, 'saldo da Alice (via nó Rust)');
  const ia = await rpc(A, 'getinfo'), ib2 = await rpc(B, 'getinfo');
  say(`blocos: JS ${ia.blocks}, Rust ${ib2.blocks} — blue score ${ia.virtual.blueScore} / ${ib2.virtual.blueScore}`);

  show('carteira enviar --para <Bob krv…> --valor 1 (RPC do nó Rust)', await run(['carteira', 'enviar', '--arquivo', 'alice.json', '--para', bob.tAddress, '--valor', '1']));
  show('carteira enviar --para <Alice krs…> --valor 5 --de transparente (blindar)', await run(['carteira', 'enviar', '--arquivo', 'alice.json', '--para', alice.sAddress, '--valor', '5', '--de', 'transparente']));
  await waitFor(async () => { await alice.sync(); return alice.balance().shielded >= 5n * COIN; }, 'moeda privada madura');
  show('carteira enviar --para <Bob krs…> --valor 2 --de privado --memo "via Rust" (FCMP)', await run(['carteira', 'enviar', '--arquivo', 'alice.json', '--para', bob.sAddress, '--valor', '2', '--de', 'privado', '--memo', 'via Rust']));
  await sleep(1500);
  show('carteira historico (Bob, via nó Rust)', (await run(['carteira', 'historico', '--arquivo', 'bob.json'])).split('\n').filter((l) => l.includes('via Rust') || l.startsWith('RECEBIDOS')).join('\n'));

  // servidor leve sobre o nó Rust + carteira leve de Bob
  js(['servidor-leve', '--porta', String(BASE + 12), '--rpc', B], 'servidor-leve');
  await waitFor(() => fetch(L + '/v1/info').then((r) => r.ok), 'servidor leve');
  show(`carteira saldo --leve ${L} (Bob, servidor leve sobre o nó Rust)`, await run(['carteira', 'saldo', '--arquivo', 'bob.json', '--leve', L]));

  // para tudo e compara os dois nós
  for (const p of procs.filter((x) => x.spawnargs.some((a) => a === 'minerar'))) p.kill();
  await sleep(3000);
  const [fa, fb] = [await rpc(A, 'getinfo'), await rpc(B, 'getinfo')];
  const keys = ['blocks', 'minted', 'feePool', 'shieldedSupply', 'shieldedOutputs', 'names'];
  const same = keys.every((k) => fa[k] === fb[k]) && fa.virtual.blueScore === fb.virtual.blueScore && fa.virtual.selectedParent === fb.virtual.selectedParent;
  say(`\nestado final — JS: ${keys.map((k) => `${k}=${fa[k]}`).join(' ')} blueScore=${fa.virtual.blueScore}`);
  say(`estado final — Rust: ${keys.map((k) => `${k}=${fb[k]}`).join(' ')} blueScore=${fb.virtual.blueScore}`);
  say(same ? 'OS DOIS NÓS CONCORDAM' : 'DIVERGÊNCIA!');
  const errs = fs.readFileSync(path.join(tmp, 'no-rust.err.log'), 'utf8').split('\n').filter((l) => /inválido|desqualificado/.test(l));
  const errsJs = fs.readFileSync(path.join(tmp, 'no-js.log'), 'utf8').split('\n').filter((l) => /inválido|desqualificado/.test(l));
  say(`blocos recusados/desqualificados — Rust: ${errs.length}, JS: ${errsJs.length}`);
  for (const l of [...errs, ...errsJs].slice(0, 5)) say('   ' + l);
  if (!same) process.exitCode = 1;
} catch (e) {
  console.error('FALHOU: ' + e.stack);
  console.error('logs em ' + tmp);
  process.exitCode = 1;
} finally { cleanup(); }
