// Demonstração local da carteira web: sobe um nó devnet com mineradores, o servidor leve,
// o app web e uma "torneira" de KRV de teste.
//   node scripts/web-demo.js
// Depois abra http://127.0.0.1:8091 (app) — e, para receber KRV de teste:
//   http://127.0.0.1:8092/?para=SEU_ENDEREÇO        (manda 10 KRV)
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getParams, COIN, formatKRV } from '../src/params.js';
import { Wallet } from '../src/wallet/wallet.js';
import { Keys } from '../src/wallet/keys.js';
import { rpc } from '../src/node/rpcclient.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'src', 'cli.js');
const params = getParams('devnet');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-web-demo-'));
const RPC = 26311, P2P = 26310, LIGHT = 8090, WEB = 8091, FAUCET = 8092;
const rpcUrl = `http://127.0.0.1:${RPC}`;
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (m) => console.log(`[demo] ${m}`);
const start = (args, name) => {
  const p = spawn(process.execPath, [cli, ...args, '--rede', 'devnet'], { stdio: ['ignore', fs.openSync(path.join(tmp, `${name}.log`), 'w'), 'inherit'] });
  procs.push(p);
};
const cleanup = () => { for (const p of procs) { try { p.kill(); } catch {} } };
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('SIGTERM', () => { cleanup(); process.exit(0); });

start(['no', '--dados', path.join(tmp, 'no'), '--porta', String(P2P), '--rpcporta', String(RPC)], 'no');
for (let i = 0; ; i++) { try { await rpc(rpcUrl, 'getinfo'); break; } catch { if (i > 100) throw new Error('nó não subiu'); await sleep(200); } }
start(['servidor-leve', '--porta', String(LIGHT), '--rpc', rpcUrl], 'servidor-leve');
start(['carteira-web', '--porta', String(WEB)], 'carteira-web');
const faucet = Wallet.create(path.join(tmp, 'torneira.json'), params, rpcUrl);
start(['minerar', '--endereco', faucet.tAddress, '--rpc', rpcUrl], 'minerador');
start(['minerar', '--endereco', Keys.random().sAddress(params), '--rpc', rpcUrl], 'minerador-privado'); // conjunto de anonimato
log(`nó devnet, mineradores, servidor leve (:${LIGHT}) e app (:${WEB}) no ar — arquivos em ${tmp}`);

let queue = Promise.resolve();
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const to = url.searchParams.get('para');
  res.setHeader('access-control-allow-origin', '*');
  if (!to) { res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }); return res.end('torneira Krevo devnet: use /?para=ENDEREÇO (manda 10 KRV)'); }
  queue = queue.then(async () => {
    try {
      const r = await faucet.send({ to, amount: 10n * COIN, from: 'transparente' });
      log(`torneira: 10 KRV → ${to.slice(0, 20)}… (tx ${r.txid.slice(0, 12)}…)`);
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ ok: true, txid: r.txid }));
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: e.message }));
    }
  });
}).listen(FAUCET, '127.0.0.1');

for (;;) {
  await sleep(5000);
  try { await faucet.sync(); } catch { continue; }
  const b = faucet.balance();
  if (!globalThis.__ready && b.transparent >= 20n * COIN) { globalThis.__ready = true; log(`torneira pronta em http://127.0.0.1:${FAUCET}/?para=ENDEREÇO (saldo ${formatKRV(b.transparent)})`); }
}
