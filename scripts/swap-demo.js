// Demonstração completa de uma troca atômica Krevo ⇄ Bitcoin usando SÓ a linha de comando:
// um nó Krevo (devnet) com minerador, o Bitcoin simulado e duas carteiras em processos
// separados, cada uma rodando "krevo troca acompanhar" sozinha.
//   node scripts/swap-demo.js
//
// Alice vende 5 KRV e recebe 0,002 BTC; Bob faz o contrário. Ninguém confia em ninguém.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getParams, COIN, formatKRV } from '../src/params.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { BTC_NETWORKS, p2wpkhAddress } from '../src/btc/address.js';
import { pubFromPriv } from '../src/btc/ecdsa.js';
import { hashToScalar } from '../src/crypto/secp256k1.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'src', 'cli.js');
const params = getParams('devnet');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-troca-'));
const BASE = 18100 + Math.floor(Math.random() * 400) * 10;
const P2P = BASE, RPC = BASE + 1, BTCPORT = BASE + 2;
const rpcUrl = `http://127.0.0.1:${RPC}`, btcApi = `http://127.0.0.1:${BTCPORT}`;
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();
const say = (m) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1).padStart(5)} s] ${m}`);

function start(args, name, onLine) {
  const p = spawn(process.execPath, [cli, ...args, '--rede', 'devnet'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const logf = fs.createWriteStream(path.join(tmp, name + '.log'));
  p.stdout.pipe(logf); p.stderr.pipe(logf);
  if (onLine) {
    let buf = '';
    p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); } });
  }
  procs.push(p);
  return p;
}
function run(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [cli, ...args, '--rede', 'devnet', '--rpc', rpcUrl], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(err || out))));
  });
}
const cleanup = () => { for (const p of procs) { try { p.kill(); } catch {} } };
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(1); });

async function waitFor(fn, what, timeout = 180_000) {
  const t = Date.now();
  for (;;) {
    try { const v = await fn(); if (v) return v; } catch {}
    if (Date.now() - t > timeout) throw new Error('tempo esgotado: ' + what);
    await sleep(300);
  }
}

async function main() {
  say(`diretório temporário: ${tmp}`);
  start(['no', '--dados', path.join(tmp, 'no'), '--porta', String(P2P), '--rpcporta', String(RPC)], 'no');
  start(['btc-simulado', '--porta', String(BTCPORT), '--bloco', '2s'], 'btc');
  await waitFor(() => rpc(rpcUrl, 'getinfo'), 'nó Krevo');
  await waitFor(async () => (await fetch(btcApi + '/blocks/tip/height')).ok, 'Bitcoin simulado');
  say('nó Krevo (devnet) e Bitcoin simulado (regtest, 1 bloco a cada 2 s) no ar');

  const fa = path.join(tmp, 'alice.json'), fb = path.join(tmp, 'bob.json');
  await run(['carteira', 'criar', '--arquivo', fa]);
  await run(['carteira', 'criar', '--arquivo', fb]);
  const alice = Wallet.load(fa, params, rpcUrl), bob = Wallet.load(fb, params, rpcUrl);
  // endereços Bitcoin "das carteiras Bitcoin" de cada um (no mundo real: Electrum, Sparrow, celular…)
  const btcAddr = (who) => p2wpkhAddress(BTC_NETWORKS.regtest, pubFromPriv(hashToScalar('demo/btc', who, String(t0))));
  const aliceBtc = btcAddr('alice'), bobBtc = btcAddr('bob');

  start(['minerar', '--endereco', alice.tAddress, '--rpc', rpcUrl], 'minerador');
  await waitFor(async () => { await alice.sync(); return alice.balance().transparent > 8n * COIN; }, 'saldo de Alice');
  say(`Alice tem KRV para vender; Bob tem BTC (endereço ${bobBtc.slice(0, 18)}…)`);

  // 1) oferta → 2) aceite → 3) confirmação (só troca de códigos, nenhum dinheiro se move)
  const offerOut = await run(['troca', 'criar', '--arquivo', fa, '--vender', 'krv', '--krv', '5', '--btc', '0,002',
    '--endereco-btc', aliceBtc, '--prazo', '2h', '--btc-api', btcApi]);
  const offerCode = offerOut.match(/krxdev1[0-9a-z]+/)[0];
  say(`Alice criou a oferta: ${offerCode.slice(0, 30)}… (${offerCode.length} caracteres)`);
  const accOut = await run(['troca', 'aceitar', '--arquivo', fb, '--codigo', offerCode, '--endereco-btc', bobBtc, '--btc-api', btcApi]);
  const accCode = accOut.match(/krxdev1[0-9a-z]+/)[0];
  say('Bob aceitou e devolveu o código de aceite');
  await run(['troca', 'confirmar', '--arquivo', fa, '--codigo', accCode]);
  say('Alice registrou o aceite. Agora cada carteira conduz a troca sozinha:');

  // 4) cada um roda "troca acompanhar"; quando a carteira de Bob pedir, ele paga em BTC
  let paid = false, payTo = null;
  const done = { alice: false, bob: false };
  const watcher = (who) => (line) => {
    if (!line.trim() || line.includes('\x1b[') || line.startsWith('bitcoin:')) return; // o QR code fica só no log
    say(`  ${who.padEnd(5)} │ ${line.replace(/^\[[^\]]+\] /, '')}`);
    const m = line.match(/pague exatamente .* para (bcrt1[0-9a-z]+)/);
    if (m) payTo = m[1];
  };
  const pa = start(['troca', 'acompanhar', '--arquivo', fa, '--intervalo', '1s', '--rpc', rpcUrl], 'troca-alice', watcher('Alice'));
  const pb = start(['troca', 'acompanhar', '--arquivo', fb, '--intervalo', '1s', '--rpc', rpcUrl], 'troca-bob', watcher('Bob'));
  pa.on('close', () => { done.alice = true; });
  pb.on('close', () => { done.bob = true; });
  await waitFor(() => payTo, 'pedido de pagamento em BTC');
  if (!paid) {
    await run(['btc-simulado', 'pagar', '--endereco', payTo, '--valor', '0,002', '--btc-api', btcApi]);
    paid = true;
    say('  (Bob pagou 0,002 BTC ao contrato pela carteira Bitcoin dele)');
  }
  await waitFor(() => done.alice && done.bob, 'fim da troca', 240_000);

  // 5) resultado
  const aliceBtcBal = (await run(['btc-simulado', 'saldo', '--endereco', aliceBtc, '--btc-api', btcApi])).trim();
  await bob.sync();
  const b = bob.balance();
  say(`RESULTADO — Alice recebeu ${aliceBtcBal} no Bitcoin; Bob recebeu ${formatKRV(b.transparent + b.transparentPending)} na Krevo (valores já sem as taxas de rede)`);
  say(`tempo total da troca (após o aceite): ${((Date.now() - t0) / 1000).toFixed(0)} s de demonstração`);
}

main().then(() => { cleanup(); process.exit(0); }).catch((e) => { console.error('FALHOU: ' + e.stack); cleanup(); process.exit(1); });
