// Full demo of a Krevo ⇄ Bitcoin atomic swap using ONLY the command line:
// a Krevo node (devnet) with a miner, the simulated Bitcoin and two wallets in separate
// processes, each one running "krevo swap watch" on its own.
//   node scripts/swap-demo.js
//
// Alice sells 5 KRV and receives 0.002 BTC; Bob does the opposite. Nobody trusts anybody.
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
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-swap-'));
const BASE = 18100 + Math.floor(Math.random() * 400) * 10;
const P2P = BASE, RPC = BASE + 1, BTCPORT = BASE + 2;
const rpcUrl = `http://127.0.0.1:${RPC}`, btcApi = `http://127.0.0.1:${BTCPORT}`;
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();
const say = (m) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1).padStart(5)} s] ${m}`);

function start(args, name, onLine) {
  const p = spawn(process.execPath, [cli, ...args, '--network', 'devnet'], { stdio: ['ignore', 'pipe', 'pipe'] });
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
    const p = spawn(process.execPath, [cli, ...args, '--network', 'devnet', '--rpc', rpcUrl], { stdio: ['ignore', 'pipe', 'pipe'] });
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
    if (Date.now() - t > timeout) throw new Error('timed out: ' + what);
    await sleep(300);
  }
}

async function main() {
  say(`temporary directory: ${tmp}`);
  start(['node', '--datadir', path.join(tmp, 'node'), '--port', String(P2P), '--rpcport', String(RPC)], 'node');
  start(['btc-sim', '--port', String(BTCPORT), '--block', '2s'], 'btc');
  await waitFor(() => rpc(rpcUrl, 'getinfo'), 'Krevo node');
  await waitFor(async () => (await fetch(btcApi + '/blocks/tip/height')).ok, 'simulated Bitcoin');
  say('Krevo node (devnet) and simulated Bitcoin (regtest, 1 block every 2 s) up');

  const fa = path.join(tmp, 'alice.json'), fb = path.join(tmp, 'bob.json');
  await run(['wallet', 'create', '--file', fa]);
  await run(['wallet', 'create', '--file', fb]);
  const alice = Wallet.load(fa, params, rpcUrl), bob = Wallet.load(fb, params, rpcUrl);
  // each one's address in their "Bitcoin wallet" (in the real world: Electrum, Sparrow, a phone…)
  const btcAddr = (who) => p2wpkhAddress(BTC_NETWORKS.regtest, pubFromPriv(hashToScalar('demo/btc', who, String(t0))));
  const aliceBtc = btcAddr('alice'), bobBtc = btcAddr('bob');

  start(['mine', '--address', alice.tAddress, '--rpc', rpcUrl], 'miner');
  await waitFor(async () => { await alice.sync(); return alice.balance().transparent > 8n * COIN; }, 'Alice\'s balance');
  say(`Alice has KRV to sell; Bob has BTC (address ${bobBtc.slice(0, 18)}…)`);

  // 1) offer → 2) acceptance → 3) confirmation (only codes are exchanged, no money moves)
  const offerOut = await run(['swap', 'create', '--file', fa, '--sell', 'krv', '--krv', '5', '--btc', '0.002',
    '--btc-address', aliceBtc, '--deadline', '2h', '--btc-api', btcApi]);
  const offerCode = offerOut.match(/krxdev1[0-9a-z]+/)[0];
  say(`Alice created the offer: ${offerCode.slice(0, 30)}… (${offerCode.length} characters)`);
  const accOut = await run(['swap', 'accept', '--file', fb, '--code', offerCode, '--btc-address', bobBtc, '--btc-api', btcApi]);
  const accCode = accOut.match(/krxdev1[0-9a-z]+/)[0];
  say('Bob accepted and sent back the acceptance code');
  await run(['swap', 'confirm', '--file', fa, '--code', accCode]);
  say('Alice recorded the acceptance. Now each wallet runs the swap on its own:');

  // 4) each one runs "swap watch"; when Bob's wallet asks, he pays in BTC
  let paid = false, payTo = null;
  const done = { alice: false, bob: false };
  const watcher = (who) => (line) => {
    if (!line.trim() || line.includes('\x1b[') || line.startsWith('bitcoin:')) return; // the QR code only goes to the log
    say(`  ${who.padEnd(5)} │ ${line.replace(/^\[[^\]]+\] /, '')}`);
    const m = line.match(/pay exactly .* to (bcrt1[0-9a-z]+)/);
    if (m) payTo = m[1];
  };
  const pa = start(['swap', 'watch', '--file', fa, '--interval', '1s', '--rpc', rpcUrl], 'swap-alice', watcher('Alice'));
  const pb = start(['swap', 'watch', '--file', fb, '--interval', '1s', '--rpc', rpcUrl], 'swap-bob', watcher('Bob'));
  pa.on('close', () => { done.alice = true; });
  pb.on('close', () => { done.bob = true; });
  await waitFor(() => payTo, 'request for the BTC payment');
  if (!paid) {
    await run(['btc-sim', 'pay', '--address', payTo, '--amount', '0.002', '--btc-api', btcApi]);
    paid = true;
    say('  (Bob paid 0.002 BTC to the contract from his Bitcoin wallet)');
  }
  await waitFor(() => done.alice && done.bob, 'end of the swap', 240_000);

  // 5) result
  const aliceBtcBal = (await run(['btc-sim', 'balance', '--address', aliceBtc, '--btc-api', btcApi])).trim();
  await bob.sync();
  const b = bob.balance();
  say(`RESULT — Alice received ${aliceBtcBal} on Bitcoin; Bob received ${formatKRV(b.transparent + b.transparentPending)} on Krevo (amounts already net of network fees)`);
  say(`total swap time (after the acceptance): ${((Date.now() - t0) / 1000).toFixed(0)} s of demo`);
}

main().then(() => { cleanup(); process.exit(0); }).catch((e) => { console.error('FAILED: ' + e.stack); cleanup(); process.exit(1); });
