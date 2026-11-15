// Regenerates the example pages in docs/ from a real local network (simnet, in-process):
//   docs/explorer-example/*.html     block explorer pages (dashboard, block, transactions, private address)
//   docs/pool-example.html           mining pool statistics page
//   docs/payment-request-example.svg printable payment request QR code
//   node scripts/examples.js
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getParams, COIN, formatKRV } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { PowState, hashMeetsTarget } from '../src/consensus/pow.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { startExplorer } from '../src/explorer/server.js';
import { startPool } from '../src/pool/pool.js';
import { buildPaymentURI } from '../src/wallet/request.js';
import { encodeQR, qrToSvg } from '../src/util/qrcode.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const docs = path.join(root, 'docs');
const params = getParams('simnet');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (m) => console.log(`[examples] ${m}`);

async function freePort() {
  return new Promise((ok) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });
}
async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    if (!solve(b)) throw new Error('could not solve the block');
    const r = await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
    if (r.status !== 'accepted') throw new Error('block not accepted: ' + JSON.stringify(r));
  }
}
/** Pool share client (the same protocol the CPU miner speaks). */
function poolClient(port) {
  const sock = net.connect(port, '127.0.0.1');
  let buf = '', job = null, id = 0;
  const pending = new Map();
  sock.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
      if (m.method === 'job') job = m.params;
      else if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    }
  });
  const req = (method, p) => new Promise((res) => { const n = ++id; pending.set(n, res); sock.write(JSON.stringify({ id: n, method, params: p }) + '\n'); });
  const ready = new Promise((r) => sock.on('connect', r));
  return {
    req, ready, close: () => sock.destroy(),
    async share() {
      for (let k = 0; k < 100 && !job; k++) await sleep(10);
      const j = job, pow = new PowState(fromHex(j.prePowHash)), tgt = fromHex(j.target);
      const ts = Math.max(j.timestamp, Date.now());
      for (let n = BigInt(Math.floor(Math.random() * 1e12)); ; n++) {
        if (hashMeetsTarget(pow.hash(ts, n), tgt)) return req('submit', { jobId: j.jobId, nonce: n.toString(), timestamp: ts });
      }
    },
  };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-examples-'));
const [p2p, rpcPort, exPort, poolPort, poolWeb] = await Promise.all([1, 2, 3, 4, 5].map(freePort));
const node = new Node({ params, datadir: dir, p2pPort: p2p, rpcPort, log: () => {}, persist: false });
await node.start();
const url = `http://127.0.0.1:${rpcPort}`;
const ex = await startExplorer({ params, rpcUrl: url, port: exPort });
const page = async (p) => (await fetch(ex.url + p)).text();
try {
  // ---------------------------------------------------------------- explorer
  const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);
  const bob = Wallet.create(path.join(dir, 'bob.json'), params, url);
  const carol = Wallet.create(path.join(dir, 'carol.json'), params, url);
  bob.privateInputs = 'fcmp'; // like every network except simnet: hide among ALL private outputs, not a ring
  await mineVia(url, alice.tAddress, 30);
  await mineVia(url, bob.sAddress, 20);
  await alice.send({ to: carol.tAddress, amount: COIN / 2n, from: 'transparent' });
  const shield = await alice.send({ to: carol.sAddress, amount: 2n * COIN, from: 'transparent', memo: 'invoice 2026-117' });
  await mineVia(url, alice.tAddress, 25);
  const priv = await bob.send({ to: carol.sAddress, amount: COIN, from: 'private', memo: 'thanks!' });
  await mineVia(url, alice.tAddress, 3);
  const info = await rpc(url, 'getinfo');
  const out = path.join(docs, 'explorer-example');
  fs.mkdirSync(out, { recursive: true });
  const write = (name, html) => { fs.writeFileSync(path.join(out, name), html); say(`docs/explorer-example/${name}`); };
  write('dashboard.html', await page('/'));
  write('block.html', await page(`/block/${info.virtual.selectedParent}`));
  write('shielding-tx.html', await page(`/tx/${shield.txid}`));
  write('private-tx.html', await page(`/tx/${priv.txid}`));
  write('private-address.html', await page(`/address/${carol.sAddress}`));

  // ---------------------------------------------------------------- pool
  const poolWallet = Wallet.create(path.join(dir, 'pool.json'), params, url);
  const pool = await startPool({ params, rpcUrl: url, wallet: poolWallet, port: poolPort, webPort: poolWeb, feePct: 1, minPayout: COIN / 100n, payoutEveryMs: 3_600_000, stateFile: path.join(dir, 'pool-state.json') });
  const A = poolClient(poolPort), B = poolClient(poolPort);
  try {
    await Promise.all([A.ready, B.ready]);
    await A.req('login', { address: alice.tAddress, worker: 'rig-a' });
    await B.req('login', { address: bob.sAddress, worker: 'rig-b' });
    for (let round = 0; round < 30; round++) { for (let k = 0; k < 2; k++) await A.share(); await B.share(); }
    for (let k = 0; k < 20; k++) await A.share();
    await sleep(2500);
    await pool.payoutNow();
    for (let k = 0; k < 10; k++) await A.share();
    fs.writeFileSync(path.join(docs, 'pool-example.html'), await (await fetch(`http://127.0.0.1:${poolWeb}/`)).text());
    say('docs/pool-example.html');
  } finally { A.close(); B.close(); await pool.stop(); }

  // ---------------------------------------------------------------- payment request
  const mainnet = getParams('mainnet');
  const shop = Wallet.create(path.join(dir, 'shop.json'), mainnet, url);
  const amount = 25n * COIN / 10n, memo = 'KRV-7F3K9Q', label = 'Sun Bakery';
  const uri = buildPaymentURI(mainnet, { address: shop.newSubaddress(`payment request ${memo}`).address, amount, memo, label });
  fs.writeFileSync(path.join(docs, 'payment-request-example.svg'), qrToSvg(encodeQR(uri, 'M'), { caption: [label, formatKRV(amount), `Order ${memo}`] }));
  say('docs/payment-request-example.svg');
} finally {
  await ex.close();
  await node.stop();
}
process.exit(0);
