// Local demo network: 3 nodes, 2 miners, 3 wallets.
// Runs every kind of transaction and measures the real confirmation time.
//   node scripts/devnet.js
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getParams, formatKRV, COIN } from '../src/params.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { nameCommit, nameReveal, nameRevealWait } from '../src/wallet/names.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'src', 'cli.js');
const params = getParams('devnet');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-devnet-'));
const BASE = 17100 + Math.floor(Math.random() * 500) * 10;
const nodes = [0, 1, 2].map((i) => ({ p2p: BASE + i * 3, rpc: BASE + i * 3 + 1, url: `http://127.0.0.1:${BASE + i * 3 + 1}` }));
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();
const say = (m) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1).padStart(5)} s] ${m}`);

function start(args, name) {
  const p = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const logf = fs.createWriteStream(path.join(tmp, name + '.log'));
  p.stdout.pipe(logf); p.stderr.pipe(logf);
  procs.push(p);
  return p;
}
function cleanup() { for (const p of procs) { try { p.kill(); } catch {} } }
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(1); });

async function waitFor(fn, what, timeout = 120_000) {
  const t = Date.now();
  for (;;) {
    try { const v = await fn(); if (v) return v; } catch {}
    if (Date.now() - t > timeout) throw new Error('timed out: ' + what);
    await sleep(250);
  }
}

async function main() {
  say(`temporary directory: ${tmp}`);
  // 1) chained nodes: n0 ← n1 ← n2 (n2 only talks to n1: messages need 2 hops)
  nodes.forEach((n, i) => {
    const peers = i > 0 ? ['--peer', `127.0.0.1:${nodes[i - 1].p2p}`] : [];
    start(['node', '--network', 'devnet', '--datadir', path.join(tmp, `n${i}`), '--port', String(n.p2p), '--rpcport', String(n.rpc), ...peers], `node${i}`);
  });
  for (const n of nodes) await waitFor(() => rpc(n.url, 'getinfo'), 'node start');
  say('3 nodes up');

  const alice = Wallet.create(path.join(tmp, 'alice.json'), params, nodes[0].url);
  const bob = Wallet.create(path.join(tmp, 'bob.json'), params, nodes[1].url);
  const carol = Wallet.create(path.join(tmp, 'carol.json'), params, nodes[2].url);

  // 2) miners: Alice mines to a transparent address (node 0); Bob to a PRIVATE address (node 1)
  start(['mine', '--network', 'devnet', '--address', alice.tAddress, '--rpc', nodes[0].url], 'miner-alice');
  start(['mine', '--network', 'devnet', '--address', bob.sAddress, '--rpc', nodes[1].url], 'miner-bob');
  say('2 miners running (Alice → transparent, Bob → private)');

  await waitFor(async () => { await alice.sync(); return alice.balance().transparent > 20n * COIN; }, 'Alice\'s mature balance');
  await waitFor(async () => { await bob.sync(); return bob.balance().shielded > 5n * COIN; }, 'Bob\'s private balance');
  say(`Alice: ${formatKRV(alice.balance().transparent)} transparent | Bob: ${formatKRV(bob.balance().shielded)} private`);

  const results = [];
  async function scenario(label, wallet, to, amount, from, watcher) {
    const tSend = Date.now();
    const r = await wallet.send({ to, amount, from });
    const tSubmitted = Date.now();
    const ms = await watcher.waitAccepted(r.txid);
    const row = { label, build: tSubmitted - tSend, confirm: Date.now() - tSubmitted, fee: r.fee, size: r.size };
    results.push(row);
    say(`${label}: confirmed in ${row.confirm} ms (seen by the recipient's node) | build ${row.build} ms | fee ${formatKRV(r.fee)} | ${r.size} bytes`);
    return ms;
  }

  // 3) transactions
  await scenario('transparent → transparent', alice, carol.tAddress, 5n * COIN, 'transparent', carol);
  await scenario('transparent → private (shield)', alice, carol.sAddress, 3n * COIN, 'transparent', carol);
  await scenario('private → private', bob, carol.sAddress, 2n * COIN, 'private', carol);
  await waitFor(async () => { await carol.sync(); return carol.data.sOwned.filter((o) => !o.spent && o.daa > 0).length >= 2; }, 'Carol seeing private outputs');
  await sleep(3000); // ring member maturity (20 blocks)
  await scenario('private → transparent (unshield)', carol, alice.tAddress, 4n * COIN, 'private', alice);

  // several transparent payments in a row, for statistics
  const lat = [];
  for (let i = 0; i < 8; i++) {
    const r = await alice.send({ to: carol.tAddress, amount: COIN / 10n, from: 'transparent' });
    const ts = Date.now();
    await carol.waitAccepted(r.txid);
    lat.push(Date.now() - ts);
    await sleep(300);
  }
  lat.sort((a, b) => a - b);
  say(`8 transparent payments: median ${lat[4]} ms, minimum ${lat[0]} ms, maximum ${lat[7]} ms`);

  // quantum protection: Carol migrates krv → krq and pays from the krq (Schnorr + ML-DSA)
  const mig = await carol.migrateQuantum();
  for (const t of mig.txs) await carol.waitAccepted(t.txid);
  say(`Carol migrated ${formatKRV(mig.moved)} to ${carol.qAddress.slice(0, 22)}… in ${mig.txs.length} transaction(s), fee ${formatKRV(mig.txs.reduce((a, t) => a + t.fee, 0n))}`);
  await scenario('quantum-safe krq → transparent (Schnorr + ML-DSA)', carol, alice.tAddress, COIN / 2n, 'transparent', alice);

  // human-readable names: Carol (owner with a quantum-safe address) registers @carol-shop; Alice pays by name
  const nc = await nameCommit(carol, '@carol-shop', { target: 'private' });
  await carol.waitAccepted(nc.txid);
  await waitFor(async () => (await nameRevealWait(carol, 'carol-shop')) === 0, 'name commitment wait');
  const nr = await nameReveal(carol, 'carol-shop');
  await carol.waitAccepted(nr.txid);
  say(`Carol registered @carol-shop (commitment + reveal, fee ${formatKRV(nr.nameFee)} to the Security Fund)`);
  await scenario('payment to @carol-shop (name → private address)', alice, '@carol-shop', COIN / 2n, 'transparent', carol);
  await sleep(1000);
  const views = await Promise.all(nodes.map((n) => rpc(n.url, 'resolvename', { name: 'carol-shop' })));
  if (new Set(views.map((v) => `${v.status}|${v.outpoint}|${v.target}`)).size !== 1) throw new Error('the nodes disagree about @carol-shop');
  say(`all 3 nodes resolve @carol-shop the same way: ${views[0].status}, owner ${views[0].owner.slice(0, 16)}… (quantum-safe), points to ${views[0].target.slice(0, 16)}…`);

  // 4) balances and consistency between nodes
  await sleep(1500);
  for (const w of [alice, bob, carol]) await w.sync();
  const b = (w) => w.balance();
  say(`balances — Alice: ${formatKRV(b(alice).transparent + b(alice).transparentImmature)} transp. | Bob: ${formatKRV(b(bob).shielded)} priv. | Carol: ${formatKRV(b(carol).transparent)} transp. + ${formatKRV(b(carol).shielded)} priv.`);
  const infos = await Promise.all(nodes.map((n) => rpc(n.url, 'getinfo')));
  infos.forEach((inf, i) => say(`node ${i}: blocks ${inf.blocks} | blue score ${inf.virtual.blueScore} | ${inf.blocksPerSecond} blocks/s | red ${inf.redBlocks} | minted ${formatKRV(BigInt(inf.minted))} | fund ${formatKRV(BigInt(inf.feePool))} | private pool ${formatKRV(BigInt(inf.shieldedSupply))}`));

  // Carol's view key allows auditing without being able to spend
  say(`Carol's view key: ${carol.keys.viewKey(params).slice(0, 30)}…`);
  fs.writeFileSync(path.join(root, 'devnet-result.json'), JSON.stringify({ results, transparentLatencies: lat, nodes: infos },
    (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  say('result saved to devnet-result.json');
}

main().then(() => { cleanup(); process.exit(0); }).catch((e) => { console.error('FAILED: ' + e.stack); cleanup(); process.exit(1); });
