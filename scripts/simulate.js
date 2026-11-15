// Global network simulation (discrete events) using the project's real GHOSTDAG.
//
// 40 nodes on 6 continents, approximate real latencies between regions, each node with
// 8 peers; Poisson mining at 10 blocks/s; transactions sent from random nodes.
// Measures: block propagation, red block rate, DAG width and the time
// until a transaction is accepted by the DAG from the point of view of every node in the world.
//
//   node scripts/simulate.js [--seconds 300] [--bps 10] [--nodes 40]

import { DagStore, Ghostdag, genesisGhostdag } from '../src/consensus/ghostdag.js';
import { computeGhostdagK } from '../src/params.js';

const arg = (k, d, legacy) => { const i = Math.max(process.argv.indexOf('--' + k), legacy ? process.argv.indexOf('--' + legacy) : -1); return i > 0 ? Number(process.argv[i + 1]) : d; };
const SECONDS = arg('seconds', 300, 'segundos'), BPS = arg('bps', 10), NODES = arg('nodes', 40, 'nos'), PEERS = 8;
const K = computeGhostdagK(BPS, 5);
let seed = 42;
const rand = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
const expo = (rate) => -Math.log(1 - rand()) / rate;

// one-way latency (ms) between regions — typical backbone values
const REG = ['South America', 'North America', 'Europe', 'Asia', 'Oceania', 'Africa'];
const LAT = [
  [15, 70, 100, 160, 160, 170],
  [70, 25, 45, 80, 80, 120],
  [100, 45, 15, 90, 140, 80],
  [160, 80, 90, 30, 60, 140],
  [160, 80, 140, 60, 15, 200],
  [170, 120, 80, 140, 200, 40],
];
const BLOCK_HOP_MS = 12; // validation + transmission of a block per hop
const TX_HOP_MS = 3;

const nodes = Array.from({ length: NODES }, (_, i) => ({
  id: i, region: i % REG.length, peers: new Set(), has: new Set(), tips: new Set(), txSeen: new Map(), pendingBlocks: [], incl: new Set(),
}));
for (const n of nodes) {
  while (n.peers.size < PEERS / 2) {
    const m = nodes[Math.floor(rand() * NODES)];
    if (m !== n) { n.peers.add(m); m.peers.add(n); }
  }
}
const lat = (a, b) => LAT[a.region][b.region] * (0.8 + 0.4 * rand());

// event queue (binary heap)
const heap = [];
const push = (t, f) => { heap.push({ t, f }); let i = heap.length - 1; while (i) { const p = (i - 1) >> 1; if (heap[p].t <= heap[i].t) break; [heap[p], heap[i]] = [heap[i], heap[p]]; i = p; } };
const pop = () => { const top = heap[0], last = heap.pop(); if (heap.length) { heap[0] = last; let i = 0; for (;;) { const l = 2 * i + 1, r = l + 1; let m = i; if (l < heap.length && heap[l].t < heap[m].t) m = l; if (r < heap.length && heap[r].t < heap[m].t) m = r; if (m === i) break; [heap[m], heap[i]] = [heap[i], heap[m]]; i = m; } } return top; };

const store = new DagStore();
const gdag = new Ghostdag(store, K);
const g = genesisGhostdag(); g.mergesetAsc = [];
store.add('G', [], g, 1n);
const blocks = new Map([['G', { parents: [], txs: [], created: 0, miner: -1 }]]);
for (const n of nodes) { n.has.add('G'); n.tips.add('G'); }

const firstSeen = new Map(); // block → [time at which each node received it]
const txs = [];              // { created, from, acceptedAt: Map(node → t) }
let blockSeq = 0;

function scheduleBlock(m, h, at, from) { push(at, () => receiveBlockAt(m, h, at, from)); }
function receiveBlockAt(n, h, t, from) {
  if (n.has.has(h)) return;
  const b = blocks.get(h);
  if (!b.parents.every((p) => n.has.has(p))) { n.pendingBlocks.push(h); return; }
  n.has.add(h);
  for (const p of b.parents) n.tips.delete(p);
  n.tips.add(h);
  firstSeen.get(h)[n.id] = t;
  for (const tx of b.txs) { n.incl.add(tx); if (!txs[tx].acceptedAt.has(n.id)) txs[tx].acceptedAt.set(n.id, t); }
  for (const m of n.peers) if (m !== from) scheduleBlock(m, h, t + lat(n, m) + BLOCK_HOP_MS, n);
  const pend = n.pendingBlocks; n.pendingBlocks = [];
  for (const o of pend) receiveBlockAt(n, o, t, null);
}
function receiveTxAt(n, id, t, from) {
  if (n.txSeen.has(id)) return;
  n.txSeen.set(id, t);
  for (const m of n.peers) if (m !== from) { const at = t + lat(n, m) + TX_HOP_MS; push(at, () => receiveTxAt(m, id, at, n)); }
}

function mine(t) {
  const n = nodes[Math.floor(rand() * NODES)];
  const tips = [...n.tips].sort((a, b) => -gdag.cmp(a, b)).slice(0, 16);
  const h = 'b' + (++blockSeq);
  const inc = [];
  for (const [id] of n.txSeen) if (!n.incl.has(id) && inc.length < 300) inc.push(id);
  const gd = gdag.run(tips);
  store.add(h, tips, gd, 1n);
  blocks.set(h, { parents: tips, txs: inc, created: t, miner: n.id });
  firstSeen.set(h, new Array(NODES).fill(null));
  receiveBlockAt(n, h, t, null);
}

// schedule mining and transactions
const END = SECONDS * 1000;
for (let t = expo(BPS / 1000); t < END; t += expo(BPS / 1000)) { const tt = t; push(tt, () => mine(tt)); }
for (let t = 5000; t < END - 10_000; t += expo(5 / 1000)) {
  const tt = t, id = txs.length, from = nodes[Math.floor(rand() * NODES)];
  txs.push({ created: tt, from: from.id, acceptedAt: new Map() });
  push(tt, () => receiveTxAt(from, id, tt, null));
}
while (heap.length) { const e = pop(); e.f(); }

// ------------------------------------------------------------- metrics
const q = (arr, p) => { const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const prop90 = [], propAll = [];
for (const [h, seen] of firstSeen) {
  const c = blocks.get(h).created, d = seen.filter((x) => x !== null).map((x) => x - c);
  if (d.length === NODES) { prop90.push(q(d, 0.9)); propAll.push(Math.max(...d)); }
}
// final color: walk the selected chain of the global "virtual"
const allTips = [...store.gd.keys()].filter((h) => store.children.get(h).length === 0);
const vgd = gdag.run(allTips.sort((a, b) => -gdag.cmp(a, b)).slice(0, 64));
let reds = vgd.mergesetReds.length, cur = vgd.selectedParent, chainLen = 0;
while (cur) { const d = store.gd.get(cur); reds += d.mergesetReds.length; cur = d.selectedParent; chainLen++; }
const mergesets = [...store.gd.values()].filter((d) => d.selectedParent).map((d) => d.mergesetBlues.length + d.mergesetReds.length);
const lats = [];
let unconfirmed = 0;
for (const tx of txs) for (const n of nodes) { const a = tx.acceptedAt.get(n.id); if (a === undefined) unconfirmed++; else lats.push(a - tx.created); }

const ms = (x) => `${Math.round(x)} ms`;
console.log(`
Simulation: ${NODES} nodes on ${REG.length} continents, ${BPS} blocks/s, k=${K}, ${SECONDS} simulated seconds`);
console.log(`blocks: ${blockSeq} | red: ${reds} (${(100 * reds / blockSeq).toFixed(2)}%) | average mergeset: ${(mergesets.reduce((a, b) => a + b, 0) / mergesets.length).toFixed(2)} | selected chain: ${chainLen}`);
console.log(`block propagation to 90% of nodes: median ${ms(q(prop90, 0.5))}, p95 ${ms(q(prop90, 0.95))} | to 100%: median ${ms(q(propAll, 0.5))}`);
console.log(`transactions: ${txs.length} | (tx, observer node) pairs: ${lats.length} | not accepted: ${unconfirmed}`);
console.log(`TIME UNTIL THE TX IS ACCEPTED BY THE DAG (sent from anywhere → seen anywhere):`);
console.log(`   median ${ms(q(lats, 0.5))} | p75 ${ms(q(lats, 0.75))} | p90 ${ms(q(lats, 0.9))} | p99 ${ms(q(lats, 0.99))}`);
console.log(`   share accepted in under 1 s: ${(100 * lats.filter((x) => x < 1000).length / lats.length).toFixed(1)}%`);
export const result = { blocks: blockSeq, reds, prop90: q(prop90, 0.5), latMedian: q(lats, 0.5), lat90: q(lats, 0.9), lat99: q(lats, 0.99) };
