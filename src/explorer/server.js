// Krevo block explorer: a dependency-free web server that queries a node over RPC.
//
//   /                 live dashboard: statistics, real-time DAG, latest blocks and transactions
//   /block/<hash>     block details (parents, children, blue/red mergeset, rewards)
//   /tx/<txid>        transaction details (private parts show as hidden)
//   /address/<addr>   balance and history of transparent / multisig addresses
//   /name/<name>      where an @name points, owner and expiry
//   /search?q=…       block hash, txid, address or @name
//   /api/…            the same data as JSON
// (Links from older versions — /bloco, /endereco, /nome, /busca, /api/painel — still work.)
// Everything that comes from the network is escaped before going into the HTML.

import http from 'node:http';
import { rpc } from '../node/rpcclient.js';
import { Transaction } from '../consensus/tx.js';
import { parseWitnessPath } from '../consensus/policy.js';
import { isPqWitness } from '../consensus/pqlock.js';
import { parseCommitWitness, isValidName, normalizeName } from '../consensus/names.js';
import { decodeAddress, encodeAddress, describeLock } from '../address.js';
import { formatKRV, MAX_SUPPLY } from '../params.js';
import { fromHex, toHex } from '../util/bytes.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (h, a = 10, b = 6) => (h && h.length > a + b + 1 ? `${h.slice(0, a)}…${h.slice(-b)}` : h ?? '');
const isHash = (s) => /^[0-9a-f]{64}$/.test(s);
const json = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v));

function ago(ms) {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
function compact(n) {
  n = Number(n);
  for (const [v, u] of [[1e12, ' T'], [1e9, ' G'], [1e6, ' M'], [1e3, ' k']]) if (n >= v) return (n / v).toFixed(1) + u;
  return String(Math.round(n));
}

// ------------------------------------------------------------------ style
export const CSS = `
:root{--bg:#f5f7fb;--panel:#fff;--text:#131826;--muted:#5f6b82;--line:#e2e6ef;--accent:#0f9d84;--blue:#3d6ff2;--red:#e0444f;--chip:#edf1f8;--edge:#c3cad8}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f19;--panel:#131a29;--text:#e7ebf4;--muted:#8d97ad;--line:#232c41;--accent:#2fd3ae;--blue:#5f8dff;--red:#ff6470;--chip:#1b2437;--edge:#3a4560}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;word-break:break-all}
header{background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.bar{max-width:1200px;margin:0 auto;padding:10px 16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.brand{display:flex;gap:8px;align-items:center;font-weight:700;font-size:18px;color:var(--text)}.brand:hover{text-decoration:none}
.net{font-size:12px;background:var(--chip);color:var(--muted);border-radius:99px;padding:2px 9px;font-weight:600}
form.search{flex:1;min-width:220px;display:flex}form.search input{flex:1;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);font-size:14px}
main{max-width:1200px;margin:0 auto;padding:18px 16px 40px}
h1{font-size:22px;margin:4px 0 14px}h2{font-size:16px;margin:0 0 10px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:10px;margin-bottom:16px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 12px}.stat b{display:block;font-size:20px}.stat span{font-size:12px;color:var(--muted)}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:860px){.cols{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px}
.kv td:first-child{color:var(--muted);width:210px;white-space:nowrap}@media(max-width:600px){.kv td:first-child{width:auto;white-space:normal}}
.chip{display:inline-block;font-size:12px;border-radius:99px;padding:1px 8px;background:var(--chip);color:var(--muted);white-space:nowrap}
.chip.blue{color:var(--blue)}.chip.red{color:var(--red)}.chip.chain{color:var(--accent)}.chip.priv{color:#9b6bff}
.muted{color:var(--muted)}.right{text-align:right}.amt{white-space:nowrap;font-variant-numeric:tabular-nums}
.dagwrap{overflow-x:auto;border-radius:10px;background:var(--bg);border:1px solid var(--line)}
.dag .e{stroke:var(--edge);stroke-width:1}.dag .e.sp{stroke:var(--accent);stroke-width:2.2}
.dag .n{fill:var(--blue)}.dag .n.red{fill:var(--red)}.dag .n.chain{fill:var(--accent)}.dag .n.tip{stroke:var(--text);stroke-width:1.5;stroke-dasharray:3 2}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:8px}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.live{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}.live:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--accent);animation:p 1.2s infinite}.live.off:before{background:var(--red);animation:none}
@keyframes p{50%{opacity:.25}}
.note{background:var(--chip);border-radius:10px;padding:10px 12px;font-size:14px}
.big{font-size:28px;font-weight:700}
footer{max-width:1200px;margin:0 auto;padding:0 16px 30px;color:var(--muted);font-size:12px}
`;

const LOGO = '<svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l8.7 5v10L12 22l-8.7-5V7z" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="7.5" r="1.8" fill="currentColor"/><circle cx="7.5" cy="14.5" r="1.8" fill="currentColor"/><circle cx="16.5" cy="14.5" r="1.8" fill="currentColor"/><path d="M12 7.5l-4.5 7M12 7.5l4.5 7M7.5 14.5h9" stroke="currentColor" stroke-width="1.2"/></svg>';

function page(params, title, body, { live = false } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Krevo Explorer</title><style>${CSS}</style></head><body>
<header><div class="bar"><a class="brand" href="/">${LOGO}Krevo Explorer</a><span class="net">${esc(params.name)}</span>
<form class="search" action="/search"><input name="q" placeholder="Search block, transaction, address or @name" aria-label="Search"></form></div></header>
<main>${body}</main><footer>Krevo (KRV) · reference implementation · the private parts of transactions are invisible by design</footer>
${live ? LIVE_SCRIPT : ''}</body></html>`;
}

const LIVE_SCRIPT = `<script>
(() => {
  const ids = ['stats', 'dag', 'blocks', 'txs'];
  let busy = false, follow = true;
  const wrap = () => document.querySelector('.dagwrap');
  document.addEventListener('scroll', () => {}, { passive: true });
  function stick() { const w = wrap(); if (w && follow) w.scrollLeft = w.scrollWidth; }
  setTimeout(() => { stick(); const w = wrap(); if (w) w.addEventListener('scroll', () => { follow = w.scrollLeft + w.clientWidth >= w.scrollWidth - 40; }); }, 50);
  async function tick() {
    if (busy || document.hidden) return;
    busy = true;
    const live = document.getElementById('live');
    try {
      const r = await fetch('/api/panel', { cache: 'no-store' });
      if (!r.ok) throw new Error();
      const d = await r.json();
      for (const id of ids) { const el = document.getElementById(id); if (el && typeof d[id] === 'string') el.innerHTML = d[id]; }
      stick();
      live && live.classList.remove('off');
    } catch { live && live.classList.add('off'); }
    busy = false;
  }
  setInterval(tick, 1000);
})();
</script>`;

// -------------------------------------------------------------- DAG (SVG)
export function dagSvg(blocks) {
  if (!blocks.length) return '<p class="muted">No blocks yet.</p>';
  const known = new Map(blocks.map((b) => [b.hash, b]));
  const minBS = Math.min(...blocks.map((b) => b.blueScore));
  const cols = new Map();
  for (const b of blocks) {
    if (!cols.has(b.blueScore)) cols.set(b.blueScore, []);
    cols.get(b.blueScore).push(b);
  }
  const COL = 30, ROW = 26, R = 8;
  let maxLane = 0;
  const pos = new Map();
  for (const list of cols.values()) {
    list.sort((a, b) => (b.chain - a.chain) || (a.hash < b.hash ? -1 : 1)); // selected chain in the middle
    list.forEach((b, i) => {
      const lane = i === 0 ? 0 : (i % 2 ? -Math.ceil(i / 2) : Math.ceil(i / 2));
      maxLane = Math.max(maxLane, Math.abs(lane));
      pos.set(b.hash, { x: 18 + (b.blueScore - minBS) * COL, lane });
    });
  }
  const H = (2 * maxLane + 1) * ROW + 16, mid = H / 2;
  const maxBS = Math.max(...blocks.map((b) => b.blueScore));
  const W = 36 + (maxBS - minBS) * COL;
  const y = (lane) => mid + lane * ROW;
  let edges = '', nodes = '';
  for (const b of blocks) {
    const p = pos.get(b.hash);
    for (const par of b.parents) {
      const q = pos.get(par);
      if (!q) continue;
      const sp = b.chain && known.get(par)?.chain;
      edges += `<line class="e${sp ? ' sp' : ''}" x1="${p.x}" y1="${y(p.lane)}" x2="${q.x}" y2="${y(q.lane)}"/>`;
    }
  }
  for (const b of blocks) {
    const p = pos.get(b.hash);
    const cls = `n${b.chain ? ' chain' : b.color === 'red' ? ' red' : ''}${b.tip ? ' tip' : ''}`;
    const tip = `block ${b.hash.slice(0, 12)} · blue score ${b.blueScore} · ${b.txs} tx · ${b.chain ? 'selected chain' : b.color === 'red' ? 'red' : 'blue'}`;
    nodes += `<a href="/block/${b.hash}"><rect class="${cls}" x="${p.x - R}" y="${y(p.lane) - R}" width="${2 * R}" height="${2 * R}" rx="4"><title>${esc(tip)}</title></rect></a>`;
  }
  return `<svg class="dag" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="DAG of recent blocks">${edges}${nodes}</svg>`;
}

// ------------------------------------------------------------ server
export function startExplorer({ params, rpcUrl, port = 8080, host = '127.0.0.1', log = () => {} }) {
  const call = (m, p) => rpc(rpcUrl, m, p);
  const txCache = new Map();

  async function getTx(txid) {
    const info = await call('gettransaction', { txid });
    const cached = txCache.get(txid);
    const tx = cached ?? Transaction.deserialize(fromHex(info.tx));
    if (!cached) { if (txCache.size > 5000) txCache.clear(); txCache.set(txid, tx); }
    return { info, tx };
  }

  function kind(tx) {
    if (tx.isCoinbase()) return { label: 'Mining reward', cls: 'chain' };
    const ms = tx.tIn.some((i) => i.sig.length !== 64);
    const tin = tx.tIn.length > 0, sin = tx.sIn.length > 0, tout = tx.tOut.length > 0, sout = tx.sOut.length > 0;
    if (ms) return { label: 'Multisig / inheritance', cls: 'blue' };
    if (tin && !sin && !sout) return { label: 'Transparent', cls: '' };
    if (tin && sout) return { label: 'Shielding (→ private)', cls: 'priv' };
    if (sin && tout) return { label: 'Unshielding (→ transparent)', cls: 'priv' };
    return { label: 'Private', cls: 'priv' };
  }
  const visible = (tx) => tx.tOut.reduce((a, o) => a + o.amount, 0n);
  const amountCell = (tx) => (tx.sOut.length && !tx.isCoinbase()
    ? (tx.tOut.length ? `${formatKRV(visible(tx))} + <span class="muted">hidden</span>` : '<span class="muted">hidden</span>')
    : formatKRV(visible(tx)));
  const addrLink = (a) => (String(a).startsWith('@')
    ? `<a href="/name/${esc(a.slice(1).split(' ')[0])}"><b>${esc(a.split(' ')[0])}</b></a> <span class="chip blue">name record</span>`
    : String(a).startsWith('name commitment') ? `<span class="chip">name commitment</span> <span class="muted">the name only appears in the reveal</span>`
      : `<a class="mono" href="/address/${esc(a)}">${esc(short(a, 14, 8))}</a>`);
  const lockText = (lock) => describeLock(params, lock);
  const blockLink = (h) => `<a class="mono" href="/block/${esc(h)}">${esc(short(h))}</a>`;
  const txLink = (h) => `<a class="mono" href="/tx/${esc(h)}">${esc(short(h))}</a>`;
  const colorChip = (b) => (b.chain ? '<span class="chip chain">chain</span>' : b.color === 'red' ? '<span class="chip red">red</span>' : '<span class="chip blue">blue</span>');

  // ---------------------------------------------------------- dashboard
  async function panel() {
    const [info, dag, mempool] = await Promise.all([call('getinfo'), call('getdag', { limit: 70 }), call('getmempool', { limit: 10 })]);
    const pct = Number((BigInt(info.minted) * 10_000n) / MAX_SUPPLY) / 100;
    const stat = (v, l) => `<div class="stat"><b>${v}</b><span>${l}</span></div>`;
    const stats = [
      stat(`${info.blocksPerSecond}`, 'blocks per second'),
      stat(info.virtual.blueScore.toLocaleString('en-US'), 'blue score'),
      stat(`${compact(info.hashrate)}H/s`, 'mining power'),
      stat(`${formatKRV(BigInt(info.minted)).replace(' KRV', '')}`, `KRV issued (${pct.toLocaleString('en-US')}% of the cap)`),
      stat(formatKRV(BigInt(info.feePool)).replace(' KRV', ''), 'KRV in the Security Fund'),
      stat(info.mempool, 'transactions in the mempool'),
      stat(info.shieldedOutputs.toLocaleString('en-US'), 'private outputs (anonymity set)'),
      stat((info.names ?? 0).toLocaleString('en-US'), 'registered names (@name)'),
      stat(formatKRV(BigInt(info.shieldedSupply ?? 0)).replace(' KRV', ''), 'KRV in the private pool (turnstile)'),
      stat(info.redBlocks, 'red blocks'),
      stat(info.tips, 'DAG tips'),
      stat(info.peers, 'connected peers'),
    ].join('');
    const recent = [...dag.blocks].reverse();
    const blocksHtml = `<table><tr><th>Block</th><th>Blue score</th><th>When</th><th class="right">Tx</th><th>Color</th></tr>${
      recent.slice(0, 12).map((b) => `<tr><td>${blockLink(b.hash)}</td><td>${b.blueScore}</td><td class="muted">${ago(b.timestamp)}</td><td class="right">${b.txs}</td><td>${colorChip(b)}</td></tr>`).join('')}</table>`;
    const ids = [...mempool.map((m) => ({ txid: m.txid, pending: true, time: m.added }))];
    for (const b of recent) for (const t of b.txids) if (ids.length < 12) ids.push({ txid: t, pending: false, time: b.timestamp });
    const rows = [];
    for (const it of ids.slice(0, 12)) {
      try {
        const { tx } = await getTx(it.txid);
        const k = kind(tx);
        rows.push(`<tr><td>${txLink(it.txid)}</td><td><span class="chip ${k.cls}">${esc(k.label)}</span></td><td class="amt">${amountCell(tx)}</td><td class="muted">${it.pending ? 'in the mempool' : ago(it.time)}</td></tr>`);
      } catch { /* it may have left the mempool */ }
    }
    const txsHtml = rows.length
      ? `<table><tr><th>Transaction</th><th>Type</th><th>Visible amount</th><th>When</th></tr>${rows.join('')}</table>`
      : '<p class="muted">No recent transactions — only mining rewards.</p>';
    return { stats, dag: dagSvg(dag.blocks), blocks: blocksHtml, txs: txsHtml };
  }

  async function homePage() {
    const p = await panel();
    return page(params, 'Dashboard', `
<div style="display:flex;justify-content:space-between;align-items:baseline;gap:10px;flex-wrap:wrap"><h1>${esc(params.name)} network</h1><span id="live" class="live">live</span></div>
<div class="stats" id="stats">${p.stats}</div>
<section class="panel"><h2>Live DAG — the latest blocks</h2>
<div class="dagwrap"><div id="dag">${p.dag}</div></div>
<div class="legend"><span><i style="background:var(--accent)"></i>selected chain</span><span><i style="background:var(--blue)"></i>blue block (parallel, accepted)</span><span><i style="background:var(--red)"></i>red block</span><span><i style="border:1.5px dashed var(--text)"></i>tip (not merged yet)</span><span>lines = references to parents · newest on the right</span></div>
<p class="muted" style="margin:8px 0 0;font-size:13px">In Bitcoin, simultaneous blocks compete and one becomes an orphan. In a BlockDAG, each block points to <b>all</b> the tips it knows — parallel blocks are stitched into the graph and nobody loses their work.</p></section>
<div class="cols"><section class="panel"><h2>Latest blocks</h2><div id="blocks">${p.blocks}</div></section>
<section class="panel"><h2>Latest transactions</h2><div id="txs">${p.txs}</div></section></div>`, { live: true });
  }

  // ------------------------------------------------------------ block
  async function blockData(hash) { return call('getblock', { hash }); }
  async function blockPage(hash) {
    const b = await blockData(hash);
    const situ = b.status === 'disq' ? '<span class="chip red">disqualified from the chain</span>' : colorChip(b);
    const list = (arr, empty = 'none') => (arr.length ? arr.map(blockLink).join('<br>') : `<span class="muted">${empty}</span>`);
    const txRows = [];
    for (const id of b.txs) {
      const { tx } = await getTx(id);
      const k = kind(tx);
      txRows.push(`<tr><td>${txLink(id)}</td><td><span class="chip ${k.cls}">${esc(k.label)}</span></td><td class="amt">${amountCell(tx)}</td></tr>`);
    }
    const rewards = b.coinbase.transparent.map((o) => `<tr><td>${addrLink(o.address)}</td><td class="amt right">${formatKRV(BigInt(o.amount))}</td></tr>`).join('')
      + (b.coinbase.shielded ? `<tr><td class="muted">${b.coinbase.shielded} reward(s) to a private address</td><td class="right muted">address hidden, amount public</td></tr>` : '');
    return page(params, `Block ${short(hash)}`, `
<h1>Block <span class="mono">${esc(short(hash, 16, 8))}</span> ${situ}</h1>
<section class="panel"><table class="kv">
<tr><td>Hash</td><td class="mono">${esc(hash)}</td></tr>
<tr><td>When</td><td>${new Date(b.timestamp).toLocaleString('en-US')} <span class="muted">(${ago(b.timestamp)})</span></td></tr>
<tr><td>Blue score / DAA score</td><td>${b.blueScore} / ${b.daaScore}</td></tr>
<tr><td>Miner</td><td>${b.miner ? addrLink(b.miner) : '<span class="muted">— (genesis)</span>'}</td></tr>
<tr><td>Transactions</td><td>${b.txs.length} (including the coinbase) · accepted ${b.accepted} from its mergeset</td></tr>
<tr><td>Size / mass</td><td>${b.size.toLocaleString('en-US')} bytes / ${b.mass.toLocaleString('en-US')} g</td></tr>
<tr><td>Selected parent</td><td>${b.selectedParent ? blockLink(b.selectedParent) : '<span class="muted">—</span>'}</td></tr>
<tr><td>Parents (${b.parents.length})</td><td>${list(b.parents, 'none (genesis)')}</td></tr>
<tr><td>Children (${b.children.length})</td><td>${list(b.children, 'none yet (it is a tip)')}</td></tr>
<tr><td>Blue mergeset</td><td>${list(b.blues)}</td></tr>
<tr><td>Red mergeset</td><td>${list(b.reds)}</td></tr>
<tr><td>UTXO commitment</td><td class="mono">${esc(b.utxoCommitment)}</td></tr>
<tr><td>Nonce / bits</td><td class="mono">${esc(b.nonce)} / 0x${Number(b.bits).toString(16)}</td></tr>
</table></section>
<div class="cols"><section class="panel"><h2>Transactions</h2><table><tr><th>Transaction</th><th>Type</th><th>Visible amount</th></tr>${txRows.join('')}</table></section>
<section class="panel"><h2>Rewards paid by this block</h2><table>${rewards || '<tr><td class="muted">none</td></tr>'}</table>
<p class="muted" style="font-size:13px">Each chain block pays, in its coinbase, the blocks of its mergeset (blue ones to their own miner; red ones to whoever merged them).</p></section></div>`);
  }

  // ------------------------------------------------------------ transaction
  async function txDetail(txid) {
    const { info, tx } = await getTx(txid);
    const inputs = [];
    for (const i of tx.tIn) {
      const prevId = toHex(i.outpoint.txid);
      let address = null, amount = null;
      try {
        const prev = (await getTx(prevId)).tx.tOut[i.outpoint.index];
        if (prev) { address = lockText(prev.lock); amount = prev.amount; }
      } catch { /* origin outside the index */ }
      const quantum = isPqWitness(i.sig);
      const reveal = parseCommitWitness(i.sig);
      const w = i.sig.length !== 64 && !quantum ? parseWitnessPath(i.sig) : null;
      inputs.push({ type: 'transparent', prevTx: prevId, index: i.outpoint.index, address, amount,
        multisig: w ? { path: w.path, m: w.p.m, n: w.p.n, delay: w.p.delay } : null, quantum,
        swapSecret: w?.secret ? toHex(w.secret) : null, nameReveal: reveal ? reveal.name : null });
    }
    for (const s of tx.sIn) {
      inputs.push(s.ring.length
        ? { type: 'shielded', ring: s.ring.map((m) => ({ tx: toHex(m.txid), index: m.index })), keyImage: toHex(s.keyImage) }
        : { type: 'shielded', fcmp: true, anonymitySet: s.anchor, ring: [], keyImage: toHex(s.keyImage) });
    }
    const outputs = [
      ...tx.tOut.map((o, n) => ({ type: 'transparent', index: n, address: lockText(o.lock), amount: o.amount })),
      ...tx.sOut.map((o, j) => ({ type: 'shielded', index: tx.tOut.length + j, oneTimeKey: toHex(o.P) })),
    ];
    return {
      txid, kind: kind(tx).label, status: info.status, confirmations: info.confirmations, includedIn: info.includedIn,
      acceptingBlock: info.acceptingBlock, fee: tx.fee, mass: tx.mass, size: tx.size, inputs, outputs,
      memo: tx.payload.length === 145 && tx.payload[0] === 1 ? 'encrypted' : null, rangeProof: tx.rangeProof.length,
      coinbasePayload: tx.isCoinbase() ? toHex(tx.payload) : null,
    };
  }
  async function txPage(txid) {
    const d = await txDetail(txid);
    const { tx } = await getTx(txid);
    const k = kind(tx);
    const st = d.status === 'accepted' ? `<span class="chip chain">accepted</span> <span class="muted">${d.confirmations} blue blocks on top</span>`
      : d.status === 'mempool' ? '<span class="chip">in the mempool</span>' : '<span class="chip red">not accepted (conflict or not merged yet)</span>';
    const ins = d.inputs.map((i) => (i.type === 'transparent'
      ? `<tr><td>${i.address ? addrLink(i.address) : '<span class="muted">unknown origin</span>'}${i.multisig ? `<br><span class="chip blue">policy: path ${i.multisig.path}, ${i.multisig.m} of ${i.multisig.n}${i.multisig.delay ? `, wait ${i.multisig.delay.toLocaleString('en-US')} blocks` : ''}</span>` : ''}${i.quantum ? '<br><span class="chip blue">hybrid signature: Schnorr + ML-DSA-44 (quantum-resistant)</span>' : ''}${i.nameReveal ? `<br><span class="chip blue">reveal of the name @${esc(i.nameReveal)}</span>` : ''}${i.swapSecret ? `<br><span class="chip blue">atomic swap: claim with revealed secret</span> <span class="mono">${esc(short(i.swapSecret, 12, 6))}</span>` : ''}<br><span class="muted">from ${txLink(i.prevTx)} #${i.index}</span></td><td class="amt right">${i.amount !== null ? formatKRV(i.amount) : '—'}</td></tr>`
      : i.fcmp ? `<tr><td><span class="chip priv">private input</span> <b>one</b> of the ${i.anonymitySet.toLocaleString('en-US')} private outputs that have ever existed is the one spent — nobody knows which<br><span class="muted">full-chain membership proof · key image</span> <span class="mono">${esc(short(i.keyImage, 12, 6))}</span></td><td class="right muted">hidden</td></tr>`
      : `<tr><td><span class="chip priv">private input</span> ring of ${i.ring.length}: <b>one</b> of these outputs is the one spent — nobody knows which<details><summary class="muted">see the ring</summary>${i.ring.map((m) => `${txLink(m.tx)} #${m.index}`).join('<br>')}</details><span class="muted">key image</span> <span class="mono">${esc(short(i.keyImage, 12, 6))}</span></td><td class="right muted">hidden</td></tr>`)).join('');
    const outs = d.outputs.map((o) => (o.type === 'transparent'
      ? `<tr><td>${addrLink(o.address)}</td><td class="amt right">${formatKRV(o.amount)}</td></tr>`
      : `<tr><td><span class="chip priv">private output</span> recipient and amount hidden<br><span class="muted">one-time key</span> <span class="mono">${esc(short(o.oneTimeKey, 12, 6))}</span></td><td class="right muted">hidden</td></tr>`)).join('');
    return page(params, `Transaction ${short(txid)}`, `
<h1>Transaction <span class="mono">${esc(short(txid, 16, 8))}</span> <span class="chip ${k.cls}">${esc(k.label)}</span></h1>
<section class="panel"><table class="kv">
<tr><td>Txid</td><td class="mono">${esc(txid)}</td></tr>
<tr><td>Status</td><td>${st}</td></tr>
<tr><td>Included in block</td><td>${d.includedIn ? blockLink(d.includedIn) : '<span class="muted">—</span>'}</td></tr>
<tr><td>Accepted by chain block</td><td>${d.acceptingBlock ? blockLink(d.acceptingBlock) : '<span class="muted">—</span>'}</td></tr>
<tr><td>Fee</td><td>${tx.isCoinbase() ? '<span class="muted">—</span>' : formatKRV(d.fee)}</td></tr>
<tr><td>Size / mass</td><td>${d.size.toLocaleString('en-US')} bytes / ${d.mass.toLocaleString('en-US')} g</td></tr>
${d.memo ? '<tr><td>Memo</td><td><span class="chip priv">encrypted</span> <span class="muted">fixed size of 145 bytes — only the recipient reads it (you cannot even tell whether there is text)</span></td></tr>' : ''}
${d.rangeProof ? `<tr><td>Range proof</td><td>Bulletproof of ${d.rangeProof} bytes: proves that no hidden amount is negative (no hidden inflation)</td></tr>` : ''}
</table></section>
<div class="cols"><section class="panel"><h2>Inputs</h2><table>${ins || '<tr><td class="muted">none — new coins from the mining reward</td></tr>'}</table></section>
<section class="panel"><h2>Outputs</h2><table>${outs}</table></section></div>`);
  }

  // ------------------------------------------------------------ address
  async function addressData(addr) {
    const a = decodeAddress(params, addr);
    if (a.type === 's') return { type: 's' };
    const h = await call('getaddresshistory', { address: addr, limit: 25 });
    const lockHex = toHex(a.data);
    const history = [];
    for (const id of h.txids) {
      try {
        const { info, tx } = await getTx(id);
        let delta = 0n;
        for (const o of tx.tOut) if (toHex(o.lock) === lockHex) delta += o.amount;
        for (const i of tx.tIn) {
          const prev = (await getTx(toHex(i.outpoint.txid))).tx.tOut[i.outpoint.index];
          if (prev && toHex(prev.lock) === lockHex) delta -= prev.amount;
        }
        history.push({ txid: id, delta, status: info.status, kind: kind(tx).label });
      } catch { /* ignore */ }
    }
    return { type: h.type, balance: h.utxos.reduce((x, u) => x + BigInt(u.amount), 0n), utxos: h.utxos, history };
  }
  async function addressPage(addr) {
    const d = await addressData(addr);
    if (d.type === 's') {
      return page(params, 'Private address', `<h1>Private address</h1>
<section class="panel"><p class="mono">${esc(addr)}</p>
<div class="note">🔒 <b>There is nothing to show — and that is privacy working.</b><br>
Payments to private addresses use a different one-time key each time, with an encrypted amount. On the network there is no record linking these outputs to this address; neither this explorer, nor the node, nor anyone else can add up the balance.<br>
For auditing, the owner can hand over their <b>view key</b> (krw1…) or a <b>payment proof</b> (krp1…) for a specific payment.</div></section>`);
    }
    const rows = d.history.map((x) => `<tr><td>${txLink(x.txid)}</td><td><span class="chip">${esc(x.kind)}</span></td><td class="amt right" style="color:${x.delta >= 0n ? 'var(--accent)' : 'var(--red)'}">${x.delta >= 0n ? '+' : '−'}${formatKRV(x.delta >= 0n ? x.delta : -x.delta)}</td><td class="muted">${x.status === 'accepted' ? 'accepted' : esc(x.status)}</td></tr>`).join('');
    return page(params, `Address ${short(addr, 12, 6)}`, `
<h1>${d.type === 'm' ? 'Policy address (multisig / inheritance)' : d.type === 'q' ? 'Quantum-safe address (krq)' : 'Transparent address'}</h1>
<section class="panel"><p class="mono">${esc(addr)}</p><div class="big">${formatKRV(d.balance)}</div>
<p class="muted">${d.utxos.length} unspent output(s)${d.utxos.some((u) => !u.mature) ? ' · part still maturing (recent mining reward)' : ''}</p>
${d.type === 'q' ? '<div class="note">Spending from here requires two signatures at the same time: Schnorr (secp256k1) and ML-DSA-44 (NIST FIPS 204, resistant to quantum computers). The keys stay hidden behind a hash until the first spend.</div>' : ''}
${d.type === 'm' ? '<div class="note">This address\'s rules (which keys, how many signatures, deadlines) are hidden behind a hash and only appear on the network when the balance is spent.</div>' : ''}</section>
<section class="panel"><h2>Recent history</h2><table><tr><th>Transaction</th><th>Type</th><th class="right">Effect on balance</th><th>Status</th></tr>${rows || '<tr><td class="muted" colspan="4">no transactions yet</td></tr>'}</table></section>`);
  }

  // ------------------------------------------------------------ search
  async function search(q) {
    q = String(q ?? '').trim();
    if (isHash(q.toLowerCase())) {
      const h = q.toLowerCase();
      try { await call('getblock', { hash: h }); return `/block/${h}`; } catch { /* not a block */ }
      try { await call('gettransaction', { txid: h }); return `/tx/${h}`; } catch { /* not a tx */ }
      return null;
    }
    if (q.startsWith('@') || isValidName(normalizeName(q))) {
      const n = normalizeName(q);
      if (isValidName(n) && (q.startsWith('@') || (await call('resolvename', { name: n })).status !== 'free')) return `/name/${n}`;
    }
    try { decodeAddress(params, q); return `/address/${encodeURIComponent(q.toLowerCase())}`; } catch { return null; }
  }

  // ------------------------------------------------------------ @name
  async function namePage(raw) {
    const n = normalizeName(raw);
    if (!isValidName(n)) throw new Error('invalid name');
    const d = await call('resolvename', { name: n });
    const when = (sec) => new Date(Date.now() + sec * 1000).toLocaleDateString('en-US');
    if (d.status === 'free') {
      return page(params, `@${n}`, `<h1>@${esc(n)}</h1><section class="panel"><div class="big">available</div>
<p class="muted">Nobody has registered this name (or the registration expired and its grace period is over).</p>
<div class="note">Registering costs ${formatKRV(BigInt(d.fee))} per year — the whole fee goes to the Security Fund, which pays future miners.</div></section>`);
    }
    const types = { t: 'transparent', s: 'private', q: 'quantum-safe', m: 'multisig' };
    return page(params, `@${n}`, `<h1>@${esc(n)} <span class="chip ${d.status === 'active' ? 'chain' : 'red'}">${esc(d.status)}</span></h1>
<section class="panel"><table class="kv">
<tr><td>Points to</td><td>${d.targetType === 's' ? `<span class="mono">${esc(short(d.target, 18, 10))}</span> <span class="chip priv">private address</span>` : addrLink(d.target)} <span class="muted">(${esc(types[d.targetType] ?? d.targetType)})</span></td></tr>
<tr><td>Owner</td><td>${addrLink(d.owner)}</td></tr>
<tr><td>Expires on</td><td>${esc(when(d.expiresIn))}${d.status !== 'active' ? ` — grace period until ${esc(when(d.graceEndsIn))}: only the owner can renew` : ''}</td></tr>
<tr><td>Deposit</td><td>${formatKRV(BigInt(d.deposit))} <span class="muted">(returned to the owner if they release the name)</span></td></tr>
<tr><td>Latest record</td><td>${txLink(d.txid)}</td></tr>
<tr><td>Renewal</td><td>${formatKRV(BigInt(d.fee))} per year</td></tr>
</table>
${d.targetType === 's' ? '<div class="note">The name is public, but payments to it are not: each one goes to a one-time address, with a hidden amount.</div>' : ''}</section>`);
  }

  // ------------------------------------------------------------ routing
  const server = http.createServer(async (req, res) => {
    const send = (code, body, type = 'text/html; charset=utf-8') => {
      res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:" });
      res.end(body);
    };
    const notFound = (msg) => send(404, page(params, 'Not found', `<h1>Not found</h1><section class="panel"><p>${esc(msg)}</p><p><a href="/">Back to the dashboard</a></p></section>`));
    try {
      if (req.method !== 'GET') return send(405, 'method not allowed', 'text/plain');
      const url = new URL(req.url, 'http://x');
      const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      const legacy = (s) => ({ bloco: 'block', endereco: 'address', nome: 'name', busca: 'search', painel: 'panel' })[s] ?? s; const a = legacy(parts[0]), b = a === 'api' ? legacy(parts[1]) : parts[1]; // links from older versions still work
      if (!a) return send(200, await homePage());
      if (a === 'search') {
        const to = await search(url.searchParams.get('q'));
        if (!to) return notFound(`Nothing found for "${url.searchParams.get('q') ?? ''}". Search for a block hash, a txid or an address on this network.`);
        res.writeHead(302, { location: to }); return res.end();
      }
      if (a === 'block' && isHash(b ?? '')) return send(200, await blockPage(b));
      if (a === 'tx' && isHash(b ?? '')) return send(200, await txPage(b));
      if (a === 'address' && b) return send(200, await addressPage(b));
      if (a === 'name' && b) return send(200, await namePage(b));
      if (a === 'api') {
        const j = (o) => send(200, json(o), 'application/json; charset=utf-8');
        const c = parts[2];
        if (b === 'panel') return j(await panel());
        if (b === 'info') return j(await call('getinfo'));
        if (b === 'dag') return j(await call('getdag', { limit: Number(url.searchParams.get('n') ?? 80) }));
        if (b === 'block' && isHash(c ?? '')) return j(await blockData(c));
        if (b === 'tx' && isHash(c ?? '')) return j(await txDetail(c));
        if (b === 'address' && c) return j(await addressData(c));
        if (b === 'name' && c) return j(await call('resolvename', { name: c }));
        return send(404, json({ error: 'unknown route' }), 'application/json');
      }
      return notFound('Page does not exist.');
    } catch (e) {
      const msg = /unknown|invalid|another network|bech32/i.test(e.message) ? e.message : 'error querying the node';
      if (!/unknown|invalid|another network|bech32/i.test(e.message)) log('explorer: ' + e.message);
      return notFound(msg);
    }
  });
  return new Promise((ok, err) => {
    server.once('error', err);
    server.listen(port, host, () => ok({ server, url: `http://${host}:${port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) }));
  });
}
