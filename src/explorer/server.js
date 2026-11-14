// Explorador de blocos do Krevo: servidor web sem dependências que consulta um nó via RPC.
//
//   /                 painel ao vivo: estatísticas, DAG em tempo real, últimos blocos e transações
//   /bloco/<hash>     detalhes do bloco (pais, filhos, mergeset azul/vermelho, recompensas)
//   /tx/<txid>        detalhes da transação (partes privadas aparecem como ocultas)
//   /endereco/<end>   saldo e histórico de endereços transparentes / multiassinatura
//   /nome/<nome>      para onde um @nome aponta, dono e vencimento
//   /busca?q=…        hash de bloco, txid, endereço ou @nome
//   /api/…            os mesmos dados em JSON
//
// Tudo que vem da rede é escapado antes de ir para o HTML.

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
  if (s < 60) return `há ${s.toFixed(s < 10 ? 1 : 0).replace('.', ',')} s`;
  if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`;
  return `há ${Math.floor(s / 86400)} d`;
}
function compact(n) {
  n = Number(n);
  for (const [v, u] of [[1e12, ' T'], [1e9, ' G'], [1e6, ' M'], [1e3, ' k']]) if (n >= v) return (n / v).toFixed(1).replace('.', ',') + u;
  return String(Math.round(n));
}

// ------------------------------------------------------------------ estilo
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
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Explorador Krevo</title><style>${CSS}</style></head><body>
<header><div class="bar"><a class="brand" href="/">${LOGO}Explorador Krevo</a><span class="net">${esc(params.name)}</span>
<form class="search" action="/busca"><input name="q" placeholder="Buscar bloco, transação, endereço ou @nome" aria-label="Buscar"></form></div></header>
<main>${body}</main><footer>Krevo (KRV) · implementação de referência · as partes privadas das transações são invisíveis por projeto</footer>
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
      const r = await fetch('/api/painel', { cache: 'no-store' });
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
  if (!blocks.length) return '<p class="muted">Sem blocos ainda.</p>';
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
    list.sort((a, b) => (b.chain - a.chain) || (a.hash < b.hash ? -1 : 1)); // cadeia selecionada no centro
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
    const tip = `bloco ${b.hash.slice(0, 12)} · blue score ${b.blueScore} · ${b.txs} tx · ${b.chain ? 'cadeia selecionada' : b.color === 'red' ? 'vermelho' : 'azul'}`;
    nodes += `<a href="/bloco/${b.hash}"><rect class="${cls}" x="${p.x - R}" y="${y(p.lane) - R}" width="${2 * R}" height="${2 * R}" rx="4"><title>${esc(tip)}</title></rect></a>`;
  }
  return `<svg class="dag" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="DAG dos blocos recentes">${edges}${nodes}</svg>`;
}

// ------------------------------------------------------------ servidor
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
    if (tx.isCoinbase()) return { label: 'Recompensa de mineração', cls: 'chain' };
    const ms = tx.tIn.some((i) => i.sig.length !== 64);
    const tin = tx.tIn.length > 0, sin = tx.sIn.length > 0, tout = tx.tOut.length > 0, sout = tx.sOut.length > 0;
    if (ms) return { label: 'Multiassinatura / herança', cls: 'blue' };
    if (tin && !sin && !sout) return { label: 'Transparente', cls: '' };
    if (tin && sout) return { label: 'Blindagem (→ privado)', cls: 'priv' };
    if (sin && tout) return { label: 'Desblindagem (→ transparente)', cls: 'priv' };
    return { label: 'Privada', cls: 'priv' };
  }
  const visible = (tx) => tx.tOut.reduce((a, o) => a + o.amount, 0n);
  const amountCell = (tx) => (tx.sOut.length && !tx.isCoinbase()
    ? (tx.tOut.length ? `${formatKRV(visible(tx))} + <span class="muted">oculto</span>` : '<span class="muted">oculto</span>')
    : formatKRV(visible(tx)));
  const addrLink = (a) => (String(a).startsWith('@')
    ? `<a href="/nome/${esc(a.slice(1).split(' ')[0])}"><b>${esc(a.split(' ')[0])}</b></a> <span class="chip blue">registro de nome</span>`
    : String(a).startsWith('compromisso') ? `<span class="chip">compromisso de nome</span> <span class="muted">o nome só aparece na revelação</span>`
      : `<a class="mono" href="/endereco/${esc(a)}">${esc(short(a, 14, 8))}</a>`);
  const lockText = (lock) => describeLock(params, lock);
  const blockLink = (h) => `<a class="mono" href="/bloco/${esc(h)}">${esc(short(h))}</a>`;
  const txLink = (h) => `<a class="mono" href="/tx/${esc(h)}">${esc(short(h))}</a>`;
  const colorChip = (b) => (b.chain ? '<span class="chip chain">cadeia</span>' : b.color === 'red' ? '<span class="chip red">vermelho</span>' : '<span class="chip blue">azul</span>');

  // ---------------------------------------------------------- painel
  async function panel() {
    const [info, dag, mempool] = await Promise.all([call('getinfo'), call('getdag', { limit: 70 }), call('getmempool', { limit: 10 })]);
    const pct = Number((BigInt(info.minted) * 10_000n) / MAX_SUPPLY) / 100;
    const stat = (v, l) => `<div class="stat"><b>${v}</b><span>${l}</span></div>`;
    const stats = [
      stat(`${String(info.blocksPerSecond).replace('.', ',')}`, 'blocos por segundo'),
      stat(info.virtual.blueScore.toLocaleString('pt-BR'), 'blue score'),
      stat(`${compact(info.hashrate)}H/s`, 'poder de mineração'),
      stat(`${formatKRV(BigInt(info.minted)).replace(' KRV', '')}`, `KRV emitidos (${pct.toLocaleString('pt-BR')}% do teto)`),
      stat(formatKRV(BigInt(info.feePool)).replace(' KRV', ''), 'KRV no Fundo de Segurança'),
      stat(info.mempool, 'transações na mempool'),
      stat(info.shieldedOutputs.toLocaleString('pt-BR'), 'saídas privadas (anonimato)'),
      stat((info.names ?? 0).toLocaleString('pt-BR'), 'nomes registrados (@nome)'),
      stat(formatKRV(BigInt(info.shieldedSupply ?? 0)).replace(' KRV', ''), 'KRV no pool privado (catraca)'),
      stat(info.redBlocks, 'blocos vermelhos'),
      stat(info.tips, 'pontas do DAG'),
      stat(info.peers, 'pares conectados'),
    ].join('');
    const recent = [...dag.blocks].reverse();
    const blocksHtml = `<table><tr><th>Bloco</th><th>Blue score</th><th>Quando</th><th class="right">Tx</th><th>Cor</th></tr>${
      recent.slice(0, 12).map((b) => `<tr><td>${blockLink(b.hash)}</td><td>${b.blueScore}</td><td class="muted">${ago(b.timestamp)}</td><td class="right">${b.txs}</td><td>${colorChip(b)}</td></tr>`).join('')}</table>`;
    const ids = [...mempool.map((m) => ({ txid: m.txid, pending: true, time: m.added }))];
    for (const b of recent) for (const t of b.txids) if (ids.length < 12) ids.push({ txid: t, pending: false, time: b.timestamp });
    const rows = [];
    for (const it of ids.slice(0, 12)) {
      try {
        const { tx } = await getTx(it.txid);
        const k = kind(tx);
        rows.push(`<tr><td>${txLink(it.txid)}</td><td><span class="chip ${k.cls}">${esc(k.label)}</span></td><td class="amt">${amountCell(tx)}</td><td class="muted">${it.pending ? 'na mempool' : ago(it.time)}</td></tr>`);
      } catch { /* pode ter saído da mempool */ }
    }
    const txsHtml = rows.length
      ? `<table><tr><th>Transação</th><th>Tipo</th><th>Valor visível</th><th>Quando</th></tr>${rows.join('')}</table>`
      : '<p class="muted">Nenhuma transação recente — só recompensas de mineração.</p>';
    return { stats, dag: dagSvg(dag.blocks), blocks: blocksHtml, txs: txsHtml };
  }

  async function homePage() {
    const p = await panel();
    return page(params, 'Painel', `
<div style="display:flex;justify-content:space-between;align-items:baseline;gap:10px;flex-wrap:wrap"><h1>Rede ${esc(params.name)}</h1><span id="live" class="live">ao vivo</span></div>
<div class="stats" id="stats">${p.stats}</div>
<section class="panel"><h2>DAG ao vivo — os últimos blocos</h2>
<div class="dagwrap"><div id="dag">${p.dag}</div></div>
<div class="legend"><span><i style="background:var(--accent)"></i>cadeia selecionada</span><span><i style="background:var(--blue)"></i>bloco azul (paralelo, aceito)</span><span><i style="background:var(--red)"></i>bloco vermelho</span><span><i style="border:1.5px dashed var(--text)"></i>ponta (ainda não fundida)</span><span>linhas = referências aos pais · mais novo à direita</span></div>
<p class="muted" style="margin:8px 0 0;font-size:13px">No Bitcoin, blocos simultâneos competem e um vira órfão. No BlockDAG, cada bloco aponta para <b>todas</b> as pontas que conhece — os paralelos são costurados no grafo e ninguém perde o trabalho.</p></section>
<div class="cols"><section class="panel"><h2>Últimos blocos</h2><div id="blocks">${p.blocks}</div></section>
<section class="panel"><h2>Últimas transações</h2><div id="txs">${p.txs}</div></section></div>`, { live: true });
  }

  // ------------------------------------------------------------ bloco
  async function blockData(hash) { return call('getblock', { hash }); }
  async function blockPage(hash) {
    const b = await blockData(hash);
    const situ = b.status === 'disq' ? '<span class="chip red">desqualificado da cadeia</span>' : colorChip(b);
    const list = (arr, empty = 'nenhum') => (arr.length ? arr.map(blockLink).join('<br>') : `<span class="muted">${empty}</span>`);
    const txRows = [];
    for (const id of b.txs) {
      const { tx } = await getTx(id);
      const k = kind(tx);
      txRows.push(`<tr><td>${txLink(id)}</td><td><span class="chip ${k.cls}">${esc(k.label)}</span></td><td class="amt">${amountCell(tx)}</td></tr>`);
    }
    const rewards = b.coinbase.transparent.map((o) => `<tr><td>${addrLink(o.address)}</td><td class="amt right">${formatKRV(BigInt(o.amount))}</td></tr>`).join('')
      + (b.coinbase.shielded ? `<tr><td class="muted">${b.coinbase.shielded} recompensa(s) para endereço privado</td><td class="right muted">oculto no endereço, valor público</td></tr>` : '');
    return page(params, `Bloco ${short(hash)}`, `
<h1>Bloco <span class="mono">${esc(short(hash, 16, 8))}</span> ${situ}</h1>
<section class="panel"><table class="kv">
<tr><td>Hash</td><td class="mono">${esc(hash)}</td></tr>
<tr><td>Quando</td><td>${new Date(b.timestamp).toLocaleString('pt-BR')} <span class="muted">(${ago(b.timestamp)})</span></td></tr>
<tr><td>Blue score / DAA score</td><td>${b.blueScore} / ${b.daaScore}</td></tr>
<tr><td>Minerador</td><td>${b.miner ? addrLink(b.miner) : '<span class="muted">— (gênesis)</span>'}</td></tr>
<tr><td>Transações</td><td>${b.txs.length} (incluindo a coinbase) · aceitou ${b.accepted} do seu mergeset</td></tr>
<tr><td>Tamanho / massa</td><td>${b.size.toLocaleString('pt-BR')} bytes / ${b.mass.toLocaleString('pt-BR')} g</td></tr>
<tr><td>Pai selecionado</td><td>${b.selectedParent ? blockLink(b.selectedParent) : '<span class="muted">—</span>'}</td></tr>
<tr><td>Pais (${b.parents.length})</td><td>${list(b.parents, 'nenhum (gênesis)')}</td></tr>
<tr><td>Filhos (${b.children.length})</td><td>${list(b.children, 'nenhum ainda (é uma ponta)')}</td></tr>
<tr><td>Mergeset azul</td><td>${list(b.blues)}</td></tr>
<tr><td>Mergeset vermelho</td><td>${list(b.reds)}</td></tr>
<tr><td>Compromisso UTXO</td><td class="mono">${esc(b.utxoCommitment)}</td></tr>
<tr><td>Nonce / bits</td><td class="mono">${esc(b.nonce)} / 0x${Number(b.bits).toString(16)}</td></tr>
</table></section>
<div class="cols"><section class="panel"><h2>Transações</h2><table><tr><th>Transação</th><th>Tipo</th><th>Valor visível</th></tr>${txRows.join('')}</table></section>
<section class="panel"><h2>Recompensas pagas por este bloco</h2><table>${rewards || '<tr><td class="muted">nenhuma</td></tr>'}</table>
<p class="muted" style="font-size:13px">Cada bloco da cadeia paga, na sua coinbase, os blocos do seu mergeset (azuis ao próprio minerador; vermelhos a quem os fundiu).</p></section></div>`);
  }

  // ------------------------------------------------------------ transação
  async function txDetail(txid) {
    const { info, tx } = await getTx(txid);
    const inputs = [];
    for (const i of tx.tIn) {
      const prevId = toHex(i.outpoint.txid);
      let address = null, amount = null;
      try {
        const prev = (await getTx(prevId)).tx.tOut[i.outpoint.index];
        if (prev) { address = lockText(prev.lock); amount = prev.amount; }
      } catch { /* origem fora do índice */ }
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
      memo: tx.payload.length === 145 && tx.payload[0] === 1 ? 'cifrado' : null, rangeProof: tx.rangeProof.length,
      coinbasePayload: tx.isCoinbase() ? toHex(tx.payload) : null,
    };
  }
  async function txPage(txid) {
    const d = await txDetail(txid);
    const { tx } = await getTx(txid);
    const k = kind(tx);
    const st = d.status === 'accepted' ? `<span class="chip chain">aceita</span> <span class="muted">${d.confirmations} blocos azuis acima</span>`
      : d.status === 'mempool' ? '<span class="chip">na mempool</span>' : '<span class="chip red">não aceita (conflito ou ainda não fundida)</span>';
    const ins = d.inputs.map((i) => (i.type === 'transparent'
      ? `<tr><td>${i.address ? addrLink(i.address) : '<span class="muted">origem desconhecida</span>'}${i.multisig ? `<br><span class="chip blue">política: caminho ${i.multisig.path}, ${i.multisig.m} de ${i.multisig.n}${i.multisig.delay ? `, espera ${i.multisig.delay.toLocaleString('pt-BR')} blocos` : ''}</span>` : ''}${i.quantum ? '<br><span class="chip blue">assinatura híbrida: Schnorr + ML-DSA-44 (resistente a quântico)</span>' : ''}${i.nameReveal ? `<br><span class="chip blue">revelação do nome @${esc(i.nameReveal)}</span>` : ''}${i.swapSecret ? `<br><span class="chip blue">troca atômica: resgate com segredo revelado</span> <span class="mono">${esc(short(i.swapSecret, 12, 6))}</span>` : ''}<br><span class="muted">de ${txLink(i.prevTx)} #${i.index}</span></td><td class="amt right">${i.amount !== null ? formatKRV(i.amount) : '—'}</td></tr>`
      : i.fcmp ? `<tr><td><span class="chip priv">entrada privada</span> <b>uma</b> das ${i.anonymitySet.toLocaleString('pt-BR')} saídas privadas que já existiram é a gasta — ninguém sabe qual<br><span class="muted">prova de pertencimento à cadeia inteira · imagem de chave</span> <span class="mono">${esc(short(i.keyImage, 12, 6))}</span></td><td class="right muted">oculto</td></tr>`
      : `<tr><td><span class="chip priv">entrada privada</span> anel de ${i.ring.length}: <b>uma</b> destas saídas é a gasta — ninguém sabe qual<details><summary class="muted">ver o anel</summary>${i.ring.map((m) => `${txLink(m.tx)} #${m.index}`).join('<br>')}</details><span class="muted">imagem de chave</span> <span class="mono">${esc(short(i.keyImage, 12, 6))}</span></td><td class="right muted">oculto</td></tr>`)).join('');
    const outs = d.outputs.map((o) => (o.type === 'transparent'
      ? `<tr><td>${addrLink(o.address)}</td><td class="amt right">${formatKRV(o.amount)}</td></tr>`
      : `<tr><td><span class="chip priv">saída privada</span> destinatário e valor ocultos<br><span class="muted">chave de uso único</span> <span class="mono">${esc(short(o.oneTimeKey, 12, 6))}</span></td><td class="right muted">oculto</td></tr>`)).join('');
    return page(params, `Transação ${short(txid)}`, `
<h1>Transação <span class="mono">${esc(short(txid, 16, 8))}</span> <span class="chip ${k.cls}">${esc(k.label)}</span></h1>
<section class="panel"><table class="kv">
<tr><td>Txid</td><td class="mono">${esc(txid)}</td></tr>
<tr><td>Situação</td><td>${st}</td></tr>
<tr><td>Incluída no bloco</td><td>${d.includedIn ? blockLink(d.includedIn) : '<span class="muted">—</span>'}</td></tr>
<tr><td>Aceita pelo bloco da cadeia</td><td>${d.acceptingBlock ? blockLink(d.acceptingBlock) : '<span class="muted">—</span>'}</td></tr>
<tr><td>Taxa</td><td>${tx.isCoinbase() ? '<span class="muted">—</span>' : formatKRV(d.fee)}</td></tr>
<tr><td>Tamanho / massa</td><td>${d.size.toLocaleString('pt-BR')} bytes / ${d.mass.toLocaleString('pt-BR')} g</td></tr>
${d.memo ? '<tr><td>Memo</td><td><span class="chip priv">cifrado</span> <span class="muted">145 bytes de tamanho fixo — só o destinatário lê (e nem dá para saber se há texto)</span></td></tr>' : ''}
${d.rangeProof ? `<tr><td>Prova de intervalo</td><td>Bulletproof de ${d.rangeProof} bytes: prova que nenhum valor oculto é negativo (sem inflação escondida)</td></tr>` : ''}
</table></section>
<div class="cols"><section class="panel"><h2>Entradas</h2><table>${ins || '<tr><td class="muted">nenhuma — moedas novas da recompensa de mineração</td></tr>'}</table></section>
<section class="panel"><h2>Saídas</h2><table>${outs}</table></section></div>`);
  }

  // ------------------------------------------------------------ endereço
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
      } catch { /* ignora */ }
    }
    return { type: h.type, balance: h.utxos.reduce((x, u) => x + BigInt(u.amount), 0n), utxos: h.utxos, history };
  }
  async function addressPage(addr) {
    const d = await addressData(addr);
    if (d.type === 's') {
      return page(params, 'Endereço privado', `<h1>Endereço privado</h1>
<section class="panel"><p class="mono">${esc(addr)}</p>
<div class="note">🔒 <b>Não há nada para mostrar — e isso é a privacidade funcionando.</b><br>
Pagamentos a endereços privados usam uma chave de uso único diferente a cada vez, com valor cifrado. Na rede não existe nenhum registro ligando estas saídas a este endereço; nem este explorador, nem o nó, nem ninguém consegue somar o saldo.<br>
Para auditoria, o dono pode entregar a sua <b>chave de visualização</b> (krw1…) ou uma <b>prova de pagamento</b> (krp1…) de um pagamento específico.</div></section>`);
    }
    const rows = d.history.map((x) => `<tr><td>${txLink(x.txid)}</td><td><span class="chip">${esc(x.kind)}</span></td><td class="amt right" style="color:${x.delta >= 0n ? 'var(--accent)' : 'var(--red)'}">${x.delta >= 0n ? '+' : '−'}${formatKRV(x.delta >= 0n ? x.delta : -x.delta)}</td><td class="muted">${x.status === 'accepted' ? 'aceita' : esc(x.status)}</td></tr>`).join('');
    return page(params, `Endereço ${short(addr, 12, 6)}`, `
<h1>${d.type === 'm' ? 'Endereço de política (multiassinatura / herança)' : d.type === 'q' ? 'Endereço quântico (krq)' : 'Endereço transparente'}</h1>
<section class="panel"><p class="mono">${esc(addr)}</p><div class="big">${formatKRV(d.balance)}</div>
<p class="muted">${d.utxos.length} saída(s) não gasta(s)${d.utxos.some((u) => !u.mature) ? ' · parte ainda amadurecendo (recompensa de mineração recente)' : ''}</p>
${d.type === 'q' ? '<div class="note">Gastar daqui exige duas assinaturas ao mesmo tempo: Schnorr (secp256k1) e ML-DSA-44 (NIST FIPS 204, resistente a computadores quânticos). As chaves ficam escondidas atrás de um hash até o primeiro gasto.</div>' : ''}
${d.type === 'm' ? '<div class="note">As regras deste endereço (quais chaves, quantas assinaturas, prazos) estão escondidas atrás de um hash e só aparecem na rede quando o saldo é gasto.</div>' : ''}</section>
<section class="panel"><h2>Histórico recente</h2><table><tr><th>Transação</th><th>Tipo</th><th class="right">Efeito no saldo</th><th>Situação</th></tr>${rows || '<tr><td class="muted" colspan="4">nenhuma transação ainda</td></tr>'}</table></section>`);
  }

  // ------------------------------------------------------------ busca
  async function search(q) {
    q = String(q ?? '').trim();
    if (isHash(q.toLowerCase())) {
      const h = q.toLowerCase();
      try { await call('getblock', { hash: h }); return `/bloco/${h}`; } catch { /* não é bloco */ }
      try { await call('gettransaction', { txid: h }); return `/tx/${h}`; } catch { /* não é tx */ }
      return null;
    }
    if (q.startsWith('@') || isValidName(normalizeName(q))) {
      const n = normalizeName(q);
      if (isValidName(n) && (q.startsWith('@') || (await call('resolvename', { name: n })).status !== 'livre')) return `/nome/${n}`;
    }
    try { decodeAddress(params, q); return `/endereco/${encodeURIComponent(q.toLowerCase())}`; } catch { return null; }
  }

  // ------------------------------------------------------------ @nome
  async function namePage(raw) {
    const n = normalizeName(raw);
    if (!isValidName(n)) throw new Error('nome inválido');
    const d = await call('resolvename', { name: n });
    const when = (sec) => new Date(Date.now() + sec * 1000).toLocaleDateString('pt-BR');
    if (d.status === 'livre') {
      return page(params, `@${n}`, `<h1>@${esc(n)}</h1><section class="panel"><div class="big">livre</div>
<p class="muted">Ninguém registrou este nome (ou o registro venceu e passou da carência).</p>
<div class="note">Registrar custa ${formatKRV(BigInt(d.fee))} por ano — a taxa vai inteira para o Fundo de Segurança, que paga os mineradores do futuro.</div></section>`);
    }
    const types = { t: 'transparente', s: 'privado', q: 'quântico', m: 'multiassinatura' };
    return page(params, `@${n}`, `<h1>@${esc(n)} <span class="chip ${d.status === 'ativo' ? 'chain' : 'red'}">${esc(d.status)}</span></h1>
<section class="panel"><table class="kv">
<tr><td>Aponta para</td><td>${d.targetType === 's' ? `<span class="mono">${esc(short(d.target, 18, 10))}</span> <span class="chip priv">endereço privado</span>` : addrLink(d.target)} <span class="muted">(${esc(types[d.targetType] ?? d.targetType)})</span></td></tr>
<tr><td>Dono</td><td>${addrLink(d.owner)}</td></tr>
<tr><td>Vence em</td><td>${esc(when(d.expiresIn))}${d.status !== 'ativo' ? ` — carência até ${esc(when(d.graceEndsIn))}: só o dono pode renovar` : ''}</td></tr>
<tr><td>Depósito</td><td>${formatKRV(BigInt(d.deposit))} <span class="muted">(volta ao dono se ele liberar o nome)</span></td></tr>
<tr><td>Último registro</td><td>${txLink(d.txid)}</td></tr>
<tr><td>Renovação</td><td>${formatKRV(BigInt(d.fee))} por ano</td></tr>
</table>
${d.targetType === 's' ? '<div class="note">O nome é público, mas os pagamentos para ele não: cada um vai para um endereço de uso único, com valor oculto.</div>' : ''}</section>`);
  }

  // ------------------------------------------------------------ roteamento
  const server = http.createServer(async (req, res) => {
    const send = (code, body, type = 'text/html; charset=utf-8') => {
      res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:" });
      res.end(body);
    };
    const notFound = (msg) => send(404, page(params, 'Não encontrado', `<h1>Não encontrado</h1><section class="panel"><p>${esc(msg)}</p><p><a href="/">Voltar ao painel</a></p></section>`));
    try {
      if (req.method !== 'GET') return send(405, 'método não permitido', 'text/plain');
      const url = new URL(req.url, 'http://x');
      const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      const [a, b] = parts;
      if (!a) return send(200, await homePage());
      if (a === 'busca') {
        const to = await search(url.searchParams.get('q'));
        if (!to) return notFound(`Nada encontrado para "${url.searchParams.get('q') ?? ''}". Procure por um hash de bloco, um txid ou um endereço desta rede.`);
        res.writeHead(302, { location: to }); return res.end();
      }
      if (a === 'bloco' && isHash(b ?? '')) return send(200, await blockPage(b));
      if (a === 'tx' && isHash(b ?? '')) return send(200, await txPage(b));
      if (a === 'endereco' && b) return send(200, await addressPage(b));
      if (a === 'nome' && b) return send(200, await namePage(b));
      if (a === 'api') {
        const j = (o) => send(200, json(o), 'application/json; charset=utf-8');
        const c = parts[2];
        if (b === 'painel') return j(await panel());
        if (b === 'info') return j(await call('getinfo'));
        if (b === 'dag') return j(await call('getdag', { limit: Number(url.searchParams.get('n') ?? 80) }));
        if (b === 'bloco' && isHash(c ?? '')) return j(await blockData(c));
        if (b === 'tx' && isHash(c ?? '')) return j(await txDetail(c));
        if (b === 'endereco' && c) return j(await addressData(c));
        if (b === 'nome' && c) return j(await call('resolvename', { name: c }));
        return send(404, json({ error: 'rota desconhecida' }), 'application/json');
      }
      return notFound('Página inexistente.');
    } catch (e) {
      const msg = /desconhecid|inválid|outra rede|bech32/i.test(e.message) ? e.message : 'erro ao consultar o nó';
      if (!/desconhecid|inválid|outra rede|bech32/i.test(e.message)) log('explorador: ' + e.message);
      return notFound(msg);
    }
  });
  return new Promise((ok, err) => {
    server.once('error', err);
    server.listen(port, host, () => ok({ server, url: `http://${host}:${port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) }));
  });
}
