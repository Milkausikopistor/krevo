// Pool de mineração do Krevo.
//
// Mineradores pequenos juntam poder de mineração e recebem de forma proporcional e
// frequente, em vez de esperar a sorte de achar um bloco sozinhos.
//
//  • Protocolo de shares (JSON por linha sobre TCP, no estilo Stratum):
//      → {"id":1,"method":"login","params":{"address":"krv1…|krs1…","worker":"rig1"}}
//      ← {"method":"job","params":{"jobId","prePowHash","timestamp","target"}}
//      → {"id":2,"method":"submit","params":{"jobId","nonce","timestamp"}}
//      ← {"id":2,"result":{"accepted":true,"block":false}}  ou  {"id":2,"error":"…"}
//  • Share = prova de trabalho com alvo mais fácil que o do bloco: mede o esforço de cada um.
//    Dificuldade ajustada por minerador (vardiff, ~1 share a cada 2 s). Se a share também
//    cumpre o alvo do bloco, o pool envia o bloco à rede.
//  • Divisão PPLNT: a recompensa REAL de cada bloco do pool (consultada no nó) é dividida,
//    depois de amadurecer, entre as shares dos últimos 60 s antes de o bloco ser achado,
//    proporcionalmente à dificuldade de cada share. Bloco vermelho não paga (como na rede).
//  • Pagamentos em lote: quem passa do mínimo recebe numa única transação, para endereço
//    transparente OU privado (o minerador escolhe ao conectar).
//  • Página web com estatísticas e API JSON.

import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import { rpc } from '../node/rpcclient.js';
import { Block } from '../consensus/block.js';
import { PowState, compactToTarget, targetToLE, hashMeetsTarget } from '../consensus/pow.js';
import { scheduledSubsidy } from '../consensus/emission.js';
import { decodeAddress } from '../address.js';
import { formatKRV, COIN } from '../params.js';
import { toHex, fromHex } from '../util/bytes.js';
import { CSS } from '../explorer/server.js';

const TWO256 = 1n << 256n;
export const MIN_WEIGHT = 256;
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (a) => (a.length > 26 ? `${a.slice(0, 16)}…${a.slice(-6)}` : a);

/** Alvo de share para uma "dificuldade" (hashes esperados por share), nunca mais difícil que o bloco. */
export function targetForWeight(w, blockTarget) {
  let t = TWO256 / BigInt(Math.max(1, Math.round(w))) - 1n;
  if (t < blockTarget) t = blockTarget;
  if (t >= TWO256) t = TWO256 - 1n;
  return t;
}
export const weightOfTarget = (t) => Number(TWO256 / (t + 1n));

/** Divide `net` grãos proporcionalmente aos pesos. A soma nunca passa de `net`. */
export function splitReward(net, weights) {
  const entries = Object.entries(weights).filter(([, w]) => w > 0);
  const total = entries.reduce((a, [, w]) => a + w, 0);
  const out = new Map();
  if (!total || net <= 0n) return out;
  const SCALE = 1_000_000_000_000n;
  for (const [addr, w] of entries) {
    const part = (net * BigInt(Math.floor((w / total) * 1e12))) / SCALE;
    if (part > 0n) out.set(addr, part);
  }
  return out;
}

/** Vardiff: mira ~targetRate shares/s por minerador; muda no máximo 4× por ajuste. */
export function nextWeight(w, sharesPerSec, targetRate = 0.5) {
  const f = sharesPerSec <= 0 ? 0.5 : Math.min(4, Math.max(0.25, sharesPerSec / targetRate));
  return Math.max(MIN_WEIGHT, w * f);
}

export function parseDuration(s) {
  const m = /^(\d+(?:[.,]\d+)?)\s*(ms|s|min|h)?$/i.exec(String(s).trim());
  if (!m) throw new Error(`duração inválida: "${s}" (ex.: 30s, 5min, 1h)`);
  const n = Number(m[1].replace(',', '.'));
  return Math.round(n * { ms: 1, s: 1000, min: 60_000, h: 3_600_000 }[(m[2] ?? 's').toLowerCase()]);
}

export async function startPool({
  params, rpcUrl, wallet, port = 5555, host = '0.0.0.0', webPort = 8081, webHost = '127.0.0.1',
  feePct = 1, minPayout = COIN, payoutEveryMs = 60_000, windowMs = 60_000, stateFile = null, log = () => {},
}) {
  const call = (m, p) => rpc(rpcUrl, m, p);
  const poolAddress = wallet.tAddress;

  // ------------------------------------------------------------ estado
  const balances = new Map(), paid = new Map();
  let blocks = [], payments = [], poolEarned = 0n;
  if (stateFile && fs.existsSync(stateFile)) {
    const s = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    for (const [a, v] of Object.entries(s.balances ?? {})) balances.set(a, BigInt(v));
    for (const [a, v] of Object.entries(s.paid ?? {})) paid.set(a, BigInt(v));
    blocks = (s.blocks ?? []).map((b) => ({ ...b, reward: b.reward === null ? null : BigInt(b.reward), credited: BigInt(b.credited ?? 0) }));
    payments = (s.payments ?? []).map((p) => ({ ...p, total: BigInt(p.total), fee: BigInt(p.fee) }));
    poolEarned = BigInt(s.poolEarned ?? 0);
    log(`pool: estado recuperado (${balances.size} mineradores, ${blocks.length} blocos)`);
  }
  let saveTimer = null;
  const save = () => {
    if (!stateFile || saveTimer) return;
    saveTimer = setTimeout(() => {
      saveTimer = null;
      const j = JSON.stringify({ balances: Object.fromEntries(balances), paid: Object.fromEntries(paid), blocks: blocks.slice(-2000), payments: payments.slice(-500), poolEarned },
        (_, v) => (typeof v === 'bigint' ? v.toString() : v));
      fs.writeFileSync(stateFile + '.tmp', j);
      fs.renameSync(stateFile + '.tmp', stateFile); // escrita atômica
    }, 500);
  };

  // ------------------------------------------------------------ trabalhos
  const jobs = new Map();
  let current = null, jobSeq = 0;
  const shares = [];                 // { addr, w, time } — janela PPLNT
  const clients = new Set();
  const stats = { sharesOk: 0, sharesBad: 0, found: 0, since: Date.now() };

  function newJob(t) {
    const header = Block.deserialize(fromHex(t.block)).header;
    const blockTarget = compactToTarget(t.bits);
    current = {
      id: String(++jobSeq), hex: t.block, prePowHash: t.prePowHash, timestamp: header.timestamp, daa: header.daaScore,
      blockTarget, blockTargetLE: targetToLE(blockTarget), blockWork: weightOfTarget(blockTarget), pow: null, seen: new Set(), created: Date.now(),
    };
    jobs.set(current.id, current);
    for (const [id, j] of jobs) if (Date.now() - j.created > 15_000 && id !== current.id) jobs.delete(id); // blocos "atrasados" ainda servem num DAG
    for (const c of clients) sendJob(c);
  }

  function sendJob(c) {
    if (!current || !c.address) return;
    const t = targetForWeight(c.weight, current.blockTarget);
    c.targets.set(current.id, { t, tLE: targetToLE(t), w: weightOfTarget(t) });
    if (c.targets.size > 64) c.targets.delete(c.targets.keys().next().value);
    write(c, { method: 'job', params: { jobId: current.id, prePowHash: current.prePowHash, timestamp: current.timestamp, target: toHex(targetToLE(t)) } });
  }

  let running = true;
  (async () => {
    let longpollid = null;
    while (running) {
      try {
        const t = await call('getblocktemplate', { address: poolAddress, longpollid });
        if (t.longpollid !== longpollid) { longpollid = t.longpollid; newJob(t); }
      } catch (e) {
        if (running) { log('pool: nó indisponível — ' + e.message); await new Promise((r) => setTimeout(r, 1000)); }
      }
    }
  })();

  // ------------------------------------------------------------ mineradores
  const write = (c, o) => { if (!c.sock.destroyed) c.sock.write(JSON.stringify(o) + '\n'); };

  function windowWeights(now = Date.now()) {
    const w = {};
    for (const s of shares) if (now - s.time <= windowMs) w[s.addr] = (w[s.addr] ?? 0) + s.w;
    return w;
  }

  async function submitBlock(job, nonce, ts) {
    const b = Block.deserialize(fromHex(job.hex));
    b.header.nonce = nonce;
    b.header.timestamp = ts;
    b._hash = null;
    try {
      const r = await call('submitblock', { block: toHex(b.serialize()) });
      if (r.status === 'accepted') {
        blocks.push({ hash: r.hash, time: Date.now(), daa: b.header.daaScore, weights: windowWeights(), status: 'pendente', reward: null, credited: 0n });
        stats.found++;
        save();
      }
    } catch (e) { log('pool: erro ao enviar bloco — ' + e.message); }
  }

  function handle(c, msg) {
    const reply = (result) => write(c, { id: msg.id ?? null, result });
    const error = (e) => write(c, { id: msg.id ?? null, error: e });
    if (msg.method === 'login') {
      if (c.address) return error('login: já autenticado');
      const address = String(msg.params?.address ?? '');
      try { decodeAddress(params, address); } catch (e) { return error('login: endereço inválido — ' + e.message); }
      c.address = address;
      c.worker = String(msg.params?.worker ?? '').slice(0, 32).replace(/[^\w.-]/g, '');
      c.weight = Math.max(MIN_WEIGHT, (current?.blockWork ?? MIN_WEIGHT * 64) / 64);
      reply({ login: true, fee: feePct, payout: { min: minPayout.toString(), everySeconds: payoutEveryMs / 1000 } });
      return sendJob(c);
    }
    if (msg.method === 'submit') {
      if (!c.address) return error('faça login antes');
      const { jobId, nonce, timestamp } = msg.params ?? {};
      const job = jobs.get(String(jobId)), tgt = c.targets.get(String(jobId));
      if (!job || !tgt) { stats.sharesBad++; return error('trabalho expirado'); }
      let n;
      try { n = BigInt(nonce); if (n < 0n || n >= 1n << 64n) throw 0; } catch { c.bad++; return error('nonce inválido'); }
      const ts = Number(timestamp);
      if (!Number.isSafeInteger(ts) || ts < job.timestamp || ts > Date.now() + 10_000) { c.bad++; return error('timestamp inválido'); }
      const key = `${n}:${ts}`;
      if (job.seen.has(key)) { c.bad++; stats.sharesBad++; return error('share repetida'); }
      job.seen.add(key);
      job.pow ??= new PowState(fromHex(job.prePowHash));
      const h = job.pow.hash(ts, n);
      if (!hashMeetsTarget(h, tgt.tLE)) {
        c.bad++; stats.sharesBad++;
        if (c.bad > 50) c.sock.destroy();
        return error('share abaixo da dificuldade');
      }
      const now = Date.now();
      shares.push({ addr: c.address, w: tgt.w, time: now });
      c.times.push(now);
      stats.sharesOk++;
      const isBlock = hashMeetsTarget(h, job.blockTargetLE);
      if (isBlock) submitBlock(job, n, ts);
      reply({ accepted: true, block: isBlock });
      // vardiff
      if (now - c.lastAdjust > 5000) {
        c.times = c.times.filter((t) => now - t <= 15_000);
        const rate = c.times.length / Math.min(15, (now - c.connected) / 1000 || 1);
        if (rate > 1 || rate < 0.2) { c.weight = nextWeight(c.weight, rate); sendJob(c); }
        c.lastAdjust = now;
      }
      return;
    }
    error('método desconhecido');
  }

  const server = net.createServer((sock) => {
    const c = { sock, buf: '', address: null, worker: '', weight: MIN_WEIGHT, targets: new Map(), times: [], bad: 0, connected: Date.now(), lastAdjust: Date.now() };
    clients.add(c);
    sock.setNoDelay(true);
    sock.on('data', (d) => {
      c.buf += d;
      if (c.buf.length > 16_384) { sock.destroy(); return; }
      let i;
      while ((i = c.buf.indexOf('\n')) >= 0) {
        const line = c.buf.slice(0, i); c.buf = c.buf.slice(i + 1);
        if (!line.trim()) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { c.bad++; if (c.bad > 50) sock.destroy(); continue; }
        try { handle(c, msg); } catch (e) { write(c, { id: msg.id ?? null, error: 'erro interno' }); log('pool: ' + e.message); }
      }
    });
    sock.on('close', () => clients.delete(c));
    sock.on('error', () => {});
  });
  await new Promise((ok, err) => { server.once('error', err); server.listen(port, host, ok); });

  // ------------------------------------------------------------ maturação e crédito
  const matureAfterMs = (params.coinbaseMaturity / params.bps) * 1000;
  function credit(b) {
    const fee = (b.reward * BigInt(Math.round(feePct * 100))) / 10_000n;
    const parts = splitReward(b.reward - fee, b.weights);
    let distributed = 0n;
    for (const [addr, v] of parts) { balances.set(addr, (balances.get(addr) ?? 0n) + v); distributed += v; }
    poolEarned += b.reward - distributed;
    b.credited = distributed;
    b.status = 'creditado';
  }
  let maturing = false;
  const matureTimer = setInterval(async () => {
    if (maturing) return;
    maturing = true;
    try {
      const now = Date.now();
      for (const b of blocks) {
        if (b.status !== 'pendente' || now - b.time < matureAfterMs * 0.8) continue;
        const r = await call('getblockreward', { hash: b.hash });
        if (r.status === 'paid') {
          b.reward = BigInt(r.amount);
          if (r.mature) { credit(b); save(); }
        } else if (r.status === 'red') { b.status = 'vermelho'; save(); }
        else if (r.status === 'unknown' || now - b.time > matureAfterMs * 20) { b.status = 'perdido'; save(); }
      }
      while (shares.length && now - shares[0].time > windowMs * 2) shares.shift();
    } catch (e) { log('pool: ' + e.message); }
    maturing = false;
  }, 1000);

  // ------------------------------------------------------------ pagamentos
  let paying = false;
  // A 10 blocos/s o pool recebe MUITAS recompensas pequenas. Cada transação de pagamento usa
  // no máximo ~140 moedas (limite de massa); por isso a rodada faz várias transações, paga
  // parcialmente quem não coube, e junta as moedinhas (consolidação) quando elas se acumulam.
  async function payoutNow() {
    if (paying) return null;
    paying = true;
    const sent = [];
    try {
      for (let round = 0; round < 6; round++) {
        const due = [...balances].filter(([, v]) => v >= minPayout).sort((a, b) => (b[1] > a[1] ? 1 : -1)).slice(0, 12);
        if (!due.length) break;
        const cap = (await wallet.capacity()).amount - COIN / 100n; // reserva para a taxa
        if (cap < minPayout || (round > 0 && cap < 5n * minPayout)) break; // evita transações minúsculas: o resto vai na próxima rodada
        let room = cap;
        const list = [];
        for (const [to, bal] of due) {
          if (room < minPayout) break;
          const amount = bal < room ? bal : room; // pagamento parcial se não couber tudo
          list.push({ to, amount });
          room -= amount;
        }
        const r = await wallet.sendMany(list);
        let total = 0n;
        for (const { to, amount } of list) {
          balances.set(to, balances.get(to) - amount);
          paid.set(to, (paid.get(to) ?? 0n) + amount);
          total += amount;
        }
        poolEarned -= r.fee; // a taxa da transação sai da parte do pool
        payments.push({ txid: r.txid, time: Date.now(), count: list.length, total, fee: r.fee });
        sent.push({ ...r, count: list.length, total });
        save();
        log(`pool: pagamento de ${formatKRV(total)} para ${list.length} minerador(es) — tx ${r.txid.slice(0, 16)}…`);
      }
      const { coins } = await wallet.capacity();
      if (coins > 300) {
        const c = await wallet.consolidate();
        if (c) log(`pool: consolidou moedas pequenas (${coins} moedas) — tx ${c.slice(0, 16)}…`);
      }
    } catch (e) {
      log('pool: pagamento adiado — ' + e.message);
    } finally { paying = false; }
    if (!sent.length) return null;
    return { txid: sent[0].txid, txs: sent.map((s) => s.txid), count: sent.reduce((a, s) => a + s.count, 0), total: sent.reduce((a, s) => a + s.total, 0n) };
  }
  const payTimer = setInterval(payoutNow, payoutEveryMs);

  // ------------------------------------------------------------ estatísticas
  function getStats() {
    const now = Date.now();
    const recent = shares.filter((s) => now - s.time <= 60_000);
    const span = Math.min(60, Math.max(1, (now - stats.since) / 1000));
    const miners = new Map();
    const ensure = (a) => { if (!miners.has(a)) miners.set(a, { address: a, hashrate: 0, shares: 0, workers: 0, immature: 0n, balance: balances.get(a) ?? 0n, paid: paid.get(a) ?? 0n }); return miners.get(a); };
    for (const s of recent) { const m = ensure(s.addr); m.hashrate += s.w / span; m.shares++; }
    for (const c of clients) if (c.address) ensure(c.address).workers++;
    for (const a of balances.keys()) ensure(a);
    const netFactor = 10_000n - BigInt(Math.round(feePct * 100));
    for (const b of blocks) {
      if (b.status !== 'pendente') continue;
      const est = ((b.reward ?? scheduledSubsidy(b.daa, params)) * netFactor) / 10_000n;
      for (const [a, v] of splitReward(est, b.weights)) ensure(a).immature += v;
    }
    const list = [...miners.values()].sort((x, y) => y.hashrate - x.hashrate);
    return {
      pool: {
        address: poolAddress, feePct, minPayout, payoutEverySeconds: payoutEveryMs / 1000, windowSeconds: windowMs / 1000,
        hashrate: list.reduce((a, m) => a + m.hashrate, 0), miners: list.filter((m) => m.workers > 0).length,
        workers: [...clients].filter((c) => c.address).length, blocksFound: blocks.length, sharesOk: stats.sharesOk, sharesBad: stats.sharesBad,
        earned: poolEarned, paidTotal: [...paid.values()].reduce((a, v) => a + v, 0n),
      },
      miners: list,
      blocks: blocks.slice(-15).reverse().map((b) => ({ hash: b.hash, time: b.time, status: b.status, reward: b.reward, credited: b.credited, miners: Object.keys(b.weights).length })),
      payments: payments.slice(-10).reverse(),
    };
  }

  const fmtH = (h) => (h >= 1e6 ? `${(h / 1e6).toFixed(2)} MH/s` : h >= 1e3 ? `${(h / 1e3).toFixed(1)} kH/s` : `${h.toFixed(0)} H/s`).replace('.', ',');
  function html() {
    const s = getStats(), p = s.pool;
    const card = (v, l) => `<div class="stat"><b>${v}</b><span>${l}</span></div>`;
    const rows = s.miners.map((m) => `<tr><td class="mono">${esc(short(m.address))}${m.address.startsWith(params.hrp.s) ? ' <span class="chip priv">privado</span>' : ''}</td><td>${fmtH(m.hashrate)}</td><td class="right">${m.shares}</td><td class="amt right muted">${formatKRV(m.immature)}</td><td class="amt right">${formatKRV(m.balance)}</td><td class="amt right">${formatKRV(m.paid)}</td></tr>`).join('');
    const brows = s.blocks.map((b) => `<tr><td class="mono">${esc(b.hash.slice(0, 16))}…</td><td class="muted">${Math.round((Date.now() - b.time) / 1000)} s atrás</td><td><span class="chip ${b.status === 'creditado' ? 'chain' : b.status === 'pendente' ? '' : 'red'}">${esc(b.status)}</span></td><td class="amt right">${b.reward !== null ? formatKRV(b.reward) : '—'}</td><td class="right">${b.miners}</td></tr>`).join('');
    const prows = s.payments.map((x) => `<tr><td class="mono">${esc(x.txid.slice(0, 16))}…</td><td class="muted">${Math.round((Date.now() - x.time) / 1000)} s atrás</td><td class="right">${x.count}</td><td class="amt right">${formatKRV(x.total)}</td></tr>`).join('');
    return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5">
<title>Pool Krevo</title><style>${CSS}</style></head><body><header><div class="bar"><span class="brand">⛏ Pool de mineração Krevo</span><span class="net">${esc(params.name)}</span></div></header><main>
<div class="stats">${card(fmtH(p.hashrate), 'poder do pool')}${card(p.miners, 'mineradores ativos')}${card(p.workers, 'máquinas conectadas')}${card(p.blocksFound, 'blocos achados')}${card(`${p.feePct}%`, 'taxa do pool')}${card(formatKRV(p.paidTotal), 'já pago aos mineradores')}</div>
<section class="panel"><h2>Como conectar</h2><p class="mono">node src/cli.js minerar --pool ENDERECO_DO_POOL:${port} --endereco SEU_ENDEREÇO --threads 4</p>
<p class="muted" style="font-size:13px">Recompensa dividida pelo método PPLNT (shares dos últimos ${p.windowSeconds} s antes de cada bloco), creditada quando a recompensa amadurece. Pagamento automático a cada ${p.payoutEverySeconds} s para saldos a partir de ${formatKRV(p.minPayout)} — inclusive para endereços privados (krs1…).</p></section>
<section class="panel"><h2>Mineradores</h2><table><tr><th>Endereço</th><th>Poder (60 s)</th><th class="right">Shares</th><th class="right">Amadurecendo</th><th class="right">Saldo a receber</th><th class="right">Já pago</th></tr>${rows || '<tr><td colspan="6" class="muted">ninguém minerando ainda</td></tr>'}</table></section>
<div class="cols"><section class="panel"><h2>Blocos do pool</h2><table><tr><th>Bloco</th><th>Quando</th><th>Situação</th><th class="right">Recompensa</th><th class="right">Mineradores</th></tr>${brows || '<tr><td colspan="5" class="muted">nenhum ainda</td></tr>'}</table></section>
<section class="panel"><h2>Pagamentos</h2><table><tr><th>Transação</th><th>Quando</th><th class="right">Mineradores</th><th class="right">Total</th></tr>${prows || '<tr><td colspan="4" class="muted">nenhum ainda</td></tr>'}</table></section></div>
</main></body></html>`;
  }
  const json = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const send = (code, body, type) => { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(body); };
    if (u.pathname === '/') return send(200, html(), 'text/html; charset=utf-8');
    if (u.pathname === '/api/stats') return send(200, json(getStats()), 'application/json');
    const m = /^\/api\/minerador\/([a-z0-9]+)$/.exec(u.pathname);
    if (m) {
      const st = getStats().miners.find((x) => x.address === m[1]);
      return st ? send(200, json(st), 'application/json') : send(404, json({ error: 'minerador desconhecido' }), 'application/json');
    }
    return send(404, 'não encontrado', 'text/plain; charset=utf-8');
  });
  await new Promise((ok, err) => { web.once('error', err); web.listen(webPort, webHost, ok); });

  return {
    stratum: `${host}:${port}`, webUrl: `http://${webHost}:${webPort}`, address: poolAddress,
    stats: getStats, payoutNow,
    async stop() {
      running = false;
      clearInterval(matureTimer); clearInterval(payTimer);
      for (const c of clients) c.sock.destroy();
      await new Promise((r) => server.close(() => r()));
      web.closeAllConnections?.();
      await new Promise((r) => web.close(() => r()));
      if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
    },
  };
}
