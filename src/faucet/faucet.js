// Torneira (faucet) de KRV de TESTE para quem opera uma rede de testes pública.
//
//   krevo torneira --rede testnet --arquivo carteira-torneira.json [--porta 8092] [--valor 10]
//
// Página simples + API:  GET /?para=ENDEREÇO  ou  POST /  {"para": "..."}   →  {"ok", "txid"}
// Contra abuso: um pedido por endereço a cada 24 h, poucos por IP por hora, teto global por hora,
// e envios em fila (a carteira assina um de cada vez). Recusa endereços de outra rede e se recusa
// a rodar na mainnet.

import http from 'node:http';
import { decodeAddress } from '../address.js';
import { formatKRV, COIN } from '../params.js';

const DAY = 24 * 3600_000, HOUR = 3600_000;

export class FaucetLimits {
  constructor({ perIpPerHour = 3, perHour = 120, addressCooldownMs = DAY, now = () => Date.now() } = {}) {
    Object.assign(this, { perIpPerHour, perHour, addressCooldownMs, now });
    this.byAddress = new Map(); // endereço → instante do último envio
    this.byIp = new Map();      // ip → instantes na última hora
    this.recent = [];           // instantes na última hora (todos)
  }
  /** Lança erro (mensagem para o usuário) se o pedido passar dos limites; senão o registra. */
  take(ip, address) {
    const t = this.now();
    this.recent = this.recent.filter((x) => t - x < HOUR);
    const ipList = (this.byIp.get(ip) ?? []).filter((x) => t - x < HOUR);
    const last = this.byAddress.get(address);
    if (last !== undefined && t - last < this.addressCooldownMs) {
      throw new Error(`este endereço já recebeu; tente de novo em ${Math.ceil((this.addressCooldownMs - (t - last)) / HOUR)} h`);
    }
    if (ipList.length >= this.perIpPerHour) throw new Error('pedidos demais deste endereço IP; tente daqui a uma hora');
    if (this.recent.length >= this.perHour) throw new Error('a torneira está muito procurada; tente daqui a pouco');
    ipList.push(t); this.byIp.set(ip, ipList); this.recent.push(t); this.byAddress.set(address, t);
    // limpeza ocasional
    if (this.byAddress.size > 100_000) for (const [a, x] of this.byAddress) if (t - x >= this.addressCooldownMs) this.byAddress.delete(a);
    if (this.byIp.size > 100_000) this.byIp.clear();
  }
  /** Devolve a cota se o envio falhou (não pune o usuário por erro da torneira). */
  undo(ip, address) {
    this.byAddress.delete(address);
    const l = this.byIp.get(ip); if (l) l.pop();
    this.recent.pop();
  }
}

const page = (params, amount, balance) => `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Torneira Krevo ${params.name}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 16px;background:#0f1419;color:#e6e6e6}
input,button{font:inherit;padding:.6rem;border-radius:8px;border:1px solid #3a4450;background:#1a2129;color:inherit;width:100%;box-sizing:border-box}
button{background:#2dd4bf;color:#062a25;font-weight:600;margin-top:.6rem;cursor:pointer}#r{margin-top:1rem;word-break:break-all}</style></head>
<body><h1>Torneira — Krevo ${params.name}</h1>
<p>Manda <b>${formatKRV(amount)}</b> de TESTE (sem valor nenhum) para o seu endereço. Um pedido por endereço a cada 24 h.</p>
<p>Saldo da torneira: ${formatKRV(balance)}</p>
<form id="f"><input id="a" placeholder="seu endereço ${params.hrp.s}1… ou ${params.hrp.t}1…" autocomplete="off" required>
<button>Pedir KRV de teste</button></form><div id="r"></div>
<script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const r=document.getElementById('r');r.textContent='enviando…';
const x=await fetch('/',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({para:document.getElementById('a').value.trim()})}).then(r=>r.json()).catch(e=>({error:e.message}));
r.textContent=x.ok?'enviado! transação '+x.txid:'erro: '+x.error;};</script></body></html>`;

/**
 * Sobe a torneira. wallet: carteira (Wallet ou LightWallet) com saldo TRANSPARENTE.
 * trustProxy: usar X-Forwarded-For (só atrás de um proxy reverso seu).
 */
export function startFaucet({ wallet, params, port = 8092, host = '127.0.0.1', amount = 10n * COIN, limits = new FaucetLimits(), trustProxy = false, log = () => {} }) {
  if (params.name === 'mainnet') return Promise.reject(new Error('torneira só em redes de teste'));
  let queue = Promise.resolve();
  let balance = 0n;
  const refresh = async () => { try { await wallet.sync(); balance = wallet.balance().transparent; } catch { /* nó indisponível: tenta depois */ } };
  const timer = setInterval(refresh, 15_000);
  refresh();

  const reply = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' }); res.end(JSON.stringify(obj)); };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const ip = (trustProxy && String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
    const handle = (to) => {
      if (!to) return reply(res, 400, { ok: false, error: 'informe o endereço (para)' });
      try {
        const a = decodeAddress(params, to);
        if (a.type !== 't' && a.type !== 's' && a.type !== 'q') throw new Error('use um endereço transparente, privado ou quântico');
      } catch (e) { return reply(res, 400, { ok: false, error: `endereço inválido: ${e.message}` }); }
      try { limits.take(ip, to); } catch (e) { return reply(res, 429, { ok: false, error: e.message }); }
      queue = queue.then(async () => {
        try {
          if (balance < amount + COIN / 100n) { await refresh(); if (balance < amount + COIN / 100n) throw new Error('a torneira está sem saldo; tente mais tarde'); }
          const r = await wallet.send({ to, amount, from: 'transparente' });
          balance -= amount + r.fee;
          log(`torneira: ${formatKRV(amount)} → ${to.slice(0, 20)}… (tx ${r.txid.slice(0, 12)}…)`);
          reply(res, 200, { ok: true, txid: r.txid, amount: amount.toString() });
        } catch (e) {
          limits.undo(ip, to);
          reply(res, 503, { ok: false, error: e.message });
        }
      });
    };
    if (req.method === 'GET' && url.pathname === '/') {
      const to = url.searchParams.get('para') ?? url.searchParams.get('to');
      if (to) return handle(to.trim());
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'" });
      return res.end(page(params, amount, balance));
    }
    if (req.method === 'POST' && url.pathname === '/') {
      let body = '';
      req.on('data', (d) => { body += d; if (body.length > 4096) req.destroy(); });
      req.on('end', () => { let to; try { const j = JSON.parse(body); to = String(j.para ?? j.to ?? '').trim(); } catch { /* corpo inválido */ } handle(to); });
      return;
    }
    reply(res, 404, { ok: false, error: 'não encontrado' });
  });
  return new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(port, host, () => {
      log(`torneira de ${params.name} em http://${host}:${server.address().port} (${formatKRV(amount)} por pedido)`);
      ok({ server, port: server.address().port, close: () => new Promise((r) => { clearInterval(timer); server.closeAllConnections?.(); server.close(() => r()); }) });
    });
  });
}
