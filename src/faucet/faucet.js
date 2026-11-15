// Faucet of TEST KRV for people who operate a public test network.
//
//   krevo faucet --network testnet --file faucet-wallet.json [--port 8092] [--amount 10]
//
// Simple page + API:  GET /?to=ADDRESS  or  POST /  {"to": "..."}   →  {"ok", "txid"}
// Against abuse: one request per address every 24 h, a few per IP per hour, a global hourly cap,
// and queued sends (the wallet signs one at a time). It rejects addresses of other networks and
// refuses to run on mainnet.

import http from 'node:http';
import { decodeAddress } from '../address.js';
import { formatKRV, COIN } from '../params.js';

const DAY = 24 * 3600_000, HOUR = 3600_000;

export class FaucetLimits {
  constructor({ perIpPerHour = 3, perHour = 120, addressCooldownMs = DAY, now = () => Date.now() } = {}) {
    Object.assign(this, { perIpPerHour, perHour, addressCooldownMs, now });
    this.byAddress = new Map(); // address → time of the last payment
    this.byIp = new Map();      // ip → times within the last hour
    this.recent = [];           // times within the last hour (all requests)
  }
  /** Throws (with a message for the user) if the request exceeds the limits; otherwise records it. */
  take(ip, address) {
    const t = this.now();
    this.recent = this.recent.filter((x) => t - x < HOUR);
    const ipList = (this.byIp.get(ip) ?? []).filter((x) => t - x < HOUR);
    const last = this.byAddress.get(address);
    if (last !== undefined && t - last < this.addressCooldownMs) {
      throw new Error(`this address already received coins; try again in ${Math.ceil((this.addressCooldownMs - (t - last)) / HOUR)} h`);
    }
    if (ipList.length >= this.perIpPerHour) throw new Error('too many requests from this IP address; try again in an hour');
    if (this.recent.length >= this.perHour) throw new Error('the faucet is very busy; try again shortly');
    ipList.push(t); this.byIp.set(ip, ipList); this.recent.push(t); this.byAddress.set(address, t);
    // occasional cleanup
    if (this.byAddress.size > 100_000) for (const [a, x] of this.byAddress) if (t - x >= this.addressCooldownMs) this.byAddress.delete(a);
    if (this.byIp.size > 100_000) this.byIp.clear();
  }
  /** Gives the quota back if sending failed (the user is not penalized for a faucet error). */
  undo(ip, address) {
    this.byAddress.delete(address);
    const l = this.byIp.get(ip); if (l) l.pop();
    this.recent.pop();
  }
}

const page = (params, amount, balance) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Krevo ${params.name} faucet</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 16px;background:#0d0916;color:#f2eefc}
input,button{font:inherit;padding:.7rem;border-radius:14px;border:1px solid #2c2347;background:#1f1736;color:inherit;width:100%;box-sizing:border-box}
button{background:linear-gradient(135deg,#7c3aed,#9333ea);color:#fff;border:0;font-weight:700;margin-top:.6rem;cursor:pointer}#r{margin-top:1rem;word-break:break-all}h1{letter-spacing:-.02em}</style></head>
<body><h1>Krevo ${params.name} faucet</h1>
<p>Sends <b>${formatKRV(amount)}</b> of TEST coins (worth nothing) to your address. One request per address every 24 h.</p>
<p>Faucet balance: ${formatKRV(balance)}</p>
<form id="f"><input id="a" placeholder="your address ${params.hrp.s}1… or ${params.hrp.t}1…" autocomplete="off" required>
<button>Get test KRV</button></form><div id="r"></div>
<script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const r=document.getElementById('r');r.textContent='sending…';
const x=await fetch('/',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({to:document.getElementById('a').value.trim()})}).then(r=>r.json()).catch(e=>({error:e.message}));
r.textContent=x.ok?'sent! transaction '+x.txid:'error: '+x.error;};</script></body></html>`;

/**
 * Starts the faucet. wallet: a wallet (Wallet or LightWallet) with a TRANSPARENT balance.
 * trustProxy: use X-Forwarded-For (only behind a reverse proxy of your own).
 */
export function startFaucet({ wallet, params, port = 8092, host = '127.0.0.1', amount = 10n * COIN, limits = new FaucetLimits(), trustProxy = false, log = () => {} }) {
  if (params.name === 'mainnet') return Promise.reject(new Error('the faucet only runs on test networks'));
  let queue = Promise.resolve();
  let balance = 0n;
  const refresh = async () => { try { await wallet.sync(); balance = wallet.balance().transparent; } catch { /* node unavailable: try later */ } };
  const timer = setInterval(refresh, 15_000);
  refresh();

  const reply = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' }); res.end(JSON.stringify(obj)); };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const ip = (trustProxy && String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
    const handle = (to) => {
      if (!to) return reply(res, 400, { ok: false, error: 'enter the address (to)' });
      try {
        const a = decodeAddress(params, to);
        if (a.type !== 't' && a.type !== 's' && a.type !== 'q') throw new Error('use a transparent, private or quantum-safe address');
      } catch (e) { return reply(res, 400, { ok: false, error: `invalid address: ${e.message}` }); }
      try { limits.take(ip, to); } catch (e) { return reply(res, 429, { ok: false, error: e.message }); }
      queue = queue.then(async () => {
        try {
          if (balance < amount + COIN / 100n) { await refresh(); if (balance < amount + COIN / 100n) throw new Error('the faucet is out of coins; try again later'); }
          const r = await wallet.send({ to, amount, from: 'transparent' });
          balance -= amount + r.fee;
          log(`faucet: ${formatKRV(amount)} → ${to.slice(0, 20)}… (tx ${r.txid.slice(0, 12)}…)`);
          reply(res, 200, { ok: true, txid: r.txid, amount: amount.toString() });
        } catch (e) {
          limits.undo(ip, to);
          reply(res, 503, { ok: false, error: e.message });
        }
      });
    };
    if (req.method === 'GET' && url.pathname === '/') {
      const to = url.searchParams.get('to') ?? url.searchParams.get('para'); // "para": older versions
      if (to) return handle(to.trim());
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'" });
      return res.end(page(params, amount, balance));
    }
    if (req.method === 'POST' && url.pathname === '/') {
      let body = '';
      req.on('data', (d) => { body += d; if (body.length > 4096) req.destroy(); });
      req.on('end', () => { let to; try { const j = JSON.parse(body); to = String(j.to ?? j.para ?? '').trim(); } catch { /* invalid body */ } handle(to); });
      return;
    }
    reply(res, 404, { ok: false, error: 'not found' });
  });
  return new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(port, host, () => {
      log(`${params.name} faucet at http://${host}:${server.address().port} (${formatKRV(amount)} per request)`);
      ok({ server, port: server.address().port, close: () => new Promise((r) => { clearInterval(timer); server.closeAllConnections?.(); server.close(() => r()); }) });
    });
  });
}
