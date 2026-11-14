// Servidor para CARTEIRAS LEVES — qualquer pessoa roda ao lado de um nó completo e expõe na
// internet. Ele NÃO recebe chaves e só oferece consultas seguras (somente leitura + transmitir
// transações já assinadas). O RPC do nó continua fechado em 127.0.0.1.
//
//   GET  /v1/info                    ponta da rede (com o cabeçalho, para a carteira checar a PoW)
//   GET  /v1/compact?start=&count=   saídas privadas compactas, BINÁRIO: 35 bytes por saída
//   POST /v1/outputs {indices}       saídas privadas completas (a carteira mistura iscas no pedido)
//   GET  /v1/keyimages/<prefixo>     imagens de chave gastas de um "balde" (1/256 do total)
//   POST /v1/utxos {locks}           moedas transparentes de endereços (que já são públicos)
//   GET  /v1/tx/<txid>               transação completa
//   GET  /v1/proof/<txid>?depth=     prova de aceitação: Merkle + cabeçalhos com PoW por cima
//   POST /v1/broadcast {tx}          transmite uma transação já assinada
//   GET  /v1/fcmp/anchor             âncora madura da árvore de todas as saídas privadas
//   POST /v1/fcmp/path {anchor, chunks}  caminhos de vários pedaços (o real misturado a iscas)
//   GET  /v1/name/<nome> · POST /v1/names {owners} · GET /v1/history/<endereço>
//   POST /v1/scan {viewKey,…}        OPCIONAL: varredura delegada (o cliente entrega a chave de
//                                    visualização; o servidor passa a ver os valores recebidos)
//
// CORS liberado (navegador/celular) e limite de requisições por IP.

import http from 'node:http';
import { rpc } from '../node/rpcclient.js';
import { decodeViewKey } from '../address.js';
import { Point } from '../crypto/secp256k1.js';
import { scanShieldedOutput, subaddressKeys } from '../crypto/stealth.js';
import { fromHex } from '../util/bytes.js';

const MAX_BODY = 2_000_000;

export async function startLightServer({ params, rpcUrl, port = 8090, host = '127.0.0.1', log = () => {}, perSec = 50, burst = 300, onRequest = null }) {
  const call = (m, p = {}) => rpc(rpcUrl, m, p);
  const buckets = new Map();
  const allow = (ip, cost) => {
    const now = Date.now();
    let b = buckets.get(ip);
    if (!b) { b = { tokens: burst, at: now }; buckets.set(ip, b); if (buckets.size > 50_000) buckets.clear(); }
    b.tokens = Math.min(burst, b.tokens + ((now - b.at) / 1000) * perSec);
    b.at = now;
    if (b.tokens < cost) return false;
    b.tokens -= cost;
    return true;
  };
  const headers = {
    'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
  };
  const sendJson = (res, code, o) => { res.writeHead(code, { ...headers, 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };

  async function route(method, path, query, body) {
    let m;
    if (method === 'GET' && path === '/v1/info') {
      const i = await call('getinfo');
      const tip = await call('getheader', { hash: i.virtual.selectedParent });
      return { json: { network: params.name, daaScore: i.virtual.daaScore, blueScore: i.virtual.blueScore, outputs: i.shieldedOutputs, tip: { hash: tip.hash, header: tip.header }, server: 'krevo-light/1' } };
    }
    if (method === 'GET' && path === '/v1/compact') {
      const r = await call('getcompactoutputs', { start: Number(query.get('start') ?? 0), count: Math.min(Number(query.get('count') ?? 5000), 20_000) });
      const head = Buffer.alloc(20);
      head.writeUInt32LE(r.total, 0); head.writeUInt32LE(r.start, 4); head.writeUInt32LE(r.count, 8); head.writeBigUInt64LE(BigInt(r.daaScore), 12);
      return { binary: Buffer.concat([head, fromHex(r.data)]), cost: Math.ceil(r.count / 2000) };
    }
    if (method === 'POST' && path === '/v1/outputs') {
      const idx = (body.indices ?? []).map(Number).filter((n) => Number.isInteger(n) && n >= 0).slice(0, 512);
      return { json: await call('getshieldedbyindex', { indices: idx }), cost: Math.ceil(idx.length / 100) };
    }
    if (method === 'GET' && (m = path.match(/^\/v1\/keyimages\/([0-9a-f]{2})$/))) return { json: await call('getkeyimagebucket', { prefix: m[1] }) };
    if (method === 'POST' && path === '/v1/utxos') return { json: await call('getutxos', { locks: (body.locks ?? []).slice(0, 16) }) };
    if (method === 'GET' && (m = path.match(/^\/v1\/tx\/([0-9a-f]{64})$/))) return { json: await call('gettransaction', { txid: m[1] }) };
    if (method === 'GET' && (m = path.match(/^\/v1\/proof\/([0-9a-f]{64})$/))) {
      const depth = Math.min(Number(query.get('depth') ?? 100), 2000);
      return { json: await call('gettxproof', { txid: m[1], depth }), cost: Math.ceil(depth / 200) };
    }
    if (method === 'GET' && path === '/v1/fcmp/anchor') return { json: await call('getfcmpanchor', {}) };
    if (method === 'POST' && path === '/v1/fcmp/path') {
      const chunks = (body.chunks ?? []).slice(0, 16);
      return { json: await call('getfcmppath', { anchor: Number(body.anchor), chunks }), cost: chunks.length };
    }
    if (method === 'POST' && path === '/v1/broadcast') return { json: await call('sendrawtransaction', { tx: String(body.tx ?? '') }), cost: 5 };
    if (method === 'GET' && (m = path.match(/^\/v1\/name\/([^/]+)$/))) return { json: await call('resolvename', { name: decodeURIComponent(m[1]) }) };
    if (method === 'POST' && path === '/v1/names') return { json: await call('listnames', { owners: (body.owners ?? []).slice(0, 16) }) };
    if (method === 'GET' && (m = path.match(/^\/v1\/history\/([^/]+)$/))) return { json: await call('getaddresshistory', { address: decodeURIComponent(m[1]) }) };
    if (method === 'POST' && path === '/v1/scan') {
      // varredura delegada: troca privacidade por economia de bateria/CPU no aparelho
      const { a, B } = decodeViewKey(params, String(body.viewKey ?? ''));
      const subs = Math.max(1, Math.min(Number(body.subaddresses ?? 1), 1000));
      const table = new Map();
      for (let i = 0; i < subs; i++) table.set(subaddressKeys(a, B, i).D.hex(), i);
      const start = Math.max(0, Number(body.start ?? 0)), count = Math.min(Number(body.count ?? 5000), 20_000);
      const matches = [];
      let i = start, total = 0;
      while (i < start + count) {
        const r = await call('getshieldedoutputs', { start: i, count: Math.min(2000, start + count - i) });
        total = r.total;
        for (const e of r.outputs) {
          const o = { P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)), encAmount: fromHex(e.encAmount), viewTag: e.viewTag };
          if (scanShieldedOutput({ a, B, table }, Point.fromBytes(fromHex(e.R)), e.j, o)) matches.push(e.index);
        }
        if (!r.outputs.length) break;
        i += r.outputs.length;
      }
      return { json: { matches, scanned: i - start, total }, cost: Math.ceil(count / 200) };
    }
    return null;
  }

  const server = http.createServer(async (req, res) => {
    const ip = req.socket.remoteAddress ?? '?';
    try {
      if (req.method === 'OPTIONS') { res.writeHead(204, headers); return res.end(); }
      const url = new URL(req.url, 'http://x');
      let raw = '';
      for await (const c of req) { raw += c; if (raw.length > MAX_BODY) { res.writeHead(413, headers); return res.end(); } }
      const body = raw ? JSON.parse(raw) : {};
      if (!allow(ip, 1)) return sendJson(res, 429, { error: 'muitas requisições; tente de novo em instantes' });
      onRequest?.({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body });
      const out = await route(req.method, url.pathname.replace(/\/+$/, ''), url.searchParams, body);
      if (!out) return sendJson(res, 404, { error: 'rota desconhecida' });
      if (out.cost > 1 && !allow(ip, out.cost - 1)) return sendJson(res, 429, { error: 'muitas requisições; tente de novo em instantes' });
      if (out.binary) { res.writeHead(200, { ...headers, 'content-type': 'application/octet-stream' }); return res.end(out.binary); }
      return sendJson(res, 200, out.json);
    } catch (e) {
      return sendJson(res, 400, { error: e.message });
    }
  });
  return new Promise((ok, err) => {
    server.once('error', err);
    server.listen(port, host, () => {
      const addr = server.address();
      ok({ server, url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${addr.port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) });
    });
  });
}
