// Bitcoin SIMULADO (estilo regtest) com a mesma API REST do mempool.space/Esplora.
//
// Serve para testar e demonstrar trocas atômicas sem dinheiro de verdade e sem instalar o
// Bitcoin Core. Não é um nó Bitcoin: não há mineração real nem rede P2P. Mas ele VALIDA de
// verdade o que importa para a troca:
//   • entradas existentes e não gastas (sem gasto duplo), soma das saídas ≤ entradas;
//   • nLockTime/finalidade pela mediana dos 11 últimos blocos (BIP-113);
//   • execução do witnessScript (P2WSH) com OP_IF/OP_SIZE/OP_SHA256/OP_CHECKLOCKTIMEVERIFY/
//     OP_CHECKSIG, regras MINIMALIF, CLEANSTACK, NULLFAIL, S baixo e DER estrito;
//   • assinaturas ECDSA sobre o hash segwit v0 (BIP-143) — o mesmo código conferido com os
//     vetores oficiais do BIP-143.
// Uso: `krevo btc-simulado` (porta 3002) — e as carteiras usam --btc-api http://127.0.0.1:3002.

import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { BtcTx } from './tx.js';
import { parseScript, OP, scriptNum, decodeScriptNum } from './script.js';
import { BTC_NETWORKS, scriptToAddress, decodeBtcAddress, sha256, hash160, hash256 } from './address.js';
import { ecdsaVerify, derDecode, isLowS } from './ecdsa.js';

const hex = (b) => Buffer.from(b).toString('hex');
const TRUE = () => Buffer.from([1]);
const FALSE = () => Buffer.alloc(0);

function castToBool(b) {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return !(i === b.length - 1 && b[i] === 0x80);
  return false;
}

function checkSig(sig, pub, scriptCode, tx, index, amount) {
  if (!sig.length) return false;
  if (sig[sig.length - 1] !== 1) throw new Error('o simulador só aceita SIGHASH_ALL');
  const rs = derDecode(sig.subarray(0, -1));
  if (!isLowS(rs)) throw new Error('assinatura com S alto (não padrão)');
  if (pub.length !== 33) throw new Error('segwit exige chave pública comprimida');
  if (!ecdsaVerify(pub, tx.sighashV0(index, scriptCode, amount), rs)) throw new Error('NULLFAIL: assinatura inválida');
  return true;
}

/** Executa um witnessScript (segwit v0). Lança erro se o gasto não for válido. */
export function runWitnessScript(script, items, { tx, index, amount }) {
  const stack = items.map((b) => Buffer.from(b));
  const exec = [];
  const pop = () => { if (!stack.length) throw new Error('pilha vazia'); return stack.pop(); };
  const top = () => { if (!stack.length) throw new Error('pilha vazia'); return stack[stack.length - 1]; };
  for (const { op, data } of parseScript(script)) {
    const running = exec.every(Boolean);
    if (op === OP.OP_IF || op === OP.OP_NOTIF) {
      let v = false;
      if (running) {
        const c = pop();
        if (c.length > 1 || (c.length === 1 && c[0] !== 1)) throw new Error('MINIMALIF: o argumento do OP_IF deve ser vazio ou 01');
        v = c.length === 1;
        if (op === OP.OP_NOTIF) v = !v;
      }
      exec.push(v);
      continue;
    }
    if (op === OP.OP_ELSE) { if (!exec.length) throw new Error('OP_ELSE sem OP_IF'); exec[exec.length - 1] = !exec[exec.length - 1]; continue; }
    if (op === OP.OP_ENDIF) { if (!exec.length) throw new Error('OP_ENDIF sem OP_IF'); exec.pop(); continue; }
    if (!running) continue;
    if (data !== undefined) { stack.push(data); continue; }
    if (op === OP.OP_0) { stack.push(FALSE()); continue; }
    if (op >= OP.OP_1 && op <= OP.OP_16) { stack.push(scriptNum(op - 0x50)); continue; }
    switch (op) {
      case OP.OP_VERIFY: if (!castToBool(pop())) throw new Error('OP_VERIFY falhou'); break;
      case OP.OP_DROP: pop(); break;
      case OP.OP_DUP: stack.push(Buffer.from(top())); break;
      case OP.OP_SIZE: stack.push(scriptNum(top().length)); break;
      case OP.OP_EQUAL:
      case OP.OP_EQUALVERIFY: {
        const eq = pop().equals(pop());
        if (op === OP.OP_EQUALVERIFY) { if (!eq) throw new Error('OP_EQUALVERIFY falhou (segredo ou tamanho errado?)'); }
        else stack.push(eq ? TRUE() : FALSE());
        break;
      }
      case OP.OP_SHA256: stack.push(sha256(pop())); break;
      case OP.OP_HASH160: stack.push(hash160(pop())); break;
      case OP.OP_CHECKSIG: {
        const pub = pop(), sig = pop();
        stack.push(checkSig(sig, pub, script, tx, index, amount) ? TRUE() : FALSE());
        break;
      }
      case OP.OP_CHECKLOCKTIMEVERIFY: {
        const lt = decodeScriptNum(top(), 5);
        const txLt = BigInt(tx.locktime);
        if (lt < 0n) throw new Error('CLTV com prazo negativo');
        if ((lt < 500_000_000n) !== (txLt < 500_000_000n)) throw new Error('CLTV: tipos de prazo diferentes');
        if (lt > txLt) throw new Error('CLTV: o nLockTime da transação é anterior ao prazo do contrato');
        if (tx.inputs[index].sequence === 0xffffffff) throw new Error('CLTV: nSequence não pode ser final');
        break;
      }
      default: throw new Error(`opcode 0x${op.toString(16)} não suportado pelo simulador`);
    }
  }
  if (exec.length) throw new Error('OP_IF sem OP_ENDIF');
  if (stack.length !== 1) throw new Error('CLEANSTACK: a pilha deve terminar com um único elemento');
  if (!castToBool(stack[0])) throw new Error('o script terminou com falso');
}

export class SimBitcoin {
  constructor({ net = BTC_NETWORKS.regtest, time = Math.floor(Date.now() / 1000), spacing = 1 } = {}) {
    this.net = net;
    this.blocks = [];
    this.txs = new Map();      // txid → { tx, prevouts, height (null = mempool) }
    this.utxos = new Map();    // "txid:vout" → { txid, vout, value, script }
    this.spentBy = new Map();  // "txid:vout" → txid que gastou
    this.byAddr = new Map();   // endereço → [txid]
    this.mempool = [];
    // 11 blocos iniciais, para a mediana de tempo já fazer sentido
    for (let i = 10; i >= 0; i--) this._block(time - i * spacing);
  }

  get tip() { return this.blocks[this.blocks.length - 1]; }
  mtp(height = this.tip.height) {
    const ts = this.blocks.slice(Math.max(0, height - 10), height + 1).map((b) => b.time).sort((a, b) => a - b);
    return ts[Math.floor(ts.length / 2)];
  }

  _block(time) {
    const height = this.blocks.length;
    const hash = hash256(Buffer.concat([Buffer.from(String(height)), Buffer.from(String(time)), randomBytes(8)])).reverse().toString('hex');
    const txids = this.mempool.splice(0);
    for (const id of txids) this.txs.get(id).height = height;
    this.blocks.push({ height, hash, time, txids });
  }

  /** Mineira n blocos; dt = segundos entre blocos (padrão: acompanha o relógio real). */
  mine(n = 1, dt) {
    for (let i = 0; i < n; i++) {
      const t = dt === undefined ? Math.max(this.tip.time + 1, Math.floor(Date.now() / 1000)) : this.tip.time + dt;
      this._block(t);
    }
    return { height: this.tip.height, time: this.tip.time, mtp: this.mtp() };
  }

  _index(address, txid) {
    if (!address) return;
    let a = this.byAddr.get(address);
    if (!a) this.byAddr.set(address, (a = []));
    if (a[a.length - 1] !== txid) a.push(txid);
  }

  _accept(txid, tx, prevouts) {
    this.txs.set(txid, { tx, prevouts, height: null });
    tx.inputs.forEach((inp, n) => {
      if (!prevouts[n]) return;
      const k = `${inp.txid}:${inp.vout}`;
      this.utxos.delete(k);
      this.spentBy.set(k, txid);
      this._index(scriptToAddress(this.net, prevouts[n].script), txid);
    });
    tx.outputs.forEach((o, vout) => {
      this.utxos.set(`${txid}:${vout}`, { txid, vout, value: o.value, script: o.script });
      this._index(scriptToAddress(this.net, o.script), txid);
    });
    this.mempool.push(txid);
  }

  /** "Torneira": cria moedas num endereço (como se alguém tivesse pago de outra carteira). */
  fund(address, sats) {
    const script = decodeBtcAddress(this.net, address).script;
    const tx = new BtcTx({ inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: randomBytes(8) }], outputs: [{ value: BigInt(sats), script }] });
    const txid = tx.txid;
    this._accept(txid, tx, [null]);
    return txid;
  }

  /** Recebe uma transação (hex). Lança erro com o motivo se for inválida. */
  submit(txHex) {
    const tx = BtcTx.parse(txHex);
    const txid = tx.txid;
    if (this.txs.has(txid)) return txid;
    if (!tx.inputs.length || !tx.outputs.length) throw new Error('transação sem entradas ou sem saídas');
    const prevouts = [];
    const seen = new Set();
    let inSum = 0n;
    for (const inp of tx.inputs) {
      const k = `${inp.txid}:${inp.vout}`;
      if (seen.has(k)) throw new Error('entrada duplicada');
      seen.add(k);
      if (this.spentBy.has(k)) throw new Error('conflito: essa saída já foi gasta');
      const u = this.utxos.get(k);
      if (!u) throw new Error('entrada inexistente');
      prevouts.push(u);
      inSum += u.value;
    }
    if (tx.locktime !== 0 && tx.inputs.some((i) => i.sequence !== 0xffffffff)) {
      const lt = tx.locktime;
      const ok = lt < 500_000_000 ? lt < this.tip.height + 1 : lt < this.mtp();
      if (!ok) throw new Error('non-final: o prazo (nLockTime) ainda não passou');
    }
    tx.inputs.forEach((inp, n) => {
      const spk = prevouts[n].script, w = inp.witness;
      if (inp.scriptSig.length) throw new Error('entrada segwit não pode ter scriptSig');
      if (spk.length === 34 && spk[0] === 0 && spk[1] === 32) {
        if (!w.length) throw new Error('testemunha ausente');
        const ws = w[w.length - 1];
        if (!sha256(ws).equals(spk.subarray(2))) throw new Error('o witnessScript não confere com o endereço');
        runWitnessScript(ws, w.slice(0, -1), { tx, index: n, amount: prevouts[n].value });
      } else if (spk.length === 22 && spk[0] === 0 && spk[1] === 20) {
        if (w.length !== 2 || !hash160(w[1]).equals(spk.subarray(2))) throw new Error('testemunha P2WPKH inválida');
        const code = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), spk.subarray(2), Buffer.from([0x88, 0xac])]);
        if (!checkSig(w[0], w[1], code, tx, n, prevouts[n].value)) throw new Error('assinatura inválida');
      } else throw new Error('o simulador só valida gastos segwit v0 (P2WSH/P2WPKH)');
    });
    const outSum = tx.outputs.reduce((a, o) => a + o.value, 0n);
    if (outSum > inSum) throw new Error('saídas maiores que as entradas');
    if (tx.outputs.some((o) => o.value < 294n)) throw new Error('saída abaixo do limite de poeira');
    this._accept(txid, tx, prevouts);
    return txid;
  }

  _status(height) {
    if (height === null) return { confirmed: false };
    const b = this.blocks[height];
    return { confirmed: true, block_height: height, block_hash: b.hash, block_time: b.time };
  }

  txJson(txid) {
    const e = this.txs.get(txid);
    if (!e) return null;
    const addr = (s) => scriptToAddress(this.net, s);
    return {
      txid, version: e.tx.version, locktime: e.tx.locktime,
      vin: e.tx.inputs.map((i, n) => ({
        txid: i.txid, vout: i.vout, is_coinbase: !e.prevouts[n], sequence: i.sequence,
        scriptsig: hex(i.scriptSig), witness: i.witness.map(hex),
        prevout: e.prevouts[n] ? { scriptpubkey: hex(e.prevouts[n].script), scriptpubkey_address: addr(e.prevouts[n].script), value: Number(e.prevouts[n].value) } : null,
      })),
      vout: e.tx.outputs.map((o) => ({ scriptpubkey: hex(o.script), scriptpubkey_address: addr(o.script), value: Number(o.value) })),
      status: this._status(e.height),
    };
  }

  addressUtxos(address) {
    const out = [];
    for (const txid of this.byAddr.get(address) ?? []) {
      const e = this.txs.get(txid);
      e.tx.outputs.forEach((o, vout) => {
        const u = this.utxos.get(`${txid}:${vout}`);
        if (u && scriptToAddress(this.net, o.script) === address) out.push({ txid, vout, value: Number(o.value), status: this._status(e.height) });
      });
    }
    return out;
  }

  addressTxs(address) { return [...(this.byAddr.get(address) ?? [])].reverse().map((id) => this.txJson(id)); }

  /** Saldo (confirmado + mempool) de um endereço — conveniência para testes e demonstrações. */
  balance(address) { return this.addressUtxos(address).reduce((a, u) => a + BigInt(u.value), 0n); }
}

/** Sobe o servidor HTTP com a API Esplora. autoMineMs > 0 mineira um bloco a cada intervalo. */
export function startSimBitcoin({ port = 3002, host = '127.0.0.1', sim = new SimBitcoin(), autoMineMs = 0, log = () => {} } = {}) {
  const send = (res, code, body, type = 'application/json') => {
    res.writeHead(code, { 'content-type': type });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      const p = url.pathname.replace(/\/+$/, '');
      let body = '';
      for await (const c of req) body += c;
      let m;
      if (req.method === 'GET' && p === '/blocks/tip/height') return send(res, 200, String(sim.tip.height), 'text/plain');
      if (req.method === 'GET' && p === '/blocks/tip/hash') return send(res, 200, sim.tip.hash, 'text/plain');
      if (req.method === 'GET' && (m = p.match(/^\/block\/([0-9a-f]{64})$/))) {
        const b = sim.blocks.find((x) => x.hash === m[1]);
        return b ? send(res, 200, { id: b.hash, height: b.height, timestamp: b.time, mediantime: sim.mtp(b.height), tx_count: b.txids.length }) : send(res, 404, 'Block not found', 'text/plain');
      }
      if (req.method === 'GET' && (m = p.match(/^\/address\/([^/]+)\/utxo$/))) return send(res, 200, sim.addressUtxos(decodeURIComponent(m[1])));
      if (req.method === 'GET' && (m = p.match(/^\/address\/([^/]+)\/txs$/))) return send(res, 200, sim.addressTxs(decodeURIComponent(m[1])));
      if (req.method === 'GET' && (m = p.match(/^\/tx\/([0-9a-f]{64})(\/hex)?$/))) {
        const j = sim.txJson(m[1]);
        if (!j) return send(res, 404, 'Transaction not found', 'text/plain');
        return m[2] ? send(res, 200, sim.txs.get(m[1]).tx.toHex(), 'text/plain') : send(res, 200, j);
      }
      if (req.method === 'POST' && p === '/tx') {
        try { const txid = sim.submit(body.trim()); log(`tx aceita ${txid}`); return send(res, 200, txid, 'text/plain'); }
        catch (e) { return send(res, 400, `sendrawtransaction RPC error: ${e.message}`, 'text/plain'); }
      }
      if (req.method === 'GET' && p === '/fee-estimates') return send(res, 200, { 1: 3, 3: 2, 6: 1, 144: 1 });
      if (req.method === 'POST' && p === '/sim/mine') {
        const { n = 1, dt } = body ? JSON.parse(body) : {};
        return send(res, 200, sim.mine(Math.min(Number(n), 1000), dt === undefined ? undefined : Number(dt)));
      }
      if (req.method === 'POST' && p === '/sim/fund') {
        const { address, sats } = JSON.parse(body);
        return send(res, 200, { txid: sim.fund(address, BigInt(sats)) });
      }
      if (req.method === 'GET' && p === '/sim/info') {
        return send(res, 200, { network: sim.net.name, height: sim.tip.height, time: sim.tip.time, mtp: sim.mtp(), mempool: sim.mempool.length });
      }
      return send(res, 404, 'not found', 'text/plain');
    } catch (e) {
      return send(res, 400, e.message, 'text/plain');
    }
  });
  let timer = null;
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      if (autoMineMs > 0) timer = setInterval(() => { const r = sim.mine(1); log(`bloco ${r.height}`); }, autoMineMs);
      const addr = server.address();
      resolve({
        sim, server, url: `http://${host}:${addr.port}`,
        close: () => new Promise((r) => { if (timer) clearInterval(timer); server.closeAllConnections?.(); server.close(() => r()); }),
      });
    });
  });
}
