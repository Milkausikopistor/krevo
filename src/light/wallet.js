// CARTEIRA LEVE: usa a Krevo sem rodar um nó, falando com um servidor leve público em que ela
// NÃO confia. O que muda em relação à carteira completa:
//
//   • chaves: nenhuma sai do aparelho — nem a de gasto, nem a de visualização (modo padrão);
//   • varredura: baixa só 35 bytes por saída privada (R, índice e view tag de 1 byte) e testa
//     aqui mesmo; só ~1 em 256 saídas precisa ser baixada inteira — e cada uma vai misturada a
//     15 iscas, então o servidor não sabe quais são suas;
//   • gastos: pergunta por "baldes" de imagens de chave (1/256 do total), nunca pela sua;
//   • verificação: cada moeda recebida só conta no saldo depois de uma PROVA — o txid confere
//     com o conteúdo, a saída está na transação, a transação está na árvore de Merkle do bloco
//     que a aceitou e há N blocos com prova de trabalho por cima (src/light/verify.js);
//   • opcional (--delegar): varredura delegada — o servidor recebe a chave de VISUALIZAÇÃO e
//     encontra seus pagamentos (economiza bateria; ele passa a ver o que você recebe, mas
//     continua sem poder gastar nem ver o que você gasta).
//
// Montar, assinar e escolher iscas das transações continua igual à carteira completa.

import { randomInt } from 'node:crypto';
import { fetchRetry } from '../node/rpcclient.js';
import { Wallet } from '../wallet/wallet.js';
import { Point } from '../crypto/secp256k1.js';
import { viewTag, scanShieldedOutput, decryptMemo } from '../crypto/stealth.js';
import { Transaction } from '../consensus/tx.js';
import { toHex, fromHex } from '../util/bytes.js';
import { verifyAcceptanceProof, headerWork } from './verify.js';
import { pqAvailable } from '../crypto/pq.js';

const PAD = 16;          // cada saída pedida vai junto com 15 iscas
const COMPACT_BATCH = 5000;

/** Cliente HTTP do servidor leve; conta os bytes recebidos (para medir o consumo). */
export class LightClient {
  constructor(base) { this.base = String(base).replace(/\/+$/, ''); this.bytes = 0; this.requests = 0; }

  async _req(path, { method = 'GET', body, binary = false } = {}) {
    let r;
    try {
      r = await fetchRetry(this.base + path, { method, body: body ? JSON.stringify(body) : undefined, headers: body ? { 'content-type': 'application/json' } : {} });
    } catch (e) { throw new Error(`não consegui falar com o servidor leve em ${this.base} (${e.cause?.code ?? e.message})`); }
    const buf = Buffer.from(await r.arrayBuffer());
    this.bytes += buf.length;
    this.requests++;
    if (!r.ok) {
      let msg = buf.toString();
      try { msg = JSON.parse(msg).error ?? msg; } catch { /* texto puro */ }
      throw new Error(msg);
    }
    return binary ? buf : JSON.parse(buf.toString());
  }

  info() { return this._req('/v1/info'); }
  async compact(start, count) {
    const b = await this._req(`/v1/compact?start=${start}&count=${count}`, { binary: true });
    if (b.length < 20) throw new Error('resposta compacta malformada');
    const total = b.readUInt32LE(0), st = b.readUInt32LE(4), n = b.readUInt32LE(8), daaScore = Number(b.readBigUInt64LE(12));
    if (st !== start || b.length !== 20 + 35 * n) throw new Error('resposta compacta malformada');
    const entries = [];
    for (let k = 0; k < n; k++) {
      const o = 20 + 35 * k;
      entries.push({ index: st + k, R: b.subarray(o, o + 33), j: b[o + 33], viewTag: b[o + 34] });
    }
    return { total, start: st, count: n, daaScore, entries };
  }
  outputs(indices) { return this._req('/v1/outputs', { method: 'POST', body: { indices } }); }
  keyImageBucket(prefix) { return this._req(`/v1/keyimages/${prefix}`); }
  utxos(locks) { return this._req('/v1/utxos', { method: 'POST', body: { locks } }); }
  tx(txid) { return this._req(`/v1/tx/${txid}`); }
  proof(txid, depth) { return this._req(`/v1/proof/${txid}?depth=${depth}`); }
  broadcast(tx) { return this._req('/v1/broadcast', { method: 'POST', body: { tx } }); }
  fcmpAnchor() { return this._req('/v1/fcmp/anchor'); }
  fcmpPath(anchor, chunks) { return this._req('/v1/fcmp/path', { method: 'POST', body: { anchor, chunks } }); }
  name(n) { return this._req(`/v1/name/${encodeURIComponent(n)}`); }
  names(owners) { return this._req('/v1/names', { method: 'POST', body: { owners } }); }
  history(a) { return this._req(`/v1/history/${encodeURIComponent(a)}`); }
  scan(body) { return this._req('/v1/scan', { method: 'POST', body }); }
}

/**
 * Carteira leve. `serverUrl` pode ter VÁRIOS servidores separados por vírgula
 * ("https://a,https://b"): a carteira compara as respostas e avisa quando discordam.
 *   • saídas privadas: os dados compactos dos servidores são comparados lote a lote; se
 *     diferirem (um escondeu ou mexeu em algo), a carteira varre os dois — o que um esconder,
 *     o outro mostra;
 *   • moedas transparentes que só um servidor mostra: se um deles PROVAR que a moeda foi
 *     gasta (transação que a gasta + prova de aceitação), ela está gasta; se ninguém provar,
 *     ela conta — quem a escondeu fica registrado;
 *   • gastos privados: basta um servidor saber da imagem de chave;
 *   • transmissão: a transação vai para todos (mais difícil de censurar).
 */
export class LightWallet extends Wallet {
  constructor(file, data, params, serverUrl, password, opts = {}) {
    super(file, data, params, serverUrl, password, opts);
    this.servers = String(serverUrl).split(',').map((u) => u.trim()).filter(Boolean).map((u) => new LightClient(u));
    if (!this.servers.length) throw new Error('informe o servidor leve');
    this.server = this.servers[0];
    this.tUnverified = [];
  }

  get light() { return (this.data.light ??= { verified: {}, fraud: {}, fraudBy: {}, maxWork: '0', delegate: false, discrepancies: [] }); }
  get proofDepth() { return this.data.light?.depth ?? this.params.lightProofDepth; }
  get serverUrls() { return this.servers.map((s) => s.base); }
  /** Bytes e consultas somados de todos os servidores. */
  get traffic() { return { bytes: this.servers.reduce((a, s) => a + s.bytes, 0), requests: this.servers.reduce((a, s) => a + s.requests, 0) }; }
  /** Divergências entre servidores encontradas na última sincronização. */
  get discrepancies() { return [...(this.data.light?.discrepancies ?? [])]; }
  /** Liga/desliga a varredura delegada (o servidor recebe a chave de visualização). */
  setDelegated(on) { this.light.delegate = !!on; this.save(); }

  /** As mesmas operações que a carteira completa pede ao nó, traduzidas para o servidor leve. */
  async call(method, p = {}) {
    const s = this.server;
    switch (method) {
      case 'getutxos': return s.utxos(p.locks);
      case 'getshieldedoutputs': {
        if (p.count) throw new Error('a carteira leve não baixa saídas completas em massa');
        const i = await s.info();
        return { total: i.outputs, daaScore: i.daaScore, outputs: [] };
      }
      case 'getshieldedbyindex': return s.outputs(p.indices);
      case 'getfcmpanchor': return s.fcmpAnchor();
      case 'getfcmppath': return s.fcmpPath(p.anchor, p.chunks);
      case 'getkeyimages': return this._keyImageStatus(p.keyImages);
      case 'sendrawtransaction': {
        // para TODOS os servidores: basta um aceitar
        const rs = await Promise.allSettled(this.servers.map((x) => x.broadcast(p.tx)));
        const ok = rs.find((r) => r.status === 'fulfilled');
        if (ok) return ok.value;
        throw rs[0].reason;
      }
      case 'gettransaction': return s.tx(p.txid);
      case 'gettransactionstatus': {
        let last = { status: 'unknown' };
        for (const x of this.servers) {
          try {
            const t = await x.tx(p.txid);
            if (t.status === 'accepted') return { status: 'accepted', confirmations: t.confirmations };
            last = { status: t.status };
          } catch (e) { if (!/desconhecida/.test(e.message) && this.servers.length === 1) throw e; }
        }
        return last;
      }
      case 'resolvename': return s.name(p.name);
      case 'listnames': return s.names(p.owners);
      case 'getaddresshistory': return s.history(p.address);
      case 'getinfo': {
        const i = await s.info();
        return { network: i.network, virtual: { daaScore: i.daaScore, blueScore: i.blueScore }, shieldedOutputs: i.outputs };
      }
      default: throw new Error(`"${method}" não está disponível na carteira leve`);
    }
  }

  /** Imagens de chave por baldes de prefixo, em todos os servidores (basta um saber do gasto). */
  async _keyImageStatus(kis, notes = null) {
    const res = new Map(kis.map((k) => [k, { spentBy: [], mempool: false }]));
    const active = this._active ?? this.servers, lagging = this._lagging ?? new Set();
    for (const [n, srv] of active.entries()) {
      for (const prefix of new Set(kis.map((k) => k.slice(0, 2)))) {
        let b;
        try { b = await srv.keyImageBucket(prefix); } catch { continue; }
        const spent = new Set(b.spent), mem = new Set(b.mempool);
        for (const k of kis) if (k.startsWith(prefix)) { const r = res.get(k); if (spent.has(k)) r.spentBy.push(n); if (mem.has(k)) r.mempool = true; }
      }
    }
    return kis.map((k) => {
      const r = res.get(k);
      if (notes && r.spentBy.length && r.spentBy.length < active.length && !lagging.size) {
        notes.push(`os servidores discordam se uma moeda privada já foi gasta (${active.filter((_, i) => !r.spentBy.includes(i)).map((x) => x.base).join(', ')} diz que não) — considerada gasta`);
      }
      return { keyImage: k, spent: r.spentBy.length > 0, inMempool: r.mempool };
    });
  }

  /** Candidatas de um intervalo, testadas AQUI pela view tag. */
  _testCompact(entries, srvIndex, out) {
    const ok = [], Rs = [];
    for (const e of entries) {
      try { Rs.push(Point.fromBytes(e.R)); ok.push(e); } catch { /* ponto inválido: não é nossa */ }
    }
    const sss = this.keys.vault.sharedMany(Rs); // a·R calculado no cofre, em lote
    ok.forEach((e, n) => { if (viewTag(sss[n], e.j) === e.viewTag) out.push({ srv: srvIndex, index: e.index }); });
  }

  /** Varre [start, total de cada servidor); compara os lotes entre servidores. */
  async _localCandidates(start, totals, notes) {
    const out = [];
    const common = Math.min(...totals);
    let diverged = false;
    for (let i = start; i < common;) {
      const n = Math.min(COMPACT_BATCH, common - i);
      const batches = await Promise.all(this._active.map((s) => s.compact(i, n)));
      const eq = (e, f) => !!e && !!f && e.j === f.j && e.viewTag === f.viewTag && Buffer.compare(e.R, f.R) === 0;
      const same = batches.every((b) => b.count === batches[0].count && b.entries.every((e, k) => eq(e, batches[0].entries[k])));
      if (same) this._testCompact(batches[0].entries, 0, out);
      else {
        let k = 0;
        while (k < n && batches.every((b) => eq(b.entries[k], batches[0].entries[k]))) k++;
        if (!diverged) notes.push(`os servidores mostram saídas privadas DIFERENTES a partir da posição ${i + k} — um deles escondeu ou alterou dados; a carteira conferiu os dois`);
        diverged = true;
        batches.forEach((b, s) => this._testCompact(b.entries, s, out));
      }
      if (!batches[0].count) break;
      i += batches[0].count;
    }
    // o que só os servidores mais adiantados já têm
    for (const [s, srv] of this._active.entries()) {
      for (let i = Math.max(start, common); i < totals[s];) {
        const c = await srv.compact(i, Math.min(COMPACT_BATCH, totals[s] - i));
        this._testCompact(c.entries, s, out);
        if (!c.count) break;
        i += c.count;
      }
    }
    return out;
  }

  /** Varredura delegada (só no primeiro servidor): ele recebe a chave de visualização. */
  async _delegatedCandidates(start, total) {
    const out = [];
    for (let i = start; i < total; i += 20_000) {
      const r = await this.server.scan({ viewKey: this.keys.viewKey(this.params), start: i, count: Math.min(20_000, total - i), subaddresses: this.subCount + 50 });
      out.push(...r.matches.map((index) => ({ srv: 0, index })));
    }
    return out;
  }

  /** Baixa as saídas pedidas de cada servidor, misturadas com iscas (PAD − 1 por saída real). */
  async _fetchPadded(cands, totals) {
    const map = new Map();
    for (const [s, srv] of this._active.entries()) {
      const mine = cands.filter((c) => c.srv === s).map((c) => c.index);
      if (!mine.length) continue;
      const want = new Set(mine);
      for (let k0 = 0; k0 < mine.length; k0++) {
        for (let k = 0, tries = 0; k < PAD - 1 && tries < PAD * 4; tries++) {
          const d = randomInt(totals[s]);
          if (!want.has(d)) { want.add(d); k++; }
        }
      }
      const all = [...want].sort(() => Math.random() - 0.5);
      for (let k = 0; k < all.length; k += 512) {
        const r = await srv.outputs(all.slice(k, k + 512));
        for (const e of r.outputs) map.set(`${s}:${e.index}`, e);
      }
    }
    return map;
  }

  /**
   * Prova que a saída `key` (txid:índice) existe e foi aceita pela rede, tentando cada servidor.
   * check(tx, índice) confere o conteúdo. "Ainda sem blocos suficientes" só adia; dado falso
   * (txid, conteúdo, Merkle, PoW) fica registrado como fraude daquele servidor.
   */
  async _verifyOutput(key, check) {
    const L = this.light;
    if (L.verified[key]) return true;
    const [txid, ix] = key.split(':');
    L.fraudBy ??= {};
    for (const srv of this._active ?? this.servers) {
      if ((L.fraudBy[txid] ?? []).includes(srv.base)) continue;
      const flag = (why) => { L.fraud[txid] = why; (L.fraudBy[txid] ??= []).push(srv.base); };
      let t, proof, tx;
      try { t = await srv.tx(txid); } catch { continue; }
      try { tx = Transaction.deserialize(fromHex(t.tx)); } catch { flag('transação ilegível'); continue; }
      if (tx.idHex !== txid) { flag('o conteúdo da transação não confere com o txid'); continue; }
      if (!check(tx, Number(ix))) { flag('a saída informada não existe nessa transação'); continue; }
      try { proof = await srv.proof(txid, this.proofDepth); } catch { continue; }
      if ((proof.chain?.length ?? 0) < this.proofDepth) continue;
      try {
        const r = verifyAcceptanceProof(txid, proof, { minDepth: this.proofDepth, minWork: BigInt(L.maxWork) / 4n });
        if (r.maxWork > BigInt(L.maxWork)) L.maxWork = r.maxWork.toString();
        L.verified[key] = { block: r.block, depth: r.depth };
        return true;
      } catch (e) { flag(e.message); }
    }
    return false;
  }

  /** Algum servidor PROVA que esta moeda transparente foi gasta? (transação que a gasta + prova) */
  async _spendProven(u) {
    const address = u.kind === 'q' ? this.qAddress : this.tAddress;
    for (const srv of this._active) {
      let h;
      try { h = await srv.history(address); } catch { continue; }
      for (const txid of (h.txids ?? []).slice(0, 100)) {
        let t;
        try { t = await srv.tx(txid); } catch { continue; }
        const tx = Transaction.deserialize(fromHex(t.tx));
        if (tx.idHex !== txid || !tx.tIn.some((i) => `${toHex(i.outpoint.txid)}:${i.outpoint.index}` === u.outpoint)) continue;
        if (await this._verifyOutput(`${txid}:spend`, () => true)) return srv.base;
      }
    }
    return null;
  }

  /** Avisos de dados falsos recebidos (txid → motivo). */
  get fraudReports() { return { ...(this.data.light?.fraud ?? {}) }; }

  async sync() {
    const L = this.light, notes = [];
    // 0) quem está no ar, na rede certa, com a ponta com PoW válida
    const infos = await Promise.all(this.servers.map((s) => s.info().catch((e) => ({ error: e.message }))));
    const up = [];
    infos.forEach((info, n) => {
      const srv = this.servers[n];
      if (info.error) { if (this.servers.length > 1) notes.push(`servidor ${srv.base} fora do ar (${info.error})`); return; }
      if (info.network !== this.params.name) throw new Error(`o servidor ${srv.base} é da rede ${info.network}, não ${this.params.name}`);
      const tip = headerWork(info.tip.header);
      if (tip.work > BigInt(L.maxWork)) L.maxWork = tip.work.toString();
      up.push({ srv, info });
    });
    if (!up.length) throw new Error(infos[0].error ?? 'nenhum servidor leve respondeu');
    this._active = up.map((x) => x.srv);
    this.server = this._active[0];
    const top = Math.max(...up.map((x) => x.info.daaScore));
    const lagTol = this.params.bps * 120;
    this._lagging = new Set();
    up.forEach((x, n) => { if (top - x.info.daaScore > lagTol) { this._lagging.add(n); notes.push(`servidor ${x.srv.base} está atrasado (${Math.round((top - x.info.daaScore) / this.params.bps)} s)`); } });
    this.data.daa = top;
    const tips = up.map((x) => x.info.daaScore);

    // 1) moedas transparentes: união das respostas, conferindo o que só um servidor mostra
    const tLock = toHex(this.keys.tKey(0).lock), qLock = pqAvailable() ? toHex(this.keys.qKey(0).lock) : null;
    const locks = qLock ? [tLock, qLock] : [tLock];
    const lists = await Promise.all(this._active.map((s) => s.utxos(locks).then((r) => r.utxos).catch(() => null)));
    const seen = new Map();
    lists.forEach((list, n) => {
      for (const u of list ?? []) {
        const e = seen.get(u.outpoint) ?? { u: { ...u, kind: u.lock === qLock ? 'q' : 't' }, by: new Set() };
        e.by.add(n);
        if (u.inMempool) e.u.inMempool = true;
        seen.set(u.outpoint, e);
      }
    });
    const all = [];
    for (const { u, by } of seen.values()) {
      const missing = this._active.map((_, n) => n).filter((n) => !by.has(n) && lists[n] !== null);
      // só é "atraso" se a ponta do servidor que não mostra a moeda está ANTES do bloco que a criou
      // (tolerância de ~1 s); fora isso, alguém está escondendo ou inventando
      const explainedByLag = missing.every((n) => tips[n] < u.daa + Math.ceil(this.params.bps));
      if (missing.length && !explainedByLag) {
        const spentBy = await this._spendProven(u);
        if (spentBy) { notes.push(`${[...by].map((n) => this._active[n].base).join(', ')} mostrou como disponível uma moeda que já foi gasta (a carteira tem a PROVA do gasto) — ignorada`); continue; }
        notes.push(`${missing.map((n) => this._active[n].base).join(', ')} escondeu uma moeda transparente de ${u.amount} grãos (ninguém provou que foi gasta) — ela conta`);
      }
      all.push(u);
    }

    // 2) saídas privadas: candidatas pela view tag (comparando servidores), depois as completas
    const LOOKAHEAD = 50;
    let scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
    const totals = up.map((x) => x.info.outputs);
    const maxT = Math.max(...totals);
    up.forEach((x, n) => {
      if (totals[n] < maxT && top - x.info.daaScore <= Math.ceil(this.params.bps)) {
        notes.push(`servidor ${x.srv.base} mostra ${maxT - totals[n]} saída(s) privada(s) a menos com a rede no mesmo ponto — escondeu dados; a carteira usou o outro`);
      }
    });
    const start = Math.max(0, Math.min(this.data.sScanned ?? 0, ...totals) - 200);
    const owned = new Map(this.data.sOwned.filter((o) => o.index < start).map((o) => [o.outpoint, o]));
    const cands = L.delegate ? await this._delegatedCandidates(start, totals[0]) : await this._localCandidates(start, totals, notes);
    const full = await this._fetchPadded(cands, totals);
    for (const c of cands) {
      const e = full.get(`${c.srv}:${c.index}`);
      if (!e || owned.has(e.outpoint)) continue;
      const o = { P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)), encAmount: fromHex(e.encAmount), viewTag: e.viewTag };
      const got = scanShieldedOutput(scanKeys, Point.fromBytes(fromHex(e.R)), e.j, o);
      if (!got) continue; // falso positivo da view tag (esperado: ~1 em 256)
      if (got.index >= this.subCount) {
        while (this.subCount <= got.index) (this.data.subaddresses ??= []).push({ label: '', created: Date.now(), recovered: true });
        scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
      }
      const memo = e.memo ? decryptMemo(fromHex(e.memo), got.ss, e.j) : null;
      owned.set(e.outpoint, {
        index: e.index, outpoint: e.outpoint, amount: got.v.toString(), mask: got.x.toString(), k: got.k.toString(16),
        P: e.P, C: e.C, daa: e.daa, coinbase: e.coinbase, keyImage: toHex(this.keys.spender(got.k, got.index).keyImage(o.P).toBytes()),
        memo: memo || null, sub: got.index,
      });
    }
    const ownedList = [...owned.values()].sort((a, b) => a.index - b.index);
    this.data.sScanned = Math.min(...totals);

    // 3) o que já foi gasto (por baldes de imagem de chave, em todos os servidores)
    if (ownedList.length) {
      const st = await this._keyImageStatus(ownedList.map((o) => o.keyImage), notes);
      st.forEach((x, n) => { ownedList[n].spent = x.spent; ownedList[n].pending = x.inMempool; });
    }

    // 4) provas: só conta no saldo (e só pode ser gasto) o que foi provado
    for (const o of ownedList) {
      if (o.spent) continue;
      o.unverified = !(await this._verifyOutput(o.outpoint, (tx, ix) => {
        const so = tx.sOut[ix - tx.tOut.length];
        return !!so && toHex(so.P) === o.P && toHex(so.C) === o.C;
      }));
    }
    const verified = [], unverified = [];
    for (const u of all) {
      const ok = await this._verifyOutput(u.outpoint, (tx, ix) => {
        const to = tx.tOut[ix];
        return !!to && BigInt(to.amount) === BigInt(u.amount) && toHex(to.lock) === u.lock && (u.coinbase === tx.isCoinbase());
      });
      (ok ? verified : unverified).push(u);
    }
    this.tUtxos = verified;
    this.tUnverified = unverified;
    this.data.sOwned = ownedList;
    L.discrepancies = [...new Set(notes)];
    this.save();
    return { candidates: cands.length, ...this.traffic, servers: this._active.length, discrepancies: L.discrepancies };
  }
}
