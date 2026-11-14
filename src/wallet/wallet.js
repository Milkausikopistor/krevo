// Carteira: guarda a semente, sincroniza com um nó via RPC e monta transações.
// Gastos privados provam pertencer à árvore de TODAS as saídas privadas (FCMP). A carteira
// pede ao nó o caminho do seu "pedaço" da árvore misturado a pedaços-isca — o nó não
// sabe qual deles é o real. (Na simnet ainda dá para usar anéis, para testes rápidos.)

import fs from 'node:fs';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { Keys } from './keys.js';
import { buildTransaction } from './builder.js';
import { decodeAddress } from '../address.js';
import { Point } from '../crypto/secp256k1.js';
import { scanShieldedOutput, decryptMemo } from '../crypto/stealth.js';
import * as fcmpParallel from '../fcmp/parallel.js';
import { parseOutpointKey, Transaction } from '../consensus/tx.js';
import { createPaymentProof, decodePaymentProof, verifyPaymentProof } from './proof.js';
import { parsePaymentURI, isExpired } from './request.js';
import { rpc } from '../node/rpcclient.js';
import { toHex, fromHex } from '../util/bytes.js';
import { generateMnemonic, normalizeMnemonic, mnemonicToEntropy, walletSeedFromMnemonic } from './bip39.js';

function encryptSeed(seed, password) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(seed), c.final()]);
  return { salt: toHex(salt), iv: toHex(iv), ct: toHex(ct), tag: toHex(c.getAuthTag()) };
}
function decryptSeed(enc, password) {
  const key = scryptSync(password, fromHex(enc.salt), 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const d = createDecipheriv('aes-256-gcm', key, fromHex(enc.iv));
  d.setAuthTag(fromHex(enc.tag));
  try { return Buffer.concat([d.update(fromHex(enc.ct)), d.final()]); } catch { throw new Error('senha incorreta'); }
}

// Campos do arquivo que ficam à vista; todo o resto (saídas, histórico, segredos de transação,
// rótulos…) vai cifrado com uma chave derivada da semente, DENTRO do cofre, quando há senha.
const PUBLIC_FIELDS = new Set(['version', 'network', 'seedEnc', 'mnemonicEnc', 'hasPassphrase', 'seed', 'mnemonic', 'sealed']);

export class Wallet {
  /** opts.seed: semente já decifrada por quem chama (ex.: a carteira do navegador). */
  constructor(file, data, params, rpcUrl, password, opts = {}) {
    this.file = file; this.data = data; this.params = params; this.rpcUrl = rpcUrl;
    const seed = opts.seed ? Buffer.from(opts.seed) : data.seedEnc ? decryptSeed(data.seedEnc, password ?? '') : fromHex(data.seed);
    // a semente vai para o cofre e a cópia daqui é apagada: as chaves não existem no JavaScript
    try { this.keys = new Keys(seed); } finally { seed.fill(0); }
    // frase de recuperação: a cifrada só é decifrada quando o usuário pede (revealMnemonic)
    this.mnemonic = data.mnemonicEnc ? null : (data.mnemonic ?? null);
    if (data.sealed) {
      Object.assign(data, JSON.parse(this.keys.vault.unseal(fromHex(data.sealed)).toString('utf8')));
      delete data.sealed;
    }
    // Arquivos antigos guardavam a chave de uso único p de cada saída privada EM TEXTO PURO (quem
    // lesse o arquivo gastava as moedas sem a senha). Agora fica só k (nível de visualização) e p
    // é calculado no cofre na hora de gastar: apaga os p e refaz a varredura.
    let migrated = false;
    for (const o of data.sOwned ?? []) {
      if (o.p !== undefined) { delete o.p; migrated = true; }
    }
    if (migrated && (data.sOwned ?? []).some((o) => o.k === undefined)) {
      data.sOwned = data.sOwned.filter((o) => o.k !== undefined);
      data.sScanned = 0;
    }
    this.tUtxos = [];
    // 'fcmp' (árvore inteira) ou 'ring' (anel de 16, legado — só onde o consenso aceita)
    this.privateInputs = params.ringInputs ? 'ring' : 'fcmp';
  }

  /**
   * Cria uma carteira nova. Por padrão gera uma frase de recuperação de 24 palavras
   * (BIP-39); `mnemonic` restaura a partir de uma frase existente. `passphrase` é a
   * "frase extra" opcional do BIP-39: sem ela, a mesma frase gera outra carteira.
   */
  static create(file, params, rpcUrl, { password, seed, mnemonic, passphrase = '', words = 24 } = {}) {
    if (fs.existsSync(file)) throw new Error(`a carteira ${file} já existe`);
    let m = null, s = seed;
    if (!s) {
      m = mnemonic ? normalizeMnemonic(mnemonic) : generateMnemonic(words);
      mnemonicToEntropy(m); // valida o checksum
      s = walletSeedFromMnemonic(m, passphrase);
    }
    const data = { version: 2, network: params.name, sScanned: 0, sOwned: [], txSecrets: {}, hasPassphrase: !!passphrase };
    if (password) {
      data.seedEnc = encryptSeed(s, password);
      if (m) data.mnemonicEnc = encryptSeed(Buffer.from(m, 'utf8'), password);
    } else {
      data.seed = toHex(s);
      if (m) data.mnemonic = m;
    }
    const w = new this(file, data, params, rpcUrl, password); // "this": também cria a carteira leve (subclasse)
    if (m) w.mnemonic = m; // para mostrar UMA vez, na criação
    w.save();
    return w;
  }

  /** Restaura a partir da frase de recuperação (e da frase extra, se foi usada). */
  static restore(file, params, rpcUrl, { mnemonic, passphrase = '', password } = {}) {
    if (!mnemonic) throw new Error('informe a frase de recuperação');
    return this.create(file, params, rpcUrl, { mnemonic, passphrase, password });
  }
  static load(file, params, rpcUrl, password) {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data.network !== params.name) throw new Error(`carteira é da rede ${data.network}`);
    return new this(file, data, params, rpcUrl, password);
  }
  /** Grava de forma atômica (arquivo temporário + rename: uma queda no meio não corrompe a carteira)
   *  e só legível pelo dono (0600). */
  save() {
    if (!this.file) return;
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.fileData(), null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    try { fs.chmodSync(this.file, 0o600); } catch { /* sistemas sem permissões POSIX */ }
  }
  /** O que vai para o disco: com senha, só os campos públicos à vista; o resto cifrado pelo cofre. */
  fileData() {
    if (!this.data.seedEnc) return this.data;
    const pub = {}, priv = {};
    for (const [k, v] of Object.entries(this.data)) (PUBLIC_FIELDS.has(k) ? pub : priv)[k] = v;
    pub.sealed = toHex(this.keys.vault.seal(Buffer.from(JSON.stringify(priv), 'utf8')));
    return pub;
  }
  /** Frase de recuperação, decifrada só agora (pede a senha de novo). */
  revealMnemonic(password) {
    if (this.data.mnemonicEnc) return decryptSeed(this.data.mnemonicEnc, password ?? '').toString('utf8');
    return this.data.mnemonic ?? null;
  }
  /** Apaga as chaves da memória (o cofre é zerado); a carteira não assina mais. */
  close() { this.keys.close(); }
  call(m, p) { return rpc(this.rpcUrl, m, p); }

  get tAddress() { return this.keys.tAddress(this.params, 0); }
  get sAddress() { return this.keys.sAddress(this.params, 0); }
  /** Endereço transparente resistente a computadores quânticos (krq1…). */
  get qAddress() { return this.keys.qAddress(this.params, 0); }
  /** Modo quântico: troco e consolidações vão para o krq1… em vez do krv1…. */
  get quantum() { return !!this.data.quantum; }
  get _changeLock() { return this.quantum ? this.keys.qKey(0).lock : this.keys.tKey(0).lock; }

  /**
   * Peso de uma moeda transparente no limite de entradas: uma entrada krq1… leva a testemunha
   * híbrida (3.830 bytes, ~5.900 de massa), ~6× uma entrada Schnorr (~1.100).
   */
  static inputWeight(u) { return u.kind === 'q' ? 6 : 1; }
  /** Maior prefixo de `coins` cujo peso total cabe em `maxInputs` entradas Schnorr-equivalentes. */
  static takeCoins(coins, maxInputs) {
    const out = [];
    let w = 0;
    for (const u of coins) { w += Wallet.inputWeight(u); if (w > maxInputs) break; out.push(u); }
    return out;
  }

  /** Entrada transparente pronta para o construtor, com as chaves certas para o tipo de endereço. */
  _tIn(u) {
    const base = { outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount) };
    if (u.kind === 'q') { const k = this.keys.qKey(0); return { ...base, signer: k.signer, pq: k }; }
    return { ...base, signer: this.keys.tKey(0).signer };
  }

  // ----------------------------------------------------------- subendereços
  /** Quantidade de endereços privados conhecidos (o principal é o índice 0). */
  get subCount() { return (this.data.subaddresses?.length ?? 0) + 1; }

  /** Cria o próximo subendereço privado, com um rótulo só seu (não vai para a rede). */
  newSubaddress(label = '') {
    (this.data.subaddresses ??= []).push({ label, created: Date.now() });
    this.save();
    const index = this.subCount - 1;
    return { index, label, address: this.keys.sAddress(this.params, index) };
  }

  subaddressLabel(i) { return i === 0 ? 'principal' : (this.data.subaddresses?.[i - 1]?.label || `subendereço ${i}`); }

  /** Lista: índice, rótulo, endereço e total recebido (não gasto) em cada endereço privado. */
  listSubaddresses() {
    return Array.from({ length: this.subCount }, (_, i) => {
      const outs = this.data.sOwned.filter((o) => (o.sub ?? 0) === i);
      return {
        index: i, label: this.subaddressLabel(i), address: this.keys.sAddress(this.params, i),
        received: outs.reduce((a, o) => a + BigInt(o.amount), 0n), count: outs.length,
      };
    });
  }

  /** Índice do subendereço desta carteira com esse endereço, ou -1. */
  subaddressIndex(address) {
    for (let i = 0; i < this.subCount; i++) if (this.keys.sAddress(this.params, i) === address) return i;
    return -1;
  }

  async sync() {
    // moedas transparentes nos dois endereços: krv1… (clássico) e krq1… (quântico)
    const tLock = toHex(this.keys.tKey(0).lock), qLock = toHex(this.keys.qKey(0).lock);
    this.tUtxos = (await this.call('getutxos', { locks: [tLock, qLock] })).utxos
      .map((u) => ({ ...u, kind: u.lock === qLock ? 'q' : 't' }));

    // Varredura das saídas privadas (com margem para reorganizações). A tabela cobre
    // todos os subendereços + 50 à frente: uma carteira restaurada pela frase encontra
    // também os subendereços criados em outro computador.
    const LOOKAHEAD = 50;
    let scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
    const start = Math.max(0, this.data.sScanned - 200);
    const owned = this.data.sOwned.filter((o) => o.index < start);
    let i = start, total = 0;
    do {
      const r = await this.call('getshieldedoutputs', { start: i, count: 2000 });
      total = r.total;
      this.data.daa = r.daaScore;
      const sss = this.keys.vault.sharedMany(r.outputs.map((e) => fromHex(e.R))); // a·R no cofre, em lote
      for (const [n, e] of r.outputs.entries()) {
        const o = { P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)), encAmount: fromHex(e.encAmount), viewTag: e.viewTag };
        const got = scanShieldedOutput(scanKeys, null, e.j, o, sss[n]);
        if (!got) continue;
        if (got.index >= this.subCount) { // subendereço criado em outra cópia da carteira
          while (this.subCount <= got.index) (this.data.subaddresses ??= []).push({ label: '', created: Date.now(), recovered: true });
          scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
        }
        const memo = e.memo ? decryptMemo(fromHex(e.memo), got.ss, e.j) : null;
        owned.push({
          index: e.index, outpoint: e.outpoint, amount: got.v.toString(), mask: got.x.toString(), k: got.k.toString(16),
          P: e.P, C: e.C, daa: e.daa, coinbase: e.coinbase, keyImage: toHex(this.keys.spender(got.k, got.index).keyImage(o.P).toBytes()),
          memo: memo || null, sub: got.index,
        });
      }
      i += r.outputs.length;
      if (!r.outputs.length) break;
    } while (i < total);
    this.data.sScanned = total;
    if (owned.length) {
      const st = await this.call('getkeyimages', { keyImages: owned.map((o) => o.keyImage) });
      st.forEach((s, n) => { owned[n].spent = s.spent; owned[n].pending = s.inMempool; });
    }
    this.data.sOwned = owned;
    this.save();
  }

  balance() {
    let tMature = 0n, tImmature = 0n, tPending = 0n, s = 0n, sPending = 0n, sImmature = 0n;
    for (const u of this.tUtxos) {
      const a = BigInt(u.amount);
      if (u.inMempool) tPending += a; else if (u.mature) tMature += a; else tImmature += a;
    }
    // carteira leve: o que o servidor informou mas ainda não foi PROVADO não conta nem pode ser gasto
    let unverified = (this.tUnverified ?? []).reduce((a, u) => a + BigInt(u.amount), 0n);
    for (const o of this.data.sOwned) {
      if (o.spent) continue;
      if (o.unverified) { unverified += BigInt(o.amount); continue; }
      if (o.pending) sPending += BigInt(o.amount); else if (!this._sMature(o)) sImmature += BigInt(o.amount); else s += BigInt(o.amount);
    }
    return { transparent: tMature, transparentImmature: tImmature, transparentPending: tPending, shielded: s, shieldedImmature: sImmature, shieldedPending: sPending, unverified };
  }

  _sMature(o) {
    // FCMP: a moeda precisa estar dentro de uma âncora madura (fcmpMaturity cobre também as coinbases)
    if (this.privateInputs === 'fcmp') return (this.data.daa ?? 0) - o.daa > this.params.fcmpMaturity;
    const need = o.coinbase ? Math.max(this.params.ringMaturity, this.params.coinbaseMaturity) : this.params.ringMaturity;
    return (this.data.daa ?? 0) - o.daa >= need;
  }

  /**
   * Dados para gastar uma saída privada. FCMP: âncora + caminho do pedaço da árvore que
   * contém a saída, pedido junto com 7 pedaços-isca. ctx guarda a âncora (a mesma para
   * todas as entradas da transação).
   */
  async _privateInput(o, ctx = {}) {
    if (o.k === undefined) throw new Error('sincronize a carteira antes de gastar (formato antigo)');
    const base = { outpoint: parseOutpointKey(o.outpoint), amount: BigInt(o.amount), mask: BigInt(o.mask), spend: this.keys.spender(BigInt('0x' + o.k), o.sub ?? 0) };
    if (this.privateInputs === 'ring') return { ...base, ring: await this._ring(o) };
    const a = (ctx.anchor ??= await this.call('getfcmpanchor', {}));
    if (o.index >= a.anchor) throw new Error('moeda privada recente demais: ela entra na árvore usada pelas provas em alguns segundos');
    const chunk = Math.floor(o.index / a.branch), total = Math.ceil(a.anchor / a.branch);
    const chunks = new Set([chunk]);
    while (chunks.size < Math.min(8, total)) chunks.add(Math.floor(Math.random() * total));
    const r = await this.call('getfcmppath', { anchor: a.anchor, chunks: [...chunks].sort(() => Math.random() - 0.5) });
    const mine = r.paths.find((x) => x.chunk === chunk);
    if (!mine) throw new Error('o servidor não devolveu o caminho na árvore');
    const path = mine.levels.map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map((h) => BigInt('0x' + h)) }));
    return {
      ...base, P: Point.fromBytes(fromHex(o.P)), C: Point.fromBytes(fromHex(o.C)),
      fcmp: { branch: a.branch, anchor: a.anchor, leafPos: o.index % a.branch, path },
    };
  }

  /** Calcula a parte cara das provas FCMP de todas as entradas ao mesmo tempo. */
  async _prepareFcmp(sInputs) {
    const f = sInputs.filter((s) => s.fcmp);
    if (!f.length) return;
    const pres = await fcmpParallel.fcmpPrepareMany(f.map((s) => ({ branch: s.fcmp.branch, N: s.fcmp.anchor, path: s.fcmp.path, leafPos: s.fcmp.leafPos, P: s.P, C: s.C })));
    f.forEach((s, i) => { s.fcmp.pre = pres[i]; });
  }

  async _ring(real) {
    const need = this.params.ringSize - 1;
    const info = await this.call('getshieldedoutputs', { start: 0, count: 0 });
    const total = info.total;
    const chosen = new Map(), rejected = new Set();
    for (let attempt = 0; attempt < 8 && chosen.size < need; attempt++) {
      // nunca pedir mais índices distintos do que existem (evita laço infinito em redes pequenas)
      const available = total - 1 - chosen.size - rejected.size;
      const want = Math.min(need * 4, available);
      if (want <= 0) break;
      const idx = new Set();
      while (idx.size < want) {
        // metade uniforme, metade enviesada para saídas recentes (como os gastos reais)
        const i = Math.random() < 0.5 ? Math.floor(Math.random() * total) : total - 1 - Math.floor(total * Math.random() ** 3);
        if (i !== real.index && !chosen.has(i) && !rejected.has(i)) idx.add(i);
      }
      const r = await this.call('getshieldedbyindex', { indices: [...idx] });
      for (const e of r.outputs) {
        const m = e.coinbase ? Math.max(this.params.ringMaturity, this.params.coinbaseMaturity) : this.params.ringMaturity;
        if (r.daaScore - e.daa >= m && chosen.size < need) chosen.set(e.index, e);
        else rejected.add(e.index);
      }
    }
    if (chosen.size < need) throw new Error('conjunto de anonimato ainda pequeno demais para um anel; aguarde mais saídas privadas na rede');
    const ring = [...chosen.values(), { index: real.index, outpoint: real.outpoint, P: real.P, C: real.C }]
      .sort((a, b) => a.index - b.index)
      .map((e) => ({ outpoint: parseOutpointKey(e.outpoint), P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)) }));
    return ring;
  }

  /**
   * Envia `amount` (grãos) para `to`. from: 'auto' | 'transparente' | 'privado'.
   * Retorna { txid, fee, from }.
   */
  async send({ to, amount, from = 'auto', feeRate, memo }) {
    // @nome → endereço registrado na rede
    let name = null;
    if (String(to).trim().startsWith('@')) {
      const info = await this.resolveName(to);
      if (info.status === 'livre') throw new Error(`${String(to).trim()} não está registrado`);
      if (info.status !== 'ativo') throw new Error(`${String(to).trim()} venceu e está em carência: confirme com o dono antes de pagar`);
      name = info.name;
      to = info.target;
    }
    await this.sync();
    const dest = decodeAddress(this.params, to);
    if (memo && dest.type !== 's') {
      throw new Error('memo só é possível em pagamentos para endereço privado (krs1…): num pagamento transparente ele ficaria público');
    }
    const bal = this.balance();
    const margin = 1_000_000n;
    let source = from;
    if (source === 'auto') {
      if (dest.type === 's' && bal.shielded >= amount + margin) source = 'privado';
      else if (bal.transparent >= amount + margin) source = 'transparente';
      else if (bal.shielded >= amount + margin) source = 'privado';
      else throw new Error('saldo insuficiente');
    }
    const outputs = [dest.type === 's' ? { type: 's', A: dest.A, B: dest.B, amount } : { type: 't', lock: dest.data, amount }];
    let tInputs = [], sInputs = [], change;
    if (source === 'transparente') {
      const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
      let acc = 0n;
      for (const u of coins) {
        if (acc >= amount + margin) break;
        tInputs.push(this._tIn(u));
        acc += BigInt(u.amount);
      }
      if (acc < amount) throw new Error('saldo transparente insuficiente');
      change = { type: 't', lock: this._changeLock };
    } else if (source === 'privado') {
      const coins = this.data.sOwned.filter((o) => !o.spent && !o.pending && !o.unverified && this._sMature(o)).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
      let acc = 0n;
      const ctx = {};
      for (const o of coins) {
        if (acc >= amount + margin) break;
        sInputs.push(await this._privateInput(o, ctx));
        acc += BigInt(o.amount);
      }
      if (acc < amount) throw new Error('saldo privado insuficiente');
      change = { type: 's', A: this.keys.A, B: this.keys.B };
    } else throw new Error('origem inválida: use transparente ou privado');

    const tp = Date.now();
    await this._prepareFcmp(sInputs);
    const { tx, fee, r } = buildTransaction({ params: this.params, tInputs, sInputs, outputs, change, feeRate, memo });
    const proveMs = Date.now() - tp;
    const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    if (r) this.data.txSecrets[res.txid] = r.toString(16);
    // registro local do envio (o segredo r permite gerar a prova de pagamento depois)
    (this.data.sent ??= {})[res.txid] = {
      to, name, amount: amount.toString(), fee: fee.toString(), memo: memo || null, from: source, time: Date.now(),
    };
    this.save();
    // anonymitySet: entre quantas saídas privadas cada entrada privada se esconde (FCMP: todas)
    const anonymitySet = sInputs.length ? (sInputs[0].fcmp ? sInputs[0].fcmp.anchor : sInputs[0].ring.length) : null;
    const prover = sInputs.some((s) => s.fcmp) ? fcmpParallel.lastProver : null;
    return { txid: res.txid, fee, from: source, size: tx.size, mass: tx.mass, name, to, privateInputs: sInputs.length, anonymitySet, proveMs, prover };
  }

  /** Consulta um @nome na rede: { status: 'ativo'|'em carência'|'livre', target, owner, … }. */
  resolveName(name) { return this.call('resolvename', { name }); }

  /**
   * Envia saídas arbitrárias pagando com o saldo transparente maduro (usado pelos @nomes).
   * extraInputs: entradas já prontas (ex.: o compromisso ou o registro de um nome);
   * extraFee: taxa além da de massa (ex.: taxa anual do nome, que vai para o Fundo de Segurança).
   */
  async sendOutputs(outputs, { extraInputs = [], extraFee = 0n, feeRate, maxInputs = 100 } = {}) {
    await this.sync();
    const want = outputs.reduce((a, o) => a + o.amount, 0n) + extraFee;
    const margin = 2_000_000n; // folga para a taxa de massa
    const tInputs = [...extraInputs];
    let acc = extraInputs.reduce((a, i) => a + i.amount, 0n);
    let weight = extraInputs.length * 6;
    const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
    for (const u of coins) {
      if (acc >= want + margin || weight + Wallet.inputWeight(u) > maxInputs) break;
      weight += Wallet.inputWeight(u);
      tInputs.push(this._tIn(u));
      acc += BigInt(u.amount);
    }
    if (acc < want) throw new Error(`saldo transparente insuficiente: precisa de ${want} grãos (+ taxa), há ${acc} (saldo privado não serve para taxas de nome)`);
    const { tx, fee } = buildTransaction({ params: this.params, tInputs, outputs, change: { type: 't', lock: this._changeLock }, feeRate, extraFee });
    const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    return { txid: res.txid, fee, tx };
  }

  /**
   * Paga vários destinos numa única transação, com o saldo transparente (usado por pools).
   * list: [{ to, amount }] — destinos transparentes e/ou privados (até 15 privados por transação).
   */
  /** Quanto dá para gastar numa transação usando no máximo `maxInputs` moedas transparentes maduras. */
  async capacity(maxInputs = 140) {
    await this.sync();
    const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
    return { amount: Wallet.takeCoins(coins, maxInputs).reduce((a, u) => a + BigInt(u.amount), 0n), coins: coins.length };
  }

  /**
   * Junta as menores moedas transparentes numa só (manutenção de quem recebe muitas
   * recompensas pequenas, como pools). Retorna o txid ou null se não houver o que juntar.
   */
  async consolidate(maxInputs = 140) {
    await this.sync();
    const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(a.amount) > BigInt(b.amount) ? 1 : -1));
    const take = Wallet.takeCoins(coins, maxInputs);
    if (take.length < 2) return null;
    const tInputs = take.map((u) => this._tIn(u));
    const { tx } = buildTransaction({ params: this.params, tInputs, sweep: { type: 't', lock: this._changeLock } });
    return (await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) })).txid;
  }

  async sendMany(list, { feeRate, maxInputs = 140 } = {}) {
    if (!list.length) throw new Error('nenhum destino');
    await this.sync();
    const outputs = list.map(({ to, amount }) => {
      const d = decodeAddress(this.params, to);
      return d.type === 's' ? { type: 's', A: d.A, B: d.B, amount } : { type: 't', lock: d.data, amount };
    });
    if (outputs.filter((o) => o.type === 's').length > 15) throw new Error('no máximo 15 destinos privados por transação');
    const total = list.reduce((a, x) => a + x.amount, 0n);
    const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
    const tInputs = [];
    let acc = 0n, weight = 0;
    for (const u of coins) {
      // limite de entradas: a transação não pode passar da massa máxima
      if (acc >= total + 5_000_000n || weight + Wallet.inputWeight(u) > maxInputs) break;
      weight += Wallet.inputWeight(u);
      tInputs.push(this._tIn(u));
      acc += BigInt(u.amount);
    }
    if (acc < total) throw new Error(`saldo transparente maduro insuficiente numa transação (${acc} < ${total} grãos)`);
    const { tx, fee } = buildTransaction({ params: this.params, tInputs, outputs, change: { type: 't', lock: this._changeLock }, feeRate });
    const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    return { txid: res.txid, fee, size: tx.size };
  }

  // ------------------------------------------------------- proteção quântica
  /**
   * Situação da carteira frente a um computador quântico.
   *   clássico: moedas em krv1… — a chave pública fica exposta no próprio endereço
   *   quântico: moedas em krq1… — protegidas por Schnorr + ML-DSA (as duas são exigidas)
   *   privado:  moedas em krs1… — o pool privado usa curvas elípticas (veja a documentação)
   */
  async quantumStatus() {
    await this.sync();
    const sum = (k) => this.tUtxos.filter((u) => u.kind === k).reduce((a, u) => a + BigInt(u.amount), 0n);
    const bal = this.balance();
    const classicPending = this.tUtxos.filter((u) => u.kind === 't' && (!u.mature || u.inMempool)).length;
    return {
      enabled: this.quantum, address: this.qAddress,
      classic: sum('t'), quantum: sum('q'), shielded: bal.shielded + bal.shieldedImmature + bal.shieldedPending,
      classicPending,
    };
  }

  /**
   * Migra para o endereço quântico: liga o modo quântico (troco e consolidações passam a ir
   * para krq1…) e move as moedas clássicas maduras (krv1…) para krq1…, em lotes.
   * includeShielded: também tira o saldo privado do pool e põe em krq1… — perde a privacidade
   * desses valores, mas fica protegido contra roubo quântico.
   */
  async migrateQuantum({ includeShielded = false, feeRate, maxInputs = 140, maxShieldedInputs = 8 } = {}) {
    this.data.quantum = true;
    this.save();
    await this.sync();
    const dest = { type: 't', lock: this.keys.qKey(0).lock };
    const txs = [];
    let moved = 0n;
    const classic = this.tUtxos.filter((u) => u.kind === 't' && u.mature && !u.inMempool);
    for (let i = 0; i < classic.length; i += maxInputs) {
      const batch = classic.slice(i, i + maxInputs);
      const tInputs = batch.map((u) => this._tIn(u));
      const { tx, fee } = buildTransaction({ params: this.params, tInputs, sweep: dest, feeRate });
      const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
      const amount = tInputs.reduce((a, x) => a + x.amount, 0n) - fee;
      txs.push({ txid: res.txid, from: 'transparente', inputs: batch.length, amount, fee });
      moved += amount;
    }
    if (includeShielded) {
      const coins = this.data.sOwned.filter((o) => !o.spent && !o.pending && !o.unverified && this._sMature(o));
      for (let i = 0; i < coins.length; i += maxShieldedInputs) {
        const batch = coins.slice(i, i + maxShieldedInputs);
        const sInputs = [], ctx = {};
        for (const o of batch) sInputs.push(await this._privateInput(o, ctx));
        await this._prepareFcmp(sInputs);
        const { tx, fee } = buildTransaction({ params: this.params, sInputs, sweep: dest, feeRate });
        const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
        const amount = sInputs.reduce((a, x) => a + x.amount, 0n) - fee;
        txs.push({ txid: res.txid, from: 'privado', inputs: batch.length, amount, fee });
        moved += amount;
      }
    }
    const pendingClassic = this.tUtxos.filter((u) => u.kind === 't' && (!u.mature || u.inMempool)).length;
    return { address: this.qAddress, txs, moved, pendingClassic };
  }

  /** Paga um link de cobrança krevo:… (valor e memo vêm do link). */
  async payRequest(uri, { from = 'auto', amount = null, feeRate } = {}) {
    const req = parsePaymentURI(this.params, uri);
    if (isExpired(req)) throw new Error('esta cobrança expirou; peça um novo QR code');
    const value = req.amount ?? amount;
    if (!value) throw new Error('a cobrança não define valor; informe o valor');
    const res = await this.send({ to: req.address, amount: value, from, feeRate, memo: req.memo ?? undefined });
    return { ...res, request: req };
  }

  /**
   * Lado de quem cobra: espera chegar o pagamento de uma cobrança desta carteira.
   * Cobrança privada → casa pelo memo (código único do pedido) e valor mínimo.
   * Cobrança transparente → casa pela primeira saída nova com valor suficiente.
   */
  async waitForPayment(req, { timeoutMs = 30 * 60_000, intervalMs = 400 } = {}) {
    const sub = req.type === 's' ? this.subaddressIndex(req.address) : -1;
    if (req.address !== this.tAddress && req.address !== this.qAddress && sub < 0) throw new Error('esta cobrança não é desta carteira');
    await this.sync();
    const seenT = new Set(this.tUtxos.map((u) => u.outpoint));
    const seenS = new Set(this.data.sOwned.map((o) => o.outpoint));
    const t0 = Date.now();
    for (;;) {
      if (req.type === 's') {
        // com memo, o código do pedido identifica o pagamento mesmo que ele tenha chegado antes de começarmos a esperar
        const hit = this.data.sOwned.find((o) => !o.coinbase && (o.sub ?? 0) === sub && (req.memo ? o.memo === req.memo : !seenS.has(o.outpoint))
          && (!req.amount || BigInt(o.amount) >= req.amount));
        if (hit) return { txid: hit.outpoint.split(':')[0], amount: BigInt(hit.amount), ms: Date.now() - t0, memo: hit.memo };
      } else {
        const hit = this.tUtxos.find((u) => !seenT.has(u.outpoint) && !u.coinbase && (!req.amount || BigInt(u.amount) >= req.amount));
        if (hit) return { txid: hit.outpoint.split(':')[0], amount: BigInt(hit.amount), ms: Date.now() - t0 };
      }
      if (Date.now() - t0 > timeoutMs || isExpired(req)) throw new Error('cobrança não paga dentro do prazo');
      await new Promise((r) => setTimeout(r, intervalMs));
      await this.sync();
    }
  }

  /** Histórico: pagamentos enviados por esta carteira e saídas privadas recebidas (com memo). */
  history() {
    const sent = Object.entries(this.data.sent ?? {}).map(([txid, s]) => ({ txid, ...s, amount: BigInt(s.amount), fee: BigInt(s.fee) }))
      .sort((a, b) => b.time - a.time);
    const received = this.data.sOwned.map((o) => ({
      txid: o.outpoint.split(':')[0], amount: BigInt(o.amount), memo: o.memo, spent: !!o.spent, coinbase: o.coinbase,
      sub: o.sub ?? 0, subLabel: this.subaddressLabel(o.sub ?? 0),
    }));
    return { sent, received };
  }

  /** Prova de pagamento para um envio feito por esta carteira a um endereço privado. */
  prove(txid, message = '') {
    const rec = this.data.sent?.[txid];
    const r = this.data.txSecrets?.[txid];
    if (!rec || !r) throw new Error('esta carteira não tem registro de ter enviado essa transação');
    if (decodeAddress(this.params, rec.to).type !== 's') {
      throw new Error('pagamentos transparentes já são públicos: o txid e o endereço bastam como prova');
    }
    return createPaymentProof(this.params, { txid: fromHex(txid), r: BigInt('0x' + r), j: 0, address: rec.to, message });
  }

  /** Verifica uma prova usando um nó (não precisa de carteira). */
  static async verifyProof(params, rpcUrl, { proof, address, message = '' }) {
    const { txid } = decodePaymentProof(params, proof);
    const info = await rpc(rpcUrl, 'gettransaction', { txid: toHex(txid) });
    const res = verifyPaymentProof(params, { proof, address, tx: Transaction.deserialize(fromHex(info.tx)), message });
    return { ...res, txid: toHex(txid), status: info.status, confirmations: info.confirmations };
  }

  /** Espera a transação ser aceita pelo virtual; retorna o tempo em ms. */
  async waitAccepted(txid, timeoutMs = 30_000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
      const s = await this.call('gettransactionstatus', { txid });
      if (s.status === 'accepted') return Date.now() - t0;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error('tempo esgotado esperando confirmação');
  }
}
