// Wallet: keeps the seed, syncs with a node over RPC and builds transactions.
// Private spends prove they belong to the tree of ALL private outputs (FCMP). The wallet asks
// the node for the path of its "chunk" of the tree mixed with decoy chunks — the node does not
// know which one is real. (On simnet rings can still be used, for fast tests.)

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
  try { return Buffer.concat([d.update(fromHex(enc.ct)), d.final()]); } catch { throw new Error('wrong password'); }
}

// File fields that stay in the clear; everything else (outputs, history, transaction secrets,
// labels…) is encrypted with a key derived from the seed, INSIDE the vault, when there is a password.
const PUBLIC_FIELDS = new Set(['version', 'network', 'seedEnc', 'mnemonicEnc', 'hasPassphrase', 'seed', 'mnemonic', 'sealed']);

export class Wallet {
  /** opts.seed: seed already decrypted by the caller (e.g. the browser wallet). */
  constructor(file, data, params, rpcUrl, password, opts = {}) {
    this.file = file; this.data = data; this.params = params; this.rpcUrl = rpcUrl;
    const seed = opts.seed ? Buffer.from(opts.seed) : data.seedEnc ? decryptSeed(data.seedEnc, password ?? '') : fromHex(data.seed);
    // the seed goes into the vault and the copy here is wiped: the keys do not exist in JavaScript
    try { this.keys = new Keys(seed); } finally { seed.fill(0); }
    // recovery phrase: the encrypted one is only decrypted when the user asks (revealMnemonic)
    this.mnemonic = data.mnemonicEnc ? null : (data.mnemonic ?? null);
    if (data.sealed) {
      Object.assign(data, JSON.parse(this.keys.vault.unseal(fromHex(data.sealed)).toString('utf8')));
      delete data.sealed;
    }
    // Old files stored each private output's one-time key p IN PLAIN TEXT (whoever read the file
    // could spend the coins without the password). Now only k (view level) is kept and p is
    // computed in the vault when spending: erase the p values and rescan.
    let migrated = false;
    for (const o of data.sOwned ?? []) {
      if (o.p !== undefined) { delete o.p; migrated = true; }
    }
    if (migrated && (data.sOwned ?? []).some((o) => o.k === undefined)) {
      data.sOwned = data.sOwned.filter((o) => o.k !== undefined);
      data.sScanned = 0;
    }
    this.tUtxos = [];
    // 'fcmp' (whole tree) or 'ring' (ring of 16, legacy — only where consensus accepts it)
    this.privateInputs = params.ringInputs ? 'ring' : 'fcmp';
  }

  /**
   * Creates a new wallet. By default it generates a 24-word recovery phrase (BIP-39);
   * `mnemonic` restores from an existing phrase. `passphrase` is BIP-39's optional
   * "extra phrase": without it, the same phrase produces a different wallet.
   */
  static create(file, params, rpcUrl, { password, seed, mnemonic, passphrase = '', words = 24 } = {}) {
    if (fs.existsSync(file)) throw new Error(`the wallet ${file} already exists`);
    let m = null, s = seed;
    if (!s) {
      m = mnemonic ? normalizeMnemonic(mnemonic) : generateMnemonic(words);
      mnemonicToEntropy(m); // validates the checksum
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
    const w = new this(file, data, params, rpcUrl, password); // "this": also creates the light wallet (subclass)
    if (m) w.mnemonic = m; // to show ONCE, at creation
    w.save();
    return w;
  }

  /** Restores from the recovery phrase (and the extra phrase, if one was used). */
  static restore(file, params, rpcUrl, { mnemonic, passphrase = '', password } = {}) {
    if (!mnemonic) throw new Error('enter the recovery phrase');
    return this.create(file, params, rpcUrl, { mnemonic, passphrase, password });
  }
  static load(file, params, rpcUrl, password) {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data.network !== params.name) throw new Error(`the wallet belongs to the ${data.network} network`);
    return new this(file, data, params, rpcUrl, password);
  }
  /** Writes atomically (temporary file + rename: a crash halfway does not corrupt the wallet)
   *  and readable only by the owner (0600). */
  save() {
    if (!this.file) return;
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.fileData(), null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    try { fs.chmodSync(this.file, 0o600); } catch { /* systems without POSIX permissions */ }
  }
  /** What goes to disk: with a password, only the public fields in the clear; the rest encrypted by the vault. */
  fileData() {
    if (!this.data.seedEnc) return this.data;
    const pub = {}, priv = {};
    for (const [k, v] of Object.entries(this.data)) (PUBLIC_FIELDS.has(k) ? pub : priv)[k] = v;
    pub.sealed = toHex(this.keys.vault.seal(Buffer.from(JSON.stringify(priv), 'utf8')));
    return pub;
  }
  /** Recovery phrase, decrypted only now (asks for the password again). */
  revealMnemonic(password) {
    if (this.data.mnemonicEnc) return decryptSeed(this.data.mnemonicEnc, password ?? '').toString('utf8');
    return this.data.mnemonic ?? null;
  }
  /** Erases the keys from memory (the vault is zeroed); the wallet no longer signs. */
  close() { this.keys.close(); }
  call(m, p) { return rpc(this.rpcUrl, m, p); }

  get tAddress() { return this.keys.tAddress(this.params, 0); }
  get sAddress() { return this.keys.sAddress(this.params, 0); }
  /** Quantum-safe transparent address (krq1…). */
  get qAddress() { return this.keys.qAddress(this.params, 0); }
  /** Quantum mode: change and consolidations go to krq1… instead of krv1…. */
  get quantum() { return !!this.data.quantum; }
  get _changeLock() { return this.quantum ? this.keys.qKey(0).lock : this.keys.tKey(0).lock; }

  /**
   * Weight of a transparent coin within the input limit: a krq1… input carries the hybrid
   * witness (3,830 bytes, ~5,900 mass), ~6× a Schnorr input (~1,100).
   */
  static inputWeight(u) { return u.kind === 'q' ? 6 : 1; }
  /** Longest prefix of `coins` whose total weight fits in `maxInputs` Schnorr-equivalent inputs. */
  static takeCoins(coins, maxInputs) {
    const out = [];
    let w = 0;
    for (const u of coins) { w += Wallet.inputWeight(u); if (w > maxInputs) break; out.push(u); }
    return out;
  }

  /** Transparent input ready for the builder, with the right keys for the address type. */
  _tIn(u) {
    const base = { outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount) };
    if (u.kind === 'q') { const k = this.keys.qKey(0); return { ...base, signer: k.signer, pq: k }; }
    return { ...base, signer: this.keys.tKey(0).signer };
  }

  // ----------------------------------------------------------- subaddresses
  /** Number of known private addresses (the main one is index 0). */
  get subCount() { return (this.data.subaddresses?.length ?? 0) + 1; }

  /** Creates the next private subaddress, with a label of your own (it never goes to the network). */
  newSubaddress(label = '') {
    (this.data.subaddresses ??= []).push({ label, created: Date.now() });
    this.save();
    const index = this.subCount - 1;
    return { index, label, address: this.keys.sAddress(this.params, index) };
  }

  subaddressLabel(i) { return i === 0 ? 'main' : (this.data.subaddresses?.[i - 1]?.label || `subaddress ${i}`); }

  /** List: index, label, address and total received (unspent) on each private address. */
  listSubaddresses() {
    return Array.from({ length: this.subCount }, (_, i) => {
      const outs = this.data.sOwned.filter((o) => (o.sub ?? 0) === i);
      return {
        index: i, label: this.subaddressLabel(i), address: this.keys.sAddress(this.params, i),
        received: outs.reduce((a, o) => a + BigInt(o.amount), 0n), count: outs.length,
      };
    });
  }

  /** Index of this wallet's subaddress with that address, or -1. */
  subaddressIndex(address) {
    for (let i = 0; i < this.subCount; i++) if (this.keys.sAddress(this.params, i) === address) return i;
    return -1;
  }

  async sync() {
    // transparent coins on both addresses: krv1… (classic) and krq1… (quantum-safe)
    const tLock = toHex(this.keys.tKey(0).lock), qLock = toHex(this.keys.qKey(0).lock);
    this.tUtxos = (await this.call('getutxos', { locks: [tLock, qLock] })).utxos
      .map((u) => ({ ...u, kind: u.lock === qLock ? 'q' : 't' }));

    // Scan of private outputs (with a margin for reorganizations). The table covers every
    // subaddress + 50 ahead: a wallet restored from the phrase also finds the subaddresses
    // created on another computer.
    const LOOKAHEAD = 50;
    let scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
    const start = Math.max(0, this.data.sScanned - 200);
    const owned = this.data.sOwned.filter((o) => o.index < start);
    let i = start, total = 0;
    do {
      const r = await this.call('getshieldedoutputs', { start: i, count: 2000 });
      total = r.total;
      this.data.daa = r.daaScore;
      const sss = this.keys.vault.sharedMany(r.outputs.map((e) => fromHex(e.R))); // a·R in the vault, in a batch
      for (const [n, e] of r.outputs.entries()) {
        const o = { P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)), encAmount: fromHex(e.encAmount), viewTag: e.viewTag };
        const got = scanShieldedOutput(scanKeys, null, e.j, o, sss[n]);
        if (!got) continue;
        if (got.index >= this.subCount) { // subaddress created in another copy of the wallet
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
    // light wallet: what the server reported but has not been PROVEN yet neither counts nor can be spent
    let unverified = (this.tUnverified ?? []).reduce((a, u) => a + BigInt(u.amount), 0n);
    for (const o of this.data.sOwned) {
      if (o.spent) continue;
      if (o.unverified) { unverified += BigInt(o.amount); continue; }
      if (o.pending) sPending += BigInt(o.amount); else if (!this._sMature(o)) sImmature += BigInt(o.amount); else s += BigInt(o.amount);
    }
    return { transparent: tMature, transparentImmature: tImmature, transparentPending: tPending, shielded: s, shieldedImmature: sImmature, shieldedPending: sPending, unverified };
  }

  _sMature(o) {
    // FCMP: the coin must be inside a mature anchor (fcmpMaturity also covers coinbases)
    if (this.privateInputs === 'fcmp') return (this.data.daa ?? 0) - o.daa > this.params.fcmpMaturity;
    const need = o.coinbase ? Math.max(this.params.ringMaturity, this.params.coinbaseMaturity) : this.params.ringMaturity;
    return (this.data.daa ?? 0) - o.daa >= need;
  }

  /**
   * Data to spend a private output. FCMP: anchor + path of the tree chunk that contains the
   * output, requested together with 7 decoy chunks. ctx keeps the anchor (the same for every
   * input of the transaction).
   */
  async _privateInput(o, ctx = {}) {
    if (o.k === undefined) throw new Error('sync the wallet before spending (old format)');
    const base = { outpoint: parseOutpointKey(o.outpoint), amount: BigInt(o.amount), mask: BigInt(o.mask), spend: this.keys.spender(BigInt('0x' + o.k), o.sub ?? 0) };
    if (this.privateInputs === 'ring') return { ...base, ring: await this._ring(o) };
    const a = (ctx.anchor ??= await this.call('getfcmpanchor', {}));
    if (o.index >= a.anchor) throw new Error('private coin too recent: it enters the tree used by the proofs in a few seconds');
    const chunk = Math.floor(o.index / a.branch), total = Math.ceil(a.anchor / a.branch);
    const chunks = new Set([chunk]);
    while (chunks.size < Math.min(8, total)) chunks.add(Math.floor(Math.random() * total));
    const r = await this.call('getfcmppath', { anchor: a.anchor, chunks: [...chunks].sort(() => Math.random() - 0.5) });
    const mine = r.paths.find((x) => x.chunk === chunk);
    if (!mine) throw new Error('the server did not return the path in the tree');
    const path = mine.levels.map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map((h) => BigInt('0x' + h)) }));
    return {
      ...base, P: Point.fromBytes(fromHex(o.P)), C: Point.fromBytes(fromHex(o.C)),
      fcmp: { branch: a.branch, anchor: a.anchor, leafPos: o.index % a.branch, path },
    };
  }

  /** Computes the expensive part of the FCMP proofs of all inputs at the same time. */
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
      // never ask for more distinct indexes than exist (avoids an infinite loop on small networks)
      const available = total - 1 - chosen.size - rejected.size;
      const want = Math.min(need * 4, available);
      if (want <= 0) break;
      const idx = new Set();
      while (idx.size < want) {
        // half uniform, half biased toward recent outputs (like real spends)
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
    if (chosen.size < need) throw new Error('anonymity set still too small for a ring; wait for more private outputs on the network');
    const ring = [...chosen.values(), { index: real.index, outpoint: real.outpoint, P: real.P, C: real.C }]
      .sort((a, b) => a.index - b.index)
      .map((e) => ({ outpoint: parseOutpointKey(e.outpoint), P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)) }));
    return ring;
  }

  /**
   * Sends `amount` (grains) to `to`. from: 'auto' | 'transparent' | 'private'.
   * Returns { txid, fee, from }.
   */
  async send({ to, amount, from = 'auto', feeRate, memo }) {
    // @name → address registered on the network
    let name = null;
    if (String(to).trim().startsWith('@')) {
      const info = await this.resolveName(to);
      if (info.status === 'free') throw new Error(`${String(to).trim()} is not registered`);
      if (info.status !== 'active') throw new Error(`${String(to).trim()} expired and is in its grace period: check with the owner before paying`);
      name = info.name;
      to = info.target;
    }
    await this.sync();
    const dest = decodeAddress(this.params, to);
    if (memo && dest.type !== 's') {
      throw new Error('a memo is only possible on payments to a private address (krs1…): in a transparent payment it would be public');
    }
    const bal = this.balance();
    const margin = 1_000_000n;
    // older Portuguese values are still accepted
    let source = ({ transparente: 'transparent', privado: 'private', shielded: 'private' })[from] ?? from;
    if (source === 'auto') {
      if (dest.type === 's' && bal.shielded >= amount + margin) source = 'private';
      else if (bal.transparent >= amount + margin) source = 'transparent';
      else if (bal.shielded >= amount + margin) source = 'private';
      else throw new Error('insufficient balance');
    }
    const outputs = [dest.type === 's' ? { type: 's', A: dest.A, B: dest.B, amount } : { type: 't', lock: dest.data, amount }];
    let tInputs = [], sInputs = [], change;
    if (source === 'transparent') {
      const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
      let acc = 0n;
      for (const u of coins) {
        if (acc >= amount + margin) break;
        tInputs.push(this._tIn(u));
        acc += BigInt(u.amount);
      }
      if (acc < amount) throw new Error('insufficient transparent balance');
      change = { type: 't', lock: this._changeLock };
    } else if (source === 'private') {
      const coins = this.data.sOwned.filter((o) => !o.spent && !o.pending && !o.unverified && this._sMature(o)).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
      let acc = 0n;
      const ctx = {};
      for (const o of coins) {
        if (acc >= amount + margin) break;
        sInputs.push(await this._privateInput(o, ctx));
        acc += BigInt(o.amount);
      }
      if (acc < amount) throw new Error('insufficient private balance');
      change = { type: 's', A: this.keys.A, B: this.keys.B };
    } else throw new Error('invalid source: use transparent or private');

    const tp = Date.now();
    await this._prepareFcmp(sInputs);
    const { tx, fee, r } = buildTransaction({ params: this.params, tInputs, sInputs, outputs, change, feeRate, memo });
    const proveMs = Date.now() - tp;
    const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    if (r) this.data.txSecrets[res.txid] = r.toString(16);
    // local record of the payment (the secret r allows creating the payment proof later)
    (this.data.sent ??= {})[res.txid] = {
      to, name, amount: amount.toString(), fee: fee.toString(), memo: memo || null, from: source, time: Date.now(),
    };
    this.save();
    // anonymitySet: among how many private outputs each private input hides (FCMP: all of them)
    const anonymitySet = sInputs.length ? (sInputs[0].fcmp ? sInputs[0].fcmp.anchor : sInputs[0].ring.length) : null;
    const prover = sInputs.some((s) => s.fcmp) ? fcmpParallel.lastProver : null;
    return { txid: res.txid, fee, from: source, size: tx.size, mass: tx.mass, name, to, privateInputs: sInputs.length, anonymitySet, proveMs, prover };
  }

  /** Looks up an @name on the network: { status: 'active'|'grace'|'free', target, owner, … }. */
  resolveName(name) { return this.call('resolvename', { name }); }

  /**
   * Sends arbitrary outputs paying with the mature transparent balance (used by @names).
   * extraInputs: ready-made inputs (e.g. the commitment or the record of a name);
   * extraFee: fee beyond the mass fee (e.g. the name's yearly fee, which goes to the Security Fund).
   */
  async sendOutputs(outputs, { extraInputs = [], extraFee = 0n, feeRate, maxInputs = 100 } = {}) {
    await this.sync();
    const want = outputs.reduce((a, o) => a + o.amount, 0n) + extraFee;
    const margin = 2_000_000n; // headroom for the mass fee
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
    if (acc < want) throw new Error(`insufficient transparent balance: needs ${want} grains (+ fee), has ${acc} (the private balance cannot pay name fees)`);
    const { tx, fee } = buildTransaction({ params: this.params, tInputs, outputs, change: { type: 't', lock: this._changeLock }, feeRate, extraFee });
    const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    return { txid: res.txid, fee, tx };
  }

  /**
   * Pays several recipients in a single transaction, with the transparent balance (used by pools).
   * list: [{ to, amount }] — transparent and/or private recipients (up to 15 private per transaction).
   */
  /** How much can be spent in one transaction using at most `maxInputs` mature transparent coins. */
  async capacity(maxInputs = 140) {
    await this.sync();
    const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
    return { amount: Wallet.takeCoins(coins, maxInputs).reduce((a, u) => a + BigInt(u.amount), 0n), coins: coins.length };
  }

  /**
   * Merges the smallest transparent coins into one (maintenance for whoever receives many small
   * rewards, like pools). Returns the txid, or null if there is nothing to merge.
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
    if (!list.length) throw new Error('no destination');
    await this.sync();
    const outputs = list.map(({ to, amount }) => {
      const d = decodeAddress(this.params, to);
      return d.type === 's' ? { type: 's', A: d.A, B: d.B, amount } : { type: 't', lock: d.data, amount };
    });
    if (outputs.filter((o) => o.type === 's').length > 15) throw new Error('at most 15 private recipients per transaction');
    const total = list.reduce((a, x) => a + x.amount, 0n);
    const coins = this.tUtxos.filter((u) => u.mature && !u.inMempool).sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
    const tInputs = [];
    let acc = 0n, weight = 0;
    for (const u of coins) {
      // input limit: the transaction cannot exceed the maximum mass
      if (acc >= total + 5_000_000n || weight + Wallet.inputWeight(u) > maxInputs) break;
      weight += Wallet.inputWeight(u);
      tInputs.push(this._tIn(u));
      acc += BigInt(u.amount);
    }
    if (acc < total) throw new Error(`insufficient mature transparent balance in one transaction (${acc} < ${total} grains)`);
    const { tx, fee } = buildTransaction({ params: this.params, tInputs, outputs, change: { type: 't', lock: this._changeLock }, feeRate });
    const res = await this.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    return { txid: res.txid, fee, size: tx.size };
  }

  // ------------------------------------------------------- quantum protection
  /**
   * The wallet's situation against a quantum computer.
   *   classic: coins on krv1… — the public key is exposed in the address itself
   *   quantum: coins on krq1… — protected by Schnorr + ML-DSA (both are required)
   *   private: coins on krs1… — the private pool uses elliptic curves (see the documentation)
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
   * Migrates to the quantum-safe address: turns quantum mode on (change and consolidations go to
   * krq1…) and moves the mature classic coins (krv1…) to krq1…, in batches.
   * includeShielded: also takes the private balance out of the pool into krq1… — it loses the
   * privacy of those amounts, but becomes protected against quantum theft.
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
      txs.push({ txid: res.txid, from: 'transparent', inputs: batch.length, amount, fee });
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
        txs.push({ txid: res.txid, from: 'private', inputs: batch.length, amount, fee });
        moved += amount;
      }
    }
    const pendingClassic = this.tUtxos.filter((u) => u.kind === 't' && (!u.mature || u.inMempool)).length;
    return { address: this.qAddress, txs, moved, pendingClassic };
  }

  /** Pays a krevo:… payment request link (amount and memo come from the link). */
  async payRequest(uri, { from = 'auto', amount = null, feeRate } = {}) {
    const req = parsePaymentURI(this.params, uri);
    if (isExpired(req)) throw new Error('this payment request has expired; ask for a new QR code');
    const value = req.amount ?? amount;
    if (!value) throw new Error('the payment request has no amount; enter the amount');
    const res = await this.send({ to: req.address, amount: value, from, feeRate, memo: req.memo ?? undefined });
    return { ...res, request: req };
  }

  /**
   * Requester's side: waits for the payment of a request made by this wallet.
   * Private request → matched by the memo (unique order code) and minimum amount.
   * Transparent request → matched by the first new output with enough value.
   */
  async waitForPayment(req, { timeoutMs = 30 * 60_000, intervalMs = 400 } = {}) {
    const sub = req.type === 's' ? this.subaddressIndex(req.address) : -1;
    if (req.address !== this.tAddress && req.address !== this.qAddress && sub < 0) throw new Error('this payment request does not belong to this wallet');
    await this.sync();
    const seenT = new Set(this.tUtxos.map((u) => u.outpoint));
    const seenS = new Set(this.data.sOwned.map((o) => o.outpoint));
    const t0 = Date.now();
    for (;;) {
      if (req.type === 's') {
        // with a memo, the order code identifies the payment even if it arrived before we started waiting
        const hit = this.data.sOwned.find((o) => !o.coinbase && (o.sub ?? 0) === sub && (req.memo ? o.memo === req.memo : !seenS.has(o.outpoint))
          && (!req.amount || BigInt(o.amount) >= req.amount));
        if (hit) return { txid: hit.outpoint.split(':')[0], amount: BigInt(hit.amount), ms: Date.now() - t0, memo: hit.memo };
      } else {
        const hit = this.tUtxos.find((u) => !seenT.has(u.outpoint) && !u.coinbase && (!req.amount || BigInt(u.amount) >= req.amount));
        if (hit) return { txid: hit.outpoint.split(':')[0], amount: BigInt(hit.amount), ms: Date.now() - t0 };
      }
      if (Date.now() - t0 > timeoutMs || isExpired(req)) throw new Error('payment request not paid in time');
      await new Promise((r) => setTimeout(r, intervalMs));
      await this.sync();
    }
  }

  /** History: payments sent by this wallet and private outputs received (with memo). */
  history() {
    const sent = Object.entries(this.data.sent ?? {}).map(([txid, s]) => ({ txid, ...s, amount: BigInt(s.amount), fee: BigInt(s.fee) }))
      .sort((a, b) => b.time - a.time);
    const received = this.data.sOwned.map((o) => ({
      txid: o.outpoint.split(':')[0], amount: BigInt(o.amount), memo: o.memo, spent: !!o.spent, coinbase: o.coinbase,
      sub: o.sub ?? 0, subLabel: this.subaddressLabel(o.sub ?? 0),
    }));
    return { sent, received };
  }

  /** Payment proof for a payment made by this wallet to a private address. */
  prove(txid, message = '') {
    const rec = this.data.sent?.[txid];
    const r = this.data.txSecrets?.[txid];
    if (!rec || !r) throw new Error('this wallet has no record of having sent that transaction');
    if (decodeAddress(this.params, rec.to).type !== 's') {
      throw new Error('transparent payments are already public: the txid and the address are proof enough');
    }
    return createPaymentProof(this.params, { txid: fromHex(txid), r: BigInt('0x' + r), j: 0, address: rec.to, message });
  }

  /** Verifies a proof using a node (no wallet needed). */
  static async verifyProof(params, rpcUrl, { proof, address, message = '' }) {
    const { txid } = decodePaymentProof(params, proof);
    const info = await rpc(rpcUrl, 'gettransaction', { txid: toHex(txid) });
    const res = verifyPaymentProof(params, { proof, address, tx: Transaction.deserialize(fromHex(info.tx)), message });
    return { ...res, txid: toHex(txid), status: info.status, confirmations: info.confirmations };
  }

  /** Waits until the transaction is accepted by the virtual block; returns the time in ms. */
  async waitAccepted(txid, timeoutMs = 30_000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
      const s = await this.call('gettransactionstatus', { txid });
      if (s.status === 'accepted') return Date.now() - t0;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error('timed out waiting for confirmation');
  }
}
