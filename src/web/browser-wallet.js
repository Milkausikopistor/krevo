// Carteira leve no navegador: os dados ficam no próprio aparelho, CIFRADOS com AES-256-GCM.
// Da senha saem DUAS chaves (PBKDF2-SHA256, 600 mil iterações pelo WebCrypto; sem contexto
// seguro — http em rede local —, 60 mil em JS puro):
//   k1 — abre o bloco SECRETO (semente + frase). Usada só ao destravar (e ao mostrar a frase);
//        a semente vai direto para o cofre (src/crypto/vault.js) e k1 é apagada.
//   k2 — cifra o resto (saídas, histórico, ajustes) a cada gravação. Fica na memória enquanto a
//        carteira está aberta, mas NÃO abre o bloco secreto.
// O servidor leve nunca recebe nada disso.

import { LightWallet, LightClient } from '../light/wallet.js';
import { getParams } from '../params.js';
import { pbkdf2, aesGcmEncrypt, aesGcmDecrypt, randomFill } from '../util/purecrypto.js';
import * as core from '../crypto/wasm.js';

const INDEX = 'krevo-carteiras';
const keyOf = (network) => `krevo-carteira-${network}`;
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

// AES-GCM no núcleo de tempo constante quando houver; senão o JavaScript
const enc = (k, iv, d) => (core.available() ? core.aesGcmEncrypt(k, iv, d) : aesGcmEncrypt(k, iv, d));
const dec = (k, iv, c, t) => (core.available() ? core.aesGcmDecrypt(k, iv, c, t) : aesGcmDecrypt(k, iv, c, t));

/** 64 bytes da senha: k1 = [0, 32) (os 32 primeiros são a chave do formato antigo), k2 = [32, 64). */
async function deriveKeys(password, saltHex, iterations) {
  const pw = new TextEncoder().encode(password);
  let out;
  if (globalThis.crypto?.subtle) {
    const km = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    out = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations }, km, 512));
  } else out = pbkdf2('sha256', pw, unhex(saltHex), iterations, 64);
  pw.fill(0);
  return { k1: out.subarray(0, 32), k2: out.slice(32), wipe: () => out.fill(0) };
}
function sealBytes(key, bytes) {
  const iv = randomFill(12);
  const { ct, tag } = enc(key, iv, bytes);
  return { iv: hex(iv), ct: hex(ct) + hex(tag) };
}
function unsealBytes(key, rec) {
  const all = unhex(rec.ct);
  try { return new Uint8Array(dec(key, unhex(rec.iv), all.subarray(0, -16), all.subarray(-16))); } catch { throw new Error('senha incorreta'); }
}
const sealJson = (key, obj) => sealBytes(key, new TextEncoder().encode(JSON.stringify(obj)));
const unsealJson = (key, rec) => JSON.parse(new TextDecoder().decode(unsealBytes(key, rec)));

/** Bloco secreto: semente (32 bytes) ‖ frase (UTF-8). */
function secretBlob(seedHex, mnemonic) {
  const m = new TextEncoder().encode(mnemonic ?? '');
  const out = new Uint8Array(32 + m.length);
  out.set(unhex(seedHex), 0);
  out.set(m, 32);
  return out;
}

export class BrowserWallet extends LightWallet {
  attach(rec, key) { this._rec = rec; this._key = key; }
  get network() { return this.params.name; }
  get serverUrl() { return this._rec.server; }
  save() {
    if (!this._key) return; // ainda montando
    const { iv, ct } = sealJson(this._key, this.data);
    localStorage.setItem(keyOf(this._rec.network), JSON.stringify({ ...this._rec, iv, ct }));
  }
  /** Um servidor, ou dois separados por vírgula (a carteira compara as respostas). */
  setServer(url) {
    this._rec.server = url;
    this.rpcUrl = url;
    this.servers = url.split(',').map((u) => u.trim()).filter(Boolean).map((u) => new LightClient(u));
    this.server = this.servers[0];
    this._active = null;
    this.save();
    remember(this._rec.network, url);
  }
  forget() {
    localStorage.removeItem(keyOf(this._rec.network));
    localStorage.setItem(INDEX, JSON.stringify(storedWallets().filter((x) => x.network !== this._rec.network)));
    this._key = null;
    this.close();
  }
  async checkPassword(password) {
    const k = await deriveKeys(password, this._rec.salt, this._rec.iter);
    try { return hex(k.k2) === hex(this._key); } finally { k.wipe(); }
  }
  /** Frase de recuperação: decifrada agora, com a senha (não fica guardada na memória). */
  async revealMnemonic(password) {
    const k = await deriveKeys(password, this._rec.salt, this._rec.iter);
    const blob = unsealBytes(k.k1, this._rec.secret);
    k.wipe();
    try { return new TextDecoder().decode(blob.subarray(32)) || null; } finally { blob.fill(0); }
  }
}

export function storedWallets() {
  try { return JSON.parse(localStorage.getItem(INDEX) ?? '[]'); } catch { return []; }
}
function remember(network, server) {
  const list = storedWallets().filter((x) => x.network !== network);
  list.unshift({ network, server });
  localStorage.setItem(INDEX, JSON.stringify(list));
}

/** Cria (frase nova) ou restaura (frase existente) e guarda cifrada neste aparelho. */
export async function createWallet({ server, password, mnemonic }) {
  const info = await new LightClient(server).info(); // descobre a rede e confere que o servidor responde
  const params = getParams(info.network);
  if (localStorage.getItem(keyOf(info.network))) throw new Error(`já existe uma carteira da rede ${info.network} neste navegador`);
  const iter = globalThis.crypto?.subtle ? 600_000 : 60_000;
  const rec = { v: 2, network: info.network, server, salt: hex(randomFill(16)), iter, kdf: 'pbkdf2-sha256' };
  const k = await deriveKeys(password, rec.salt, iter);
  const w = BrowserWallet.create(null, params, server, { mnemonic });
  // semente e frase saem dos dados comuns e vão para o bloco secreto
  const blob = secretBlob(w.data.seed, w.data.mnemonic);
  rec.secret = sealBytes(k.k1, blob);
  blob.fill(0);
  delete w.data.seed; delete w.data.mnemonic;
  w.mnemonic = null;
  w.attach(rec, k.k2);
  k.wipe();
  w.save();
  remember(info.network, server);
  return w;
}

export async function unlockWallet(network, password) {
  const raw = localStorage.getItem(keyOf(network));
  if (!raw) throw new Error('nenhuma carteira desta rede neste navegador');
  const rec = JSON.parse(raw);
  const k = await deriveKeys(password, rec.salt, rec.iter);
  const meta = { v: 2, network: rec.network, server: rec.server, salt: rec.salt, iter: rec.iter, kdf: rec.kdf };
  let data, blob;
  if (rec.v === 1) {
    // formato antigo: tudo num bloco só, com a chave k1 → migra para o novo (semente à parte)
    data = unsealJson(k.k1, rec);
    blob = secretBlob(data.seed, data.mnemonic);
    meta.secret = sealBytes(k.k1, blob);
    delete data.seed; delete data.mnemonic;
  } else {
    blob = unsealBytes(k.k1, rec.secret);
    meta.secret = rec.secret;
    data = unsealJson(k.k2, rec);
  }
  let w;
  try {
    w = new BrowserWallet(null, data, getParams(rec.network), rec.server, undefined, { seed: blob.subarray(0, 32) });
  } finally { blob.fill(0); }
  w.attach(meta, k.k2);
  k.wipe();
  if (rec.v === 1) w.save();
  return w;
}
