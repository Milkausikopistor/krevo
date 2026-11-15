// Light wallet in the browser: the data stays on the device, ENCRYPTED with AES-256-GCM.
// The password yields TWO keys (PBKDF2-SHA256, 600,000 iterations via WebCrypto; without a secure
// context — plain http on a local network — 60,000 in pure JavaScript):
//   k1 — opens the SECRET block (seed + phrase). Used only to unlock (and to show the phrase);
//        the seed goes straight into the vault (src/crypto/vault.js) and k1 is wiped.
//   k2 — encrypts everything else (outputs, history, settings) on every save. It stays in memory
//        while the wallet is open, but it CANNOT open the secret block.
// The light server never receives any of this.

import { LightWallet, LightClient } from '../light/wallet.js';
import { getParams } from '../params.js';
import { pbkdf2, aesGcmEncrypt, aesGcmDecrypt, randomFill } from '../util/purecrypto.js';
import * as core from '../crypto/wasm.js';

const INDEX = 'krevo-wallets';
const keyOf = (network) => `krevo-wallet-${network}`;
// Earlier versions used Portuguese storage keys (krevo-carteiras, krevo-carteira-<network>): move them once.
try {
  const oldIndex = localStorage.getItem('krevo-carteiras');
  if (oldIndex !== null && localStorage.getItem(INDEX) === null) localStorage.setItem(INDEX, oldIndex);
  for (const k of Object.keys(localStorage)) {
    const m = k.match(/^krevo-carteira-(.+)$/);
    if (!m) continue;
    if (localStorage.getItem(keyOf(m[1])) === null) localStorage.setItem(keyOf(m[1]), localStorage.getItem(k));
    localStorage.removeItem(k);
  }
  localStorage.removeItem('krevo-carteiras');
} catch { /* storage unavailable */ }
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

// AES-GCM in the constant-time core when available; otherwise JavaScript
const enc = (k, iv, d) => (core.available() ? core.aesGcmEncrypt(k, iv, d) : aesGcmEncrypt(k, iv, d));
const dec = (k, iv, c, t) => (core.available() ? core.aesGcmDecrypt(k, iv, c, t) : aesGcmDecrypt(k, iv, c, t));

/** 64 bytes from the password: k1 = [0, 32) (the first 32 are the old format's key), k2 = [32, 64). */
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
  try { return new Uint8Array(dec(key, unhex(rec.iv), all.subarray(0, -16), all.subarray(-16))); } catch { throw new Error('wrong password'); }
}
const sealJson = (key, obj) => sealBytes(key, new TextEncoder().encode(JSON.stringify(obj)));
const unsealJson = (key, rec) => JSON.parse(new TextDecoder().decode(unsealBytes(key, rec)));

/** Secret block: seed (32 bytes) ‖ phrase (UTF-8). */
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
    if (!this._key) return; // still being set up
    const { iv, ct } = sealJson(this._key, this.data);
    localStorage.setItem(keyOf(this._rec.network), JSON.stringify({ ...this._rec, iv, ct }));
  }
  /** One server, or two separated by a comma (the wallet compares their answers). */
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
  /** Recovery phrase: decrypted now, with the password (it is not kept in memory). */
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

/** Creates (new phrase) or restores (existing phrase) and stores it encrypted on this device. */
export async function createWallet({ server, password, mnemonic }) {
  const info = await new LightClient(server).info(); // finds out the network and checks that the server answers
  const params = getParams(info.network);
  if (localStorage.getItem(keyOf(info.network))) throw new Error(`a wallet for the ${info.network} network already exists in this browser`);
  const iter = globalThis.crypto?.subtle ? 600_000 : 60_000;
  const rec = { v: 2, network: info.network, server, salt: hex(randomFill(16)), iter, kdf: 'pbkdf2-sha256' };
  const k = await deriveKeys(password, rec.salt, iter);
  const w = BrowserWallet.create(null, params, server, { mnemonic });
  // seed and phrase leave the regular data and go into the secret block
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
  if (!raw) throw new Error('no wallet for this network in this browser');
  const rec = JSON.parse(raw);
  const k = await deriveKeys(password, rec.salt, rec.iter);
  const meta = { v: 2, network: rec.network, server: rec.server, salt: rec.salt, iter: rec.iter, kdf: rec.kdf };
  let data, blob;
  if (rec.v === 1) {
    // old format: everything in one block, under key k1 → migrate to the new one (seed kept apart)
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
