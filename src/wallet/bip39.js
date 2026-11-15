// Recovery phrase — BIP-39 standard (the same as Bitcoin, Ledger, Trezor…).
//
// 24 words = 256 bits of randomness + 8 check bits (checksum).
// The last word carries part of the checksum: a mistyped or swapped word is
// almost always detected (1 chance in 256 of passing with 24 words, 1 in 16
// with 12).
//
// BIP-39 seed = PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase, 2048, 64 bytes).
// Krevo wallet seed = H("wallet/bip39", BIP-39 seed) — 32 bytes.

import { createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import { WORDS } from './wordlist-en.js';
import { H } from '../crypto/hash.js';

const INDEX = new Map(WORDS.map((w, i) => [w, i]));
const BY_PREFIX = new Map(WORDS.map((w, i) => [w.slice(0, 4), i])); // the first 4 letters are unique
export const VALID_LENGTHS = [12, 15, 18, 21, 24];

const bits = (buf) => [...buf].map((b) => b.toString(2).padStart(8, '0')).join('');

export function entropyToMnemonic(entropy) {
  if (![16, 20, 24, 28, 32].includes(entropy.length)) throw new Error('entropy must have 16–32 bytes (multiple of 4)');
  const cs = entropy.length / 4; // checksum bits
  const all = bits(entropy) + bits(createHash('sha256').update(entropy).digest()).slice(0, cs);
  const out = [];
  for (let i = 0; i < all.length; i += 11) out.push(WORDS[parseInt(all.slice(i, i + 11), 2)]);
  return out.join(' ');
}

export function generateMnemonic(words = 24) {
  if (!VALID_LENGTHS.includes(words)) throw new Error(`the phrase must have ${VALID_LENGTHS.join(', ')} words`);
  return entropyToMnemonic(randomBytes((words / 3) * 4));
}

/**
 * Normalizes what the user typed: lowercase, extra spaces, and accepts the
 * first 4 letters of each word (e.g. "aban" = "abandon").
 * Throws an error saying which word is wrong.
 */
export function normalizeMnemonic(input) {
  const raw = String(input).normalize('NFKD').toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (!VALID_LENGTHS.includes(raw.length)) {
    throw new Error(`the phrase has ${raw.length} words; it must have ${VALID_LENGTHS.join(', ')}`);
  }
  return raw.map((w, i) => {
    if (INDEX.has(w)) return w;
    const p = w.length >= 4 ? BY_PREFIX.get(w.slice(0, 4)) : undefined;
    if (p !== undefined && WORDS[p].startsWith(w)) return WORDS[p];
    throw new Error(`word ${i + 1} ("${w}") is not in the BIP-39 list`);
  }).join(' ');
}

/** Validates (including the checksum) and returns the entropy. */
export function mnemonicToEntropy(mnemonic) {
  const words = normalizeMnemonic(mnemonic).split(' ');
  const all = words.map((w) => INDEX.get(w).toString(2).padStart(11, '0')).join('');
  const cs = words.length / 3;
  const entBits = all.slice(0, all.length - cs);
  const entropy = Buffer.from(entBits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const expected = bits(createHash('sha256').update(entropy).digest()).slice(0, cs);
  if (expected !== all.slice(-cs)) {
    throw new Error('invalid phrase (checksum mismatch): check that all words are correct and in order');
  }
  return entropy;
}

export const validateMnemonic = (m) => { try { mnemonicToEntropy(m); return true; } catch { return false; } };

export function mnemonicToSeed(mnemonic, passphrase = '') {
  const m = normalizeMnemonic(mnemonic);
  mnemonicToEntropy(m); // ensures a valid checksum
  return pbkdf2Sync(Buffer.from(m.normalize('NFKD'), 'utf8'),
    Buffer.from(('mnemonic' + passphrase).normalize('NFKD'), 'utf8'), 2048, 64, 'sha512');
}

/** 32-byte seed used by the Krevo wallet keys. */
export const walletSeedFromMnemonic = (mnemonic, passphrase = '') =>
  Buffer.from(H('wallet/bip39', mnemonicToSeed(mnemonic, passphrase)));
