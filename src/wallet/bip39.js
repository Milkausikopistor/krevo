// Frase de recuperação — padrão BIP-39 (o mesmo de Bitcoin, Ledger, Trezor…).
//
// 24 palavras = 256 bits de aleatoriedade + 8 bits de verificação (checksum).
// A última palavra carrega parte do checksum: uma palavra digitada errada ou
// trocada de lugar é detectada quase sempre (1 chance em 256 de passar com 24
// palavras, 1 em 16 com 12).
//
// Semente BIP-39 = PBKDF2-HMAC-SHA512(frase, "mnemonic" + frase extra, 2048, 64 bytes).
// Semente da carteira Krevo = H("wallet/bip39", semente BIP-39) — 32 bytes.

import { createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import { WORDS } from './wordlist-en.js';
import { H } from '../crypto/hash.js';

const INDEX = new Map(WORDS.map((w, i) => [w, i]));
const BY_PREFIX = new Map(WORDS.map((w, i) => [w.slice(0, 4), i])); // as 4 primeiras letras são únicas
export const VALID_LENGTHS = [12, 15, 18, 21, 24];

const bits = (buf) => [...buf].map((b) => b.toString(2).padStart(8, '0')).join('');

export function entropyToMnemonic(entropy) {
  if (![16, 20, 24, 28, 32].includes(entropy.length)) throw new Error('entropia deve ter 16–32 bytes (múltiplo de 4)');
  const cs = entropy.length / 4; // bits de checksum
  const all = bits(entropy) + bits(createHash('sha256').update(entropy).digest()).slice(0, cs);
  const out = [];
  for (let i = 0; i < all.length; i += 11) out.push(WORDS[parseInt(all.slice(i, i + 11), 2)]);
  return out.join(' ');
}

export function generateMnemonic(words = 24) {
  if (!VALID_LENGTHS.includes(words)) throw new Error(`a frase deve ter ${VALID_LENGTHS.join(', ')} palavras`);
  return entropyToMnemonic(randomBytes((words / 3) * 4));
}

/**
 * Normaliza o que o usuário digitou: minúsculas, espaços extras, e aceita as
 * 4 primeiras letras de cada palavra (ex.: "aban" = "abandon").
 * Lança erro dizendo qual palavra está errada.
 */
export function normalizeMnemonic(input) {
  const raw = String(input).normalize('NFKD').toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (!VALID_LENGTHS.includes(raw.length)) {
    throw new Error(`a frase tem ${raw.length} palavras; precisa ter ${VALID_LENGTHS.join(', ')}`);
  }
  return raw.map((w, i) => {
    if (INDEX.has(w)) return w;
    const p = w.length >= 4 ? BY_PREFIX.get(w.slice(0, 4)) : undefined;
    if (p !== undefined && WORDS[p].startsWith(w)) return WORDS[p];
    throw new Error(`palavra ${i + 1} ("${w}") não existe na lista BIP-39`);
  }).join(' ');
}

/** Valida (incluindo o checksum) e devolve a entropia. */
export function mnemonicToEntropy(mnemonic) {
  const words = normalizeMnemonic(mnemonic).split(' ');
  const all = words.map((w) => INDEX.get(w).toString(2).padStart(11, '0')).join('');
  const cs = words.length / 3;
  const entBits = all.slice(0, all.length - cs);
  const entropy = Buffer.from(entBits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const expected = bits(createHash('sha256').update(entropy).digest()).slice(0, cs);
  if (expected !== all.slice(-cs)) {
    throw new Error('frase inválida (checksum não confere): confira se todas as palavras estão certas e na ordem');
  }
  return entropy;
}

export const validateMnemonic = (m) => { try { mnemonicToEntropy(m); return true; } catch { return false; } };

export function mnemonicToSeed(mnemonic, passphrase = '') {
  const m = normalizeMnemonic(mnemonic);
  mnemonicToEntropy(m); // garante checksum válido
  return pbkdf2Sync(Buffer.from(m.normalize('NFKD'), 'utf8'),
    Buffer.from(('mnemonic' + passphrase).normalize('NFKD'), 'utf8'), 2048, 64, 'sha512');
}

/** Semente de 32 bytes usada pelas chaves da carteira Krevo. */
export const walletSeedFromMnemonic = (mnemonic, passphrase = '') =>
  Buffer.from(H('wallet/bip39', mnemonicToSeed(mnemonic, passphrase)));
