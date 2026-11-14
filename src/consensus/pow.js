// Prova de trabalho "KrevoHash": BLAKE2b + multiplicação por matriz 64×64.
//
// Inspirada no kHeavyHash do Kaspa: a cada modelo de bloco, uma matriz 64×64 de
// 4 bits é gerada a partir do hash pré-PoW. Cada tentativa:
//   h1 = BLAKE2b("pow1" || prePow || timestamp || nonce)
//   v  = 64 nibbles de h1;  p_i = (Σ_j M[i][j]·v_j) >> 10
//   h2 = BLAKE2b("pow2" || h1 XOR p)
// A etapa de matriz é limitada por cálculo (não por memória), barata para
// verificar e eficiente em energia em hardware dedicado; a verificação de um
// bloco custa microssegundos, então nós comuns validam 10 blocos/s com folga.

import { createHash } from 'node:crypto';
import { u64le } from '../util/bytes.js';

const ONE256 = 1n << 256n;

// ----------------------------------------------------- alvo compacto (bits)
export function compactToTarget(bits) {
  const exp = bits >>> 24, mant = BigInt(bits & 0x007fffff);
  if (bits & 0x00800000) throw new Error('alvo negativo');
  return exp <= 3 ? mant >> BigInt(8 * (3 - exp)) : mant << BigInt(8 * (exp - 3));
}
export function targetToCompact(t) {
  if (t <= 0n) return 0;
  let size = Math.ceil(t.toString(16).length / 2);
  let mant = size <= 3 ? Number(t << BigInt(8 * (3 - size))) : Number(t >> BigInt(8 * (size - 3)));
  if (mant & 0x00800000) { mant >>>= 8; size++; }
  return ((size << 24) | mant) >>> 0;
}
export const calcWork = (bits) => ONE256 / (compactToTarget(bits) + 1n);

// ------------------------------------------------------ gerador xoshiro256**
function xoshiro(seed) {
  const M = (1n << 64n) - 1n;
  const s = [0, 1, 2, 3].map((i) => seed.readBigUInt64LE(i * 8));
  const rotl = (x, k) => ((x << k) | (x >> (64n - k))) & M;
  return () => {
    const result = (rotl((s[1] * 5n) & M, 7n) * 9n) & M;
    const t = (s[1] << 17n) & M;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t; s[3] = rotl(s[3], 45n);
    return result;
  };
}

function rankModPrime(mat) { // posto da matriz 64×64 sobre GF(65521) — determinístico
  const p = 65521, a = Array.from({ length: 64 }, (_, i) => Array.from(mat.subarray(i * 64, i * 64 + 64)));
  let rank = 0;
  for (let col = 0; col < 64 && rank < 64; col++) {
    let piv = -1;
    for (let r = rank; r < 64; r++) if (a[r][col] % p !== 0) { piv = r; break; }
    if (piv < 0) continue;
    [a[rank], a[piv]] = [a[piv], a[rank]];
    let inv = 1, b = a[rank][col] % p, e = p - 2;
    while (e > 0) { if (e & 1) inv = (inv * b) % p; b = (b * b) % p; e >>= 1; }
    for (let r = 0; r < 64; r++) {
      if (r === rank || a[r][col] === 0) continue;
      const f = (a[r][col] * inv) % p;
      for (let c = col; c < 64; c++) a[r][c] = ((a[r][c] - f * a[rank][c]) % p + p) % p;
    }
    rank++;
  }
  return rank;
}

export function generateMatrix(prePowHash) {
  const next = xoshiro(prePowHash);
  for (;;) {
    const m = new Uint8Array(4096);
    for (let i = 0; i < 4096; i += 16) {
      let v = next();
      for (let j = 0; j < 16; j++) { m[i + j] = Number(v & 15n); v >>= 4n; }
    }
    if (rankModPrime(m) === 64) return m;
  }
}

const P1 = Buffer.from('KRV/KrevoHash/1');
const P2 = Buffer.from('KRV/KrevoHash/2');

export class PowState {
  constructor(prePowHash) {
    this.prePowHash = Buffer.from(prePowHash);
    this.matrix = generateMatrix(this.prePowHash);
    this.v = new Uint8Array(64);
    this.mix = Buffer.alloc(32);
  }
  /** Retorna o hash final (32 bytes, interpretado como inteiro little-endian). */
  hash(timestamp, nonce) {
    const h1 = createHash('blake2b512').update(P1).update(this.prePowHash)
      .update(u64le(timestamp)).update(u64le(nonce)).digest();
    const v = this.v, m = this.matrix, mix = this.mix;
    for (let i = 0; i < 32; i++) { v[2 * i] = h1[i] >> 4; v[2 * i + 1] = h1[i] & 15; }
    for (let i = 0; i < 32; i++) {
      let s0 = 0, s1 = 0;
      const r0 = 128 * i, r1 = r0 + 64;
      for (let j = 0; j < 64; j++) { s0 += m[r0 + j] * v[j]; s1 += m[r1 + j] * v[j]; }
      mix[i] = h1[i] ^ ((((s0 >> 10) & 15) << 4) | ((s1 >> 10) & 15));
    }
    return createHash('blake2b512').update(P2).update(mix).digest().subarray(0, 32);
  }
}

/** Compara hash (little-endian) com alvo sem converter para BigInt. */
export function hashMeetsTarget(hash, targetLE) {
  for (let i = 31; i >= 0; i--) {
    if (hash[i] < targetLE[i]) return true;
    if (hash[i] > targetLE[i]) return false;
  }
  return true;
}
export function targetToLE(target) {
  const b = Buffer.alloc(32);
  let t = target;
  for (let i = 0; i < 32; i++) { b[i] = Number(t & 0xffn); t >>= 8n; }
  return b;
}

export function checkPow(header) {
  const target = compactToTarget(header.bits);
  const st = new PowState(header.prePowHash());
  return hashMeetsTarget(st.hash(header.timestamp, header.nonce), targetToLE(target));
}
