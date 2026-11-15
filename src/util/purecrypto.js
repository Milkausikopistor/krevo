// Pure JavaScript cryptography, so the wallet can run in the BROWSER (where the node:crypto
// module does not exist). Only what the wallet uses:
//   BLAKE2b-512 (RFC 7693) · SHA-256 e SHA-512 (FIPS 180-4) · HMAC · PBKDF2 · AES-256-GCM
// The SHA-2 constants are COMPUTED (roots of primes) and the AES S-box comes from inverses in
// GF(2⁸) — no hand-typed tables. Everything is checked against Node.js's OpenSSL with
// thousands of random inputs (test/purecrypto.test.js).
// Works with Uint8Array (does not depend on Buffer).

const u8 = (x) => (x instanceof Uint8Array ? x : new Uint8Array(x));

// ------------------------------------------------------------------ SHA-2 constants
function primes(n) {
  const out = [];
  for (let c = 2; out.length < n; c++) if (out.every((p) => c % p)) out.push(c);
  return out;
}
function iroot(x, k) { // ⌊x^(1/k)⌋ for BigInt (Newton)
  if (x < 2n) return x;
  let r = 1n << BigInt(Math.ceil(x.toString(2).length / k));
  for (;;) {
    const nr = ((BigInt(k) - 1n) * r + x / r ** BigInt(k - 1)) / BigInt(k);
    if (nr >= r) return r;
    r = nr;
  }
}
const fracBits = (p, k, bits) => iroot(BigInt(p) << BigInt(k * bits), k) & ((1n << BigInt(bits)) - 1n);
const P80 = primes(80);
const K256 = new Uint32Array(P80.slice(0, 64).map((p) => Number(fracBits(p, 3, 32))));
const H256 = new Uint32Array(P80.slice(0, 8).map((p) => Number(fracBits(p, 2, 32))));
const K512 = new Uint32Array(160), H512 = new Uint32Array(16);
P80.forEach((p, i) => { const v = fracBits(p, 3, 64); K512[2 * i] = Number(v >> 32n); K512[2 * i + 1] = Number(v & 0xffffffffn); });
P80.slice(0, 8).forEach((p, i) => { const v = fracBits(p, 2, 64); H512[2 * i] = Number(v >> 32n); H512[2 * i + 1] = Number(v & 0xffffffffn); });

function mdPad(data, blockLen, lenBytes) {
  const bitLen = BigInt(data.length) * 8n;
  const total = Math.ceil((data.length + 1 + lenBytes) / blockLen) * blockLen;
  const out = new Uint8Array(total);
  out.set(data);
  out[data.length] = 0x80;
  for (let i = 0; i < 8; i++) out[total - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  return out;
}

export function sha256(data) {
  const m = mdPad(u8(data), 64, 8);
  const h = Uint32Array.from(H256), w = new Uint32Array(64);
  for (let o = 0; o < m.length; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = (m[o + 4 * i] << 24) | (m[o + 4 * i + 1] << 16) | (m[o + 4 * i + 2] << 8) | m[o + 4 * i + 3];
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (hh + S1 + ((e & f) ^ (~e & g)) + K256[i] + w[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) { out[4 * i] = h[i] >>> 24; out[4 * i + 1] = h[i] >>> 16; out[4 * i + 2] = h[i] >>> 8; out[4 * i + 3] = h[i]; }
  return out;
}

// SHA-512 with 32-bit pairs (high, low)
export function sha512(data) {
  const m = mdPad(u8(data), 128, 16);
  const h = Uint32Array.from(H512), w = new Uint32Array(160);
  const add = (...xs) => { // sum of 64-bit pairs → [high, low]
    let lo = 0, hi = 0;
    for (let i = 0; i < xs.length; i += 2) { lo += xs[i + 1]; hi += xs[i] + Math.floor(lo / 0x100000000); lo >>>= 0; }
    return [hi >>> 0, lo >>> 0];
  };
  const rotr = (hi, lo, n) => (n < 32
    ? [((hi >>> n) | (lo << (32 - n))) >>> 0, ((lo >>> n) | (hi << (32 - n))) >>> 0]
    : [((lo >>> (n - 32)) | (hi << (64 - n))) >>> 0, ((hi >>> (n - 32)) | (lo << (64 - n))) >>> 0]);
  const shr = (hi, lo, n) => [hi >>> n, ((lo >>> n) | (hi << (32 - n))) >>> 0];
  const x3 = (a, b, c) => [(a[0] ^ b[0] ^ c[0]) >>> 0, (a[1] ^ b[1] ^ c[1]) >>> 0];
  for (let o = 0; o < m.length; o += 128) {
    for (let i = 0; i < 32; i++) w[i] = ((m[o + 4 * i] << 24) | (m[o + 4 * i + 1] << 16) | (m[o + 4 * i + 2] << 8) | m[o + 4 * i + 3]) >>> 0;
    for (let i = 16; i < 80; i++) {
      const [ah, al] = [w[2 * (i - 15)], w[2 * (i - 15) + 1]], [bh, bl] = [w[2 * (i - 2)], w[2 * (i - 2) + 1]];
      const s0 = x3(rotr(ah, al, 1), rotr(ah, al, 8), shr(ah, al, 7));
      const s1 = x3(rotr(bh, bl, 19), rotr(bh, bl, 61), shr(bh, bl, 6));
      const r = add(w[2 * (i - 16)], w[2 * (i - 16) + 1], s0[0], s0[1], w[2 * (i - 7)], w[2 * (i - 7) + 1], s1[0], s1[1]);
      w[2 * i] = r[0]; w[2 * i + 1] = r[1];
    }
    const v = Array.from({ length: 8 }, (_, i) => [h[2 * i], h[2 * i + 1]]);
    for (let i = 0; i < 80; i++) {
      const [a, b, c, d, e, f, g, hh] = v;
      const S1 = x3(rotr(e[0], e[1], 14), rotr(e[0], e[1], 18), rotr(e[0], e[1], 41));
      const ch = [((e[0] & f[0]) ^ (~e[0] & g[0])) >>> 0, ((e[1] & f[1]) ^ (~e[1] & g[1])) >>> 0];
      const t1 = add(hh[0], hh[1], S1[0], S1[1], ch[0], ch[1], K512[2 * i], K512[2 * i + 1], w[2 * i], w[2 * i + 1]);
      const S0 = x3(rotr(a[0], a[1], 28), rotr(a[0], a[1], 34), rotr(a[0], a[1], 39));
      const maj = [((a[0] & b[0]) ^ (a[0] & c[0]) ^ (b[0] & c[0])) >>> 0, ((a[1] & b[1]) ^ (a[1] & c[1]) ^ (b[1] & c[1])) >>> 0];
      const t2 = add(S0[0], S0[1], maj[0], maj[1]);
      v[7] = g; v[6] = f; v[5] = e; v[4] = add(d[0], d[1], t1[0], t1[1]); v[3] = c; v[2] = b; v[1] = a; v[0] = add(t1[0], t1[1], t2[0], t2[1]);
    }
    for (let i = 0; i < 8; i++) { const r = add(h[2 * i], h[2 * i + 1], v[i][0], v[i][1]); h[2 * i] = r[0]; h[2 * i + 1] = r[1]; }
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) { out[4 * i] = h[i] >>> 24; out[4 * i + 1] = h[i] >>> 16; out[4 * i + 2] = h[i] >>> 8; out[4 * i + 3] = h[i]; }
  return out;
}

// ------------------------------------------------------------------ BLAKE2b (RFC 7693)
const B2_IV = new Uint32Array([ // the same initial values as SHA-512, in (low, high) pairs
  ...Array.from({ length: 8 }, (_, i) => [H512[2 * i + 1], H512[2 * i]]).flat(),
]);
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

export function blake2b(data, outLen = 64) {
  data = u8(data);
  const h = Uint32Array.from(B2_IV);
  h[0] ^= 0x01010000 ^ outLen;
  const v = new Uint32Array(32), m = new Uint32Array(32);
  const add64 = (a, b) => { const lo = v[a] + v[b]; v[a + 1] = v[a + 1] + v[b + 1] + (lo >= 0x100000000 ? 1 : 0); v[a] = lo; };
  const addM = (a, i) => { const lo = v[a] + m[i]; v[a + 1] = v[a + 1] + m[i + 1] + (lo >= 0x100000000 ? 1 : 0); v[a] = lo; };
  const G = (a, b, c, d, x, y) => {
    add64(a, b); addM(a, x);
    let lo = v[d] ^ v[a], hi = v[d + 1] ^ v[a + 1]; v[d] = hi; v[d + 1] = lo;                                     // >>> 32
    add64(c, d);
    lo = v[b] ^ v[c]; hi = v[b + 1] ^ v[c + 1]; v[b] = (lo >>> 24) | (hi << 8); v[b + 1] = (hi >>> 24) | (lo << 8); // >>> 24
    add64(a, b); addM(a, y);
    lo = v[d] ^ v[a]; hi = v[d + 1] ^ v[a + 1]; v[d] = (lo >>> 16) | (hi << 16); v[d + 1] = (hi >>> 16) | (lo << 16); // >>> 16
    add64(c, d);
    lo = v[b] ^ v[c]; hi = v[b + 1] ^ v[c + 1]; v[b] = (hi >>> 31) | (lo << 1); v[b + 1] = (lo >>> 31) | (hi << 1);   // >>> 63
  };
  const blocks = Math.max(1, Math.ceil(data.length / 128));
  const block = new Uint8Array(128);
  for (let n = 0; n < blocks; n++) {
    const last = n === blocks - 1;
    block.fill(0);
    block.set(data.subarray(128 * n, 128 * (n + 1)));
    const t = last ? data.length : 128 * (n + 1);
    for (let i = 0; i < 16; i++) { v[i] = h[i]; v[i + 16] = B2_IV[i]; }
    v[24] ^= t >>> 0; v[25] ^= Math.floor(t / 0x100000000);
    if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
    for (let i = 0; i < 32; i++) m[i] = block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      G(0, 8, 16, 24, 2 * s[0], 2 * s[1]); G(2, 10, 18, 26, 2 * s[2], 2 * s[3]);
      G(4, 12, 20, 28, 2 * s[4], 2 * s[5]); G(6, 14, 22, 30, 2 * s[6], 2 * s[7]);
      G(0, 10, 20, 30, 2 * s[8], 2 * s[9]); G(2, 12, 22, 24, 2 * s[10], 2 * s[11]);
      G(4, 14, 16, 26, 2 * s[12], 2 * s[13]); G(6, 8, 18, 28, 2 * s[14], 2 * s[15]);
    }
    for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i + 16];
  }
  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) out[i] = h[i >> 2] >>> (8 * (i & 3));
  return out;
}

// ------------------------------------------------------------------ HMAC and PBKDF2
const HASHES = { sha256: [sha256, 64, 32], sha512: [sha512, 128, 64] };
export function hmac(alg, key, data) {
  const [fn, block] = HASHES[alg];
  let k = u8(key);
  if (k.length > block) k = fn(k);
  const ipad = new Uint8Array(block + data.length), opad = new Uint8Array(block + HASHES[alg][2]);
  for (let i = 0; i < block; i++) { ipad[i] = (k[i] ?? 0) ^ 0x36; opad[i] = (k[i] ?? 0) ^ 0x5c; }
  ipad.set(u8(data), block);
  opad.set(fn(ipad), block);
  return fn(opad);
}
export function pbkdf2(alg, password, salt, iterations, keyLen) {
  const hLen = HASHES[alg][2], out = new Uint8Array(keyLen);
  salt = u8(salt);
  for (let blk = 1, o = 0; o < keyLen; blk++, o += hLen) {
    const s = new Uint8Array(salt.length + 4);
    s.set(salt); s[salt.length] = blk >>> 24; s[salt.length + 1] = blk >>> 16; s[salt.length + 2] = blk >>> 8; s[salt.length + 3] = blk;
    let u = hmac(alg, password, s);
    const t = Uint8Array.from(u);
    for (let i = 1; i < iterations; i++) { u = hmac(alg, password, u); for (let j = 0; j < hLen; j++) t[j] ^= u[j]; }
    out.set(t.subarray(0, Math.min(hLen, keyLen - o)), o);
  }
  return out;
}

// ------------------------------------------------------------------ AES-256 and GCM
const SBOX = new Uint8Array(256);
{
  const mul = (a, b) => { let p = 0; for (; b; b >>= 1) { if (b & 1) p ^= a; a = (a << 1) ^ (a & 0x80 ? 0x11b : 0); } return p & 0xff; };
  for (let x = 0; x < 256; x++) {
    let inv = 0;
    if (x) for (let y = 1; y < 256; y++) if (mul(x, y) === 1) { inv = y; break; }
    let s = inv;
    for (let r = 1; r <= 4; r++) s ^= ((inv << r) | (inv >> (8 - r))) & 0xff;
    SBOX[x] = s ^ 0x63;
  }
}
const xtime = (a) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;

function expandKey(key) {
  if (key.length !== 32) throw new Error('AES-256 needs a 32-byte key');
  const w = new Uint8Array(240);
  w.set(key);
  let rcon = 1;
  for (let i = 32; i < 240; i += 4) {
    let t = w.slice(i - 4, i);
    if (i % 32 === 0) {
      t = Uint8Array.of(SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]);
      rcon = xtime(rcon);
    } else if (i % 32 === 16) t = t.map((b) => SBOX[b]);
    for (let j = 0; j < 4; j++) w[i + j] = w[i - 32 + j] ^ t[j];
  }
  return w;
}
function aesBlock(w, input) {
  const s = Uint8Array.from(input);
  for (let i = 0; i < 16; i++) s[i] ^= w[i];
  for (let round = 1; round <= 14; round++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    // ShiftRows (state in columns: s[c*4 + r])
    const t = Uint8Array.from(s);
    for (let c = 0; c < 4; c++) for (let r = 1; r < 4; r++) s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
    if (round < 14) {
      for (let c = 0; c < 4; c++) {
        const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3], x = a0 ^ a1 ^ a2 ^ a3;
        s[4 * c] ^= x ^ xtime(a0 ^ a1); s[4 * c + 1] ^= x ^ xtime(a1 ^ a2);
        s[4 * c + 2] ^= x ^ xtime(a2 ^ a3); s[4 * c + 3] ^= x ^ xtime(a3 ^ a0);
      }
    }
    for (let i = 0; i < 16; i++) s[i] ^= w[16 * round + i];
  }
  return s;
}

const toBig = (b) => { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; };
const fromBig = (x, n) => { const out = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; } return out; };
const R_GCM = 0xe1n << 120n;
function gmul(x, y) {
  let z = 0n, v = y;
  for (let i = 127; i >= 0; i--) {
    if ((x >> BigInt(i)) & 1n) z ^= v;
    v = v & 1n ? (v >> 1n) ^ R_GCM : v >> 1n;
  }
  return z;
}
function ghash(H, data) {
  let y = 0n;
  for (let o = 0; o < data.length; o += 16) {
    const blk = new Uint8Array(16);
    blk.set(data.subarray(o, o + 16));
    y = gmul(y ^ toBig(blk), H);
  }
  return y;
}

/** AES-256-GCM, 12-byte IV, no additional data. Returns { ct, tag }. */
export function aesGcmEncrypt(key, iv, plain) {
  const w = expandKey(u8(key));
  if (iv.length !== 12) throw new Error('the GCM IV must have 12 bytes');
  const H = toBig(aesBlock(w, new Uint8Array(16)));
  const j0 = new Uint8Array(16); j0.set(iv); j0[15] = 1;
  plain = u8(plain);
  const ct = new Uint8Array(plain.length), ctr = Uint8Array.from(j0);
  for (let o = 0; o < plain.length; o += 16) {
    for (let i = 15; i >= 12; i--) if (++ctr[i] !== 256) break; else ctr[i] = 0;
    const ks = aesBlock(w, ctr);
    for (let i = 0; i < 16 && o + i < plain.length; i++) ct[o + i] = plain[o + i] ^ ks[i];
  }
  const padded = new Uint8Array(Math.ceil(ct.length / 16) * 16 + 16);
  padded.set(ct);
  padded.set(fromBig(BigInt(ct.length) * 8n, 8), padded.length - 8);
  const s = ghash(H, padded) ^ toBig(aesBlock(w, j0));
  return { ct, tag: fromBig(s, 16) };
}
/** Decrypts and checks the tag; throws if it does not match (like Node). */
export function aesGcmDecrypt(key, iv, ct, tag) {
  ct = u8(ct);
  const { ct: plain, tag: expected } = aesGcmEncrypt(key, iv, ct); // CTR is symmetric; the tag is over the ciphertext
  const w = expandKey(u8(key));
  const H = toBig(aesBlock(w, new Uint8Array(16)));
  const j0 = new Uint8Array(16); j0.set(iv); j0[15] = 1;
  const padded = new Uint8Array(Math.ceil(ct.length / 16) * 16 + 16);
  padded.set(ct);
  padded.set(fromBig(BigInt(ct.length) * 8n, 8), padded.length - 8);
  const real = fromBig(ghash(H, padded) ^ toBig(aesBlock(w, j0)), 16);
  void expected;
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= real[i] ^ (tag[i] ?? 0);
  if (diff || tag.length !== 16) throw new Error('Unsupported state or unable to authenticate data');
  return plain;
}

// ------------------------------------------------------------------ randomness
export function randomFill(n) {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) globalThis.crypto.getRandomValues(out.subarray(o, Math.min(n, o + 65536)));
  return out;
}
