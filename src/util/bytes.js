// Byte utilities and canonical binary serialization.
// Every consensus structure (blocks, transactions) uses this format.

export const ZERO32 = Buffer.alloc(32);

export const toHex = (b) => Buffer.from(b).toString('hex');
export function fromHex(h) {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error('invalid hex');
  }
  return Buffer.from(h, 'hex');
}

export function bigToBytesBE(n, len = 32) {
  if (n < 0n) throw new Error('negative number');
  const h = n.toString(16);
  if (h.length > len * 2) throw new Error('number too large');
  return Buffer.from(h.padStart(len * 2, '0'), 'hex');
}
export const bytesToBigBE = (b) => (b.length ? BigInt('0x' + toHex(b)) : 0n);
export const bytesToBigLE = (b) => bytesToBigBE(Buffer.from(b).reverse());
export const bigToBytesLE = (n, len) => bigToBytesBE(n, len).reverse();

export function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
}
export function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

export const MAX_U64 = (1n << 64n) - 1n;

/** Binary writer (little-endian, Bitcoin-style varints). */
export class Writer {
  constructor() { this.parts = []; this.length = 0; }
  _push(b) { this.parts.push(b); this.length += b.length; return this; }
  u8(n) { return this._push(Buffer.from([n & 0xff])); }
  u16(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return this._push(b); }
  u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return this._push(b); }
  u64(n) {
    const v = BigInt(n);
    if (v < 0n || v > MAX_U64) throw new Error('u64 fora do intervalo');
    const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return this._push(b);
  }
  varint(n) {
    n = Number(n);
    if (!Number.isSafeInteger(n) || n < 0) throw new Error('invalid varint');
    if (n < 0xfd) return this.u8(n);
    if (n <= 0xffff) { this.u8(0xfd); return this.u16(n); }
    if (n <= 0xffffffff) { this.u8(0xfe); return this.u32(n); }
    this.u8(0xff); return this.u64(n);
  }
  bytes(b, len) {
    b = Buffer.from(b);
    if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`);
    return this._push(b);
  }
  varbytes(b) { b = Buffer.from(b); this.varint(b.length); return this._push(b); }
  done() { return Buffer.concat(this.parts, this.length); }
}

/** Strict binary reader: any read out of bounds throws. */
export class Reader {
  constructor(buf) { this.buf = Buffer.from(buf); this.pos = 0; }
  _need(n) { if (this.pos + n > this.buf.length) throw new Error('unexpected end of data'); }
  u8() { this._need(1); return this.buf[this.pos++]; }
  u16() { this._need(2); const v = this.buf.readUInt16LE(this.pos); this.pos += 2; return v; }
  u32() { this._need(4); const v = this.buf.readUInt32LE(this.pos); this.pos += 4; return v; }
  u64() { this._need(8); const v = this.buf.readBigUInt64LE(this.pos); this.pos += 8; return v; }
  varint(max = 1_000_000) {
    const f = this.u8();
    let v;
    if (f < 0xfd) v = f;
    else if (f === 0xfd) { v = this.u16(); if (v < 0xfd) throw new Error('non-canonical varint'); }
    else if (f === 0xfe) { v = this.u32(); if (v <= 0xffff) throw new Error('non-canonical varint'); }
    else { const b = this.u64(); if (b <= 0xffffffffn) throw new Error('non-canonical varint'); v = Number(b); }
    if (v > max) throw new Error(`varint acima do limite (${v} > ${max})`);
    return v;
  }
  bytes(n) { this._need(n); const b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return Buffer.from(b); }
  varbytes(max = 1_000_000) { return this.bytes(this.varint(max)); }
  end() { if (this.pos !== this.buf.length) throw new Error('bytes left over after the end of the structure'); }
  get remaining() { return this.buf.length - this.pos; }
}
