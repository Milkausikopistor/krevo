// Buffer for the browser: a Uint8Array subclass with the Node.js methods the wallet code uses
// (checked method by method against Node's Buffer in test/purecrypto.test.js).
// As in Node, subarray() and slice() return VIEWS of the same bytes.

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
const enc = new TextEncoder(), dec = new TextDecoder();

export class Buffer extends Uint8Array {
  static from(x, encoding) {
    if (typeof x === 'string') return Buffer._fromString(x, encoding);
    if (x instanceof ArrayBuffer) return new Buffer(x.slice(0));
    if (ArrayBuffer.isView(x)) { const b = new Buffer(x.byteLength); b.set(new Uint8Array(x.buffer, x.byteOffset, x.byteLength)); return b; }
    if (Array.isArray(x)) { const b = new Buffer(x.length); for (let i = 0; i < x.length; i++) b[i] = x[i] & 255; return b; }
    if (x && x.type === 'Buffer' && Array.isArray(x.data)) return Buffer.from(x.data);
    throw new TypeError('Buffer.from: unsupported type');
  }
  static _fromString(s, encoding = 'utf8') {
    switch (String(encoding).toLowerCase()) {
      case 'hex': {
        const n = s.length >> 1, b = new Buffer(n);
        let i = 0;
        for (; i < n; i++) {
          const v = parseInt(s.substr(2 * i, 2), 16);
          if (Number.isNaN(v) || !/^[0-9a-fA-F]{2}$/.test(s.substr(2 * i, 2))) break; // like Node: stops at the first invalid pair
          b[i] = v;
        }
        return i === n ? b : b.subarray(0, i);
      }
      case 'utf8': case 'utf-8': return Buffer.from(enc.encode(s));
      case 'ascii': case 'latin1': case 'binary': {
        const b = new Buffer(s.length);
        for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 255;
        return b;
      }
      case 'base64': return Buffer._fromString(atob(s.replace(/[^A-Za-z0-9+/=]/g, '')), 'latin1');
      default: throw new TypeError(`unknown encoding: ${encoding}`);
    }
  }
  static alloc(n, fill) {
    const b = new Buffer(n);
    if (fill !== undefined) b.fill(typeof fill === 'string' ? fill.charCodeAt(0) : fill);
    return b;
  }
  static allocUnsafe(n) { return new Buffer(n); }
  static isBuffer(x) { return x instanceof Buffer; }
  static byteLength(s, encoding = 'utf8') { return typeof s === 'string' ? Buffer.from(s, encoding).length : s.byteLength; }
  static concat(list, total) {
    const len = total ?? list.reduce((a, b) => a + b.length, 0);
    const out = new Buffer(len);
    let o = 0;
    for (const b of list) {
      if (o >= len) break;
      const part = b.length + o > len ? b.subarray(0, len - o) : b;
      out.set(part, o);
      o += part.length;
    }
    return out;
  }
  static compare(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
  }

  toString(encoding = 'utf8', start = 0, end = this.length) {
    const v = this.subarray(start, end);
    switch (String(encoding).toLowerCase()) {
      case 'hex': { let s = ''; for (let i = 0; i < v.length; i++) s += HEX[v[i]]; return s; }
      case 'utf8': case 'utf-8': return dec.decode(v);
      case 'ascii': { let s = ''; for (let i = 0; i < v.length; i++) s += String.fromCharCode(v[i] & 0x7f); return s; }
      case 'latin1': case 'binary': { let s = ''; for (let i = 0; i < v.length; i++) s += String.fromCharCode(v[i]); return s; }
      case 'base64': return btoa(v.toString('latin1'));
      default: throw new TypeError(`unknown encoding: ${encoding}`);
    }
  }
  toJSON() { return { type: 'Buffer', data: Array.from(this) }; }
  equals(o) {
    if (this.length !== o.length) return false;
    for (let i = 0; i < this.length; i++) if (this[i] !== o[i]) return false;
    return true;
  }
  compare(o) { return Buffer.compare(this, o); }
  copy(target, tStart = 0, sStart = 0, sEnd = this.length) {
    const src = this.subarray(sStart, sEnd);
    const n = Math.max(0, Math.min(src.length, target.length - tStart));
    target.set(src.subarray(0, n), tStart);
    return n;
  }
  slice(start, end) { return this.subarray(start, end); }
  _dv() { return new DataView(this.buffer, this.byteOffset, this.byteLength); }
  readUInt8(o = 0) { return this._dv().getUint8(o); }
  readUInt16LE(o = 0) { return this._dv().getUint16(o, true); }
  readUInt16BE(o = 0) { return this._dv().getUint16(o, false); }
  readUInt32LE(o = 0) { return this._dv().getUint32(o, true); }
  readUInt32BE(o = 0) { return this._dv().getUint32(o, false); }
  readBigUInt64LE(o = 0) { return this._dv().getBigUint64(o, true); }
  readBigUInt64BE(o = 0) { return this._dv().getBigUint64(o, false); }
  writeUInt8(v, o = 0) { this._dv().setUint8(o, v); return o + 1; }
  writeUInt16LE(v, o = 0) { this._dv().setUint16(o, v, true); return o + 2; }
  writeUInt16BE(v, o = 0) { this._dv().setUint16(o, v, false); return o + 2; }
  writeUInt32LE(v, o = 0) { this._dv().setUint32(o, v, true); return o + 4; }
  writeUInt32BE(v, o = 0) { this._dv().setUint32(o, v, false); return o + 4; }
  writeBigUInt64LE(v, o = 0) { this._dv().setBigUint64(o, BigInt(v), true); return o + 8; }
  writeBigUInt64BE(v, o = 0) { this._dv().setBigUint64(o, BigInt(v), false); return o + 8; }
}

/** Installs it as a global (browsers do not have it). */
export function installBuffer() { if (!globalThis.Buffer) globalThis.Buffer = Buffer; }
