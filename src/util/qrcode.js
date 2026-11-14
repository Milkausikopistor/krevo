// Gerador de QR Code (ISO/IEC 18004), sem dependências.
// Modo byte (UTF-8), versões 1–40, correção de erro L/M/Q/H, máscara escolhida
// pela pontuação de penalidade da norma. Algoritmo no estilo da implementação de
// referência de Project Nayuki (MIT).

const ECC_CODEWORDS_PER_BLOCK = [
  // versão: 0 (inválida), 1..40
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // L
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28], // M
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // Q
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // H
];
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25], // L
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49], // M
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68], // Q
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81], // H
];
const ECL = { L: 0, M: 1, Q: 2, H: 3 };
const ECL_FORMAT_BITS = [1, 0, 3, 2];

const getBit = (x, i) => ((x >>> i) & 1) !== 0;

function numRawDataModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const na = Math.floor(ver / 7) + 2;
    r -= (25 * na - 10) * na - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}
const numDataCodewords = (ver, e) =>
  Math.floor(numRawDataModules(ver) / 8) - ECC_CODEWORDS_PER_BLOCK[e][ver] * NUM_ERROR_CORRECTION_BLOCKS[e][ver];

// ------------------------------------------------- Reed–Solomon sobre GF(256)
function rsMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}
function rsDivisor(degree) {
  const r = new Array(degree).fill(0);
  r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < r.length; j++) {
      r[j] = rsMul(r[j], root);
      if (j + 1 < r.length) r[j] ^= r[j + 1];
    }
    root = rsMul(root, 0x02);
  }
  return r;
}
export function rsRemainder(data, divisor) {
  const r = divisor.map(() => 0);
  for (const b of data) {
    const f = b ^ r.shift();
    r.push(0);
    divisor.forEach((c, i) => { r[i] ^= rsMul(c, f); });
  }
  return r;
}

// ------------------------------------------------------------- símbolo
class QR {
  constructor(ver, e, dataCodewords) {
    this.version = ver; this.ecl = e; this.size = ver * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.isFunction = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.drawFunctionPatterns();
    this.drawCodewords(this.addEccAndInterleave(dataCodewords));
    let best = 0, bestScore = Infinity;
    for (let m = 0; m < 8; m++) {
      this.applyMask(m); this.drawFormatBits(m);
      const s = this.penalty();
      if (s < bestScore) { best = m; bestScore = s; }
      this.applyMask(m); // desfaz (XOR)
    }
    this.mask = best;
    this.applyMask(best); this.drawFormatBits(best);
    this.isFunction = null;
  }

  set(x, y, dark) { this.modules[y][x] = dark; this.isFunction[y][x] = true; }

  drawFunctionPatterns() {
    const n = this.size;
    for (let i = 0; i < n; i++) { this.set(6, i, i % 2 === 0); this.set(i, 6, i % 2 === 0); }
    this.drawFinder(3, 3); this.drawFinder(n - 4, 3); this.drawFinder(3, n - 4);
    const pos = this.alignmentPositions(), na = pos.length;
    for (let i = 0; i < na; i++) {
      for (let j = 0; j < na; j++) {
        if (!((i === 0 && j === 0) || (i === 0 && j === na - 1) || (i === na - 1 && j === 0))) this.drawAlignment(pos[i], pos[j]);
      }
    }
    this.drawFormatBits(0);
    this.drawVersion();
  }

  drawFinder(x, y) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const d = Math.max(Math.abs(dx), Math.abs(dy)), xx = x + dx, yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) this.set(xx, yy, d !== 2 && d !== 4);
      }
    }
  }
  drawAlignment(x, y) {
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  alignmentPositions() {
    if (this.version === 1) return [];
    const na = Math.floor(this.version / 7) + 2;
    const step = Math.floor((this.version * 8 + na * 3 + 5) / (na * 4 - 4)) * 2;
    const r = [6];
    for (let p = this.size - 7; r.length < na; p -= step) r.splice(1, 0, p);
    return r;
  }

  drawFormatBits(mask) {
    const data = (ECL_FORMAT_BITS[this.ecl] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const n = this.size;
    for (let i = 0; i <= 5; i++) this.set(8, i, getBit(bits, i));
    this.set(8, 7, getBit(bits, 6));
    this.set(8, 8, getBit(bits, 7));
    this.set(7, 8, getBit(bits, 8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, getBit(bits, i));
    for (let i = 0; i < 8; i++) this.set(n - 1 - i, 8, getBit(bits, i));
    for (let i = 8; i < 15; i++) this.set(8, n - 15 + i, getBit(bits, i));
    this.set(8, n - 8, true); // módulo escuro fixo
  }

  drawVersion() {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const c = getBit(bits, i), a = this.size - 11 + (i % 3), b = Math.floor(i / 3);
      this.set(a, b, c); this.set(b, a, c);
    }
  }

  addEccAndInterleave(data) {
    const v = this.version, e = this.ecl;
    const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[e][v], eccLen = ECC_CODEWORDS_PER_BLOCK[e][v];
    const raw = Math.floor(numRawDataModules(v) / 8);
    const numShort = numBlocks - (raw % numBlocks), shortLen = Math.floor(raw / numBlocks);
    const div = rsDivisor(eccLen);
    const blocks = [];
    for (let i = 0, k = 0; i < numBlocks; i++) {
      const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
      k += dat.length;
      const ecc = rsRemainder(dat, div);
      if (i < numShort) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    const out = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach((b, j) => { if (i !== shortLen - eccLen || j >= numShort) out.push(b[i]); });
    }
    return out;
  }

  drawCodewords(data) {
    const n = this.size;
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < n; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j, upward = ((right + 1) & 2) === 0, y = upward ? n - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  applyMask(mask) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        let inv;
        switch (mask) {
          case 0: inv = (x + y) % 2 === 0; break;
          case 1: inv = y % 2 === 0; break;
          case 2: inv = x % 3 === 0; break;
          case 3: inv = (x + y) % 3 === 0; break;
          case 4: inv = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: inv = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: inv = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: inv = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        }
        if (!this.isFunction[y][x] && inv) this.modules[y][x] = !this.modules[y][x];
      }
    }
  }

  /** Penalidade da norma (regras N1–N4): só afeta a facilidade de leitura, não a validade. */
  penalty() {
    const n = this.size, m = this.modules;
    let score = 0, dark = 0;
    const lineScore = (get) => {
      let s = 0;
      for (let a = 0; a < n; a++) {
        let run = 1;
        const line = [];
        for (let b = 0; b < n; b++) line.push(get(a, b));
        for (let b = 1; b <= n; b++) {
          if (b < n && line[b] === line[b - 1]) run++;
          else { if (run >= 5) s += 3 + (run - 5); run = 1; }
        }
        const str = line.map((v) => (v ? '1' : '0')).join('');
        for (const pat of ['10111010000', '00001011101']) {
          let idx = str.indexOf(pat);
          while (idx >= 0) { s += 40; idx = str.indexOf(pat, idx + 1); }
        }
      }
      return s;
    };
    score += lineScore((a, b) => m[a][b]);
    score += lineScore((a, b) => m[b][a]);
    for (let y = 0; y < n - 1; y++) {
      for (let x = 0; x < n - 1; x++) {
        const c = m[y][x];
        if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) score += 3;
      }
    }
    for (const row of m) for (const c of row) if (c) dark++;
    score += 10 * Math.floor(Math.abs((dark * 100) / (n * n) - 50) / 5);
    return score;
  }
}

/** Codifica texto (UTF-8) e devolve { version, size, mask, modules: boolean[][] }. */
export function encodeQR(text, level = 'M') {
  const e = ECL[level];
  if (e === undefined) throw new Error('nível de correção inválido');
  const bytes = [...Buffer.from(text, 'utf8')];
  let ver = 1;
  for (; ver <= 40; ver++) {
    const ccBits = ver < 10 ? 8 : 16;
    if (bytes.length < 2 ** ccBits && 4 + ccBits + bytes.length * 8 <= numDataCodewords(ver, e) * 8) break;
  }
  if (ver > 40) throw new Error('texto longo demais para um QR code');
  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(0x4, 4);
  put(bytes.length, ver < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const cap = numDataCodewords(ver, e) * 8;
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  const q = new QR(ver, e, data);
  return { version: q.version, size: q.size, mask: q.mask, modules: q.modules };
}

/** Desenho para terminal: meio-blocos com cores ANSI fixas (preto no branco), 2 linhas por caractere. */
export function qrToTerminal(qr, border = 2) {
  const n = qr.size, dark = (x, y) => x >= 0 && y >= 0 && x < n && y < n && qr.modules[y][x];
  const W = '\x1b[97m', B = '\x1b[30m', WB = '\x1b[107m', BB = '\x1b[40m', RESET = '\x1b[0m';
  const lines = [];
  for (let y = -border; y < n + border; y += 2) {
    let s = '', fg = null, bg = null;
    for (let x = -border; x < n + border; x++) {
      const top = dark(x, y), bottom = dark(x, y + 1);
      if (top !== fg) { s += top ? B : W; fg = top; }       // só emite cor quando muda
      if (bottom !== bg) { s += bottom ? BB : WB; bg = bottom; }
      s += '▀';
    }
    lines.push(s + RESET);
  }
  return lines.join('\n');
}

/** SVG autocontido (escala livre, ótimo para imprimir). `caption` aparece abaixo do código. */
export function qrToSvg(qr, { border = 4, caption = [] } = {}) {
  const n = qr.size + border * 2, capH = caption.length ? caption.length * 3 + 2 : 0;
  let path = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) if (qr.modules[y][x]) path += `M${x + border},${y + border}h1v1h-1z`;
  }
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const texts = caption.map((t, i) =>
    `<text x="${n / 2}" y="${n + 2.4 + i * 3}" font-family="Arial, sans-serif" font-size="2.2" text-anchor="middle" fill="#000">${esc(t)}</text>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n + capH}" width="${(n) * 8}" height="${(n + capH) * 8}" shape-rendering="crispEdges">` +
    `<rect width="100%" height="100%" fill="#fff"/><path d="${path}" fill="#000"/>${texts}</svg>\n`;
}
