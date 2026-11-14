// Servidor de arquivos do app web da carteira (krevo carteira-web).
//
// IMPORTANTE: numa carteira web, quem entrega o CÓDIGO poderia roubar as chaves. Por isso o app
// NÃO é servido pelo servidor leve (que não é confiável): rode-o no seu computador, ou hospede
// numa origem em que você confie, e aponte para QUALQUER servidor leve — este sim pode ser de
// terceiros. A política de segurança (CSP) só permite código deste mesmo endereço.
// 'wasm-unsafe-eval' permite compilar o núcleo criptográfico em WebAssembly (src/crypto/krevo_core.wasm),
// também servido daqui — não libera eval() de JavaScript.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TYPES = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.html': 'text/html; charset=utf-8', '.wasm': 'application/wasm' };

export function startWebWallet({ port = 8091, host = '127.0.0.1', log = () => {} } = {}) {
  const index = fs.readFileSync(path.join(SRC, 'web', 'index.html'), 'utf8');
  const importmap = index.match(/<script type="importmap">([\s\S]*?)<\/script>/)[1];
  const imHash = createHash('sha256').update(importmap).digest('base64');
  const csp = [
    "default-src 'self'", `script-src 'self' 'sha256-${imHash}' 'wasm-unsafe-eval'`, "style-src 'self'", "img-src 'self' data: blob:",
    'connect-src *', "media-src 'self' blob:", "worker-src 'self'", "manifest-src 'self'",
    "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'",
  ].join('; ');
  const security = { 'content-security-policy': csp, 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=(self), microphone=(), geolocation=()' };

  const server = http.createServer((req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      let file;
      if (url.pathname === '/' || url.pathname === '/index.html') file = path.join(SRC, 'web', 'index.html');
      else if (url.pathname === '/manifest.webmanifest') file = path.join(SRC, 'web', 'manifest.webmanifest');
      else if (url.pathname === '/sw.js') file = path.join(SRC, 'web', 'sw.js');
      else if (url.pathname.startsWith('/src/')) file = path.resolve(SRC, '.' + decodeURIComponent(url.pathname.slice(4)));
      const type = file && TYPES[path.extname(file)];
      if (!file || !type || !file.startsWith(SRC + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', ...security });
        return res.end('não encontrado');
      }
      res.writeHead(200, { 'content-type': type, 'cache-control': 'no-cache', ...security });
      res.end(fs.readFileSync(file));
    } catch {
      res.writeHead(400); res.end();
    }
  });
  return new Promise((ok, err) => {
    server.once('error', err);
    server.listen(port, host, () => {
      const a = server.address();
      log(`carteira web em http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${a.port}`);
      ok({ server, url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${a.port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) });
    });
  });
}
