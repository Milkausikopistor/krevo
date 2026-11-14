// node --import ./test/browser/register.mjs …  →  ambiente "de navegador": Buffer e node:crypto
// trocados pelas versões em JavaScript puro do app web.
import { register } from 'node:module';
import { Buffer as WebBuffer } from '../../src/web/shims/buffer.js';
globalThis.Buffer = WebBuffer;
register('./hooks.mjs', import.meta.url);
