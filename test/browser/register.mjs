// node --import ./test/browser/register.mjs …  →  "browser" environment: Buffer and node:crypto
// replaced by the web app's pure-JavaScript versions.
import { register } from 'node:module';
import { Buffer as WebBuffer } from '../../src/web/shims/buffer.js';
globalThis.Buffer = WebBuffer;
register('./hooks.mjs', import.meta.url);
