// Compila o núcleo criptográfico para WebAssembly e copia para src/crypto/krevo_core.wasm.
//   rustup target add wasm32-unknown-unknown   (uma vez)
//   node rust/krevo-wasm/build.mjs [--release]
// O .wasm compilado já vem no repositório; recompile depois de mudar rust/krevod/src.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const release = process.argv.includes('--release');
const args = ['build', '--target', 'wasm32-unknown-unknown', ...(release ? ['--release'] : [])];
const r = spawnSync('cargo', args, { cwd: here, stdio: 'inherit' });
if (r.status !== 0) process.exit(r.status ?? 1);
const targetDir = process.env.CARGO_TARGET_DIR ?? path.join(here, 'target');
const src = path.join(targetDir, 'wasm32-unknown-unknown', release ? 'release' : 'debug', 'krevo_wasm.wasm');
const dst = path.resolve(here, '../../src/crypto/krevo_core.wasm');
fs.copyFileSync(src, dst);
const bytes = fs.readFileSync(dst);
console.log(`${path.relative(process.cwd(), dst)}: ${bytes.length} bytes, sha256 ${createHash('sha256').update(bytes).digest('hex')}`);
