// Nós-semente de cada rede (seeds/<rede>.txt): uma lista mantida por pull requests de quem roda
// nós públicos. Só no Node.js (o app do navegador não conecta a nós P2P).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../seeds');

/** Endereços "host:porta" da rede (linhas vazias e comentários # são ignorados). */
export function parseSeeds(text) {
  return text.split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter((l) => /^[\w.\-[\]:]+:\d{1,5}$/.test(l));
}

export function seedsFor(network) {
  try { return parseSeeds(fs.readFileSync(path.join(DIR, `${network}.txt`), 'utf8')); } catch { return []; }
}
