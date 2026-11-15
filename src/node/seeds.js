// Seed nodes of each network (seeds/<network>.txt): a list maintained through pull requests from
// people who run public nodes. Node.js only (the browser app does not connect to P2P nodes).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../seeds');

/** "host:port" addresses of the network (empty lines and # comments are ignored). */
export function parseSeeds(text) {
  return text.split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter((l) => /^[\w.\-[\]:]+:\d{1,5}$/.test(l));
}

export function seedsFor(network) {
  try { return parseSeeds(fs.readFileSync(path.join(DIR, `${network}.txt`), 'utf8')); } catch { return []; }
}
