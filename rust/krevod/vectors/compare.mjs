// Reprocessa arquivos de blocos no nó JavaScript (referência) e no krevod (Rust) e compara
// o estado final campo a campo.
//   node rust/krevod/vectors/compare.mjs <krevod.exe> <arquivo.dat | pasta>…
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const [bin, ...inputs] = process.argv.slice(2);
const files = inputs.flatMap((p) => (fs.statSync(p).isDirectory() ? fs.readdirSync(p).filter((f) => f.endsWith('.dat')).map((f) => path.join(p, f)) : [p]));
let ok = 0, bad = 0, jsMs = 0, rsMs = 0;
for (const f of files) {
  const net = (path.basename(f).match(/(mainnet|testnet|devnet|simnet)/) ?? [null, process.env.KREVO_NET ?? 'devnet'])[1];
  let t = Date.now();
  const js = JSON.parse(execFileSync(process.execPath, [path.join(here, 'replay.mjs'), net, f], { stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 26 }).toString());
  jsMs += Date.now() - t; t = Date.now();
  const rs = JSON.parse(execFileSync(bin, ['replay', '--rede', net, '--arquivo', f], { stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 26 }).toString());
  rsMs += Date.now() - t;
  delete rs.replayMs;
  const same = JSON.stringify(js) === JSON.stringify(rs);
  if (same) ok++; else bad++;
  const diff = same ? '' : Object.keys(js).filter((k) => JSON.stringify(js[k]) !== JSON.stringify(rs[k])).map((k) => `${k}: js=${JSON.stringify(js[k])} rust=${JSON.stringify(rs[k])}`).join(' | ');
  console.log(`${same ? 'IGUAL ' : 'DIFERE'} ${path.basename(f)} (${js.blocks} blocos, ${js.chain} na cadeia, ${js.disq} desqualificados, ${js.sCount} saídas privadas, ${js.kiCount} gastos privados) ${diff}`);
}
console.log(`\n${ok} iguais, ${bad} diferentes — tempo total: JavaScript ${(jsMs / 1000).toFixed(1)} s, Rust ${(rsMs / 1000).toFixed(1)} s`);
process.exitCode = bad ? 1 : 0;
