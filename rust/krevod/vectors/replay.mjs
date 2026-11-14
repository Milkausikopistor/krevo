// Reprocessa um arquivo de blocos com o nó de REFERÊNCIA (JavaScript) e imprime o mesmo resumo
// que `krevod replay` imprime — os dois precisam ser idênticos.
//   node rust/krevod/vectors/replay.mjs <rede> <caminho/blocos.dat>
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const imp = (p) => import(new URL(`file:///${root.replace(/\\/g, '/')}/src/${p}`).href);
const { getParams } = await imp('params.js');
const { Consensus } = await imp('consensus/consensus.js');
const { BlockFile } = await imp('node/storage.js');
const { H } = await imp('crypto/hash.js');
const { toHex } = await imp('util/bytes.js');

const [net, file] = process.argv.slice(2);
const c = new Consensus(getParams(net));
const bf = new BlockFile(path.dirname(file));
bf.file = file;
const t = Date.now();
let ok = 0, other = 0;
for (const b of bf.readAll()) {
  const r = c.addBlock(b, { trusted: true });
  if (r.status === 'accepted') ok++; else other++;
}
c._moveBase(c.virtual.gd.selectedParent);
const v = c.virtual, view = v.view;
const statuses = [...c.status.entries()].map(([h, s]) => [h, s === 'chain' ? 'chain' : 'disq']).sort((a, b) => (a[0] < b[0] ? -1 : 1));
const parts = [];
for (const [h, s] of statuses) parts.push(h, s);
const out = {
  blocks: c.store.gd.size,
  chain: statuses.filter((x) => x[1] === 'chain').length,
  disq: statuses.filter((x) => x[1] === 'disq').length,
  statusDigest: toHex(H('replay/status', ...parts)),
  virtual: { blueScore: v.gd.blueScore, daaScore: v.gd.daaScore, selectedParent: v.gd.selectedParent, parents: v.parents.length, bits: v.bits },
  utxoCommitment: toHex(v.acceptance.muhash.clone().digest()),
  acceptedRoot: toHex(v.acceptance.acceptedRoot),
  minted: v.acceptance.minted.toString(),
  feePool: v.acceptance.pool.toString(),
  shielded: (v.acceptance.shielded ?? 0n).toString(),
  sCount: view.sCount,
  tCount: c.utxo.t.size + view.diff.addT.size - view.diff.remT.size,
  kiCount: c.utxo.ki.size + view.diff.addKI.length,
  names: view.allNames().size,
};
console.error(`${ok} blocos aceitos, ${other} outros, em ${((Date.now() - t) / 1000).toFixed(2)} s`);
console.log(JSON.stringify(out, null, 1));
