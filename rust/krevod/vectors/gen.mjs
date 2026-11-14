// Gera vetores de teste com o nó de referência em JavaScript (src/) para o nó em Rust.
//   node rust/krevod/vectors/gen.mjs   →   rust/krevod/vectors/vectors.json
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const imp = (p) => import(new URL(`file:///${root.replace(/\\/g, '/')}/src/${p}`).href);

const { H } = await imp('crypto/hash.js');
const { mulG, randomScalar, modN } = await imp('crypto/secp256k1.js');
const { Hv, commit } = await imp('crypto/pedersen.js');
const { schnorrSign } = await imp('crypto/schnorr.js');
const { clsagSign, keyImage, encodeClsag, hashPointForKeyImage } = await imp('crypto/clsag.js');
const { proveRange } = await imp('crypto/bulletproofs.js');
const { MuHash } = await imp('crypto/muhash.js');
const { makeShieldedOutput } = await imp('crypto/stealth.js');
const { mldsaKeyFromSeed, mldsaSign } = await imp('crypto/pq.js');
const { getParams } = await imp('params.js');
const { buildGenesis } = await imp('consensus/consensus.js');
const { PowState, compactToTarget, targetToCompact, calcWork } = await imp('consensus/pow.js');
const { subsidyForMonth, cappedSubsidy } = await imp('consensus/emission.js');
const { toHex } = await imp('util/bytes.js');

const hex = (b) => toHex(b);
const v = {};

v.hash = { h64: hex((await imp('crypto/hash.js')).H64('teste', 'abc', Buffer.from([1, 2, 3]), 42)), h: hex(H('vazio')) };
v.pedersen = { hv: Hv.hex(), commit: commit(123456789n, 987654321n).hex() };
const k = 0x1234567890abcdefn;
v.mulG = { k: k.toString(16), p: mulG(k).hex() };

// Schnorr
const sx = randomScalar(), sP = mulG(sx), msg = Buffer.from('mensagem de teste');
v.schnorr = { p: sP.hex(), msg: hex(msg), sig: hex(schnorrSign(sx, msg)), binding: hex(schnorrSign(sx, msg, 'binding')) };

// CLSAG (anel de 4)
const ring = [], secrets = [];
for (let i = 0; i < 4; i++) { const p = randomScalar(), x = randomScalar(); secrets.push({ p, x }); ring.push({ P: mulG(p), C: commit(1000n + BigInt(i), x) }); }
const pi = 2, pm = randomScalar(), pseudo = commit(1002n, pm);
const csig = clsagSign(msg, ring, pseudo, pi, secrets[pi].p, modN(secrets[pi].x - pm));
v.clsag = { msg: hex(msg), ring: ring.map((m) => ({ P: m.P.hex(), C: m.C.hex() })), pseudo: pseudo.hex(), sig: hex(encodeClsag(csig)), ki: csig.I.hex(),
  hp: hashPointForKeyImage(ring[0].P).hex(), kiCheck: keyImage(secrets[pi].p, ring[pi].P).hex() };

// Bulletproofs (2 valores)
const rp = proveRange([5000n, 7n], [randomScalar(), randomScalar()]);
v.range = { V: rp.V.map((x) => x.hex()), proof: hex(rp.proof) };

// MuHash
const mh = new MuHash(); mh.add(Buffer.from('a')); mh.add(Buffer.from('b')); mh.remove(Buffer.from('a'));
v.muhash = hex(mh.digest());

// coinbase privada
const A = mulG(11n), B = mulG(22n), r = 33n;
const so = makeShieldedOutput({ A, B }, r, 1, 5_000_000_000n, true);
v.stealth = { A: A.hex(), B: B.hex(), r: r.toString(16), j: 1, v: '5000000000', R: so.R.hex(), P: so.P.hex(), C: so.C.hex(), enc: hex(so.encAmount), tag: so.viewTag };

// ML-DSA-44
const kp = mldsaKeyFromSeed(Buffer.alloc(32, 7));
v.mldsa = { pub: hex(kp.pub), msg: hex(msg), sig: hex(mldsaSign(kp.priv, msg)) };

// gênesis, PoW, emissão, alvos
v.genesis = {};
for (const n of ['mainnet', 'testnet', 'devnet', 'simnet']) {
  const g = buildGenesis(getParams(n));
  v.genesis[n] = { hash: g.hashHex, block: hex(g.serialize()), prepow: hex(g.header.prePowHash()) };
}
const st = new PowState(Buffer.from(v.genesis.devnet.prepow, 'hex'));
v.pow = { prepow: v.genesis.devnet.prepow, ts: 1794355200123, nonce: '987654321', hash: hex(st.hash(1794355200123, 987654321n)) };
const dp = getParams('devnet');
v.emission = [0n, 1n, 47n, 48n, 49n, 1000n, 3071n].map((m) => ({ month: m.toString(), subsidy: subsidyForMonth(m, dp).toString() }));
v.capped = cappedSubsidy(0, 1_000_000_000n * 100_000_000n - 5n, dp).toString();
v.targets = [0x1f0fffff, 0x207fffff, 0x1d00ffff, 0x1b0404cb].map((b) => ({ bits: b, target: compactToTarget(b).toString(16), back: targetToCompact(compactToTarget(b)), work: calcWork(b).toString() }));

fs.writeFileSync(path.join(here, 'vectors.json'), JSON.stringify(v, null, 1));
console.log('vetores gravados em', path.join(here, 'vectors.json'));

// ---------------------------------------------------------------- FCMP
{
  const { CurveTree } = await imp('fcmp/tree.js');
  const { fcmpProve } = await imp('fcmp/fcmp.js');
  const outs = [];
  for (let i = 0; i < 21; i++) { const p = randomScalar(), x = randomScalar(), val = BigInt(1000 + i); outs.push({ p, x, v: val, P: mulG(p), C: commit(val, x) }); }
  const tree = new CurveTree(4, (i) => ({ key: 'o' + i, P: outs[i].P.toBytes(), C: outs[i].C.toBytes() }));
  const cases = [];
  for (const [N, i] of [[3, 1], [16, 13], [21, 6]]) {
    const root = tree.root(N), o = outs[i], pm = randomScalar(), m = Buffer.from('sighash ' + N);
    const r = fcmpProve({ branch: 4, N, path: tree.pathForChunk(N, Math.floor(i / 4)), leafPos: i % 4, P: o.P, C: o.C, p: o.p, x: o.x, v: o.v, pseudoMask: pm, msg: m });
    cases.push({ N, depth: root.depth, root: root.point.hex(), count: root.count, msg: hex(m), proof: hex(r.proof), ki: r.keyImage.hex(), pseudo: r.pseudo.hex(),
      path: tree.pathForChunk(N, Math.floor(i / 4)).map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map((x) => x.toString(16)) })) });
  }
  const vv = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8'));
  vv.fcmp = { branch: 4, outputs: outs.map((o) => ({ P: o.P.hex(), C: o.C.hex() })), cases };
  fs.writeFileSync(path.join(here, 'vectors.json'), JSON.stringify(vv, null, 1));
  console.log('FCMP: casos', cases.map((c) => `N=${c.N} d=${c.depth}`).join(', '));
}
