// FCMP — full-chain membership proof for a private input.
//
// Instead of hiding the spent coin among 16 decoys (a ring), the spender proves that it is
// ONE of the N private outputs that have ever existed, without saying which. The anonymity
// set is the entire network.
//
// The prover re-randomizes the output and the path up to the root:
//   P̂ = P + r1·T     Î = I + r1·T_I     Ĉ = C + r1·T_C        (I = Hp(P))
//   L̂ = L + r2·G6    N̂_l = N_l + r·G_blind(l)                  (path nodes, blinded)
// and publishes two circuit Bulletproofs (one on each curve of the cycle):
//   • over E2: "unblinding" P̂, Î, Ĉ with the bits of r1 yields exactly the coordinates
//     opened by the leaf L̂; and each E1 node on the path, unblinded, is a child of the node above;
//   • over E1: the leaf and each E2 node on the path, unblinded with r2, are children of the node
//     above — up to the public root.
// Finally, a generalized Schnorr proof (GSP) shows, without revealing anything:
//   P̂ = p·G + t·T            (the spender knows the key)
//   p·P̂ = q·G + y·T          (binds y = p·t)
//   KI = p·Î − y·T_I         (so KI = p·Hp(P): the SAME key image as the rings)
//   Ĉ − C' = a·G + b·T_C     (the pseudo-commitment C' has the same amount)
// A key image equal to the rings' prevents spending the same output twice, through
// either of the two paths.

import { E1, E2, Fp, Fn } from './curve.js';
import { ConstraintSystem, bitsGadget, windowsGadget, fixedBaseTable, unblindGadget,
  permissibleGadget, selectGadget } from './circuit.js';
import { bpGens, bpProve, bpVerifyInto, BpBatch, Transcript, nextPow2, encodeBpProof,
  decodeBpProof, bpProofSize } from './bp.js';
import { segment, LEAF_BLIND, LEAF_WIDTH, leafData, makePermissible, depthFor } from './tree.js';
import { Point, G, hashToScalar, randomScalar, hedgedScalar, modN, scalarToBytes, scalarFromBytes,
  multiexp } from '../crypto/secp256k1.js';
import { commit } from '../crypto/pedersen.js';
import * as core from '../crypto/wasm.js';
import { H } from '../crypto/hash.js';

const W = 86;                       // 3-bit windows (258 bits ≥ 256)
const SCALAR_GATES = 7 * W;         // bits (3W) + window products (4W)
const UNBLIND_GATES = 3 * W + 1;    // (W−1) 3-gate additions + final addition (3) + check (1)

// ------------------------------------------------------------------ public bases
let _bases = null;
export function bases() {
  if (!_bases) {
    const T = E1.gen('fcmp/T'), TI = E1.gen('fcmp/TI'), TC = E1.gen('fcmp/TC');
    const s = (p) => Point.fromAffine(p.x, p.y);
    _bases = { T, TI, TC, O1: E1.gen('fcmp/Omega'), O2: E2.gen('fcmp/Omega'), sT: s(T), sTI: s(TI), sTC: s(TC) };
  }
  return _bases;
}
const tableCache = new Map();
function table(curve, base, omega) {
  const key = curve.name + ':' + base.hex();
  let t = tableCache.get(key);
  if (!t) { t = fixedBaseTable(curve, base, omega, W); tableCache.set(key, t); }
  return t;
}
const toE1 = (p) => { const a = p.affine(); return E1.point(a[0], a[1]); };
const toSecp = (p) => Point.fromAffine(p.x, p.y);

/** Sizes of the two circuits for depth d (the worst case fixes n). */
export function circuitSizes(d, b) {
  const sel = UNBLIND_GATES + 1 + (b - 1);
  const g2 = SCALAR_GATES + 3 * UNBLIND_GATES + Math.floor(d / 2) * sel;
  const g1 = SCALAR_GATES + (1 + Math.floor((d - 1) / 2)) * sel;
  let p1 = 0, p2 = LEAF_BLIND;
  for (let l = 1; l <= d; l++) { const s = segment(l, b); if (l % 2) p1 = Math.max(p1, s.blind); else p2 = Math.max(p2, s.blind); }
  return { n1: nextPow2(Math.max(g1, p1 + 1)), n2: nextPow2(Math.max(g2, p2 + 1)), K1: Math.ceil(d / 2), K2: 1 + Math.floor(d / 2) };
}
const GSP_SIZE = 7 * 32;
export function fcmpProofSize(N, b) {
  const d = depthFor(N, b), s = circuitSizes(d, b);
  return 4 * 33 + (d - 1) * 33 + bpProofSize(s.n1, s.K1) + bpProofSize(s.n2, s.K2) + GSP_SIZE;
}

// ------------------------------------------------------------------ circuits
function addNodeVC(cs, st, w, l) {
  const seg = segment(l, st.b);
  if (l === st.d) { // root: public, no blinding
    const e = w ? new Map(w.levels[l].entries.map((v, j) => [seg.off + j, v])) : null;
    return cs.addVC(st.root, e, 0n);
  }
  let e = null;
  if (w) {
    e = new Map(w.levels[l].entries.map((v, j) => [seg.off + j, v]));
    e.set(seg.blind, l % 2 ? w.r1 : w.r2);
  }
  return cs.addVC(st.hats[l], e, w ? w.levels[l].k : 0n);
}

function selectInParent(cs, st, parentLevel, vcIdx, x) {
  const seg = segment(parentLevel, st.b);
  const count = parentLevel === st.d ? st.rootCount : st.b;
  const entries = [];
  for (let j = 0; j < count; j++) entries.push(cs.vc(vcIdx, seg.off + j));
  selectGadget(cs, entries, x);
}

/** Circuit over E2 (field F_p): points of E1 are unblinded with r1. */
function buildE2(st, w) {
  const B = bases(), cs = new ConstraintSystem(Fp.m, !!w);
  cs.addVC(st.Lhat, w ? new Map([...w.coords.map((v, i) => [i, v]), [LEAF_BLIND, w.r2]]) : null, w ? w.kL : 0n);
  const vcOf = new Map();
  for (let l = 2; l <= st.d; l += 2) vcOf.set(l, addNodeVC(cs, st, w, l));
  const wins = windowsGadget(cs, bitsGadget(cs, w ? w.r1 : 0n, 3 * W));
  const r = w ? w.r1 : 0n;
  [[st.Phat, B.T, 0], [st.Ihat, B.TI, 2], [st.Chat, B.TC, 4]].forEach(([pt, base, i]) => {
    const res = unblindGadget(cs, wins, table(E1, base, B.O1), pt, r);
    cs.constrain(res.P.x.sub(cs.vc(0, i)));
    cs.constrain(res.P.y.sub(cs.vc(0, i + 1)));
  });
  for (let l = 1; l < st.d; l += 2) {
    const seg = segment(l, st.b);
    const res = unblindGadget(cs, wins, table(E1, bpGens(E1, seg.blind + 1).G[seg.blind], B.O1), st.hats[l], r);
    permissibleGadget(cs, res.P.y, res.v ? res.v[1] : 0n, (v) => Fp.sqrt(v));
    selectInParent(cs, st, l + 1, vcOf.get(l + 1), res.P.x);
  }
  return cs;
}

/** Circuit over E1 (field F_n): the leaf and the E2 nodes are unblinded with r2. */
function buildE1(st, w) {
  const B = bases(), cs = new ConstraintSystem(Fn.m, !!w);
  const vcOf = new Map();
  for (let l = 1; l <= st.d; l += 2) vcOf.set(l, addNodeVC(cs, st, w, l));
  const wins = windowsGadget(cs, bitsGadget(cs, w ? w.r2 : 0n, 3 * W));
  const r = w ? w.r2 : 0n;
  const leafBase = bpGens(E2, LEAF_BLIND + 1).G[LEAF_BLIND];
  let res = unblindGadget(cs, wins, table(E2, leafBase, B.O2), st.Lhat, r);
  permissibleGadget(cs, res.P.y, res.v ? res.v[1] : 0n, (v) => Fn.sqrt(v));
  selectInParent(cs, st, 1, vcOf.get(1), res.P.x);
  for (let l = 2; l < st.d; l += 2) {
    const seg = segment(l, st.b);
    res = unblindGadget(cs, wins, table(E2, bpGens(E2, seg.blind + 1).G[seg.blind], B.O2), st.hats[l], r);
    permissibleGadget(cs, res.P.y, res.v ? res.v[1] : 0n, (v) => Fn.sqrt(v));
    selectInParent(cs, st, l + 1, vcOf.get(l + 1), res.P.x);
  }
  return cs;
}

function transcriptFor(label, st) {
  const tr = new Transcript('fcmp/' + label);
  tr.add('st', st.b, st.N, st.d, st.root, st.rootCount, st.Phat, st.Ihat, st.Chat, st.Lhat);
  for (let l = 1; l < st.d; l++) tr.add('hat', l, st.hats[l]);
  return tr;
}

// ------------------------------------------------------------------ GSP
function gspChallenge(ctx, R) { return hashToScalar('fcmp/gsp', ctx, ...R); }

const GSP_W = ['p', 't', 'q', 'y', 'a', 'b'];
function gspProve(ctx, pub, wit) {
  // Rust core: constant time, hedged nonces, proof checked before returning
  if (core.available()) return core.gspProve(ctx, pub.Phat.toBytes(), pub.Ihat.toBytes(), pub.D.toBytes(), GSP_W.map((n) => modN(wit[n])));
  const B = bases();
  const secret = GSP_W.map((n) => scalarToBytes(wit[n]));
  const k = Object.fromEntries(GSP_W.map((n, i) => [n, hedgedScalar('fcmp/gsp/nonce/' + i, ...secret, ctx)]));
  const R = [
    multiexp([k.p, k.t], [G, B.sT]),
    multiexp([k.p, modN(-k.q), modN(-k.y)], [pub.Phat, G, B.sT]),
    multiexp([k.p, modN(-k.y)], [pub.Ihat, B.sTI]),
    multiexp([k.a, k.b], [G, B.sTC]),
  ];
  const e = gspChallenge(ctx, R);
  const s = GSP_W.map((n) => modN(k[n] + e * wit[n]));
  const proof = Buffer.concat([scalarToBytes(e), ...s.map(scalarToBytes)]);
  if (!gspVerify(ctx, pub, proof)) throw new Error('fcmp: ownership proof failed (verification)');
  return proof;
}

/** Ownership proof with explicit witnesses (used by the JavaScript vault, src/crypto/vault.js). */
export const gspProveWit = (ctx, pub, wit) => gspProve(ctx, pub, wit);

function gspVerify(ctx, pub, buf) {
  const B = bases();
  const v = [];
  for (let i = 0; i < 7; i++) v.push(scalarFromBytes(buf.subarray(32 * i, 32 * i + 32)));
  const [e, sp, st, sq, sy, sa, sb] = v;
  const ne = modN(-e);
  const R = [
    multiexp([sp, st, ne], [G, B.sT, pub.Phat]),
    multiexp([sp, modN(-sq), modN(-sy)], [pub.Phat, G, B.sT]),
    multiexp([sp, modN(-sy), ne], [pub.Ihat, B.sTI, pub.KI]),
    multiexp([sa, sb, ne], [G, B.sTC, pub.D]),
  ];
  return gspChallenge(ctx, R) === e;
}

// ------------------------------------------------------------------ prove
/**
 * Builds the public statement and the witness of an input, for given blindings (r1, r2).
 *  path: [{ level, idx, entries }] from level 1 up to the root (tree.pathForChunk)
 *  leafPos: position of the output within the level-1 node (global index % branch)
 *  P, C: the output's points (Point or 33 bytes)
 */
function setup({ branch: b, N, path, leafPos, P, C }, r1, r2) {
  const d = depthFor(N, b);
  if (path.length !== d) throw new Error('fcmp: path with the wrong depth');
  const leaf = leafData(P, C);
  if (path[0].entries[leafPos] !== leaf.x) throw new Error('fcmp: the output is not at that position in the tree');
  const levels = [];
  let childX = leaf.x;
  for (let l = 1; l <= d; l++) {
    const { entries, idx } = path[l - 1];
    const pos = l === 1 ? leafPos : path[l - 2].idx % b;
    if (entries[pos] !== childX) throw new Error(`fcmp: inconsistent path at level ${l}`);
    const seg = segment(l, b), gens = bpGens(seg.curve, seg.blind + 1);
    const raw = seg.curve.msm(entries, gens.G.slice(seg.off, seg.off + entries.length));
    const perm = l < d ? makePermissible(seg.curve, raw, gens.h) : { k: 0n, point: raw };
    levels[l] = { entries, idx, raw, k: perm.k, point: perm.point };
    childX = perm.point.x;
  }
  const B = bases();
  const Pe = toE1(leaf.P), Ie = toE1(leaf.I), Ce = toE1(leaf.C);
  const st = {
    b, N, d, root: levels[d].raw, rootCount: levels[d].entries.length,
    Phat: Pe.add(B.T.mul(r1)), Ihat: Ie.add(B.TI.mul(r1)), Chat: Ce.add(B.TC.mul(r1)),
    Lhat: leaf.point.add(bpGens(E2, LEAF_BLIND + 1).G[LEAF_BLIND].mul(r2)), hats: [],
  };
  for (let l = 1; l < d; l++) {
    const seg = segment(l, b);
    st.hats[l] = levels[l].point.add(bpGens(seg.curve, seg.blind + 1).G[seg.blind].mul(l % 2 ? r1 : r2));
  }
  return { st, w: { r1, r2, coords: leaf.coords, kL: leaf.k, levels }, leaf, sizes: circuitSizes(d, b) };
}

/** One of the two Bulletproofs ('E1' or 'E2'), already encoded. */
function proveHalfFrom({ st, w, sizes }, half) {
  const cs = half === 'E1' ? buildE1(st, w) : buildE2(st, w);
  cs.n = half === 'E1' ? sizes.n1 : sizes.n2;
  if (cs.nGates > cs.n) throw new Error('fcmp: circuit larger than expected');
  const curve = half === 'E1' ? E1 : E2;
  return encodeBpProof(curve, bpProve(curve, cs, transcriptFor(half, st)));
}

/** For the proving threads: job = { branch, N, path, leafPos, P, C (bytes), r1, r2 }. */
export function proveHalf(job, half) { return proveHalfFrom(setup(job, job.r1, job.r2), half); }

/** Fresh blindings for an input. */
export function newBlinds() { return { r1: randomScalar(), r2: Fp.random() }; }

/** Expensive part (the two circuit proofs), sequential. Does not depend on the signed message. */
export function fcmpPrepare(args, blinds = newBlinds()) {
  const s = setup(args, blinds.r1, blinds.r2);
  return finishPrep(s, proveHalfFrom(s, 'E1'), proveHalfFrom(s, 'E2'));
}
/** Joins the statement with the two proofs (from here or from the threads). */
export function finishPrep(s, bp1, bp2) {
  return { st: s.st, leaf: s.leaf, r1: s.w.r1, head: encodeHead(s.st), bps: Buffer.concat([bp1, bp2]) };
}
export function setupFor(args, blinds) { return setup(args, blinds.r1, blinds.r2); }

/**
 * Final, fast part: the generalized Schnorr proof bound to the transaction (msg = sighash).
 *  p: one-time key;  x, v: blinding and amount of C;  pseudoMask: of C' = commit(v, pseudoMask)
 * Returns { proof, keyImage, pseudo }.
 */
export function fcmpFinish(pre, { p, spend, P, x, v, pseudoMask, msg }) {
  const { st, leaf, r1, head, bps } = pre;
  const pseudo = commit(v, pseudoMask);
  // with the vault (spend), the one-time key never leaves the core: it computes the key image and the proof
  const KI = spend ? spend.keyImage(P instanceof Point ? P : Point.fromBytes(P)) : leaf.I.mul(p);
  const pub = { Phat: toSecp(st.Phat), Ihat: toSecp(st.Ihat), D: toSecp(st.Chat).sub(pseudo), KI };
  const ctx = H('fcmp/ctx', msg, head, bps, pseudo, KI);
  const gsp = spend ? spend.gsp(ctx, pub.Phat, pub.Ihat, pub.D, P instanceof Point ? P : Point.fromBytes(P), r1, modN(x - pseudoMask))
    : gspProve(ctx, pub, { p: modN(p), t: r1, q: modN(p * p), y: modN(p * r1), a: modN(x - pseudoMask), b: r1 });
  return { proof: Buffer.concat([head, bps, gsp]), keyImage: KI, pseudo };
}

/** Full proof (sequential). See fcmpPrepare / fcmpFinish and src/fcmp/parallel.js. */
export function fcmpProve(args) { return fcmpFinish(fcmpPrepare(args), args); }

function encodeHead(st) {
  const parts = [st.Phat.toBytes(), st.Ihat.toBytes(), st.Chat.toBytes(), st.Lhat.toBytes()];
  for (let l = 1; l < st.d; l++) parts.push(st.hats[l].toBytes());
  return Buffer.concat(parts);
}

// ------------------------------------------------------------------ verify
/**
 * Checks an input's proof and adds the Bulletproofs equations to the batches
 * (batch = { e1: BpBatch(E1), e2: BpBatch(E2) }). Throws if anything does not check out;
 * the final verdict comes from batch.e1.check() && batch.e2.check().
 *  root: { point, count } of the tree with N outputs (tree.root(N))
 */
export function fcmpVerifyInto(batch, { branch: b, N, root, proof, keyImage, pseudo, msg }) {
  const d = depthFor(N, b), sizes = circuitSizes(d, b);
  if (proof.length !== fcmpProofSize(N, b)) throw new Error('fcmp: proof size');
  if (keyImage.isInf()) throw new Error('fcmp: invalid key image');
  let o = 0;
  const e1 = () => { const p = E1.fromBytes(proof.subarray(o, o + 33)); o += 33; return p; };
  const e2 = () => { const p = E2.fromBytes(proof.subarray(o, o + 33)); o += 33; return p; };
  const st = { b, N, d, root: root.point, rootCount: root.count, Phat: e1(), Ihat: e1(), Chat: e1(), Lhat: e2(), hats: [] };
  for (let l = 1; l < d; l++) st.hats[l] = l % 2 ? e1() : e2();
  const headLen = o;
  const s1 = bpProofSize(sizes.n1, sizes.K1), s2 = bpProofSize(sizes.n2, sizes.K2);
  const pr1 = decodeBpProof(E1, proof.subarray(o, o + s1), sizes.n1, sizes.K1); o += s1;
  const pr2 = decodeBpProof(E2, proof.subarray(o, o + s2), sizes.n2, sizes.K2); o += s2;
  const gsp = proof.subarray(o);
  // GSP first (cheap)
  const pub = { Phat: toSecp(st.Phat), Ihat: toSecp(st.Ihat), D: toSecp(st.Chat).sub(pseudo), KI: keyImage };
  const ctx = H('fcmp/ctx', msg, proof.subarray(0, headLen), proof.subarray(headLen, headLen + s1 + s2), pseudo, keyImage);
  if (!gspVerify(ctx, pub, gsp)) throw new Error('fcmp: invalid ownership/key image proof');
  const cs2 = buildE2(st, null); cs2.n = sizes.n2;
  const cs1 = buildE1(st, null); cs1.n = sizes.n1;
  bpVerifyInto(batch.e2, cs2, pr2, transcriptFor('E2', st));
  bpVerifyInto(batch.e1, cs1, pr1, transcriptFor('E1', st));
}

export function newFcmpBatch() { return { e1: new BpBatch(E1), e2: new BpBatch(E2) }; }
export function fcmpVerify(args) {
  try {
    const b = newFcmpBatch();
    fcmpVerifyInto(b, args);
    return b.e1.check() && b.e2.check();
  } catch { return false; }
}
