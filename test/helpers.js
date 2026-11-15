import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Point } from '../src/crypto/secp256k1.js';
import { scanShieldedOutput } from '../src/crypto/stealth.js';
import { keyImage } from '../src/crypto/clsag.js';
import { parseOutpointKey } from '../src/consensus/tx.js';
import { solve } from '../src/node/solver.js';
import { toHex } from '../src/util/bytes.js';

export class Clock {
  constructor() { this.t = Date.now(); }
  next() { this.t += 100; return this.t; }
}

export function mine(c, minerData, txs, clock, parents = null) {
  const t = clock.next();
  const b = parents
    ? c.buildTemplateOn(parents, minerData, txs, randomBytes(4), t)
    : c.buildTemplate(minerData, txs, randomBytes(4), t);
  assert.ok(solve(b), 'PoW');
  const r = c.addBlock(b, { now: t + 1000 });
  assert.equal(r.status, 'accepted', r.reason);
  return b;
}

export function tUtxos(c, keys, i = 0) {
  return c.utxosByLock(toHex(keys.tKey(i).lock)).map((u) => ({
    outpoint: parseOutpointKey(u.key), amount: u.amount, signer: keys.tKey(i).signer, daa: u.daa, coinbase: u.coinbase,
  }));
}

export function matureTUtxos(c, keys, i = 0) {
  const daa = c.virtual.gd.daaScore;
  return tUtxos(c, keys, i).filter((u) => !u.coinbase || daa - u.daa >= c.params.coinbaseMaturity);
}

/** Scans all private outputs of the virtual and returns the wallet's (unspent) ones. */
export function scanShielded(c, keys) {
  const v = c.virtual.view, out = [];
  for (let i = 0; i < v.sCount; i++) {
    const key = v.sAt(i), e = v.getS(key);
    const o = { P: Point.fromBytes(e.P), C: Point.fromBytes(e.C), encAmount: e.encAmount, viewTag: e.viewTag };
    const got = scanShieldedOutput(keys.scanKeys, Point.fromBytes(e.R), e.j, o);
    if (!got) continue;
    const spend = keys.spender(got.k, got.index); // the one-time key stays in the vault
    const ki = toHex(spend.keyImage(o.P).toBytes());
    if (v.hasKI(ki)) continue;
    out.push({ outpoint: parseOutpointKey(key), amount: got.v, mask: got.x, spend, P: o.P, C: o.C, daa: e.daa, coinbase: e.coinbase, index: i });
  }
  return out;
}

/** Builds a ring: the real output + random mature decoys. */
export function makeRing(c, real) {
  const v = c.virtual.view, p = c.params, daa = c.virtual.gd.daaScore;
  const cands = [];
  for (let i = 0; i < v.sCount; i++) {
    const key = v.sAt(i), e = v.getS(key);
    const need = e.coinbase ? Math.max(p.ringMaturity, p.coinbaseMaturity) : p.ringMaturity;
    if (daa - e.daa < need || i === real.index) continue;
    cands.push({ outpoint: parseOutpointKey(key), P: Point.fromBytes(e.P), C: Point.fromBytes(e.C) });
  }
  cands.sort(() => Math.random() - 0.5);
  const ring = [...cands.slice(0, p.ringSize - 1), { outpoint: real.outpoint, P: real.P, C: real.C }];
  assert.equal(ring.length, p.ringSize, 'enough decoys');
  return ring.sort(() => Math.random() - 0.5);
}

/**
 * Block of k consecutive FREE ports (P2P node, RPC, servers…). The tests run in parallel:
 * picking within a narrow range made two files grab the same port (EADDRINUSE). Range
 * 20000–32000 (outside the ephemeral ports of Linux, 32768+, and Windows, 49152+), checked by binding
 * each port before returning it.
 */
export async function freePorts(k = 2) {
  const { createServer } = await import('node:net');
  const listenOn = (port) => new Promise((ok, fail) => { const s = createServer(); s.once('error', fail); s.listen(port, () => ok(s)); });
  for (let attempt = 0; attempt < 200; attempt++) {
    const base = 20000 + Math.floor(Math.random() * (12000 - k));
    const servers = [];
    try {
      for (let i = 0; i < k; i++) servers.push(await listenOn(base + i));
      return base;
    } catch { /* ocupada: tenta outro bloco */ } finally {
      await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))));
    }
  }
  throw new Error('no free block of ports');
}
