// Spending policies: M-of-N multisig and paths with time locks (consensus rule).
//
// The address stores only the HASH of the policy (like Bitcoin's P2WSH): the keys and the
// rules only appear on the network when the money is spent.
//
// Version 1 — one path, no waiting (simple multisig):
//   policy:  [0x01][M][N][N × key (33)]
//   witness: policy ‖ [M] ‖ M × ([index][signature 64])
//
// Version 2 — several alternative paths ("OR"), each with a minimum wait:
//   policy:  [0x02][C] ‖ C × ([M][N][wait u64][N × key (33)])
//   witness: policy ‖ [path] ‖ [M] ‖ M × ([index][signature 64])
// The wait is RELATIVE: number of blocks (daaScore) since the output was created.
// Inheritance example: path 0 = owner (1-of-1, no wait); path 1 = heirs
// (1-of-2, 1-year wait). If the owner moves the money, the new output starts the count
// from zero — that is the "proof of life".
//
// Version 3 — like 2, but each path can also require a SECRET (hash lock):
//   policy:  [0x03][C] ‖ C × ([M][N][wait u64][has hash: 0|1][SHA-256 (32), if any][N × key])
//   witness: policy ‖ [path] ‖ [secret (32), if the path has a hash] ‖ [M] ‖ M × ([index][signature])
// The secret must be exactly 32 bytes and SHA-256(secret) = hash. It is the same hash as
// Bitcoin's OP_SHA256: that is why the same lock works for Krevo ⇄ Bitcoin atomic swaps
// (whoever claims on one side reveals the secret, which unlocks the other side).
//
// Rules: M Schnorr signatures from DIFFERENT keys of the chosen path (increasing indexes),
// over the same transaction message, output age ≥ wait and, if any, the right secret.
// The order of keys within a path is canonical.

import { createHash } from 'node:crypto';
import { H } from '../crypto/hash.js';
import { Point } from '../crypto/secp256k1.js';
import { schnorrVerify } from '../crypto/schnorr.js';
import { u64le } from '../util/bytes.js';

export const POLICY_VERSION = 0x01;
export const POLICY_VERSION_PATHS = 0x02;
export const POLICY_VERSION_HASHLOCK = 0x03;
export const SECRET_SIZE = 32;
export const sha256 = (b) => createHash('sha256').update(b).digest();
const hasPathByte = (ver) => ver === POLICY_VERSION_PATHS || ver === POLICY_VERSION_HASHLOCK;
export const MAX_POLICY_KEYS = 15;
export const MAX_PATHS = 4;
export const MAX_DELAY = 2 ** 40; // ~3,500 years at 10 blocks/s
export const LOCK_MULTISIG = 0x03;

function canonicalKeys(m, pubkeys) {
  const keys = pubkeys.map((k) => (Buffer.isBuffer(k) ? k : k.toBytes()));
  const n = keys.length;
  if (!Number.isInteger(m) || m < 1 || m > n || n > MAX_POLICY_KEYS) throw new Error(`invalid policy: ${m}-of-${n} (at most ${MAX_POLICY_KEYS} keys)`);
  keys.forEach((k) => Point.fromBytes(k)); // valid keys
  keys.sort(Buffer.compare);
  for (let i = 1; i < n; i++) if (keys[i].equals(keys[i - 1])) throw new Error('repeated key in the policy');
  return keys;
}

/** Simple multisig (version 1). */
export function encodePolicy(m, pubkeys) {
  const keys = canonicalKeys(m, pubkeys);
  return Buffer.concat([Buffer.from([POLICY_VERSION, m, keys.length]), ...keys]);
}

/**
 * Several paths: [{ m, keys, delay, hash? }]. Without any hash → version 2 (inheritance format);
 * with some path requiring a secret (hash = SHA-256 of 32 bytes) → version 3.
 */
export function encodePolicyPaths(paths) {
  if (!paths.length || paths.length > MAX_PATHS) throw new Error(`the policy needs 1 to ${MAX_PATHS} paths`);
  const v3 = paths.some((p) => p.hash);
  const parts = [Buffer.from([v3 ? POLICY_VERSION_HASHLOCK : POLICY_VERSION_PATHS, paths.length])];
  for (const p of paths) {
    const delay = Number(p.delay ?? 0);
    if (!Number.isInteger(delay) || delay < 0 || delay > MAX_DELAY) throw new Error('invalid wait');
    const keys = canonicalKeys(p.m, p.keys);
    parts.push(Buffer.from([p.m, keys.length]), u64le(delay));
    if (v3) {
      if (p.hash && (!Buffer.isBuffer(p.hash) || p.hash.length !== 32)) throw new Error('the lock hash must have 32 bytes');
      parts.push(p.hash ? Buffer.concat([Buffer.from([1]), p.hash]) : Buffer.from([0]));
    }
    parts.push(...keys);
  }
  return Buffer.concat(parts);
}

function readKeys(buf, o, n) {
  if (buf.length < o + 33 * n) throw new Error('truncated policy');
  const keys = [];
  for (let i = 0; i < n; i++) {
    const k = buf.subarray(o + 33 * i, o + 33 * (i + 1));
    if (i > 0 && Buffer.compare(buf.subarray(o + 33 * (i - 1), o + 33 * i), k) >= 0) throw new Error('keys out of canonical order');
    keys.push(Point.fromBytes(k));
  }
  return keys;
}

/**
 * Reads a policy from the start of `buf`.
 * Returns { version, paths:[{m, n, keys, delay}], bytes, m, n, keys } (m/n/keys = path 0).
 */
export function parsePolicy(buf) {
  const ver = buf[0];
  const paths = [];
  let o;
  if (ver === POLICY_VERSION) {
    const m = buf[1], n = buf[2];
    if (m < 1 || m > n || n > MAX_POLICY_KEYS) throw new Error('invalid policy');
    paths.push({ m, n, keys: readKeys(buf, 3, n), delay: 0 });
    o = 3 + 33 * n;
  } else if (ver === POLICY_VERSION_PATHS || ver === POLICY_VERSION_HASHLOCK) {
    const c = buf[1];
    if (!c || c > MAX_PATHS) throw new Error('invalid number of paths');
    o = 2;
    for (let i = 0; i < c; i++) {
      if (buf.length < o + 10) throw new Error('truncated policy');
      const m = buf[o], n = buf[o + 1];
      const delayBig = buf.readBigUInt64LE(o + 2);
      if (m < 1 || m > n || n > MAX_POLICY_KEYS || delayBig > BigInt(MAX_DELAY)) throw new Error('invalid policy');
      o += 10;
      let hash = null;
      if (ver === POLICY_VERSION_HASHLOCK) {
        if (buf.length < o + 1) throw new Error('truncated policy');
        const flag = buf[o++];
        if (flag > 1) throw new Error('invalid policy');
        if (flag) {
          if (buf.length < o + 32) throw new Error('truncated policy');
          hash = Buffer.from(buf.subarray(o, o + 32));
          o += 32;
        }
      }
      paths.push({ m, n, keys: readKeys(buf, o, n), delay: Number(delayBig), hash });
      o += 33 * n;
    }
    if (ver === POLICY_VERSION_HASHLOCK && !paths.some((p) => p.hash)) throw new Error('v3 policy without a hash lock');
  } else throw new Error('unknown policy version');
  return { version: ver, paths, bytes: Buffer.from(buf.subarray(0, o)), m: paths[0].m, n: paths[0].n, keys: paths[0].keys };
}

export const policyHash = (policyBytes) => H('lock/multisig', policyBytes);
export const multisigLock = (policyBytes) => Buffer.concat([Buffer.from([LOCK_MULTISIG]), policyHash(policyBytes)]);

export function witnessSize(policyBytes, path = 0) {
  const pol = parsePolicy(policyBytes);
  const p = pol.paths[path];
  return pol.bytes.length + (hasPathByte(pol.version) ? 1 : 0) + (p.hash ? SECRET_SIZE : 0) + 1 + p.m * 65;
}

/**
 * Builds the witness (Map index → signature) for the chosen path; uses the first M.
 * secret: the 32-byte secret, if the path has a hash lock.
 */
export function encodeWitness(policyBytes, sigs, path = 0, secret = null) {
  const pol = parsePolicy(policyBytes);
  const p = pol.paths[path];
  if (!p) throw new Error('path does not exist in the policy');
  const chosen = [...sigs.entries()].sort((a, b) => a[0] - b[0]).slice(0, p.m);
  if (chosen.length < p.m) throw new Error(`missing signatures: ${chosen.length} of ${p.m}`);
  let pre = Buffer.alloc(0);
  if (p.hash) {
    if (!secret || secret.length !== SECRET_SIZE || !sha256(secret).equals(p.hash)) throw new Error('secret missing or wrong for this path');
    pre = Buffer.from(secret);
  }
  const head = hasPathByte(pol.version) ? Buffer.concat([Buffer.from([path]), pre, Buffer.from([p.m])]) : Buffer.from([p.m]);
  return Buffer.concat([pol.bytes, head, ...chosen.flatMap(([i, s]) => [Buffer.from([i]), s])]);
}

/**
 * Reads policy + path (+ revealed secret, if any) from the witness, without verifying
 * signatures. null if malformed. { pol, path, p, secret, o }
 */
export function parseWitnessPath(witness) {
  try {
    const pol = parsePolicy(witness);
    let o = pol.bytes.length;
    const path = hasPathByte(pol.version) ? witness[o++] : 0;
    const p = pol.paths[path];
    if (!p) return null;
    let secret = null;
    if (p.hash) {
      if (witness.length < o + SECRET_SIZE) return null;
      secret = Buffer.from(witness.subarray(o, o + SECRET_SIZE));
      o += SECRET_SIZE;
    }
    return { pol, path, p, secret, o };
  } catch {
    return null;
  }
}

/** Wait (in blocks) required by the path used in the witness; null if malformed. */
export function witnessDelay(witness) {
  const w = parseWitnessPath(witness);
  return w ? w.p.delay : null;
}

/** Consensus rule: does the witness satisfy the lock for the message? (the wait is checked separately) */
export function verifyMultisigWitness(lock, witness, msg) {
  try {
    if (lock.length !== 33 || lock[0] !== LOCK_MULTISIG) return false;
    const w = parseWitnessPath(witness);
    if (!w || !policyHash(w.pol.bytes).equals(lock.subarray(1))) return false;
    if (w.p.hash && !sha256(w.secret).equals(w.p.hash)) return false; // hash lock: wrong secret
    let o = w.o;
    if (witness[o++] !== w.p.m) return false;
    if (witness.length !== o + w.p.m * 65) return false;
    let last = -1;
    for (let k = 0; k < w.p.m; k++, o += 65) {
      const idx = witness[o];
      if (idx <= last || idx >= w.p.n) return false; // increasing indexes ⇒ different keys
      last = idx;
      if (!schnorrVerify(w.p.keys[idx], msg, witness.subarray(o + 1, o + 65))) return false;
    }
    return true;
  } catch {
    return false;
  }
}
