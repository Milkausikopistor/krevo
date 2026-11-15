// Human-readable names: pay @bakery instead of krs1qyp3h27…
//
// Registered on the network itself, with no authority, Namecoin-style: each name is a special
// OUTPUT in the UTXO set. Whoever can spend the output owns the name. That is why
// reorganizations, the MuHash commitment and ownership work with the same machinery as coins.
//
//   record:        lock [0x05][len][name][expiry u64][len][owner lock][destination]
//                  amount = deposit (≥ 0.01 KRV, returned to the owner when the name is released)
//   commitment:    lock [0x06][H("name/commit", name, salt, owner lock)]
//
// Registering requires two transactions:
//   1. COMMITMENT — publishes only a hash: nobody knows which name you want;
//   2. REVEAL     — after ≥ nameCommitMin blocks, spends the commitment (reveals name and salt) and
//                   creates the record. Whoever sees the reveal and tries to copy the name is too late:
//                   their commitment would be too recent. This is the protection against front-running.
//
// Yearly fee by length (short names are scarce): 100% goes to the Security Fund, that is, to
// future miners; it is not burned and does not go to any organization.
// It expires after 1 year; there is a 30-day grace period in which only the owner can renew;
// after that the name is free again. Changing the destination or transferring the name is free.

import { H } from '../crypto/hash.js';
import { Writer, Reader } from '../util/bytes.js';

export const LOCK_NAME = 0x05;
export const LOCK_NAME_COMMIT = 0x06;
export const COMMIT_WITNESS = 0xc1;
export const NAME_MIN = 3, NAME_MAX = 32;

export function normalizeName(s) {
  let n = String(s ?? '').trim().toLowerCase();
  if (n.startsWith('@')) n = n.slice(1);
  return n;
}
export function isValidName(n) {
  return typeof n === 'string' && n.length >= NAME_MIN && n.length <= NAME_MAX &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])$/.test(n) && !n.includes('--');
}
/** Normalizes ("@Bakery" → "bakery") and validates; throws an explanatory error. */
export function checkName(s) {
  const n = normalizeName(s);
  if (!isValidName(n)) {
    throw new Error(`invalid name "${s}": use ${NAME_MIN} to ${NAME_MAX} characters among a-z, 0-9 and hyphen (no accents, not starting or ending with a hyphen and no "--")`);
  }
  return n;
}

/** Fee per period (1 year): 3 letters, 4, 5, 6 or more. */
export function nameFee(params, name) {
  const f = params.nameFees;
  return name.length <= 3 ? f[0] : name.length === 4 ? f[1] : name.length === 5 ? f[2] : f[3];
}

export function encodeNameRecord({ name, expiry, owner, target }) {
  if (!isValidName(name)) throw new Error('invalid name');
  const w = new Writer();
  w.u8(LOCK_NAME); w.u8(name.length); w.bytes(Buffer.from(name, 'ascii'));
  w.u64(expiry); w.u8(owner.length); w.bytes(owner); w.bytes(target);
  return w.done();
}

/** { name, expiry, owner (lock), target (address data) } — throws if malformed. */
export function parseNameRecord(lock) {
  const b = Buffer.from(lock);
  if (b[0] !== LOCK_NAME) throw new Error('not a name record');
  const r = new Reader(b);
  r.u8();
  const name = r.bytes(r.u8()).toString('ascii');
  if (!isValidName(name)) throw new Error('invalid name in the record');
  const expiry = Number(r.u64());
  const owner = r.bytes(r.u8());
  const target = r.bytes(r.remaining);
  if (!owner.length || !target.length) throw new Error('incomplete name record');
  return { name, expiry, owner, target };
}

/** Just the name (fast, for indexes). */
export function nameOfLock(lock) {
  if (lock[0] !== LOCK_NAME || lock.length < 2 + lock[1]) return null;
  return Buffer.from(lock.subarray(2, 2 + lock[1])).toString('ascii');
}

export const nameCommitHash = (name, salt, owner) => H('name/commit', name, salt, owner);
export const nameCommitLock = (hash) => Buffer.concat([Buffer.from([LOCK_NAME_COMMIT]), hash]);

/** Start of the witness of whoever spends a commitment; the owner's witness comes right after. */
export function commitWitnessPrefix(name, salt, owner) {
  if (salt.length !== 32) throw new Error('the salt must have 32 bytes');
  return Buffer.concat([Buffer.from([COMMIT_WITNESS, name.length]), Buffer.from(name, 'ascii'), salt, Buffer.from([owner.length]), owner]);
}

/** { name, salt, owner, inner } or null. */
export function parseCommitWitness(w) {
  try {
    if (w[0] !== COMMIT_WITNESS) return null;
    const r = new Reader(w);
    r.u8();
    const name = r.bytes(r.u8()).toString('ascii');
    if (!isValidName(name)) return null;
    const salt = r.bytes(32);
    const owner = r.bytes(r.u8());
    const inner = r.bytes(r.remaining);
    return { name, salt, owner, inner };
  } catch { return null; }
}
