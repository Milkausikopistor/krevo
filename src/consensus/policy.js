// Políticas de gasto: multiassinatura M-de-N e caminhos com bloqueio por tempo (regra de consenso).
//
// O endereço guarda só o HASH da política (como o P2WSH do Bitcoin): as chaves e as
// regras só aparecem na rede quando o dinheiro é gasto.
//
// Versão 1 — um caminho, sem espera (multiassinatura simples):
//   política:   [0x01][M][N][N × chave (33)]
//   testemunha: política ‖ [M] ‖ M × ([índice][assinatura 64])
//
// Versão 2 — vários caminhos alternativos ("OU"), cada um com espera mínima:
//   política:   [0x02][C] ‖ C × ([M][N][espera u64][N × chave (33)])
//   testemunha: política ‖ [caminho] ‖ [M] ‖ M × ([índice][assinatura 64])
// A espera é RELATIVA: número de blocos (daaScore) desde que a saída foi criada.
// Exemplo de herança: caminho 0 = dono (1-de-1, sem espera); caminho 1 = herdeiros
// (1-de-2, espera de 1 ano). Se o dono movimentar o dinheiro, a saída nova começa a
// contagem do zero — é a "prova de vida".
//
// Versão 3 — como a 2, mas cada caminho pode exigir também um SEGREDO (trava de hash):
//   política:   [0x03][C] ‖ C × ([M][N][espera u64][tem hash: 0|1][SHA-256 (32), se tiver][N × chave])
//   testemunha: política ‖ [caminho] ‖ [segredo (32), se o caminho tiver hash] ‖ [M] ‖ M × ([índice][assinatura])
// O segredo precisa ter exatamente 32 bytes e SHA-256(segredo) = hash. É o mesmo hash do
// OP_SHA256 do Bitcoin: por isso a mesma trava serve para trocas atômicas Krevo ⇄ Bitcoin
// (quem resgata de um lado revela o segredo, que destrava o outro lado).
//
// Regras: M assinaturas Schnorr de chaves DIFERENTES do caminho escolhido (índices
// crescentes), sobre a mesma mensagem da transação, idade da saída ≥ espera e, se houver,
// o segredo certo. A ordem das chaves dentro de um caminho é canônica.

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
export const MAX_DELAY = 2 ** 40; // ~3.500 anos a 10 blocos/s
export const LOCK_MULTISIG = 0x03;

function canonicalKeys(m, pubkeys) {
  const keys = pubkeys.map((k) => (Buffer.isBuffer(k) ? k : k.toBytes()));
  const n = keys.length;
  if (!Number.isInteger(m) || m < 1 || m > n || n > MAX_POLICY_KEYS) throw new Error(`política inválida: ${m}-de-${n} (máximo ${MAX_POLICY_KEYS} chaves)`);
  keys.forEach((k) => Point.fromBytes(k)); // chaves válidas
  keys.sort(Buffer.compare);
  for (let i = 1; i < n; i++) if (keys[i].equals(keys[i - 1])) throw new Error('chave repetida na política');
  return keys;
}

/** Multiassinatura simples (versão 1). */
export function encodePolicy(m, pubkeys) {
  const keys = canonicalKeys(m, pubkeys);
  return Buffer.concat([Buffer.from([POLICY_VERSION, m, keys.length]), ...keys]);
}

/**
 * Vários caminhos: [{ m, keys, delay, hash? }]. Sem nenhum hash → versão 2 (formato da herança);
 * com algum caminho exigindo segredo (hash = SHA-256 de 32 bytes) → versão 3.
 */
export function encodePolicyPaths(paths) {
  if (!paths.length || paths.length > MAX_PATHS) throw new Error(`a política precisa de 1 a ${MAX_PATHS} caminhos`);
  const v3 = paths.some((p) => p.hash);
  const parts = [Buffer.from([v3 ? POLICY_VERSION_HASHLOCK : POLICY_VERSION_PATHS, paths.length])];
  for (const p of paths) {
    const delay = Number(p.delay ?? 0);
    if (!Number.isInteger(delay) || delay < 0 || delay > MAX_DELAY) throw new Error('espera inválida');
    const keys = canonicalKeys(p.m, p.keys);
    parts.push(Buffer.from([p.m, keys.length]), u64le(delay));
    if (v3) {
      if (p.hash && (!Buffer.isBuffer(p.hash) || p.hash.length !== 32)) throw new Error('hash da trava precisa ter 32 bytes');
      parts.push(p.hash ? Buffer.concat([Buffer.from([1]), p.hash]) : Buffer.from([0]));
    }
    parts.push(...keys);
  }
  return Buffer.concat(parts);
}

function readKeys(buf, o, n) {
  if (buf.length < o + 33 * n) throw new Error('política truncada');
  const keys = [];
  for (let i = 0; i < n; i++) {
    const k = buf.subarray(o + 33 * i, o + 33 * (i + 1));
    if (i > 0 && Buffer.compare(buf.subarray(o + 33 * (i - 1), o + 33 * i), k) >= 0) throw new Error('chaves fora da ordem canônica');
    keys.push(Point.fromBytes(k));
  }
  return keys;
}

/**
 * Lê uma política do início de `buf`.
 * Retorna { version, paths:[{m, n, keys, delay}], bytes, m, n, keys } (m/n/keys = caminho 0).
 */
export function parsePolicy(buf) {
  const ver = buf[0];
  const paths = [];
  let o;
  if (ver === POLICY_VERSION) {
    const m = buf[1], n = buf[2];
    if (m < 1 || m > n || n > MAX_POLICY_KEYS) throw new Error('política inválida');
    paths.push({ m, n, keys: readKeys(buf, 3, n), delay: 0 });
    o = 3 + 33 * n;
  } else if (ver === POLICY_VERSION_PATHS || ver === POLICY_VERSION_HASHLOCK) {
    const c = buf[1];
    if (!c || c > MAX_PATHS) throw new Error('número de caminhos inválido');
    o = 2;
    for (let i = 0; i < c; i++) {
      if (buf.length < o + 10) throw new Error('política truncada');
      const m = buf[o], n = buf[o + 1];
      const delayBig = buf.readBigUInt64LE(o + 2);
      if (m < 1 || m > n || n > MAX_POLICY_KEYS || delayBig > BigInt(MAX_DELAY)) throw new Error('política inválida');
      o += 10;
      let hash = null;
      if (ver === POLICY_VERSION_HASHLOCK) {
        if (buf.length < o + 1) throw new Error('política truncada');
        const flag = buf[o++];
        if (flag > 1) throw new Error('política inválida');
        if (flag) {
          if (buf.length < o + 32) throw new Error('política truncada');
          hash = Buffer.from(buf.subarray(o, o + 32));
          o += 32;
        }
      }
      paths.push({ m, n, keys: readKeys(buf, o, n), delay: Number(delayBig), hash });
      o += 33 * n;
    }
    if (ver === POLICY_VERSION_HASHLOCK && !paths.some((p) => p.hash)) throw new Error('política v3 sem trava de hash');
  } else throw new Error('versão de política desconhecida');
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
 * Monta a testemunha (Map índice → assinatura) para o caminho escolhido; usa as M primeiras.
 * secret: o segredo de 32 bytes, se o caminho tiver trava de hash.
 */
export function encodeWitness(policyBytes, sigs, path = 0, secret = null) {
  const pol = parsePolicy(policyBytes);
  const p = pol.paths[path];
  if (!p) throw new Error('caminho inexistente na política');
  const chosen = [...sigs.entries()].sort((a, b) => a[0] - b[0]).slice(0, p.m);
  if (chosen.length < p.m) throw new Error(`faltam assinaturas: ${chosen.length} de ${p.m}`);
  let pre = Buffer.alloc(0);
  if (p.hash) {
    if (!secret || secret.length !== SECRET_SIZE || !sha256(secret).equals(p.hash)) throw new Error('segredo ausente ou errado para este caminho');
    pre = Buffer.from(secret);
  }
  const head = hasPathByte(pol.version) ? Buffer.concat([Buffer.from([path]), pre, Buffer.from([p.m])]) : Buffer.from([p.m]);
  return Buffer.concat([pol.bytes, head, ...chosen.flatMap(([i, s]) => [Buffer.from([i]), s])]);
}

/**
 * Lê política + caminho (+ segredo revelado, se houver) da testemunha, sem verificar
 * assinaturas. null se malformada. { pol, path, p, secret, o }
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

/** Espera (em blocos) exigida pelo caminho usado na testemunha; null se malformada. */
export function witnessDelay(witness) {
  const w = parseWitnessPath(witness);
  return w ? w.p.delay : null;
}

/** Regra de consenso: a testemunha satisfaz a trava para a mensagem? (a espera é checada à parte) */
export function verifyMultisigWitness(lock, witness, msg) {
  try {
    if (lock.length !== 33 || lock[0] !== LOCK_MULTISIG) return false;
    const w = parseWitnessPath(witness);
    if (!w || !policyHash(w.pol.bytes).equals(lock.subarray(1))) return false;
    if (w.p.hash && !sha256(w.secret).equals(w.p.hash)) return false; // trava de hash: segredo errado
    let o = w.o;
    if (witness[o++] !== w.p.m) return false;
    if (witness.length !== o + w.p.m * 65) return false;
    let last = -1;
    for (let k = 0; k < w.p.m; k++, o += 65) {
      const idx = witness[o];
      if (idx <= last || idx >= w.p.n) return false; // índices crescentes ⇒ chaves diferentes
      last = idx;
      if (!schnorrVerify(w.p.keys[idx], msg, witness.subarray(o + 1, o + 65))) return false;
    }
    return true;
  } catch {
    return false;
  }
}
