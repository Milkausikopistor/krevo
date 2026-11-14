// Nomes legíveis: pagar para @padaria em vez de krs1qyp3h27…
//
// Registro na própria rede, sem autoridade, no estilo do Namecoin: cada nome é uma SAÍDA
// especial no conjunto UTXO. Quem pode gastar a saída é o dono do nome. Por isso
// reorganizações, o compromisso MuHash e a posse funcionam com a mesma maquinaria das moedas.
//
//   registro:      trava [0x05][tam][nome][vencimento u64][tam][trava do dono][destino]
//                  valor = depósito (≥ 0,01 KRV, volta ao dono quando ele libera o nome)
//   compromisso:   trava [0x06][H("name/commit", nome, sal, trava do dono)]
//
// Registrar exige duas transações:
//   1. COMPROMISSO — publica só um hash: ninguém sabe qual nome você quer;
//   2. REVELAÇÃO   — depois de ≥ nameCommitMin blocos, gasta o compromisso (revela nome e sal) e
//                    cria o registro. Quem vir a revelação e tentar copiar o nome chega tarde:
//                    o compromisso dele seria novo demais. É a proteção contra "furar a fila".
//
// Taxa anual por tamanho (nomes curtos são escassos): vai 100% para o Fundo de Segurança, ou
// seja, para os mineradores do futuro; não é queimada e não vai para nenhuma organização.
// Vence em 1 ano; há 30 dias de carência em que só o dono renova; depois disso o nome fica
// livre de novo. Alterar o destino ou transferir o nome não paga taxa.

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
/** Normaliza ("@Padaria" → "padaria") e valida; lança erro explicativo. */
export function checkName(s) {
  const n = normalizeName(s);
  if (!isValidName(n)) {
    throw new Error(`nome inválido "${s}": use de ${NAME_MIN} a ${NAME_MAX} caracteres entre a-z, 0-9 e hífen (sem acento, sem começar ou terminar com hífen e sem "--")`);
  }
  return n;
}

/** Taxa por período (1 ano): 3 letras, 4, 5, 6 ou mais. */
export function nameFee(params, name) {
  const f = params.nameFees;
  return name.length <= 3 ? f[0] : name.length === 4 ? f[1] : name.length === 5 ? f[2] : f[3];
}

export function encodeNameRecord({ name, expiry, owner, target }) {
  if (!isValidName(name)) throw new Error('nome inválido');
  const w = new Writer();
  w.u8(LOCK_NAME); w.u8(name.length); w.bytes(Buffer.from(name, 'ascii'));
  w.u64(expiry); w.u8(owner.length); w.bytes(owner); w.bytes(target);
  return w.done();
}

/** { name, expiry, owner (trava), target (dados de endereço) } — lança erro se malformado. */
export function parseNameRecord(lock) {
  const b = Buffer.from(lock);
  if (b[0] !== LOCK_NAME) throw new Error('não é um registro de nome');
  const r = new Reader(b);
  r.u8();
  const name = r.bytes(r.u8()).toString('ascii');
  if (!isValidName(name)) throw new Error('nome inválido no registro');
  const expiry = Number(r.u64());
  const owner = r.bytes(r.u8());
  const target = r.bytes(r.remaining);
  if (!owner.length || !target.length) throw new Error('registro de nome incompleto');
  return { name, expiry, owner, target };
}

/** Só o nome (rápido, para índices). */
export function nameOfLock(lock) {
  if (lock[0] !== LOCK_NAME || lock.length < 2 + lock[1]) return null;
  return Buffer.from(lock.subarray(2, 2 + lock[1])).toString('ascii');
}

export const nameCommitHash = (name, salt, owner) => H('name/commit', name, salt, owner);
export const nameCommitLock = (hash) => Buffer.concat([Buffer.from([LOCK_NAME_COMMIT]), hash]);

/** Início da testemunha de quem gasta um compromisso; a testemunha do dono vem logo depois. */
export function commitWitnessPrefix(name, salt, owner) {
  if (salt.length !== 32) throw new Error('sal precisa ter 32 bytes');
  return Buffer.concat([Buffer.from([COMMIT_WITNESS, name.length]), Buffer.from(name, 'ascii'), salt, Buffer.from([owner.length]), owner]);
}

/** { name, salt, owner, inner } ou null. */
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
