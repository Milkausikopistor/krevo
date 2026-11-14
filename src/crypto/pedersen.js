// Compromissos de Pedersen: C = x·G + v·H
//   x = fator de cegamento (secreto), v = valor.
// H é gerado por hash ("nada na manga"): ninguém conhece log_G(H), então
// ninguém consegue abrir um compromisso para dois valores diferentes.
// Compromissos são homomórficos: C(v1,x1) + C(v2,x2) = C(v1+v2, x1+x2),
// o que permite provar que entradas = saídas + taxa sem revelar valores.

import { FixedBase, hashToPoint, mulG, modN, INF, Point } from './secp256k1.js';
import * as core from './wasm.js';

export const Hv = hashToPoint('pedersen/H', 'gerador de valor do Krevo');
const H_TABLE = new FixedBase(Hv);

// v·H no núcleo de tempo constante (valores e máscaras são segredos da carteira)
export function mulH(v) {
  if (!core.available()) return H_TABLE.mul(v);
  v = modN(v);
  if (v === 0n) return INF;
  const r = core.mulH(v);
  return Point.fromAffine(r[0], r[1]);
}
export const commit = (v, x) => mulG(x).add(mulH(v));
