// Verificação de "SPV" para carteiras leves: a carteira não confia no servidor.
//
// Para cada transação que lhe paga, ela pede uma prova de aceitação e confere sozinha:
//   1. o caminho de Merkle leva o txid até o acceptedIdMerkleRoot do cabeçalho do bloco que
//      aceitou a transação (o txid é o hash do conteúdo, que a carteira também recalcula);
//   2. esse cabeçalho e os N seguintes da cadeia selecionada têm prova de trabalho válida,
//      cada um aponta para o anterior como pai, e blue score/blue work só crescem;
//   3. a dificuldade de cada um não é muito menor que a maior já vista pela carteira
//      (impede um servidor de "minerar" cabeçalhos falsos baratos).
// Inventar um pagamento exigiria minerar N blocos com dificuldade real — caro de propósito.

import { Header, verifyMerkleProof } from '../consensus/block.js';
import { checkPow, calcWork } from '../consensus/pow.js';
import { Reader, fromHex } from '../util/bytes.js';

export function parseHeader(hex) {
  const r = new Reader(fromHex(hex));
  const h = Header.read(r);
  r.end();
  return h;
}

/** Confere a PoW de um cabeçalho e devolve o trabalho dele (para aprender a dificuldade atual). */
export function headerWork(hex) {
  const h = parseHeader(hex);
  if (!checkPow(h)) throw new Error('cabeçalho da ponta sem prova de trabalho válida');
  return { header: h, work: calcWork(h.bits) };
}

/**
 * Lança erro se a prova for inválida. minDepth: blocos exigidos por cima;
 * minWork: trabalho mínimo por bloco (BigInt). Retorna { block, depth, workOnTop, maxWork }.
 */
export function verifyAcceptanceProof(txid, proof, { minDepth, minWork = 0n }) {
  const hdrs = [proof.header, ...(proof.chain ?? [])].map(parseHeader);
  if (hdrs[0].hashHex !== proof.block) throw new Error('o cabeçalho não corresponde ao bloco informado');
  if (!verifyMerkleProof(fromHex(txid), proof.merkle, hdrs[0].acceptedIdMerkleRoot)) {
    throw new Error('caminho de Merkle inválido: esse bloco não aceitou a transação');
  }
  let workOnTop = 0n, maxWork = 0n;
  hdrs.forEach((h, i) => {
    if (!checkPow(h)) throw new Error('cabeçalho sem prova de trabalho válida');
    const w = calcWork(h.bits);
    if (w < minWork) throw new Error('dificuldade baixa demais para a rede (cabeçalho suspeito)');
    if (w > maxWork) maxWork = w;
    if (i > 0) {
      const prev = hdrs[i - 1];
      if (!h.parents.some((p) => p.equals(prev.hash))) throw new Error('cabeçalhos não encadeados');
      if (h.blueScore <= prev.blueScore || h.blueWork <= prev.blueWork) throw new Error('cadeia de cabeçalhos inconsistente');
      workOnTop += w;
    }
  });
  if (hdrs.length - 1 < minDepth) throw new Error(`só ${hdrs.length - 1} blocos por cima (exigidos ${minDepth})`);
  return { block: proof.block, depth: hdrs.length - 1, workOnTop, maxWork };
}
