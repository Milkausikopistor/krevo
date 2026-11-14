// Troca atômica Krevo ⇄ Bitcoin — sem corretora e sem confiar na outra parte.
//
// Duas pessoas: quem INICIA (cria o segredo) e quem PARTICIPA.
//   1. o iniciador cria a oferta (código krx1…) com H = SHA-256(segredo); o segredo fica com ele
//   2. o participante aceita (código krx1… de aceite) — ainda nenhum dinheiro se move
//   3. o iniciador trava o que vende num contrato HTLC (prazo LONGO)
//   4. o participante confere na rede e trava o que vende noutro HTLC com o MESMO H (prazo CURTO)
//   5. o iniciador resgata o contrato do participante — e, ao resgatar, PUBLICA o segredo
//   6. o participante lê o segredo na rede e resgata o contrato do iniciador
// Se alguém sumir no meio, cada um pega de volta o que travou depois do próprio prazo. O prazo
// do participante é menor, para que ele sempre tenha tempo de usar o segredo revelado.
//
// Contratos:
//   Krevo:   política v3 com 2 caminhos — [resgate: chave de quem recebe + segredo]
//            ou [reembolso: chave de quem travou, depois de N blocos] (src/consensus/policy.js)
//   Bitcoin: script P2WSH com OP_SHA256 + OP_CHECKLOCKTIMEVERIFY (src/btc/script.js)
// As chaves (Krevo e Bitcoin) e o segredo de cada troca vêm da frase de 24 palavras.

import { Writer, Reader, toHex, fromHex } from '../util/bytes.js';
import { encode as bech32mEncode, decode as bech32mDecode } from '../util/bech32m.js';
import { H } from '../crypto/hash.js';
import { hashToScalar, mulG, Point } from '../crypto/secp256k1.js';
import { schnorrSign } from '../crypto/schnorr.js';
import { encodePolicyPaths, multisigLock, encodeWitness, parseWitnessPath, sha256 } from '../consensus/policy.js';
import { Transaction, parseOutpointKey } from '../consensus/tx.js';
import { encodeAddress } from '../address.js';
import { formatKRV } from '../params.js';
import { buildTransaction } from './builder.js';
import { btcNetwork, decodeBtcAddress } from '../btc/address.js';
import { btcHtlc, spendBtcHtlc, findSecretInWitnesses, DUST } from '../btc/htlc.js';
import { Esplora, defaultBtcApi } from '../btc/esplora.js';
import { BitcoinCore } from '../btc/core.js';

const VERSION = 1, MSG_OFFER = 1, MSG_ACCEPT = 2;
const DIRS = ['krv', 'btc'];                       // o que o INICIADOR vende
const BTC_NETS = ['mainnet', 'testnet', 'signet', 'regtest'];
export const DEFAULT_INITIATOR_WINDOW = 48 * 3600;
export const DEFAULT_PARTICIPANT_WINDOW = 24 * 3600;
const MIN_BTC = 10_000n;

// ------------------------------------------------------------------ valores BTC
const SAT = 100_000_000n;
export function formatBTC(sats) {
  sats = BigInt(sats);
  const whole = sats / SAT, frac = (sats % SAT).toString().padStart(8, '0').replace(/0+$/, '');
  return whole.toLocaleString('pt-BR') + (frac ? ',' + frac : '') + ' BTC';
}
const btcDecimal = (sats) => { const f = (sats % SAT).toString().padStart(8, '0').replace(/0+$/, ''); return `${sats / SAT}${f ? '.' + f : ''}`; };
export function parseBTC(str) {
  const s = String(str).trim().replace(',', '.');
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error(`valor em BTC inválido: ${str}`);
  const [w, f = ''] = s.split('.');
  return BigInt(w) * SAT + BigInt(f.padEnd(8, '0'));
}
export function formatDuration(sec) {
  sec = Math.round(sec);
  if (sec < 0) return 'já passou';
  if (sec < 120) return `${sec} s`;
  if (sec < 7200) return `${Math.round(sec / 60)} min`;
  if (sec < 172_800) return `${(sec / 3600).toFixed(1).replace('.', ',')} h`;
  return `${(sec / 86400).toFixed(1).replace('.', ',')} dias`;
}

// --------------------------------------------------------------- mensagens krx1…
function encodeOffer(o) {
  const w = new Writer();
  w.u8(VERSION); w.u8(MSG_OFFER); w.u8(DIRS.indexOf(o.dir)); w.u8(BTC_NETS.indexOf(o.btcNet));
  w.u64(o.krv); w.u64(o.btc); w.bytes(o.hash, 32); w.bytes(o.iKrv, 33); w.bytes(o.iBtc, 33);
  w.u64(o.iWindow); w.u64(o.pWindow); w.u64(o.created);
  return w.done();
}
function decodeOffer(b) {
  const r = new Reader(b);
  if (r.u8() !== VERSION || r.u8() !== MSG_OFFER) throw new Error('não é uma oferta de troca');
  const dir = DIRS[r.u8()], btcNet = BTC_NETS[r.u8()];
  if (!dir || !btcNet) throw new Error('oferta de troca inválida');
  const o = {
    dir, btcNet, krv: r.u64(), btc: r.u64(), hash: r.bytes(32), iKrv: r.bytes(33), iBtc: r.bytes(33),
    iWindow: Number(r.u64()), pWindow: Number(r.u64()), created: Number(r.u64()),
  };
  r.end();
  Point.fromBytes(o.iKrv); Point.fromBytes(o.iBtc);
  validateTerms(o);
  return o;
}
function encodeAccept(a) {
  const w = new Writer();
  w.u8(VERSION); w.u8(MSG_ACCEPT); w.bytes(a.offerHash, 32); w.bytes(a.pKrv, 33); w.bytes(a.pBtc, 33); w.u64(a.accepted);
  return w.done();
}
function decodeAccept(b) {
  const r = new Reader(b);
  if (r.u8() !== VERSION || r.u8() !== MSG_ACCEPT) throw new Error('não é um aceite de troca');
  const a = { offerHash: r.bytes(32), pKrv: r.bytes(33), pBtc: r.bytes(33), accepted: Number(r.u64()) };
  r.end();
  Point.fromBytes(a.pKrv); Point.fromBytes(a.pBtc);
  return a;
}
const offerHash = (bytes) => H('swap/offer', bytes);
const swapId = (bytes) => toHex(offerHash(bytes)).slice(0, 12);

export function decodeSwapCode(params, code) {
  const { hrp, bytes } = bech32mDecode(String(code).trim());
  if (hrp !== params.hrp.x) throw new Error(`código de troca de outra rede (prefixo ${hrp}, esperado ${params.hrp.x})`);
  if (bytes[1] === MSG_OFFER) return { kind: 'offer', bytes, offer: decodeOffer(bytes) };
  if (bytes[1] === MSG_ACCEPT) return { kind: 'accept', bytes, accept: decodeAccept(bytes) };
  throw new Error('código de troca desconhecido');
}

function validateTerms(o) {
  if (o.krv <= 0n) throw new Error('valor em KRV precisa ser positivo');
  if (o.btc < MIN_BTC) throw new Error(`valor em BTC pequeno demais (mínimo ${formatBTC(MIN_BTC)}, para cobrir as taxas do Bitcoin)`);
  if (!(o.pWindow > 0) || !(o.iWindow >= o.pWindow * 1.5)) throw new Error('o prazo do iniciador precisa ser pelo menos 1,5× o do participante');
}

/** Krevo mainnet ↔ Bitcoin mainnet; redes de teste da Krevo ↔ só Bitcoin de teste. */
export function checkPairing(params, btcNet) {
  if ((params.name === 'mainnet') !== (btcNet === 'mainnet')) {
    throw new Error(params.name === 'mainnet'
      ? 'na Krevo mainnet a troca precisa ser com Bitcoin mainnet'
      : `a rede Krevo "${params.name}" é de teste: só troca com Bitcoin de teste (testnet, signet ou regtest) — nunca com bitcoins de verdade`);
  }
}

// ------------------------------------------------------------------ contratos
export function swapKeys(w, index) {
  // chaves no cofre; o segredo da troca (pré-imagem do hash) pode sair: ele é revelado no resgate
  const v = w.keys.vault;
  const krv = v.signer({ swapKrv: index }), btc = v.signer({ swapBtc: index });
  return { krv, krvPub: krv.P.toBytes(), btc, btcPub: btc.P.toBytes(), secret: v.swapSecret(index) };
}

/** Os dois contratos da troca. initiatorLock = o que o iniciador trava; participantLock = idem. */
export function swapContracts(params, offer, accept) {
  const net = btcNetwork(offer.btcNet);
  const krevo = (claimPub, refundPub, windowSec) => {
    const delay = Math.ceil(windowSec * params.bps);
    const policy = encodePolicyPaths([{ m: 1, keys: [claimPub], delay: 0, hash: offer.hash }, { m: 1, keys: [refundPub], delay }]);
    const lock = multisigLock(policy);
    return { chain: 'krevo', policy, lock, address: encodeAddress(params, lock), delay, window: windowSec, amount: offer.krv };
  };
  const btc = (claimPub, refundPub, locktime) => ({ chain: 'btc', ...btcHtlc(net, { hash: offer.hash, claimPub, refundPub, locktime }), amount: offer.btc });
  if (offer.dir === 'krv') {
    return { net, initiatorLock: krevo(accept.pKrv, offer.iKrv, offer.iWindow), participantLock: btc(offer.iBtc, accept.pBtc, accept.accepted + offer.pWindow) };
  }
  return { net, initiatorLock: btc(accept.pBtc, offer.iBtc, offer.created + offer.iWindow), participantLock: krevo(offer.iKrv, accept.pKrv, offer.pWindow) };
}

const fmtAmount = (c) => (c.chain === 'krevo' ? formatKRV(c.amount) : formatBTC(c.amount));
const nowS = (w) => (w.clock ? w.clock() : Math.floor(Date.now() / 1000));

// ------------------------------------------------------------------ registro na carteira
function store(w) { return (w.data.swaps ??= {}); }
export function getSwap(w, id) {
  const all = store(w);
  const s = all[id] ?? Object.values(all).find((x) => x.id.startsWith(id));
  if (!s) throw new Error(`troca ${id} não encontrada nesta carteira`);
  return s;
}
function parts(s) {
  const offer = decodeOffer(fromHex(s.offer));
  const accept = s.accept ? decodeAccept(fromHex(s.accept)) : null;
  return { offer, accept };
}
// Fonte de dados do Bitcoin: o seu Bitcoin Core (btcRpc) ou uma API Esplora (btcApi / mempool.space).
// Um cliente por processo e por troca: o Bitcoin Core só reescaneia uma vez.
const btcClients = new Map();
async function btcClient(s, offer) {
  const key = s.btcRpc ? `rpc:${s.btcRpc}:${offer.created}` : `api:${s.btcApi || defaultBtcApi(offer.btcNet)}`;
  let c = btcClients.get(key);
  if (!c) {
    if (s.btcRpc) {
      c = new BitcoinCore(s.btcRpc, { since: offer.created - 7200 });
      await c.assertNetwork(offer.btcNet);
    } else c = new Esplora(s.btcApi || defaultBtcApi(offer.btcNet));
    btcClients.set(key, c);
  }
  return c;
}

/**
 * Cria uma oferta. sell: 'krv' (vendo KRV, recebo BTC) ou 'btc' (vendo BTC, recebo KRV).
 * btcPayout: SEU endereço Bitcoin — onde você recebe os BTC, ou para onde volta o reembolso.
 */
export function createOffer(w, { sell, krv, btc, btcNet = 'regtest', btcPayout, iWindow = DEFAULT_INITIATOR_WINDOW, pWindow = DEFAULT_PARTICIPANT_WINDOW, btcApi = null, btcRpc = null }) {
  if (!DIRS.includes(sell)) throw new Error('informe o que você vende: krv ou btc');
  checkPairing(w.params, btcNet);
  const net = btcNetwork(btcNet);
  if (!btcPayout) throw new Error('informe o seu endereço Bitcoin (para receber ou para o reembolso)');
  decodeBtcAddress(net, btcPayout);
  const index = (w.data.swapNext = (w.data.swapNext ?? 0) + 1) - 1;
  const k = swapKeys(w, index);
  const offer = { dir: sell, btcNet: net.name, krv: BigInt(krv), btc: BigInt(btc), hash: sha256(k.secret), iKrv: k.krvPub, iBtc: k.btcPub, iWindow: Math.round(iWindow), pWindow: Math.round(pWindow), created: nowS(w) };
  validateTerms(offer);
  const bytes = encodeOffer(offer);
  const id = swapId(bytes);
  store(w)[id] = { id, role: 'initiator', index, offer: toHex(bytes), accept: null, btcPayout, btcApi, btcRpc, secret: toHex(k.secret), created: Date.now() };
  w.save();
  return { id, code: bech32mEncode(w.params.hrp.x, bytes), offer };
}

/** Lado do participante: aceita uma oferta (nada se move ainda). Retorna o código de aceite. */
export function acceptOffer(w, code, { btcPayout, btcApi = null, btcRpc = null }) {
  const d = decodeSwapCode(w.params, code);
  if (d.kind !== 'offer') throw new Error('isto não é uma oferta (é um aceite?)');
  const offer = d.offer;
  checkPairing(w.params, offer.btcNet);
  const net = btcNetwork(offer.btcNet);
  if (!btcPayout) throw new Error('informe o seu endereço Bitcoin (para receber ou para o reembolso)');
  decodeBtcAddress(net, btcPayout);
  const id = swapId(d.bytes);
  if (store(w)[id]) throw new Error('esta troca já está registrada nesta carteira');
  const age = nowS(w) - offer.created;
  if (offer.dir === 'btc' && offer.iWindow - age < offer.pWindow * 1.25) throw new Error('esta oferta é antiga demais: o prazo do iniciador já está curto');
  const index = (w.data.swapNext = (w.data.swapNext ?? 0) + 1) - 1;
  const k = swapKeys(w, index);
  const accept = { offerHash: offerHash(d.bytes), pKrv: k.krvPub, pBtc: k.btcPub, accepted: nowS(w) };
  const bytes = encodeAccept(accept);
  store(w)[id] = { id, role: 'participant', index, offer: toHex(d.bytes), accept: toHex(bytes), btcPayout, btcApi, btcRpc, secret: null, created: Date.now() };
  w.save();
  return { id, code: bech32mEncode(w.params.hrp.x, bytes), offer };
}

/** Lado do iniciador: registra o aceite recebido. */
export function importAcceptance(w, code) {
  const d = decodeSwapCode(w.params, code);
  if (d.kind !== 'accept') throw new Error('isto não é um aceite de troca');
  const s = Object.values(store(w)).find((x) => x.role === 'initiator' && offerHash(fromHex(x.offer)).equals(d.accept.offerHash));
  if (!s) throw new Error('este aceite não corresponde a nenhuma oferta criada por esta carteira');
  if (s.accept && s.accept !== toHex(d.bytes)) throw new Error('esta oferta já foi aceita por outra pessoa');
  const { offer } = parts(s);
  if (d.accept.accepted < offer.created - 600) throw new Error('aceite com data anterior à oferta');
  s.accept = toHex(d.bytes);
  w.save();
  return s;
}

/** Resumo legível dos termos, do ponto de vista desta carteira. */
export function describeSwap(w, s) {
  const { offer, accept } = parts(s);
  const iAmInit = s.role === 'initiator';
  const krvGive = (offer.dir === 'krv') === iAmInit;
  const out = {
    id: s.id, role: iAmInit ? 'iniciador' : 'participante', btcNet: offer.btcNet,
    give: krvGive ? formatKRV(offer.krv) : formatBTC(offer.btc), receive: krvGive ? formatBTC(offer.btc) : formatKRV(offer.krv),
    windows: { initiator: offer.iWindow, participant: offer.pWindow }, accepted: !!accept, btcPayout: s.btcPayout,
    price: `${(Number(offer.btc) / Number(offer.krv)).toPrecision(4).replace('.', ',')} BTC por KRV`,
  };
  if (accept) {
    const c = swapContracts(w.params, offer, accept);
    out.myContract = iAmInit ? c.initiatorLock : c.participantLock;
    out.theirContract = iAmInit ? c.participantLock : c.initiatorLock;
  }
  return out;
}

export function listSwaps(w) { return Object.values(store(w)).map((s) => ({ ...describeSwap(w, s), status: s.status ?? 'em andamento' })); }

// ------------------------------------------------------------------ observar as redes
async function observeKrevo(w, c, hash) {
  const r = await w.call('getutxos', { locks: [toHex(c.lock)] });
  const daa = r.daaScore;
  const amount = r.utxos.reduce((a, u) => a + BigInt(u.amount), 0n);
  const free = r.utxos.filter((u) => !u.inMempool);
  const hist = await w.call('getaddresshistory', { address: c.address });
  const st = { chain: 'krevo', address: c.address, amount, funded: amount >= c.amount, utxos: free, spending: free.length < r.utxos.length };
  for (const txid of hist.txids) {
    const t = await w.call('gettransaction', { txid });
    if (t.status !== 'accepted') continue;
    const tx = Transaction.deserialize(fromHex(t.tx));
    for (const i of tx.tIn) {
      const pw = parseWitnessPath(i.sig);
      if (!pw || !pw.pol.bytes.equals(c.policy)) continue;
      if (pw.path === 0 && pw.secret && sha256(pw.secret).equals(hash)) { st.claimed = true; st.claimTxid = txid; st.secret = pw.secret; }
      if (pw.path === 1) { st.refunded = true; st.refundTxid = txid; }
    }
  }
  if (r.utxos.length) {
    const minDaa = Math.min(...r.utxos.map((u) => u.daa)), maxDaa = Math.max(...r.utxos.map((u) => u.daa));
    st.timeLeft = (minDaa + c.delay - daa) / w.params.bps;
    st.refundable = free.length > 0 && daa - maxDaa >= c.delay;
  } else { st.timeLeft = null; st.refundable = false; }
  return st;
}

async function observeBtc(btc, c, hash, minConf, now) {
  const [tip, utxos, txs] = await Promise.all([btc.tip(), btc.utxos(c.address), btc.txs(c.address)]);
  const confs = (u) => (u.status?.confirmed ? tip.height - u.status.block_height + 1 : 0);
  const confirmed = utxos.filter((u) => confs(u) >= minConf);
  const sum = (a) => a.reduce((x, u) => x + BigInt(u.value), 0n);
  const st = {
    chain: 'btc', address: c.address, amount: sum(utxos), amountConfirmed: sum(confirmed),
    funded: sum(confirmed) >= c.amount, seen: sum(utxos) >= c.amount, utxos: confirmed, allUtxos: utxos,
    timeLeft: c.locktime - Math.max(now, tip.time), refundable: utxos.length > 0 && tip.mtp > c.locktime, tip,
  };
  for (const t of txs) {
    for (const v of t.vin) {
      if (v.prevout?.scriptpubkey_address !== c.address) continue;
      const wit = (v.witness ?? []).map((x) => Buffer.from(x, 'hex'));
      const sec = findSecretInWitnesses([wit], hash);
      if (sec) { st.claimed = true; st.claimTxid = t.txid; st.secret = sec; }
      else if (wit.length === 3) { st.refunded = true; st.refundTxid = t.txid; }
    }
  }
  st.spending = false;
  return st;
}

// ------------------------------------------------------------------ gastar os contratos
async function spendContract(w, s, offer, c, st, keys, secret, feeRate) {
  if (c.chain === 'btc') {
    const btc = await btcClient(s, offer);
    const utxos = (secret ? st.utxos : st.allUtxos).map((u) => ({ txid: u.txid, vout: u.vout, value: u.value }));
    const r = spendBtcHtlc({ net: btcNetwork(offer.btcNet), htlc: c, utxos, to: s.btcPayout, feeRate: feeRate ?? await btc.feeRate(), key: keys.btc, secret });
    const txid = await btc.broadcast(r.hex);
    return { txid, amount: formatBTC(r.value), fee: formatBTC(r.fee) };
  }
  const path = secret ? 0 : 1;
  const tInputs = st.utxos.map((u) => ({ outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount), policy: c.policy, path }));
  const { tx, fee } = buildTransaction({ params: w.params, tInputs, sweep: { type: 't', lock: w._changeLock } });
  const witness = encodeWitness(c.policy, new Map([[0, keys.krv.sign(tx.sighash())]]), path, secret);
  tx.tIn.forEach((i) => { i.sig = witness; });
  tx.invalidate();
  const res = await w.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
  return { txid: res.txid, amount: formatKRV(tInputs.reduce((a, i) => a + i.amount, 0n) - fee), fee: formatKRV(fee) };
}

/**
 * Dá o próximo passo da troca (no máximo UMA ação por chamada) e diz o que está acontecendo.
 * Retorna { action, message, done, ... }. Ações: lock, pay-btc, claim, refund, abort, done, wait-*.
 * dryRun: só diz o que faria.
 */
export async function swapStep(w, id, { minConf = 1, feeRate, dryRun = false } = {}) {
  const s = getSwap(w, id);
  const { offer, accept } = parts(s);
  if (!accept) return { action: 'wait-accept', done: false, message: 'aguardando a outra parte aceitar — envie a ela o código da oferta (krx1…)' };
  const c = swapContracts(w.params, offer, accept);
  const keys = swapKeys(w, s.index);
  const iAmInit = s.role === 'initiator';
  const myC = iAmInit ? c.initiatorLock : c.participantLock;
  const theirC = iAmInit ? c.participantLock : c.initiatorLock;
  const now = nowS(w);
  const btcC = myC.chain === 'btc' ? myC : theirC, krvC = myC.chain === 'krevo' ? myC : theirC;
  const [bst, kst] = await Promise.all([observeBtc(await btcClient(s, offer), btcC, offer.hash, minConf, now), observeKrevo(w, krvC, offer.hash)]);
  const my = myC.chain === 'btc' ? bst : kst, their = theirC.chain === 'btc' ? bst : kst;
  const base = { my, their, myContract: myC, theirContract: theirC };
  const out = (action, message, done = false, extra = {}) => {
    if (done && !dryRun && s.status !== action) { s.status = action === 'abort' ? 'abandonada' : my.refunded ? 'reembolsada' : 'concluída'; w.save(); }
    return { ...base, action, message, done, ...extra };
  };

  // o participante descobre o segredo quando o iniciador resgata o contrato DELE
  if (!s.secret && my.secret) { s.secret = toHex(my.secret); if (!dryRun) w.save(); }
  const secret = s.secret ? fromHex(s.secret) : null;

  if (their.claimed) return out('done', `troca concluída: você recebeu ${fmtAmount(theirC)} (menos a taxa de rede do resgate)`, true);
  if (my.refunded && !my.funded) return out('done', 'troca cancelada: o que você travou voltou para você (reembolso)', true);

  // 1) resgatar o que a outra parte travou
  if (secret && their.funded && !their.claimed && !their.spending) {
    const claimMargin = offer.pWindow / 8;
    // o iniciador só revela o segredo se ainda houver folga antes do prazo do participante
    if (!iAmInit || (their.timeLeft !== null && their.timeLeft >= claimMargin)) {
      if (dryRun) return out('claim', `resgatar ${fmtAmount(theirC)}`);
      const r = await spendContract(w, s, offer, theirC, their, keys, secret, feeRate);
      s.claimTxid = r.txid; w.save();
      return out('claim', `resgate enviado: ${r.amount} (taxa ${r.fee}) — tx ${r.txid}${iAmInit ? '. O segredo agora está público; a outra parte vai usá-lo para resgatar.' : ''}`, false, { txid: r.txid });
    }
  }
  // 2) reembolso do que eu travei, depois do meu prazo
  if (my.refundable && !my.claimed && !my.spending) {
    if (dryRun) return out('refund', 'reembolsar o que você travou');
    const r = await spendContract(w, s, offer, myC, my, keys, null, feeRate);
    s.refundTxid = r.txid; w.save();
    return out('refund', `reembolso enviado: ${r.amount} (taxa ${r.fee}) — tx ${r.txid}`, false, { txid: r.txid });
  }
  // 3) travar a minha parte
  if (!my.funded && !my.claimed && !my.refunded) {
    if (!iAmInit) {
      if (!their.funded) return out('wait-their-lock', `aguardando o iniciador travar ${fmtAmount(theirC)}${theirC.chain === 'btc' ? ` (com ${minConf} confirmação(ões))` : ''} no contrato ${theirC.address}`);
      const myLeft = myC.chain === 'btc' ? myC.locktime - Math.max(now, bst.tip.time) : offer.pWindow;
      const margin = offer.pWindow / 4;
      if (their.timeLeft < myLeft + margin) {
        return out('abort', `o prazo do iniciador acaba em ${formatDuration(their.timeLeft)} — curto demais para você travar com segurança. Não trave nada: a troca termina aqui sem perdas para você.`, true);
      }
    }
    if (myC.chain === 'krevo') {
      if (s.lockTxid) return out('wait-my-lock', `aguardando a confirmação da sua trava (tx ${s.lockTxid})`);
      if (dryRun) return out('lock', `travar ${fmtAmount(myC)} no contrato ${myC.address}`);
      const r = await w.send({ to: myC.address, amount: myC.amount, from: 'auto' });
      s.lockTxid = r.txid; w.save();
      return out('lock', `travado ${fmtAmount(myC)} no contrato ${myC.address} (tx ${r.txid}, taxa ${formatKRV(r.fee)})`, false, { txid: r.txid });
    }
    const uri = `bitcoin:${myC.address}?amount=${btcDecimal(myC.amount)}`;
    return out('pay-btc', my.seen
      ? `pagamento visto em ${myC.address}; aguardando ${minConf} confirmação(ões) no Bitcoin`
      : `pague exatamente ${formatBTC(myC.amount)} para ${myC.address} usando a sua carteira Bitcoin (o QR abaixo já leva o valor)`,
    false, { uri, address: myC.address, amount: myC.amount, seen: my.seen });
  }
  // 4) esperar
  if (iAmInit) {
    if (!their.funded) {
      return out('wait-their-lock', `sua parte está travada. Aguardando o participante travar ${fmtAmount(theirC)}${theirC.chain === 'btc' ? ` (com ${minConf} confirmação(ões))` : ''}. Se ele não travar, seu reembolso libera em ${formatDuration(my.timeLeft ?? 0)}.`);
    }
    return out('wait-refund', `o prazo do participante acaba em ${formatDuration(their.timeLeft)}: por segurança o segredo NÃO será revelado. Seu reembolso libera em ${formatDuration(my.timeLeft ?? 0)}.`);
  }
  return out('wait-secret', `sua parte está travada. Aguardando o iniciador resgatar (isso revela o segredo). Se ele sumir, seu reembolso libera em ${formatDuration(my.timeLeft ?? 0)}.`);
}

export { DUST };
