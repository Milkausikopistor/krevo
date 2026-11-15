// Krevo ⇄ Bitcoin atomic swap — no exchange and no need to trust the other party.
//
// Two people: the INITIATOR (creates the secret) and the PARTICIPANT.
//   1. the initiator creates the offer (code krx1…) with H = SHA-256(secret); the secret stays with them
//   2. the participant accepts (acceptance code krx1…) — no money moves yet
//   3. the initiator locks what they sell in an HTLC contract (LONG deadline)
//   4. the participant checks on the network and locks what they sell in another HTLC with the SAME H (SHORT deadline)
//   5. the initiator claims the participant's contract — and, by claiming, PUBLISHES the secret
//   6. the participant reads the secret on the network and claims the initiator's contract
// If someone disappears halfway, each one takes back what they locked after their own deadline.
// The participant's deadline is shorter, so they always have time to use the revealed secret.
//
// Contracts:
//   Krevo:   v3 policy with 2 paths — [claim: recipient's key + secret]
//            or [refund: key of whoever locked, after N blocks] (src/consensus/policy.js)
//   Bitcoin: P2WSH script with OP_SHA256 + OP_CHECKLOCKTIMEVERIFY (src/btc/script.js)
// The keys (Krevo and Bitcoin) and the secret of each swap come from the 24-word phrase.

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
const DIRS = ['krv', 'btc'];                       // what the INITIATOR sells
const BTC_NETS = ['mainnet', 'testnet', 'signet', 'regtest'];
export const DEFAULT_INITIATOR_WINDOW = 48 * 3600;
export const DEFAULT_PARTICIPANT_WINDOW = 24 * 3600;
const MIN_BTC = 10_000n;

// ------------------------------------------------------------------ BTC amounts
const SAT = 100_000_000n;
export function formatBTC(sats) {
  sats = BigInt(sats);
  const whole = sats / SAT, frac = (sats % SAT).toString().padStart(8, '0').replace(/0+$/, '');
  return whole.toLocaleString('pt-BR') + (frac ? ',' + frac : '') + ' BTC';
}
const btcDecimal = (sats) => { const f = (sats % SAT).toString().padStart(8, '0').replace(/0+$/, ''); return `${sats / SAT}${f ? '.' + f : ''}`; };
export function parseBTC(str) {
  const s = String(str).trim().replace(',', '.');
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error(`invalid BTC amount: ${str}`);
  const [w, f = ''] = s.split('.');
  return BigInt(w) * SAT + BigInt(f.padEnd(8, '0'));
}
export function formatDuration(sec) {
  sec = Math.round(sec);
  if (sec < 0) return 'already passed';
  if (sec < 120) return `${sec} s`;
  if (sec < 7200) return `${Math.round(sec / 60)} min`;
  if (sec < 172_800) return `${(sec / 3600).toFixed(1).replace('.', ',')} h`;
  return `${(sec / 86400).toFixed(1).replace('.', ',')} dias`;
}

// --------------------------------------------------------------- krx1… messages
function encodeOffer(o) {
  const w = new Writer();
  w.u8(VERSION); w.u8(MSG_OFFER); w.u8(DIRS.indexOf(o.dir)); w.u8(BTC_NETS.indexOf(o.btcNet));
  w.u64(o.krv); w.u64(o.btc); w.bytes(o.hash, 32); w.bytes(o.iKrv, 33); w.bytes(o.iBtc, 33);
  w.u64(o.iWindow); w.u64(o.pWindow); w.u64(o.created);
  return w.done();
}
function decodeOffer(b) {
  const r = new Reader(b);
  if (r.u8() !== VERSION || r.u8() !== MSG_OFFER) throw new Error('not a swap offer');
  const dir = DIRS[r.u8()], btcNet = BTC_NETS[r.u8()];
  if (!dir || !btcNet) throw new Error('invalid swap offer');
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
  if (r.u8() !== VERSION || r.u8() !== MSG_ACCEPT) throw new Error('not a swap acceptance');
  const a = { offerHash: r.bytes(32), pKrv: r.bytes(33), pBtc: r.bytes(33), accepted: Number(r.u64()) };
  r.end();
  Point.fromBytes(a.pKrv); Point.fromBytes(a.pBtc);
  return a;
}
const offerHash = (bytes) => H('swap/offer', bytes);
const swapId = (bytes) => toHex(offerHash(bytes)).slice(0, 12);

export function decodeSwapCode(params, code) {
  const { hrp, bytes } = bech32mDecode(String(code).trim());
  if (hrp !== params.hrp.x) throw new Error(`swap code from another network (prefix ${hrp}, expected ${params.hrp.x})`);
  if (bytes[1] === MSG_OFFER) return { kind: 'offer', bytes, offer: decodeOffer(bytes) };
  if (bytes[1] === MSG_ACCEPT) return { kind: 'accept', bytes, accept: decodeAccept(bytes) };
  throw new Error('unknown swap code');
}

function validateTerms(o) {
  if (o.krv <= 0n) throw new Error('the KRV amount must be positive');
  if (o.btc < MIN_BTC) throw new Error(`BTC amount too small (minimum ${formatBTC(MIN_BTC)}, to cover Bitcoin fees)`);
  if (!(o.pWindow > 0) || !(o.iWindow >= o.pWindow * 1.5)) throw new Error('the initiator\'s deadline must be at least 1.5× the participant\'s');
}

/** Krevo mainnet ↔ Bitcoin mainnet; Krevo test networks ↔ test Bitcoin only. */
export function checkPairing(params, btcNet) {
  if ((params.name === 'mainnet') !== (btcNet === 'mainnet')) {
    throw new Error(params.name === 'mainnet'
      ? 'on Krevo mainnet the swap must be with Bitcoin mainnet'
      : `the Krevo "${params.name}" network is a test network: it only swaps with test Bitcoin (testnet, signet or regtest) — never with real bitcoins`);
  }
}

// ------------------------------------------------------------------ contracts
export function swapKeys(w, index) {
  // keys in the vault; the swap secret (hash preimage) may leave: it is revealed when claiming
  const v = w.keys.vault;
  const krv = v.signer({ swapKrv: index }), btc = v.signer({ swapBtc: index });
  return { krv, krvPub: krv.P.toBytes(), btc, btcPub: btc.P.toBytes(), secret: v.swapSecret(index) };
}

/** The swap's two contracts. initiatorLock = what the initiator locks; participantLock = likewise. */
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

// ------------------------------------------------------------------ record in the wallet
function store(w) { return (w.data.swaps ??= {}); }
export function getSwap(w, id) {
  const all = store(w);
  const s = all[id] ?? Object.values(all).find((x) => x.id.startsWith(id));
  if (!s) throw new Error(`swap ${id} not found in this wallet`);
  return s;
}
function parts(s) {
  const offer = decodeOffer(fromHex(s.offer));
  const accept = s.accept ? decodeAccept(fromHex(s.accept)) : null;
  return { offer, accept };
}
// Bitcoin data source: your Bitcoin Core (btcRpc) or an Esplora API (btcApi / mempool.space).
// One client per process and per swap: Bitcoin Core only rescans once.
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
 * Creates an offer. sell: 'krv' (I sell KRV, receive BTC) or 'btc' (I sell BTC, receive KRV).
 * btcPayout: YOUR Bitcoin address — where you receive the BTC, or where the refund goes back.
 */
export function createOffer(w, { sell, krv, btc, btcNet = 'regtest', btcPayout, iWindow = DEFAULT_INITIATOR_WINDOW, pWindow = DEFAULT_PARTICIPANT_WINDOW, btcApi = null, btcRpc = null }) {
  if (!DIRS.includes(sell)) throw new Error('enter what you sell: krv or btc');
  checkPairing(w.params, btcNet);
  const net = btcNetwork(btcNet);
  if (!btcPayout) throw new Error('enter your Bitcoin address (to receive, or for the refund)');
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

/** Participant's side: accepts an offer (nothing moves yet). Returns the acceptance code. */
export function acceptOffer(w, code, { btcPayout, btcApi = null, btcRpc = null }) {
  const d = decodeSwapCode(w.params, code);
  if (d.kind !== 'offer') throw new Error('this is not an offer (is it an acceptance?)');
  const offer = d.offer;
  checkPairing(w.params, offer.btcNet);
  const net = btcNetwork(offer.btcNet);
  if (!btcPayout) throw new Error('enter your Bitcoin address (to receive, or for the refund)');
  decodeBtcAddress(net, btcPayout);
  const id = swapId(d.bytes);
  if (store(w)[id]) throw new Error('this swap is already registered in this wallet');
  const age = nowS(w) - offer.created;
  if (offer.dir === 'btc' && offer.iWindow - age < offer.pWindow * 1.25) throw new Error('this offer is too old: the initiator\'s deadline is already short');
  const index = (w.data.swapNext = (w.data.swapNext ?? 0) + 1) - 1;
  const k = swapKeys(w, index);
  const accept = { offerHash: offerHash(d.bytes), pKrv: k.krvPub, pBtc: k.btcPub, accepted: nowS(w) };
  const bytes = encodeAccept(accept);
  store(w)[id] = { id, role: 'participant', index, offer: toHex(d.bytes), accept: toHex(bytes), btcPayout, btcApi, btcRpc, secret: null, created: Date.now() };
  w.save();
  return { id, code: bech32mEncode(w.params.hrp.x, bytes), offer };
}

/** Initiator's side: records the acceptance received. */
export function importAcceptance(w, code) {
  const d = decodeSwapCode(w.params, code);
  if (d.kind !== 'accept') throw new Error('this is not a swap acceptance');
  const s = Object.values(store(w)).find((x) => x.role === 'initiator' && offerHash(fromHex(x.offer)).equals(d.accept.offerHash));
  if (!s) throw new Error('this acceptance does not match any offer created by this wallet');
  if (s.accept && s.accept !== toHex(d.bytes)) throw new Error('this offer was already accepted by someone else');
  const { offer } = parts(s);
  if (d.accept.accepted < offer.created - 600) throw new Error('acceptance dated before the offer');
  s.accept = toHex(d.bytes);
  w.save();
  return s;
}

/** Readable summary of the terms, from this wallet's point of view. */
export function describeSwap(w, s) {
  const { offer, accept } = parts(s);
  const iAmInit = s.role === 'initiator';
  const krvGive = (offer.dir === 'krv') === iAmInit;
  const out = {
    id: s.id, role: iAmInit ? 'iniciador' : 'participante', btcNet: offer.btcNet,
    give: krvGive ? formatKRV(offer.krv) : formatBTC(offer.btc), receive: krvGive ? formatBTC(offer.btc) : formatKRV(offer.krv),
    windows: { initiator: offer.iWindow, participant: offer.pWindow }, accepted: !!accept, btcPayout: s.btcPayout,
    price: `${(Number(offer.btc) / Number(offer.krv)).toPrecision(4)} BTC per KRV`,
  };
  if (accept) {
    const c = swapContracts(w.params, offer, accept);
    out.myContract = iAmInit ? c.initiatorLock : c.participantLock;
    out.theirContract = iAmInit ? c.participantLock : c.initiatorLock;
  }
  return out;
}

export function listSwaps(w) { return Object.values(store(w)).map((s) => ({ ...describeSwap(w, s), status: s.status ?? 'in progress' })); }

// ------------------------------------------------------------------ watching the networks
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

// ------------------------------------------------------------------ spending the contracts
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
 * Takes the swap's next step (at most ONE action per call) and says what is happening.
 * Returns { action, message, done, ... }. Actions: lock, pay-btc, claim, refund, abort, done, wait-*.
 * dryRun: only says what it would do.
 */
export async function swapStep(w, id, { minConf = 1, feeRate, dryRun = false } = {}) {
  const s = getSwap(w, id);
  const { offer, accept } = parts(s);
  if (!accept) return { action: 'wait-accept', done: false, message: 'waiting for the other party to accept — send them the offer code (krx1…)' };
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
    if (done && !dryRun && s.status !== action) { s.status = action === 'abort' ? 'abandoned' : my.refunded ? 'refunded' : 'completed'; w.save(); }
    return { ...base, action, message, done, ...extra };
  };

  // the participant learns the secret when the initiator claims THEIR contract
  if (!s.secret && my.secret) { s.secret = toHex(my.secret); if (!dryRun) w.save(); }
  const secret = s.secret ? fromHex(s.secret) : null;

  if (their.claimed) return out('done', `swap completed: you received ${fmtAmount(theirC)} (minus the network fee of the claim)`, true);
  if (my.refunded && !my.funded) return out('done', 'swap cancelled: what you locked came back to you (refund)', true);

  // 1) claim what the other party locked
  if (secret && their.funded && !their.claimed && !their.spending) {
    const claimMargin = offer.pWindow / 8;
    // the initiator only reveals the secret if there is still slack before the participant's deadline
    if (!iAmInit || (their.timeLeft !== null && their.timeLeft >= claimMargin)) {
      if (dryRun) return out('claim', `resgatar ${fmtAmount(theirC)}`);
      const r = await spendContract(w, s, offer, theirC, their, keys, secret, feeRate);
      s.claimTxid = r.txid; w.save();
      return out('claim', `claim sent: ${r.amount} (fee ${r.fee}) — tx ${r.txid}${iAmInit ? '. The secret is now public; the other party will use it to claim.' : ''}`, false, { txid: r.txid });
    }
  }
  // 2) refund of what I locked, after my deadline
  if (my.refundable && !my.claimed && !my.spending) {
    if (dryRun) return out('refund', 'refund what you locked');
    const r = await spendContract(w, s, offer, myC, my, keys, null, feeRate);
    s.refundTxid = r.txid; w.save();
    return out('refund', `refund sent: ${r.amount} (fee ${r.fee}) — tx ${r.txid}`, false, { txid: r.txid });
  }
  // 3) lock my part
  if (!my.funded && !my.claimed && !my.refunded) {
    if (!iAmInit) {
      if (!their.funded) return out('wait-their-lock', `waiting for the initiator to lock ${fmtAmount(theirC)}${theirC.chain === 'btc' ? ` (with ${minConf} confirmation(s))` : ''} in the contract ${theirC.address}`);
      const myLeft = myC.chain === 'btc' ? myC.locktime - Math.max(now, bst.tip.time) : offer.pWindow;
      const margin = offer.pWindow / 4;
      if (their.timeLeft < myLeft + margin) {
        return out('abort', `the initiator's deadline ends in ${formatDuration(their.timeLeft)} — too short for you to lock safely. Do not lock anything: the swap ends here with no loss for you.`, true);
      }
    }
    if (myC.chain === 'krevo') {
      if (s.lockTxid) return out('wait-my-lock', `waiting for the confirmation of your lock (tx ${s.lockTxid})`);
      if (dryRun) return out('lock', `travar ${fmtAmount(myC)} no contrato ${myC.address}`);
      const r = await w.send({ to: myC.address, amount: myC.amount, from: 'auto' });
      s.lockTxid = r.txid; w.save();
      return out('lock', `locked ${fmtAmount(myC)} in the contract ${myC.address} (tx ${r.txid}, fee ${formatKRV(r.fee)})`, false, { txid: r.txid });
    }
    const uri = `bitcoin:${myC.address}?amount=${btcDecimal(myC.amount)}`;
    return out('pay-btc', my.seen
      ? `payment seen at ${myC.address}; waiting for ${minConf} confirmation(s) on Bitcoin`
      : `pay exactly ${formatBTC(myC.amount)} to ${myC.address} using your Bitcoin wallet (the QR below already includes the amount)`,
    false, { uri, address: myC.address, amount: myC.amount, seen: my.seen });
  }
  // 4) wait
  if (iAmInit) {
    if (!their.funded) {
      return out('wait-their-lock', `your part is locked. Waiting for the participant to lock ${fmtAmount(theirC)}${theirC.chain === 'btc' ? ` (with ${minConf} confirmation(s))` : ''}. If they do not lock, your refund unlocks in ${formatDuration(my.timeLeft ?? 0)}.`);
    }
    return out('wait-refund', `the participant's deadline ends in ${formatDuration(their.timeLeft)}: for safety the secret will NOT be revealed. Your refund unlocks in ${formatDuration(my.timeLeft ?? 0)}.`);
  }
  return out('wait-secret', `your part is locked. Waiting for the initiator to claim (that reveals the secret). If they disappear, your refund unlocks in ${formatDuration(my.timeLeft ?? 0)}.`);
}

export { DUST };
