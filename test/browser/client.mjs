// Client run in the "browser" environment (see register.mjs): restores a light wallet,
// syncs (scan + proofs with PoW), shows the balance and sends — all with the web app's pieces.
//   node --import ./test/browser/register.mjs test/browser/client.mjs <server> <network> <phrase> [destination amount from]
import nodeCryptoProbe from 'node:crypto';
import { getParams } from '../../src/params.js';
import { LightWallet } from '../../src/light/wallet.js';
import { createHash } from '../../src/web/shims/crypto.js';
import { pqAvailable } from '../../src/crypto/pq.js';

const [server, net, phrase, to, amount, from, mode] = process.argv.slice(2);
const out = {
  env: {
    webBuffer: Buffer.name === 'Buffer' && !('poolSize' in Buffer), // Node's Buffer has poolSize; ours does not
    nodeCryptoInTest: typeof nodeCryptoProbe.createHash === 'function', // the test itself still sees the real node:crypto
  },
};
const params = getParams(net);
const w = LightWallet.restore(null, params, server, { mnemonic: phrase });
const t0 = Date.now();
out.sync = await w.sync();
out.syncMs = Date.now() - t0;
const b = w.balance();
out.balance = Object.fromEntries(Object.entries(b).map(([k, v]) => [k, v.toString()]));
out.address = w.sAddress;
out.memos = w.history().received.map((r) => r.memo).filter(Boolean);
out.blakeIsShim = createHash('blake2b512').update('x').digest('hex').length === 128;
out.pq = pqAvailable(); // ML-DSA here comes from the WebAssembly core (the browser has no OpenSSL)
out.qAddress = out.pq ? w.qAddress : null;
if (mode === 'migrate') {
  // quantum-safe address: move the classic transparent coins to krq (signed with Schnorr only)
  const m = await w.migrateQuantum();
  out.migrated = { txids: m.txs.map((x) => x.txid), moved: m.moved.toString() };
}
if (mode === 'fcmp') {
  process.env.KREVO_NO_THREADS = '1'; // as in the browser: no threads nor native prover, the proof is sequential
  process.env.KREVO_NO_NATIVE = '1';
  w.privateInputs = 'fcmp';
}
if (to) {
  const r = await w.send({ to, amount: BigInt(amount), from: from ?? 'auto' });
  out.sent = { txid: r.txid, fee: r.fee.toString(), from: r.from, anonymitySet: r.anonymitySet, proveMs: r.proveMs };
}
console.log(JSON.stringify(out));
