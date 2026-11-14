// Cliente rodado no ambiente "de navegador" (ver register.mjs): restaura uma carteira leve,
// sincroniza (varredura + provas com PoW), mostra o saldo e envia — tudo com as peças do app web.
//   node --import ./test/browser/register.mjs test/browser/client.mjs <servidor> <rede> <frase> [destino valor de]
import nodeCryptoProbe from 'node:crypto';
import { getParams } from '../../src/params.js';
import { LightWallet } from '../../src/light/wallet.js';
import { createHash } from '../../src/web/shims/crypto.js';

const [server, net, phrase, to, amount, from, mode] = process.argv.slice(2);
const out = {
  env: {
    webBuffer: Buffer.name === 'Buffer' && !('poolSize' in Buffer), // o Buffer do Node tem poolSize; o nosso não
    nodeCryptoInTest: typeof nodeCryptoProbe.createHash === 'function', // o próprio teste ainda vê o node:crypto real
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
if (mode === 'fcmp') {
  process.env.KREVO_NO_THREADS = '1'; // como no navegador: sem threads nem provador nativo, prova em sequência
  process.env.KREVO_NO_NATIVE = '1';
  w.privateInputs = 'fcmp';
}
if (to) {
  const r = await w.send({ to, amount: BigInt(amount), from: from ?? 'auto' });
  out.sent = { txid: r.txid, fee: r.fee.toString(), from: r.from, anonymitySet: r.anonymitySet, proveMs: r.proveMs };
}
console.log(JSON.stringify(out));
