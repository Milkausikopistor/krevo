// Módulo Bitcoin conferido com os vetores OFICIAIS dos BIPs (não com ele mesmo):
//   BIP-143 (hash de assinatura segwit + assinaturas do Bitcoin Core com RFC 6979),
//   BIP-350 (endereços Bech32/Bech32m válidos e inválidos) e o endereço do bloco gênese.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BTC_NETWORKS, decodeBtcAddress, decodeSegwit, scriptToAddress, base58checkDecode, hash160, sha256, p2wpkhAddress } from '../src/btc/address.js';
import { btcHtlc, spendBtcHtlc, findSecretInWitnesses } from '../src/btc/htlc.js';
import { SimBitcoin } from '../src/btc/simbtc.js';
import { BtcTx } from '../src/btc/tx.js';
import { ecdsaSign, ecdsaVerify, derEncode, derDecode, pubFromPriv } from '../src/btc/ecdsa.js';
import { scriptNum, decodeScriptNum } from '../src/btc/script.js';

const hex = (h) => Buffer.from(h.replace(/\s+/g, ''), 'hex');
const big = (h) => BigInt('0x' + h);

test('endereços: vetores do BIP-350 (Bech32 e Bech32m) e Base58 do bloco gênese', () => {
  const valid = [
    ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
    ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
    ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'],
    ['BC1SW50QGDZ25J', '6002751e'],
    ['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', '5210751e76e8199196d454941c45d1b3a323'],
    ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
    ['tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c', '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
    ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
  ];
  for (const [addr, spk] of valid) {
    const net = addr.toLowerCase().startsWith('tb') ? BTC_NETWORKS.testnet : BTC_NETWORKS.mainnet;
    assert.equal(decodeBtcAddress(net, addr).script.toString('hex'), spk, addr);
    assert.equal(scriptToAddress(net, hex(spk)), addr.toLowerCase(), 'ida e volta');
  }
  const invalid = [
    'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
    'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
    'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
    'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
    'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
    'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
    'bc1pw5dgrnzv',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
    'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
    'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
    'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
    'bc1gmk9yu',
  ];
  for (const addr of invalid) {
    for (const hrp of ['bc', 'tb']) assert.throws(() => decodeSegwit(hrp, addr), undefined, addr);
  }
  // endereço do bloco gênese (chave pública da coinbase de 2009)
  const genesis = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
  assert.equal(base58checkDecode(genesis).toString('hex'), '0062e907b15cbf27d5425399ebf6f0fb50ebb88f18');
  assert.equal(decodeBtcAddress(BTC_NETWORKS.mainnet, genesis).script.toString('hex'), '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac');
  assert.equal(scriptToAddress(BTC_NETWORKS.mainnet, hex('76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac')), genesis);
  assert.throws(() => decodeBtcAddress(BTC_NETWORKS.testnet, genesis), /outra rede/);
  assert.throws(() => decodeBtcAddress(BTC_NETWORKS.mainnet, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb'), /verificação/);
  assert.throws(() => decodeBtcAddress(BTC_NETWORKS.regtest, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'), /outra rede/);
});

test('BIP-143 (P2WPKH nativo): hash de assinatura, assinatura RFC 6979 idêntica e transação assinada idêntica', () => {
  const unsigned = '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000';
  const tx = BtcTx.parse(unsigned);
  assert.equal(tx.toHex(), unsigned, 'ida e volta da serialização');
  const priv = big('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9');
  const pub = pubFromPriv(priv);
  assert.equal(pub.toString('hex'), '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357');
  assert.equal(hash160(pub).toString('hex'), '1d0f172a0ecb48aee1be1f2687d2963ae33f71a1');
  const scriptCode = hex('76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac');
  const sh = tx.sighashV0(1, scriptCode, 600_000_000n);
  assert.equal(sh.toString('hex'), 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670');
  const sig = Buffer.concat([derEncode(ecdsaSign(priv, sh)), Buffer.from([1])]);
  assert.equal(sig.toString('hex'), '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01',
    'assinatura igual à do Bitcoin Core (nonce RFC 6979)');
  // monta a transação assinada: entrada 0 (P2PK legado) com o scriptSig do BIP; entrada 1 com a nossa testemunha
  tx.inputs[0].scriptSig = hex('4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01');
  tx.inputs[1].witness = [sig, pub];
  assert.equal(tx.toHex(), '01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000');
  assert.equal(BtcTx.parse(tx.toHex()).toHex(), tx.toHex(), 'leitura com testemunha');
  assert.ok(ecdsaVerify(pub, sh, derDecode(sig.subarray(0, -1))));
  assert.equal(ecdsaVerify(pub, Buffer.alloc(32, 7), derDecode(sig.subarray(0, -1))), false);
});

test('BIP-143 (P2SH-P2WSH 6-de-6): hash de assinatura com witnessScript e assinatura idêntica', () => {
  const tx = BtcTx.parse('010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000');
  const ws = hex('56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae');
  assert.equal(sha256(ws).toString('hex'), 'a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54', 'programa P2WSH do BIP');
  const sh = tx.sighashV0(0, ws, 987_654_321n);
  assert.equal(sh.toString('hex'), '185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c');
  const priv = big('730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6');
  assert.equal(pubFromPriv(priv).toString('hex'), '0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3');
  assert.equal(derEncode(ecdsaSign(priv, sh)).toString('hex'), '304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce');
});

test('números de script e DER estrito', () => {
  for (const n of [1, 16, 32, 127, 128, 255, 256, -1, -128, 1_794_000_000, 2 ** 31 - 1]) {
    assert.equal(decodeScriptNum(scriptNum(n), 5), BigInt(n), String(n));
  }
  assert.equal(scriptNum(128).toString('hex'), '8000');
  assert.throws(() => decodeScriptNum(Buffer.from([0x01, 0x00])), /mínimo/);
  const sig = derEncode({ r: 1n, s: 2n });
  assert.deepEqual(derDecode(sig), { r: 1n, s: 2n });
  assert.throws(() => derDecode(Buffer.from('3006020200010201 02'.replace(/ /g, ''), 'hex')));
});

test('HTLC no Bitcoin simulado: resgate com segredo, reembolso só após o prazo, ataques recusados', () => {
  const net = BTC_NETWORKS.regtest;
  const sim = new SimBitcoin({ net, spacing: 600 });
  const claimKey = 0x1111n, refundKey = 0x2222n, otherKey = 0x3333n;
  const secret = Buffer.alloc(32, 0x5a), hash = sha256(secret);
  const deadline = sim.tip.time + 3600; // 1 hora
  const h = btcHtlc(net, { hash, claimPub: pubFromPriv(claimKey), refundPub: pubFromPriv(refundKey), locktime: deadline });
  assert.match(h.address, /^bcrt1q/);
  assert.equal(h.address.length, 64, 'P2WSH (programa de 32 bytes)');
  const dest = p2wpkhAddress(net, pubFromPriv(0x4444n));
  const fund = () => { const txid = sim.fund(h.address, 100_000n); sim.mine(1, 600); return [{ txid, vout: 0, value: 100_000 }]; };

  // resgate com o segredo certo
  const u1 = fund();
  const ok = spendBtcHtlc({ net, htlc: h, utxos: u1, to: dest, feeRate: 2, key: claimKey, secret });
  assert.equal(sim.submit(ok.hex), ok.txid);
  assert.equal(sim.balance(dest), ok.value);
  assert.ok(ok.fee > 0n && ok.fee < 1_000n, `taxa ${ok.fee} sat`);
  // o segredo fica visível para a outra parte
  const w = sim.addressTxs(h.address).flatMap((t) => t.vin.filter((v) => v.prevout?.scriptpubkey_address === h.address).map((v) => v.witness.map((x) => Buffer.from(x, 'hex'))));
  assert.ok(findSecretInWitnesses(w, hash).equals(secret));
  assert.throws(() => sim.submit(ok.hex.replace(/.{8}$/, '01000000')), /já foi gasta|conflito/);

  const u2 = fund();
  // segredo errado
  const bad = spendBtcHtlc({ net, htlc: h, utxos: u2, to: dest, feeRate: 2, key: claimKey, secret: Buffer.alloc(32, 1) });
  assert.throws(() => sim.submit(bad.hex), /EQUALVERIFY/);
  // chave errada (quem só pode reembolsar tentando resgatar)
  const wrongKey = spendBtcHtlc({ net, htlc: h, utxos: u2, to: dest, feeRate: 2, key: otherKey, secret });
  assert.throws(() => sim.submit(wrongKey.hex), /NULLFAIL/);
  // segredo de 31 bytes cujo hash bate: OP_SIZE 32 recusa (protege a outra rede)
  const s31 = Buffer.alloc(31, 7);
  const h31 = btcHtlc(net, { hash: sha256(s31), claimPub: pubFromPriv(claimKey), refundPub: pubFromPriv(refundKey), locktime: deadline });
  const t31 = sim.fund(h31.address, 100_000n); sim.mine(1, 600);
  const c31 = spendBtcHtlc({ net, htlc: h31, utxos: [{ txid: t31, vout: 0, value: 100_000 }], to: dest, feeRate: 2, key: claimKey, secret: Buffer.alloc(32) });
  c31.tx.inputs[0].witness[1] = s31;
  assert.throws(() => sim.submit(c31.tx.toHex()), /EQUALVERIFY/);

  // reembolso antes do prazo: recusado
  const early = spendBtcHtlc({ net, htlc: h, utxos: u2, to: dest, feeRate: 2, key: refundKey });
  assert.throws(() => sim.submit(early.hex), /non-final/);
  // trapaça: nLockTime menor que o prazo do contrato
  const cheat = spendBtcHtlc({ net, htlc: { ...h, locktime: deadline - 3000 }, utxos: u2, to: dest, feeRate: 2, key: refundKey });
  sim.mine(12, 600); // a mediana de tempo passa do prazo
  assert.ok(sim.mtp() > deadline);
  assert.throws(() => sim.submit(cheat.hex), /CLTV/);
  // depois do prazo, só quem tem a chave de reembolso
  assert.throws(() => sim.submit(spendBtcHtlc({ net, htlc: h, utxos: u2, to: dest, feeRate: 2, key: claimKey }).hex), /NULLFAIL/);
  const refund = spendBtcHtlc({ net, htlc: h, utxos: u2, to: dest, feeRate: 2, key: refundKey });
  assert.equal(sim.submit(refund.hex), refund.txid);
});
