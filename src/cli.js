#!/usr/bin/env node
// Krevo command line.
import path from 'node:path';
import readline from 'node:readline/promises';
import { getParams, formatKRV, parseKRV } from './params.js';
import { Node } from './node/node.js';
import { runMiner, runPoolMiner } from './node/miner.js';
import { startPool, parseDuration } from './pool/pool.js';
import { Wallet } from './wallet/wallet.js';
import { rpc } from './node/rpcclient.js';
import { buildGenesis } from './consensus/consensus.js';
import { emissionSchedule } from './consensus/emission.js';
import { startExplorer } from './explorer/server.js';
import fs from 'node:fs';
import { seedsFor } from './node/seeds.js';
import { startFaucet } from './faucet/faucet.js';
import { encodeQR, qrToTerminal, qrToSvg } from './util/qrcode.js';
import { createOffer, acceptOffer, importAcceptance, swapStep, listSwaps, describeSwap, getSwap, decodeSwapCode, parseBTC, formatBTC, formatDuration } from './wallet/swap.js';
import { startSimBitcoin } from './btc/simbtc.js';
import { LightWallet, LightClient } from './light/wallet.js';
import { EscrowContract, myRole, escrowStatus, escrowFund, escrowPropose, describeEscrowProposal, escrowSign, escrowReclaim } from './wallet/escrow.js';
import { proveReserves, verifyReserves, buildLiabilities, verifyLiability, parseAccountsCsv } from './wallet/reserves.js';
import { startLightServer } from './light/server.js';
import { startWebWallet } from './web/serve.js';
import { checkName } from './consensus/names.js';
import { nameCommit, nameReveal, nameRevealWait, nameUpdate, nameTransfer, nameRenew, nameRelease, myNames } from './wallet/names.js';
import { defaultBtcApi } from './btc/esplora.js';
import { buildPaymentURI, parsePaymentURI, isExpired, newOrderCode } from './wallet/request.js';
import { multisigKey, encodeMultisigKey, MultisigGroup, groupUtxos, proposePayment, checkProposalInputs,
  signProposal, mergeProposals, finalizeProposal, inheritanceStatus, spendAlone, parseWait, formatWait } from './wallet/multisig.js';

const HELP = `
Krevo (KRV) — reference implementation

USAGE
  krevo node      [--network devnet] [--datadir ./data] [--port N] [--rpcport N] [--rpchost 127.0.0.1] [--peer host:port ...] [--no-seeds]
  krevo mine      --address ADDRESS [--rpc URL] [--threads N]                solo mining (on your node)
  krevo mine      --pool HOST:PORT --address ADDRESS [--threads N] [--worker rig1]   on a pool
  krevo pool      --file pool-wallet.json [--port 5555] [--web-port 8081] [--fee 1]
                  [--min-payout 1] [--interval 60s] [--rpc URL]                runs a mining pool
  krevo wallet    create | restore | phrase | address | balance | send | viewkey
                  [--file wallet.json] [--rpc URL] [--password PASSWORD]   (or KREVO_SENHA, or a hidden prompt)
        create     [--words 12|24] [--passphrase TEXT]
        restore    [--phrase "word1 word2 …"] [--passphrase TEXT]   (without --phrase it is asked in the terminal)
        phrase     shows the stored recovery phrase
        send       --to ADDRESS --amount 1.5 [--from transparent|private] [--memo "text"]
        history    payments sent and received (with memos)
        prove      --txid TXID [--message "text"]          creates a payment proof (krp1…)
        check-proof --proof krp1… --address krs1… [--message "text"]   (no wallet needed)
        request    --amount 2.5 [--memo "Order 123"] [--label "My Shop"] [--expires MINUTES]
                   [--transparent] [--svg file.svg] [--wait]          shows a QR code and a krevo: link
        pay        --uri "krevo:…" [--from transparent|private] [--yes]    pays a payment request
        subaddress   [--label "Customer X"]   creates a new private address (impossible to link to the others)
        subaddresses                         lists the private addresses and how much each one received
  krevo wallet quantum  address | status | migrate           protection against quantum computers
        address    shows your quantum-safe address (krq1…: Schnorr + ML-DSA, both signatures are required)
        status     how much is on classic, quantum-safe and private addresses
        migrate    [--include-private] [--yes]   moves krv1… → krq1… and turns quantum mode on (change goes to krq1…)
  krevo name   register | show | mine | update | transfer | renew | release | price     human-readable names (@name)
        register @bakery [--to private|transparent|ADDRESS]   reserves the name (commitment + reveal)
        show @bakery            where the name points to, owner and expiry (anyone can look it up)
        mine                    this wallet's names
        update @bakery --to private|transparent|ADDRESS        changes the destination (no fee)
        transfer @bakery --to NEW_OWNER_ADDRESS                 krv, krq or multisig (no fee)
        renew @bakery           one more year (pays the fee)   ·   release @bakery   returns the deposit
        price @bakery           yearly fee: 3 letters 100 KRV · 4 → 20 · 5 → 5 · 6 or more → 1 KRV
  (paying a name: krevo wallet send --to @bakery --amount 2)
  krevo escrow  create | import | status | fund | release | refund | sign | reclaim   escrow contract
        create     --name Order42 --buyer krk1… --seller krk1… --arbiter krk1… --amount 50 --deadline 30d
        import     --name Order42 --code krm1…           (the other parties)
        fund       --name Order42                        (buyer)
        release    --name Order42 --to SELLER_ADDRESS   ·   refund --name … --to BUYER_ADDRESS
                   creates a proposal already signed by you (a file); the other party uses "sign"
        sign       --proposal proposal.json              checks, signs and, with 2 of 3, sends
        reclaim    --name Order42 [--to ADDRESS]         (buyer, after the deadline, alone)
  krevo reserves  prove | verify | liabilities | check                          proof of reserves (exchanges)
        prove      --message "Exchange X — 2026-11-13" [--out reserves.json]
        verify     --proof reserves.json [--message "…"] [--liabilities root.json]   (anyone, with a node)
        liabilities --customers customers.csv [--out folder]   sum tree: root.json + one proof per customer
        check      --proof customer.json --root root.json     (the customer checks their own account)
  krevo swap  create | accept | confirm | watch | step | status | list     atomic swap with Bitcoin
        create     --sell krv|btc --krv 100 --btc 0.001 --btc-address YOUR_BITCOIN_ADDRESS
                   [--btc-network regtest|testnet|signet] [--window 48h] [--btc-api URL | --btc-rpc URL]   makes the offer
        accept     --code krx1… --btc-address YOUR_BITCOIN_ADDRESS [--btc-api URL | --btc-rpc URL]   makes the acceptance
        confirm    --code krx1…      whoever made the offer records the acceptance received
        watch      [--id ID]         drives the swap to the end: locks, checks, claims or refunds
        step       [--id ID]         only the next step   ·   status [--id ID]   ·   list
  krevo btc-sim [--port 3002] [--block 10s]          local test Bitcoin (same API as mempool.space)
        pay --address bcrt1… --amount 0.001  ·  balance --address bcrt1…  ·  mine [--blocks 1] [--seconds 600]
  krevo wallet multisig  key | create | import | list | balance | propose | sign | send
        key                                     shows your multisig key (krk1…)
        create   --name Company --min 2 --keys krk1…,krk1…,krk1…   (or --descriptor krm1…)
        propose  --name Company --to ADDRESS --amount 5 [--memo "…"] [--out proposal.json]
        sign     --proposal proposal.json [--yes]      checks and adds your signature
        send     --proposal proposal.json [--proposal other.json]   merges M signatures and sends
        (in inheritance plans with several heirs: propose ... --path 1)
  krevo wallet inheritance  create | status | renew | send | import | claim
        create    --name Grandma --heirs krk1…[,krk1…] [--min 1] --after 365d   (d, m=months, a=years, h, min, s)
        status    --name Grandma              balance and when the heirs will be able to claim
        renew     --name Grandma              proof of life: moves the balance and resets the countdown
        send      --name Grandma --to … --amount …    the owner spends normally, without waiting
        import    --name Grandma --descriptor krm1…    (heir) follows the plan
        claim     --name Grandma [--to ADDRESS]        (heir) claims the unlocked balance
  (request uses a new subaddress for every payment request; --main-address to use the main one)
  krevo info      [--rpc URL]
  krevo explorer [--port 8080] [--rpc URL] [--public]   block explorer in the browser (live DAG)
  krevo light-server [--port 8090] [--public] [--rpc URL]   server for light wallets (never receives keys)
  krevo web-wallet [--port 8091] [--public]          wallet app for browsers and phones (installable)
  krevo faucet --file faucet-wallet.json [--port 8092] [--amount 10] [--public] [--trusted-proxy]
                                                     faucet of TEST KRV for testnet operators
  LIGHT WALLET: add --light SERVER_URL to wallet | name | swap — works without a node of your own
        wallet scanning local | delegated --light URL    local = private (default); delegated = the server sees what you receive
  krevo emission  [--network mainnet]
  krevo genesis   [--network mainnet]

Addresses: krv1… = transparent (public amounts)   krs1… = private (amounts and recipient hidden)
           krq1… = transparent, resistant to quantum computers

The original Portuguese command and option names still work (e.g. carteira enviar --para … --valor …).
`;

// Command, subcommand and option names are English. The original Portuguese names (and a few
// synonyms) are still accepted: they are normalized to the English names below.
const LEGACY_OPTS = {
  leve: 'light', comprador: 'buyer', vendedor: 'seller', arbitro: 'arbiter', prazo: 'deadline', window: 'deadline', passivos: 'liabilities', clientes: 'customers', raiz: 'root',
  rede: 'network', dados: 'datadir', porta: 'port', rpcporta: 'rpcport', par: 'peer', endereco: 'address',
  arquivo: 'file', senha: 'password', para: 'to', valor: 'amount', de: 'from',
  frase: 'phrase', 'frase-extra': 'passphrase', palavras: 'words', mensagem: 'message', prova: 'proof',
  rotulo: 'label', expira: 'expires', transparente: 'transparent', aguardar: 'wait', sim: 'yes',
  'endereco-principal': 'main-address', nome: 'name', minimo: 'min', chaves: 'keys', descritor: 'descriptor',
  proposta: 'proposal', saida: 'out', caminho: 'path', herdeiros: 'heirs', apos: 'after', 'incluir-privado': 'include-private',
  vender: 'sell', 'endereco-btc': 'btc-address', 'rede-btc': 'btc-network', codigo: 'code',
  blocos: 'blocks', segundos: 'seconds', bloco: 'block',
  publico: 'public', 'sem-sementes': 'no-seeds', 'proxy-confiavel': 'trusted-proxy',
  trabalhador: 'worker', 'porta-web': 'web-port', taxa: 'fee', 'pagamento-minimo': 'min-payout', intervalo: 'interval', estado: 'state',
};
const LEGACY_CMDS = {
  no: 'node', minerar: 'mine', carteira: 'wallet', emissao: 'emission', explorador: 'explorer', troca: 'swap', 'btc-simulado': 'btc-sim',
  nome: 'name', names: 'name', 'servidor-leve': 'light-server', 'carteira-web': 'web-wallet', torneira: 'faucet', garantia: 'escrow', reservas: 'reserves',
};
const LEGACY_SUBS = {
  criar: 'create', restaurar: 'restore', frase: 'phrase', endereco: 'address', saldo: 'balance', enviar: 'send',
  'chave-visualizacao': 'viewkey', historico: 'history', provar: 'prove', 'verificar-prova': 'check-proof',
  cobrar: 'request', pagar: 'pay', subendereco: 'subaddress', subenderecos: 'subaddresses', heranca: 'inheritance', varredura: 'scanning',
  quantica: 'quantum', 'quântica': 'quantum',
};
const LEGACY_FROM = { transparente: 'transparent', privado: 'private', shielded: 'private' };

function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k0 = a.slice(2), k = LEGACY_OPTS[k0] ?? k0;
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      if (o[k] === undefined) o[k] = v; else o[k] = [].concat(o[k], v);
    } else o._.push(a);
  }
  if (o._[0]) o._[0] = LEGACY_CMDS[o._[0]] ?? o._[0];
  if (o._[1]) o._[1] = LEGACY_SUBS[o._[1]] ?? o._[1];
  if (typeof o.from === 'string') o.from = LEGACY_FROM[o.from] ?? o.from;
  return o;
}

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];
const params = getParams(args.network ?? 'devnet');
const rpcUrl = args.rpc ?? `http://127.0.0.1:${params.defaultRpcPort}`;
// Light wallet: --light LIGHT_SERVER_URL — uses Krevo without a node of your own (the server never gets keys)
const lightUrl = typeof args.light === 'string' ? args.light : undefined;
const WalletClass = lightUrl ? LightWallet : Wallet;
const walletUrl = lightUrl ?? rpcUrl;
const ts = () => new Date().toISOString().slice(11, 23);
const log = (m) => console.log(`[${ts()}] ${m}`);
const str = (v) => (typeof v === 'string' ? v : undefined);
/** Default file/folder name (English); one created by an older version with the Portuguese name is still used. */
const defaultFile = (english, portuguese) => (!fs.existsSync(english) && fs.existsSync(portuguese) ? portuguese : english);

async function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try { return await rl.question(question); } finally { rl.close(); }
}

function printPhrase(mnemonic, hasPassphrase) {
  const words = mnemonic.split(' ');
  const cols = 4, rows = Math.ceil(words.length / cols);
  console.log(`\nRECOVERY PHRASE (${words.length} words):\n`);
  for (let r = 0; r < rows; r++) {
    let line = '';
    for (let c = 0; c < cols; c++) {
      const i = c * rows + r;
      if (i < words.length) line += `${String(i + 1).padStart(2)}. ${words[i].padEnd(10)}  `;
    }
    console.log('  ' + line.trimEnd());
  }
  console.log('\n  ⚠  Write these words on PAPER, in order, and keep them somewhere safe.');
  console.log('     With them you can recover the wallet on any computer, even if you lose this file.');
  console.log('     Whoever has the phrase controls the funds: never type it into websites, nor send it in a message or photo.');
  if (hasPassphrase) console.log('     You used an EXTRA PHRASE: it is also required to restore (write it down separately).');
}

const MS_ALIASES = { chave: 'key', criar: 'create', importar: 'import', lista: 'list', saldo: 'balance', propor: 'propose', assinar: 'sign', enviar: 'send' }; // legacy names

async function multisigCommand(w) {
  const cmd2 = MS_ALIASES[args._[2]] ?? args._[2];
  const groups = (w.data.multisigs ??= {});
  const group = () => {
    const name = str(args.name);
    if (!name || !groups[name]) throw new Error(`enter --name of an existing group (${Object.keys(groups).join(', ') || 'none yet'})`);
    return MultisigGroup.fromDescriptor(params, groups[name].descriptor, name);
  };
  const balanceOf = async (g) => (await groupUtxos(rpcUrl, g)).reduce((a, u) => a + BigInt(u.amount), 0n);
  const files = () => [].concat(args.proposal ?? []).filter((x) => typeof x === 'string');
  const showProposal = (d) => {
    console.log(`  group:   ${d.group.m} of ${d.group.n} signatures  (${d.group.address.slice(0, 26)}…)`);
    for (const p of d.payments) {
      console.log(`  PAYS:    ${formatKRV(p.amount)} → ${p.to.slice(0, 30)}…${p.private ? ' (private, amount checked)' : ''}${p.memo ? `  memo: "${p.memo}"` : ''}`);
    }
    console.log(`  change:  ${formatKRV(d.change)} back to the group`);
    console.log(`  fee:     ${formatKRV(d.fee)}`);
    console.log(`  signatures: ${d.have} of ${d.need}${d.signers.length ? ` (participants ${d.signers.map((i) => '#' + (i + 1)).join(', ')})` : ''}`);
  };
  switch (cmd2) {
    case 'key':
      console.log(encodeMultisigKey(params, multisigKey(w.keys).P));
      console.log('Send this key to the other participants. It is public and comes from your recovery phrase.');
      return;
    case 'create':
    case 'import': {
      const name = str(args.name);
      if (!name) throw new Error('enter --name for the group (e.g. --name Company)');
      let g;
      if (args.descriptor) g = MultisigGroup.fromDescriptor(params, str(args.descriptor), name);
      else {
        const keys = [].concat(args.keys ?? []).flatMap((k) => String(k).split(',')).map((x) => x.trim()).filter(Boolean);
        if (!args.min || keys.length < 1) throw new Error('enter --min M and --keys krk1…,krk1… (or --descriptor krm1…)');
        g = MultisigGroup.create(params, Number(args.min), keys, name);
      }
      groups[name] = { descriptor: g.descriptor, m: g.m, n: g.n, created: Date.now() };
      w.save();
      console.log(`Group "${name}": requires ${g.m} of ${g.n} signatures`);
      console.log(`Group address (receive here):\n  ${g.address}`);
      console.log(`Descriptor (the other participants import it; KEEP it together with the phrase):\n  ${g.descriptor}`);
      if (g.indexOf(multisigKey(w.keys).P) < 0) console.log('⚠ Your key is not in this group: you can follow the balance, but you cannot sign.');
      return;
    }
    case 'list':
      if (!Object.keys(groups).length) console.log('No groups. Create one with: wallet multisig create --name … --min … --keys …');
      for (const name of Object.keys(groups)) {
        const g = MultisigGroup.fromDescriptor(params, groups[name].descriptor, name);
        console.log(`${name}: ${g.m} of ${g.n} | balance ${formatKRV(await balanceOf(g))}\n  ${g.address}`);
      }
      return;
    case 'balance': {
      const g = group();
      console.log(`${g.name} (${g.m} of ${g.n}): ${formatKRV(await balanceOf(g))}`);
      return;
    }
    case 'propose': {
      const g = group();
      if (!str(args.to) || !str(args.amount)) throw new Error('enter --to ADDRESS and --amount');
      const prop = await proposePayment({ params, rpcUrl, group: g, to: str(args.to), amount: parseKRV(args.amount), memo: str(args.memo), path: Number(args.path ?? 0) });
      const out = path.resolve(str(args.out) ?? `proposal-${prop.txid.slice(0, 8)}.json`);
      fs.writeFileSync(out, JSON.stringify(prop, null, 2));
      console.log(`Proposal created: ${out}`);
      showProposal(await checkProposalInputs(params, rpcUrl, prop));
      console.log(`\nSend the file to the signers. Each one runs:\n  wallet multisig sign --proposal ${path.basename(out)}`);
      return;
    }
    case 'sign': {
      const file = files()[0];
      if (!file) throw new Error('enter --proposal file.json');
      const prop = JSON.parse(fs.readFileSync(file, 'utf8'));
      const d = await checkProposalInputs(params, rpcUrl, prop); // checks everything by reading the transaction itself
      console.log('YOU ARE AUTHORIZING:');
      showProposal(d);
      if (args.yes !== true) {
        const a = await ask('Sign? (y/N) ');
        if (!/^(s|sim|y|yes)$/i.test(a.trim())) { console.log('Not signed.'); return; }
      }
      const r = signProposal(params, prop, w.keys);
      const out = str(args.out) ?? file;
      fs.writeFileSync(out, JSON.stringify(prop, null, 2));
      console.log(`Signature of participant #${r.index + 1} added (${r.have} of ${r.need}). File: ${out}`);
      if (r.have >= r.need) console.log(`Ready to send: wallet multisig send --proposal ${path.basename(out)}`);
      else console.log('Pass the file on to the next signer.');
      return;
    }
    case 'send': {
      const fl = files();
      if (!fl.length) throw new Error('enter --proposal file.json (repeat it to merge copies)');
      const prop = mergeProposals(fl.map((f) => JSON.parse(fs.readFileSync(f, 'utf8'))));
      const tx = finalizeProposal(params, prop);
      const t0 = Date.now();
      const res = await rpc(rpcUrl, 'sendrawtransaction', { tx: tx.serialize().toString('hex') });
      console.log(`Sent! txid ${res.txid}`);
      await w.waitAccepted(res.txid);
      console.log(`  confirmed in ${((Date.now() - t0) / 1000).toFixed(2)} s`);
      return;
    }
    default:
      console.log(HELP);
  }
}

// ------------------------------------------------------------------ escrow
const ESCROW_ALIASES = { criar: 'create', importar: 'import', depositar: 'fund', liberar: 'release', reembolsar: 'refund', assinar: 'sign', resgatar: 'reclaim' }; // legacy names
function openWallet() {
  const file = path.resolve(args.file ?? defaultFile(`wallet-${params.name}.json`, `carteira-${params.name}.json`));
  if (!fs.existsSync(file)) throw new Error(`wallet not found: ${file} (create one with: krevo wallet create, or use --file)`);
  return Wallet.load(file, params, rpcUrl, str(args.password));
}
function printEscrow(c, role) {
  console.log(`Escrow "${c.label}" — you are the ${role ? c.roleName(role) : '(not a party)'}`);
  console.log(`  amount: ${formatKRV(c.amount)} · time for the buyer to reclaim alone: ${formatWait(c.delay, params)} after the deposit`);
  console.log(`  address: ${c.address}`);
}
async function escrowCommand() {
  const sub = ESCROW_ALIASES[args._[1]] ?? args._[1];
  if (sub === 'sign') {
    const w = openWallet();
    const file = str(args.proposal);
    if (!file) throw new Error('enter --proposal proposal.json');
    const prop = JSON.parse(fs.readFileSync(file, 'utf8'));
    const info = describeEscrowProposal(params, prop);
    console.log(`Proposal: ${info.kind === 'release' ? 'RELEASE to the seller' : 'REFUND the buyer'} — ${formatKRV(info.amount)} to ${info.to}`);
    console.log(`  already signed by: ${info.signedBy.map((r) => info.contract.roleName(r)).join(', ')} · you: ${info.contract.roleName(myRole(info.contract, w.keys))}`);
    if (!args.yes) { console.log('Check the destination and repeat with --yes to sign.'); return; }
    const r = await escrowSign({ params, rpcUrl, prop, walletKeys: w.keys });
    fs.writeFileSync(file, JSON.stringify(prop, null, 2));
    if (r.sent) { console.log(`Sent with 2 of 3 signatures! txid ${r.txid} (fee ${formatKRV(r.fee)})`); await w.waitAccepted(r.txid); console.log('  confirmed by the network'); }
    else console.log(`Signed (${r.have} of 2). Send ${file} to another party to sign.`);
    return;
  }
  const w = openWallet();
  const store = (w.data.escrows ??= {});
  const name = str(args.name);
  if (!name) throw new Error('enter --name (a nickname for the contract)');
  if (sub === 'create') {
    if (!args.buyer || !args.seller || !args.arbiter || !args.amount) throw new Error('enter --buyer, --seller and --arbiter (krk1… keys) and --amount');
    const c = EscrowContract.create(params, { buyer: str(args.buyer), seller: str(args.seller), arbiter: str(args.arbiter), delay: parseWait(args.deadline ?? '30d', params), amount: parseKRV(args.amount), label: name });
    store[name] = { code: c.code, created: Date.now() };
    w.save();
    printEscrow(c, myRole(c, w.keys));
    console.log(`\nSend this code to the other parties (they use: krevo escrow import --name ${name} --code …):\n\n${c.code}\n`);
    return;
  }
  if (sub === 'import') {
    const c = EscrowContract.fromCode(params, str(args.code) ?? '');
    store[name] = { code: c.code, created: Date.now() };
    w.save();
    printEscrow(c, myRole(c, w.keys));
    return;
  }
  if (!store[name]) throw new Error(`no escrow called "${name}" in this wallet`);
  const c = EscrowContract.fromCode(params, store[name].code);
  const role = myRole(c, w.keys);
  if (sub === 'status') {
    printEscrow(c, role);
    const st = await escrowStatus(params, rpcUrl, c);
    console.log(`  balance in the contract: ${formatKRV(st.balance)} ${st.empty ? '(no deposit yet, or already settled)' : st.funded ? '(deposited)' : '(incomplete deposit)'}`);
    if (!st.empty) console.log(`  the buyer can reclaim alone ${st.refundable ? 'NOW' : `in ${st.refundIn}`}`);
  } else if (sub === 'fund') {
    const r = await escrowFund(w, c);
    console.log(`Deposited ${formatKRV(c.amount)} into the escrow (tx ${r.txid}, fee ${formatKRV(r.fee)})`);
  } else if (sub === 'release' || sub === 'refund') {
    const prop = await escrowPropose({ params, rpcUrl, contract: c, walletKeys: w.keys, kind: sub, to: str(args.to) });
    const out = path.resolve(str(args.out) ?? `escrow-${name}-${sub === 'release' ? 'release' : 'refund'}.json`);
    fs.writeFileSync(out, JSON.stringify(prop, null, 2));
    console.log(`Proposal to ${sub === 'release' ? 'release to the seller' : 'refund the buyer'} ${formatKRV(BigInt(prop.amount))} created and signed by you (${c.roleName(role)}).`);
    console.log(`  Send ${out} to another party to run: krevo escrow sign --proposal ${path.basename(out)} --yes`);
  } else if (sub === 'reclaim') {
    const r = await escrowReclaim({ params, rpcUrl, contract: c, walletKeys: w.keys, to: str(args.to) ?? w.tAddress });
    console.log(`Reclaimed ${formatKRV(r.amount)} (tx ${r.txid})`);
  } else throw new Error('use: krevo escrow create | import | status | fund | release | refund | sign | reclaim');
}

// ------------------------------------------------------------------ proof of reserves
const RES_ALIASES = { provar: 'prove', verificar: 'verify', passivos: 'liabilities', conferir: 'check' }; // legacy names
async function reservesCommand() {
  const sub = RES_ALIASES[args._[1]] ?? args._[1];
  if (sub === 'prove') {
    const w = openWallet();
    const proof = await proveReserves(w, str(args.message));
    const out = path.resolve(str(args.out) ?? 'reserves.json');
    fs.writeFileSync(out, JSON.stringify(proof, null, 2));
    console.log(`Proof of reserves: ${formatKRV(BigInt(proof.total))} in ${proof.transparent.length} transparent coin(s) and ${proof.private.length} private one(s)`);
    console.log(`  message: "${proof.message}"\n  file: ${out} (can be published)`);
  } else if (sub === 'verify') {
    const proof = JSON.parse(fs.readFileSync(path.resolve(str(args.proof) ?? defaultFile('reserves.json', 'reservas.json')), 'utf8'));
    const r = await verifyReserves(params, rpcUrl, proof, { message: str(args.message) });
    console.log(r.valid ? `✅ RESERVES PROVEN: ${formatKRV(r.total)}` : `❌ PROOF HAS PROBLEMS — total that actually checks out: ${formatKRV(r.total)}`);
    console.log(`  transparent ${formatKRV(r.transparent)} · private ${formatKRV(r.private)} · ${r.coins} coin(s) · message: "${proof.message}"`);
    for (const i of r.issues) console.log(`  ⚠ ${i}`);
    if (args.liabilities) {
      const root = JSON.parse(fs.readFileSync(path.resolve(str(args.liabilities)), 'utf8'));
      const owed = BigInt(root.total);
      console.log(r.total >= owed
        ? `✅ SOLVENT: reserves ${formatKRV(r.total)} ≥ owed to customers ${formatKRV(owed)} (${root.accounts} accounts)`
        : `❌ MONEY MISSING: reserves ${formatKRV(r.total)} < owed to customers ${formatKRV(owed)}`);
    }
    if (!r.valid) process.exitCode = 2;
  } else if (sub === 'liabilities') {
    const accounts = parseAccountsCsv(fs.readFileSync(path.resolve(str(args.customers) ?? defaultFile('customers.csv', 'clientes.csv')), 'utf8'));
    const { root, proofs } = buildLiabilities(accounts, { label: str(args.label) ?? '' });
    const dir = path.resolve(str(args.out) ?? 'liabilities');
    fs.mkdirSync(path.join(dir, 'customers'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'root.json'), JSON.stringify(root, null, 2));
    for (const p of proofs) fs.writeFileSync(path.join(dir, 'customers', `${p.id.replace(/[^\w.-]/g, '_')}.json`), JSON.stringify(p, null, 2));
    console.log(`Liabilities tree: ${root.accounts} accounts, total owed ${formatKRV(BigInt(root.total))}`);
    console.log(`  publish ${path.join(dir, 'root.json')}; give each customer (privately) their own file in ${path.join(dir, 'customers')}`);
  } else if (sub === 'check') {
    const proof = JSON.parse(fs.readFileSync(path.resolve(str(args.proof)), 'utf8'));
    const root = JSON.parse(fs.readFileSync(path.resolve(str(args.root) ?? 'root.json'), 'utf8'));
    const r = verifyLiability(proof, root);
    console.log(r.valid
      ? `✅ Your account "${proof.id}" with ${formatKRV(r.balance)} is included in the published total (${formatKRV(r.total)}).`
      : `❌ DOES NOT match: ${r.reason}`);
    if (!r.valid) process.exitCode = 2;
  } else throw new Error('use: krevo reserves prove | verify | liabilities | check');
}

// ------------------------------------------------------------------ names (@name)
const NAME_ALIASES = {
  resolve: 'show', address: 'show', list: 'mine', create: 'register', // synonyms
  ver: 'show', meus: 'mine', registrar: 'register', alterar: 'update', transferir: 'transfer', renovar: 'renew', liberar: 'release', preco: 'price', 'preço': 'price', // legacy names
};
const whenFromNow = (sec) => new Date(Date.now() + sec * 1000).toLocaleDateString('pt-BR');
const nameTypes = { t: 'transparent', s: 'private', q: 'quantum-safe', m: 'multisig' };
function printName(info) {
  if (info.status === 'free') { console.log(`@${info.name} is FREE — registering costs ${formatKRV(BigInt(info.fee))} per year`); return; }
  console.log(`@${info.name}  (${info.status})`);
  console.log(`  points to:   ${info.target}  (${nameTypes[info.targetType] ?? info.targetType})`);
  console.log(`  owner:       ${info.owner}`);
  console.log(`  expires:     ${whenFromNow(info.expiresIn)} (${formatDuration(info.expiresIn)})${info.status === 'grace' ? ` — grace period until ${whenFromNow(info.graceEndsIn)}: only the owner can renew` : ''}`);
  console.log(`  deposit:     ${formatKRV(BigInt(info.deposit))} (returned to the owner when the name is released) · renewal ${formatKRV(BigInt(info.fee))}/year`);
}

async function nameCommand() {
  const sub = NAME_ALIASES[args._[1]] ?? args._[1];
  const raw = args._[2];
  const loadWallet = () => {
    const file = path.resolve(args.file ?? defaultFile(`wallet-${params.name}.json`, `carteira-${params.name}.json`));
    if (!fs.existsSync(file)) throw new Error(`wallet not found: ${file} (create one with: krevo wallet create, or use --file)`);
    return WalletClass.load(file, params, walletUrl, str(args.password));
  };
  const needName = () => { if (!raw) throw new Error(`enter the name, e.g.: krevo name ${sub} @bakery`); return raw; };
  const confirm = async (w, txid, label) => {
    await w.waitAccepted(txid);
    console.log(`  ${label} confirmed (tx ${txid.slice(0, 16)}…)`);
  };
  switch (sub) {
    case 'show':
    case 'price': {
      printName(lightUrl ? await new LightClient(lightUrl.split(',')[0]).name(needName()) : await rpc(rpcUrl, 'resolvename', { name: needName() }));
      return;
    }
    case 'mine': {
      const w = loadWallet();
      const list = await myNames(w);
      if (!list.length) console.log('this wallet has no names yet (register one with: krevo name register @yourname)');
      for (const n of list) console.log(`@${n.name.padEnd(20)} → ${n.target.slice(0, 28)}…  ${n.status}, expires ${whenFromNow(n.expiresIn)}`);
      return;
    }
    case 'register': {
      const w = loadWallet();
      const name = checkName(needName());
      const pending = ['committed', 'compromisso'].includes(w.data.names?.[name]?.state);
      if (!pending) {
        const r = await nameCommit(w, name, { target: str(args.to) ?? 'private' });
        console.log(`1/2 commitment sent for @${name} (just a hash: nobody knows yet which name it is)`);
        console.log(`    yearly name fee: ${formatKRV(r.nameFee)} — it goes to the Security Fund (future miners)`);
        await confirm(w, r.txid, 'commitment');
      } else console.log(`continuing the registration of @${name} (commitment already made)`);
      for (;;) {
        const wait = await nameRevealWait(w, name);
        if (wait === 0) break;
        if (wait !== null) process.stdout.write(`\r    waiting ${Math.ceil(wait)} s (protection against someone copying the name)…   `);
        await sleep(1000);
      }
      process.stdout.write('\n');
      const r = await nameReveal(w, name);
      console.log(`2/2 reveal sent: @${name} registered`);
      await confirm(w, r.txid, 'registration');
      printName(await w.resolveName(name));
      console.log(`\nNow anyone can pay with:  krevo wallet send --to @${name} --amount 1`);
      return;
    }
    case 'update':
    case 'transfer':
    case 'renew':
    case 'release': {
      const w = loadWallet();
      const name = needName();
      let r;
      if (sub === 'update') {
        if (!str(args.to)) throw new Error('enter --to private | transparent | ADDRESS');
        r = await nameUpdate(w, name, str(args.to));
      } else if (sub === 'transfer') {
        if (!str(args.to)) throw new Error('enter --to NEW_OWNER_ADDRESS (krv, krq or multisig)');
        r = await nameTransfer(w, name, str(args.to));
      } else if (sub === 'renew') r = await nameRenew(w, name);
      else r = await nameRelease(w, name);
      const what = { alterar: 'destination changed', transferir: 'name transferred', renovar: `renewed (fee ${formatKRV(r.nameFee ?? 0n)})`, liberar: 'name released; deposit returned' }[sub];
      console.log(`${what} — network fee ${formatKRV(r.fee)}`);
      await confirm(w, r.txid, 'operation');
      printName(await w.resolveName(name));
      return;
    }
    default:
      throw new Error('use: krevo name register | show | mine | update | transfer | renew | release | price  @name');
  }
}

// ------------------------------------------------------------------ atomic swaps
const SWAP_ALIASES = { criar: 'create', aceitar: 'accept', confirmar: 'confirm', lista: 'list', avancar: 'step', 'avançar': 'step', acompanhar: 'watch' }; // legacy names
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function parseWindow(s) {
  const m = /^(\d+(?:[.,]\d+)?)\s*(s|min|h|d)?$/i.exec(String(s).trim());
  if (!m) throw new Error(`invalid time window: "${s}" (e.g. 48h, 2d, 90min)`);
  return Math.round(Number(m[1].replace(',', '.')) * { s: 1, min: 60, h: 3600, d: 86400 }[(m[2] ?? 'h').toLowerCase()]);
}
const defaultBtcNet = () => (params.name === 'mainnet' ? 'mainnet' : params.name === 'testnet' ? 'testnet' : 'regtest');
function latestSwapId(w) {
  const all = Object.values(w.data.swaps ?? {});
  if (!all.length) throw new Error('no swaps in this wallet (create one with: krevo swap create …)');
  const open = all.filter((s) => !s.status);
  return (open.length ? open : all).sort((a, b) => b.created - a.created)[0].id;
}
function printTerms(d) {
  console.log(`  you give:     ${d.give}`);
  console.log(`  you receive:  ${d.receive}   (${d.price})`);
  console.log(`  windows:      initiator ${formatDuration(d.windows.initiator)} · participant ${formatDuration(d.windows.participant)} · Bitcoin ${d.btcNet}`);
  console.log(`  your Bitcoin address (payout/refund): ${d.btcPayout}`);
}
function contractLine(c, st) {
  const what = c.chain === 'krevo' ? 'Krevo  ' : 'Bitcoin';
  const amt = c.chain === 'krevo' ? formatKRV(c.amount) : formatBTC(c.amount);
  const state = st.claimed ? 'claimed' : st.refunded ? 'refunded' : st.funded ? `locked · deadline in ${formatDuration(st.timeLeft ?? 0)}` : st.seen ? 'paid, waiting for confirmation' : 'not locked yet';
  return `${what} ${amt.padEnd(16)} ${c.address}\n                     → ${state}`;
}
function printStep(r, showQr) {
  console.log(`[${new Date().toLocaleTimeString('en-US')}] ${r.message}`);
  if (r.action === 'pay-btc' && showQr && !r.seen) console.log('\n' + qrToTerminal(encodeQR(r.uri, 'M')) + '\n' + r.uri + '\n');
}

async function swapCommand(w, sub) {
  switch (SWAP_ALIASES[sub] ?? sub) {
    case 'create': {
      const sell = str(args.sell)?.toLowerCase();
      if (sell !== 'krv' && sell !== 'btc') throw new Error('use --sell krv (you sell KRV and receive BTC) or --sell btc (you sell BTC and receive KRV)');
      if (!args.krv || !args.btc) throw new Error('enter --krv AMOUNT and --btc AMOUNT');
      const iWindow = parseWindow(args.deadline ?? '48h');
      const r = createOffer(w, {
        sell, krv: parseKRV(args.krv), btc: parseBTC(args.btc), btcNet: str(args['btc-network']) ?? defaultBtcNet(),
        btcPayout: str(args['btc-address']), iWindow, pWindow: Math.round(iWindow / 2), btcApi: str(args['btc-api']) ?? null, btcRpc: str(args['btc-rpc']) ?? null,
      });
      console.log(`Offer created — swap ${r.id}`);
      printTerms(describeSwap(w, getSwap(w, r.id)));
      console.log(`\nSend this code to the other party (it is not secret; the secret stays only in your wallet):\n\n${r.code}\n`);
      console.log('When you receive the acceptance code:  krevo swap confirm --code krx1…');
      return;
    }
    case 'accept': {
      const code = str(args.code);
      if (!code) throw new Error('enter --code krx1… (the offer you received)');
      if (decodeSwapCode(params, code).kind !== 'offer') throw new Error('this code is an acceptance, not an offer');
      const r = acceptOffer(w, code, { btcPayout: str(args['btc-address']), btcApi: str(args['btc-api']) ?? null, btcRpc: str(args['btc-rpc']) ?? null });
      console.log(`Offer accepted — swap ${r.id}`);
      printTerms(describeSwap(w, getSwap(w, r.id)));
      console.log(`\nSend this acceptance code to whoever made the offer:\n\n${r.code}\n`);
      console.log(`Then run:  krevo swap watch --id ${r.id}   (the wallet checks everything before locking your money)`);
      return;
    }
    case 'confirm': {
      const s = importAcceptance(w, str(args.code) ?? '');
      console.log(`Acceptance recorded — swap ${s.id}.\nNow run:  krevo swap watch --id ${s.id}`);
      return;
    }
    case 'list': {
      const l = listSwaps(w);
      if (!l.length) console.log('no swaps in this wallet');
      for (const d of l) console.log(`${d.id}  ${d.role.padEnd(12)} gives ${d.give.padEnd(20)} receives ${d.receive.padEnd(20)} ${d.accepted ? d.status : 'waiting for acceptance'}`);
      return;
    }
    case 'status': {
      const s = getSwap(w, str(args.id) ?? latestSwapId(w));
      const d = describeSwap(w, s);
      console.log(`Swap ${s.id} — you are the ${d.role}`);
      printTerms(d);
      if (!d.myContract) { console.log('\nWaiting for the other party to accept.'); return; }
      const r = await swapStep(w, s.id, { dryRun: true });
      console.log(`  your contract:     ${contractLine(d.myContract, r.my)}`);
      console.log(`  their contract:    ${contractLine(d.theirContract, r.their)}`);
      console.log(`\nNext step: ${r.message}`);
      return;
    }
    case 'step': {
      const r = await swapStep(w, str(args.id) ?? latestSwapId(w));
      printStep(r, true);
      return;
    }
    case 'watch': {
      const id = str(args.id) ?? latestSwapId(w);
      const every = parseDuration(args.interval ?? '5s');
      console.log(`Watching swap ${getSwap(w, id).id} (Ctrl+C to stop; you can come back later — nothing is lost)`);
      let last = null, shownQr = false;
      for (;;) {
        let r;
        try { r = await swapStep(w, id); }
        catch (e) { console.log(`  (temporary failure: ${e.message} — trying again)`); await sleep(every); continue; }
        const key = `${r.action}:${r.seen ?? ''}`;
        if (key !== last || ['lock', 'claim', 'refund'].includes(r.action)) { printStep(r, !shownQr); if (r.action === 'pay-btc') shownQr = true; last = key; }
        if (r.done) break;
        await sleep(every);
      }
      return;
    }
    default:
      throw new Error('use: krevo swap create | accept | confirm | watch | step | status | list');
  }
}

const Q_ALIASES = { endereco: 'address', migrar: 'migrate' }; // legacy names
async function quantumCommand(w) {
  const cmd2 = Q_ALIASES[args._[2]] ?? args._[2];
  switch (cmd2) {
    case 'address':
      console.log(`Quantum-safe address: ${w.qAddress}`);
      console.log('  To spend, the network requires TWO signatures: Schnorr (secp256k1) AND ML-DSA-44 (NIST FIPS 204).');
      console.log('  The keys stay hidden behind a hash until the first spend and come from your 24-word phrase.');
      return;
    case 'status': {
      const st = await w.quantumStatus();
      const total = st.classic + st.quantum + st.shielded;
      const pct = (v) => (total ? `${(Number((v * 1000n) / total) / 10).toLocaleString('en-US')}%` : '—');
      console.log(`Quantum mode: ${st.enabled ? 'ON (change and consolidations go to krq1…)' : 'off'}`);
      console.log(`  protected  quantum   (krq1…): ${formatKRV(st.quantum).padStart(22)}  ${pct(st.quantum)}`);
      console.log(`  exposed    classic   (krv1…): ${formatKRV(st.classic).padStart(22)}  ${pct(st.classic)}   (the public key is in the address itself)`);
      console.log(`  exposed    private   (krs1…): ${formatKRV(st.shielded).padStart(22)}  ${pct(st.shielded)}   (the private pool uses elliptic curves)`);
      if (st.classic > 0n) console.log('  → run "wallet quantum migrate" to move the classic balance to the quantum-safe address.');
      return;
    }
    case 'migrate': {
      const inc = !!args['include-private'];
      if (inc && !args.yes) {
        const st = await w.quantumStatus();
        console.log(`Warning: ${formatKRV(st.shielded)} will leave the private pool to ${w.qAddress.slice(0, 24)}…`);
        console.log('  The AMOUNTS become public (but protected against quantum theft). Repeat with --yes to confirm.');
        return;
      }
      const r = await w.migrateQuantum({ includeShielded: inc });
      console.log(`Quantum mode on. Address: ${r.address}`);
      if (!r.txs.length) console.log('  Nothing to move now (no mature classic coins).');
      for (const t of r.txs) console.log(`  ${t.from.padEnd(12)} ${String(t.inputs).padStart(3)} coins → ${formatKRV(t.amount)}  (fee ${formatKRV(t.fee)})  tx ${t.txid.slice(0, 16)}…`);
      if (r.txs.length) console.log(`  Total moved: ${formatKRV(r.moved)}`);
      if (r.pendingClassic) console.log(`  ${r.pendingClassic} classic coin(s) still immature or pending: run "migrate" again later.`);
      return;
    }
    default:
      throw new Error('use: wallet quantum address | status | migrate [--include-private]');
  }
}

const INH_ALIASES = { criar: 'create', renovar: 'renew', enviar: 'send', importar: 'import', resgatar: 'claim' }; // legacy names

async function inheritanceCommand(w) {
  const cmd2 = INH_ALIASES[args._[2]] ?? args._[2];
  const groups = (w.data.multisigs ??= {});
  const myKey = multisigKey(w.keys).P;
  const plan = () => {
    const name = str(args.name);
    if (!name || !groups[name]) throw new Error(`enter --name of an existing plan (${Object.keys(groups).join(', ') || 'none yet'})`);
    const g = MultisigGroup.fromDescriptor(params, groups[name].descriptor, name);
    if (!g.isInheritance) throw new Error(`"${name}" is not an inheritance plan`);
    return g;
  };
  const role = (g) => (g.indexOf(myKey, 0) >= 0 ? 'owner' : g.indexOf(myKey, 1) >= 0 ? 'heir' : 'observer');
  switch (cmd2) {
    case 'create': {
      const name = str(args.name);
      const heirs = [].concat(args.heirs ?? []).flatMap((k) => String(k).split(',')).map((x) => x.trim()).filter(Boolean);
      if (!name || !heirs.length || !args.after) throw new Error('enter --name, --heirs krk1…[,krk1…] and --after (e.g. 365d)');
      const delay = parseWait(args.after, params);
      if (delay < 1) throw new Error('the waiting time must be greater than zero');
      const g = MultisigGroup.createInheritance(params, myKey, heirs, Number(args.min ?? 1), delay, name);
      groups[name] = { descriptor: g.descriptor, kind: 'heranca', created: Date.now() };
      w.save();
      console.log(`Inheritance plan "${name}"`);
      console.log(`  you (owner) can spend whenever you want, alone`);
      console.log(`  ${g.paths[1].m} of ${g.paths[1].n} heir(s) can claim if the balance stays UNTOUCHED for ${formatWait(delay, params)}`);
      console.log(`Plan address (deposit here):\n  ${g.address}`);
      console.log(`Descriptor (give it to the heirs; they import it with "inheritance import"):\n  ${g.descriptor}`);
      console.log(`Important: run "inheritance renew" before the deadline to prove you are alive — it resets the countdown.`);
      return;
    }
    case 'import': {
      const name = str(args.name);
      if (!name || !args.descriptor) throw new Error('enter --name and --descriptor krm1…');
      const g = MultisigGroup.fromDescriptor(params, str(args.descriptor), name);
      if (!g.isInheritance) throw new Error('this descriptor is not an inheritance plan');
      groups[name] = { descriptor: g.descriptor, kind: 'heranca', created: Date.now() };
      w.save();
      console.log(`Plan "${name}" imported. Your role: ${role(g)}. Waiting time: ${formatWait(g.paths[1].delay, params)} without movement.`);
      console.log(`  ${g.address}`);
      return;
    }
    case 'status': {
      const g = plan();
      const s = await inheritanceStatus(params, rpcUrl, g);
      console.log(`Plan "${g.name}" — your role: ${role(g)}`);
      console.log(`  balance:          ${formatKRV(s.balance)}`);
      console.log(`  waiting time:     ${formatWait(s.delay, params)} without movement`);
      if (!s.count) console.log('  (no balance in the plan)');
      else if (s.claimable === s.balance) console.log(`  heirs:            CAN CLAIM EVERYTHING now (${formatKRV(s.claimable)})`);
      else {
        if (s.claimable > 0n) console.log(`  already unlocked: ${formatKRV(s.claimable)}`);
        console.log(`  unlocks in:       ${formatWait(s.nextUnlock, params)}${s.fullUnlock !== s.nextUnlock ? ` (the whole balance in ${formatWait(s.fullUnlock, params)})` : ''}`);
      }
      return;
    }
    case 'renew': {
      const g = plan();
      if (role(g) !== 'owner') throw new Error('only the owner can renew');
      const r = await spendAlone({ params, rpcUrl, group: g, path: 0, keys: w.keys, to: g.address, sweep: true });
      await w.waitAccepted(r.txid);
      console.log(`Proof of life recorded: ${formatKRV(r.amount)} moved to the plan itself (fee ${formatKRV(r.fee)}).`);
      console.log(`The heirs' countdown restarted: ${formatWait(g.paths[1].delay, params)}.`);
      return;
    }
    case 'send': {
      const g = plan();
      if (role(g) !== 'owner') throw new Error('only the owner can spend without waiting (heirs use "claim")');
      const r = await spendAlone({ params, rpcUrl, group: g, path: 0, keys: w.keys, to: str(args.to), amount: parseKRV(args.amount), memo: str(args.memo) });
      await w.waitAccepted(r.txid);
      console.log(`Sent ${formatKRV(r.amount)} (fee ${formatKRV(r.fee)}). txid ${r.txid}`);
      return;
    }
    case 'claim': {
      const g = plan();
      if (role(g) !== 'heir') throw new Error('only an heir can claim');
      const to = str(args.to) ?? w.tAddress;
      const r = await spendAlone({ params, rpcUrl, group: g, path: 1, keys: w.keys, to, sweep: true });
      await w.waitAccepted(r.txid);
      console.log(`Claimed: ${formatKRV(r.amount)} → ${to.slice(0, 28)}… (fee ${formatKRV(r.fee)}). txid ${r.txid}`);
      return;
    }
    default:
      console.log(HELP);
  }
}

/** Reads a password without showing it in the terminal. */
function askHidden(question) {
  const stdin = process.stdin;
  if (!stdin.isTTY) return Promise.resolve(undefined);
  process.stdout.write(question);
  return new Promise((ok) => {
    let buf = '';
    const done = () => { stdin.setRawMode(false); stdin.pause(); stdin.off('data', on); process.stdout.write(String.fromCharCode(10)); ok(buf); };
    const on = (chunk) => {
      for (const ch of chunk) {
        const c = ch.charCodeAt(0); // 13/10 = Enter, 4 = Ctrl+D, 3 = Ctrl+C, 127/8 = apagar
        if (c === 13 || c === 10 || c === 4) return done();
        if (c === 3) process.exit(130);
        if (c === 127 || c === 8) buf = buf.slice(0, -1); else buf += ch;
      }
    };
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8'); stdin.on('data', on);
  });
}

/**
 * Wallet password without --password on the command line (it ends up in the shell history and
 * in the process list): the KREVO_SENHA variable, or a hidden prompt when the wallet is encrypted.
 */
async function resolvePassword() {
  if (str(args.password) !== undefined) return;
  const envPassword = process.env.KREVO_PASSWORD ?? process.env.KREVO_SENHA; // KREVO_SENHA: older versions
  if (envPassword) { args.password = envPassword; return; }
  const file = path.resolve(args.file ?? (cmd === 'pool' ? defaultFile(`pool-wallet-${params.name}.json`, `carteira-pool-${params.name}.json`) : cmd === 'faucet' ? defaultFile(`faucet-wallet-${params.name}.json`, `carteira-torneira-${params.name}.json`) : defaultFile(`wallet-${params.name}.json`, `carteira-${params.name}.json`)));
  try {
    if (!fs.existsSync(file) || !JSON.parse(fs.readFileSync(file, 'utf8')).seedEnc) return;
  } catch { return; }
  const pw = await askHidden('Wallet password: ');
  if (pw !== undefined) args.password = pw;
}

async function main() {
  if (['wallet', 'escrow', 'reserves', 'name', 'pool', 'swap', 'faucet'].includes(cmd) && !['create', 'restore', 'check-proof'].includes(args._[1])) await resolvePassword();
  switch (cmd) {
    case 'node': {
      // given peers + the network's seed nodes (seeds/<network>.txt), unless --no-seeds
      const given = [].concat(args.peer ?? []).filter((x) => x !== true);
      const peers = [...new Set([...given, ...(args['no-seeds'] ? [] : seedsFor(params.name))])];
      if (peers.length > given.length) log(`${params.name} seed nodes: ${peers.length - given.length}`);
      const node = new Node({
        params, datadir: args.datadir ?? defaultFile('./data', './dados'), p2pPort: Number(args.port ?? params.defaultP2pPort),
        rpcPort: Number(args.rpcport ?? params.defaultRpcPort), rpcHost: str(args.rpchost) ?? '127.0.0.1', peers, log,
      });
      await node.start();
      let last = 0;
      node.on('block', () => {
        const now = Date.now();
        if (now - last < 5000) return;
        last = now;
        const v = node.consensus.virtual;
        log(`blue score ${v.gd.blueScore} | blocks ${node.consensus.store.gd.size} | tips ${node.consensus.tips.size} | mempool ${node.mempool.txs.size} | peers ${node.p2p.peers.size}`);
      });
      const stop = async () => { log('shutting down…'); await node.stop(); process.exit(0); };
      process.on('SIGINT', stop); process.on('SIGTERM', stop);
      break;
    }
    case 'mine': {
      const address = args.address;
      if (!address) throw new Error('enter --address');
      if (args.pool) {
        log(`mining on pool ${args.pool} for ${address}`);
        await runPoolMiner({ pool: String(args.pool), address, worker: str(args.worker) ?? 'cpu', threads: Number(args.threads ?? 1), log });
        break;
      }
      log(`mining for ${address} via ${rpcUrl}`);
      await runMiner({ rpcUrl, address, threads: Number(args.threads ?? 1), log });
      break;
    }
    case 'wallet': {
      const sub = args._[1];
      const file = path.resolve(args.file ?? defaultFile(`wallet-${params.name}.json`, `carteira-${params.name}.json`));
      if (sub === 'create') {
        const w = WalletClass.create(file, params, walletUrl, {
          password: str(args.password) ?? process.env.KREVO_PASSWORD ?? process.env.KREVO_SENHA, passphrase: str(args.passphrase) ?? '', words: Number(args.words ?? 24),
        });
        console.log(`Wallet created: ${file}`);
        printPhrase(w.mnemonic, w.data.hasPassphrase);
        console.log(`\nTransparent address:  ${w.tAddress}\nPrivate address:      ${w.sAddress}\nQuantum-safe address: ${w.qAddress}`);
        return;
      }
      if (sub === 'restore') {
        const phrase = str(args.phrase) ?? await ask('Type the recovery phrase (words separated by spaces): ');
        const w = WalletClass.restore(file, params, walletUrl, {
          mnemonic: phrase, passphrase: str(args.passphrase) ?? '', password: str(args.password),
        });
        console.log(`Wallet restored to ${file}\nTransparent address: ${w.tAddress}\nPrivate address:     ${w.sAddress}`);
        console.log('Use "wallet balance" to sync with the network and see your funds.');
        return;
      }
      if (sub === 'check-proof') {
        const proof = str(args.proof), address = str(args.address);
        if (!proof || !address) throw new Error('enter --proof krp1… and --address krs1… (the address that should have received)');
        const r = await Wallet.verifyProof(params, rpcUrl, { proof, address, message: str(args.message) ?? '' });
        if (!r.valid) {
          console.log(`❌ INVALID PROOF: ${r.reason}`);
          process.exitCode = 2;
          return;
        }
        console.log(`✅ VALID PROOF\n  transaction: ${r.txid}\n  paid ${formatKRV(r.total)} to the address ${address.slice(0, 24)}…`);
        if (r.memo) console.log(`  memo: "${r.memo}"`);
        console.log(`  status: ${r.status === 'accepted' ? `confirmed (${r.confirmations} blue blocks on top)` : r.status}`);
        return;
      }
      const w = WalletClass.load(file, params, walletUrl, str(args.password));
      if (sub === 'multisig') {
        await multisigCommand(w);
      } else if (sub === 'inheritance') {
        await inheritanceCommand(w);
      } else if (sub === 'quantum') {
        await quantumCommand(w);
      } else if (sub === 'phrase') {
        const phrase = w.revealMnemonic(str(args.password));
        if (!phrase) throw new Error('this wallet was created before recovery phrases existed; there is no stored phrase');
        printPhrase(phrase, w.data.hasPassphrase);
      } else if (sub === 'address') {
        console.log(`Transparent:  ${w.tAddress}\nPrivate:      ${w.sAddress}\nQuantum-safe: ${w.qAddress}${w.quantum ? '   (quantum mode on: change goes here)' : ''}`);
      } else if (sub === 'balance') {
        await w.sync();
        const b = w.balance();
        console.log(`Transparent: ${formatKRV(b.transparent)}  (immature: ${formatKRV(b.transparentImmature)}, pending: ${formatKRV(b.transparentPending)})`);
        console.log(`Private:     ${formatKRV(b.shielded)}  (maturing: ${formatKRV(b.shieldedImmature)}, pending: ${formatKRV(b.shieldedPending)})`);
        if (lightUrl) {
          if (b.unverified > 0n) console.log(`Waiting for proof: ${formatKRV(b.unverified)}  (the server reported it, but blocks on top are still missing — it neither counts nor can be spent)`);
          const fraud = Object.entries(w.fraudReports);
          for (const [txid, why] of fraud) console.log(`⚠ the light server sent FALSE data about transaction ${txid.slice(0, 16)}…: ${why}`);
          const tr = w.traffic;
          for (const d of w.discrepancies) console.log(`⚠ ${d}`);
          const n = w.serverUrls.length;
          console.log(`Light wallet · ${n > 1 ? `${n} servers compared${w.discrepancies.length ? '' : ' (they agree)'}` : `server ${lightUrl}`} · scanning ${w.light.delegate ? 'DELEGATED (the server sees what you receive)' : 'local (the server sees nothing)'} · ${(tr.bytes / 1024).toFixed(1)} KB downloaded in ${tr.requests} requests`);
        }
      } else if (sub === 'scanning') {
        if (!lightUrl) throw new Error('the scanning mode only applies to the light wallet (use --light URL)');
        const mode = args._[2];
        if (mode !== 'local' && mode !== 'delegada' && mode !== 'delegated') throw new Error('use: krevo wallet scanning local | delegated --light URL');
        w.setDelegated(mode === 'delegada' || mode === 'delegated');
        console.log(mode !== 'local'
          ? 'DELEGATED scanning: the server receives your view key and finds your payments (saves battery).\n  It can then see how much you receive — but it still cannot spend nor see what you spend.'
          : 'LOCAL scanning: your device tests the outputs; the server receives no key.');
      } else if (sub === 'send') {
        const amount = parseKRV(args.amount);
        const t0 = Date.now();
        const r = await w.send({ to: args.to, amount, from: args.from ?? 'auto', memo: str(args.memo) });
        if (r.name) console.log(`@${r.name} → ${r.to}`);
        if (r.privateInputs) {
          console.log(w.privateInputs === 'fcmp'
            ? `Private input(s): ${r.privateInputs}, each one hidden among ALL ${r.anonymitySet.toLocaleString('en-US')} private outputs of the network (proofs in ${(r.proveMs / 1000).toFixed(1)} s${r.prover === 'native' ? ', native Rust prover' : r.prover?.startsWith('wasm') ? ', Rust core in WebAssembly' : ''})`
            : `Private input(s): ${r.privateInputs}, in a ring of ${r.anonymitySet}`);
        }
        console.log(`Sent! txid ${r.txid}\n  from: ${r.from} | fee: ${formatKRV(r.fee)} | size: ${r.size} bytes`);
        const ms = await w.waitAccepted(r.txid);
        console.log(`  confirmed (accepted by the DAG) ${((Date.now() - t0) / 1000).toFixed(2)} s after sending (${ms} ms after submission)`);
      } else if (sub === 'history') {
        await w.sync();
        const h = w.history();
        console.log('SENT');
        if (!h.sent.length) console.log('  (none)');
        for (const s of h.sent) {
          console.log(`  ${new Date(s.time).toLocaleString('en-US')}  -${formatKRV(s.amount)}  to ${s.to.slice(0, 20)}…  fee ${formatKRV(s.fee)}${s.memo ? `  memo: "${s.memo}"` : ''}`);
          console.log(`      txid ${s.txid}`);
        }
        console.log('RECEIVED (private)');
        if (!h.received.length) console.log('  (none)');
        for (const r of h.received) {
          console.log(`  +${formatKRV(r.amount)}${r.coinbase ? '  (mining)' : ''}${r.spent ? '  [spent]' : ''}${r.memo ? `  memo: "${r.memo}"` : ''}  → ${r.subLabel}   tx ${r.txid.slice(0, 16)}…`);
        }
      } else if (sub === 'subaddress') {
        const s = w.newSubaddress(str(args.label) ?? '');
        console.log(`Subaddress #${s.index}${s.label ? ` (${s.label})` : ''}:
${s.address}`);
        console.log('Nobody can link this address to your other addresses. Money received goes into the same balance.');
      } else if (sub === 'subaddresses') {
        await w.sync();
        for (const s of w.listSubaddresses()) {
          console.log(`#${String(s.index).padEnd(3)} ${s.label.padEnd(28).slice(0, 28)} received: ${formatKRV(s.received).padStart(16)} (${s.count} outputs)`);
          console.log(`     ${s.address}`);
        }
      } else if (sub === 'request') {
        const transparent = args.transparent === true;
        const amount = str(args.amount) ? parseKRV(args.amount) : null;
        let memo = str(args.memo) ?? null;
        if (transparent && memo) throw new Error('memos only work on private payment requests (without --transparent)');
        if (!transparent && !memo) memo = newOrderCode(); // identifies the payment when it arrives
        const label = str(args.label) ?? null;
        const expires = args.expires ? Math.floor(Date.now() / 1000) + Number(args.expires) * 60 : null;
        // each private payment request goes to a NEW subaddress: different customers cannot link
        // their invoices to each other nor to the shop's main address
        let address = w.tAddress;
        if (!transparent) {
          address = args['main-address'] ? w.sAddress
            : w.newSubaddress(`payment request ${memo}${label ? ` — ${label}` : ''}`).address;
        }
        const uri = buildPaymentURI(params, { address, amount, memo, label, expires });
        const qr = encodeQR(uri, 'M');
        console.log(`\nPAYMENT REQUEST${label ? ` — ${label}` : ''}`);
        console.log(`  amount: ${amount ? formatKRV(amount) : '(the payer chooses)'}`);
        if (memo) console.log(`  order:  ${memo}`);
        console.log(`  type:   ${transparent ? 'transparent (public amount)' : 'private (amount and recipient hidden)'}`);
        if (expires) console.log(`  expires: ${new Date(expires * 1000).toLocaleString('en-US')}`);
        console.log('\n' + qrToTerminal(qr) + '\n');
        console.log(uri + '\n');
        if (args.svg) {
          const out = path.resolve(typeof args.svg === 'string' ? args.svg : `payment-request-${memo ?? Date.now()}.svg`);
          const caption = [label, amount ? `${formatKRV(amount)}` : null, memo ? `Order ${memo}` : null].filter(Boolean);
          fs.writeFileSync(out, qrToSvg(qr, { caption }));
          console.log(`QR code saved to ${out} (open it in a browser or print it)`);
        }
        if (args.wait) {
          console.log('Waiting for payment… (Ctrl+C to cancel)');
          const req = parsePaymentURI(params, uri);
          const t0 = Date.now();
          const got = await w.waitForPayment(req);
          console.log(`\n✅ PAID! ${formatKRV(got.amount)} received in ${((Date.now() - t0) / 1000).toFixed(1)} s${got.memo ? ` (order ${got.memo})` : ''}`);
          console.log(`   tx ${got.txid}`);
        }
      } else if (sub === 'pay') {
        const uri = str(args.uri) ?? await ask('Paste the payment link (krevo:…): ');
        const req = parsePaymentURI(params, uri);
        console.log(`\nPAYMENT${req.label ? ` to ${req.label}` : ''}`);
        console.log(`  address: ${req.address.slice(0, 28)}… (${req.type === 's' ? 'private' : 'transparent'})`);
        console.log(`  amount:   ${req.amount ? formatKRV(req.amount) : '(not set in the link)'}`);
        if (req.memo) console.log(`  memo:     ${req.memo}`);
        if (req.expires) console.log(`  expires:  ${new Date(req.expires * 1000).toLocaleString('en-US')}`);
        if (isExpired(req)) throw new Error('this payment request has expired; ask for a new QR code');
        const amount = req.amount ?? (str(args.amount) ? parseKRV(args.amount) : null);
        if (!amount) throw new Error('the link does not set the amount; use --amount');
        if (args.yes !== true) {
          const a = await ask('Confirm payment? (y/N) ');
          if (!/^(s|sim|y|yes)$/i.test(a.trim())) { console.log('Cancelled.'); return; }
        }
        const t0 = Date.now();
        const r = await w.payRequest(uri, { from: args.from ?? 'auto', amount });
        console.log(`Sent! txid ${r.txid}\n  from: ${r.from} | fee: ${formatKRV(r.fee)}`);
        await w.waitAccepted(r.txid);
        console.log(`  confirmed in ${((Date.now() - t0) / 1000).toFixed(2)} s`);
      } else if (sub === 'prove') {
        const txid = str(args.txid);
        if (!txid) throw new Error('enter --txid');
        const proof = w.prove(txid, str(args.message) ?? '');
        console.log(proof);
        console.log('\nSend this proof together with the recipient\'s address. Anyone can verify it with:');
        console.log(`  node src/cli.js wallet check-proof --proof ${proof.slice(0, 16)}… --address ${w.data.sent[txid].to.slice(0, 16)}…${args.message ? ' --message "…"' : ''}`);
        console.log('It reveals the amount and memo of THIS payment, and nothing else about your wallet.');
      } else if (sub === 'viewkey') {
        console.log(w.keys.viewKey(params));
        console.log('Whoever has this key sees the amounts received on your private address, but can NOT spend.');
      } else console.log(HELP);
      break;
    }
    case 'pool': {
      const file = path.resolve(args.file ?? defaultFile(`pool-wallet-${params.name}.json`, `carteira-pool-${params.name}.json`));
      if (!fs.existsSync(file)) throw new Error(`pool wallet not found: ${file} (create one with: wallet create --file ${path.basename(file)})`);
      const wallet = Wallet.load(file, params, rpcUrl, str(args.password));
      const pool = await startPool({
        params, rpcUrl, wallet, port: Number(args.port ?? 5555), webPort: Number(args['web-port'] ?? 8081),
        feePct: Number(String(args.fee ?? '1').replace(',', '.')), minPayout: parseKRV(args['min-payout'] ?? '1'),
        payoutEveryMs: parseDuration(args.interval ?? '60s'), stateFile: path.resolve(args.state ?? defaultFile(file.replace(/\.json$/, '') + '-state.json', file.replace(/\.json$/, '') + '-estado.json')), log,
      });
      log(`Pool running | miners connect to :${Number(args.port ?? 5555)} | stats at ${pool.webUrl} | rewards arrive at ${pool.address}`);
      break;
    }
    case 'name': {
      await nameCommand();
      break;
    }
    case 'escrow': {
      await escrowCommand();
      break;
    }
    case 'reserves': {
      await reservesCommand();
      break;
    }
    case 'faucet': {
      const file = path.resolve(args.file ?? defaultFile(`faucet-wallet-${params.name}.json`, `carteira-torneira-${params.name}.json`));
      if (!fs.existsSync(file)) throw new Error(`faucet wallet not found: ${file} (create one with: wallet create --file ${path.basename(file)} and send KRV to its transparent address)`);
      const w = WalletClass.load(file, params, walletUrl, str(args.password));
      await startFaucet({
        wallet: w, params, port: Number(args.port ?? 8092), host: args.public ? '0.0.0.0' : '127.0.0.1',
        amount: parseKRV(String(args.amount ?? '10')), trustProxy: !!args['trusted-proxy'], log,
      });
      break;
    }
    case 'swap': {
      const file = path.resolve(args.file ?? defaultFile(`wallet-${params.name}.json`, `carteira-${params.name}.json`));
      if (!fs.existsSync(file)) throw new Error(`wallet not found: ${file} (create one with: krevo wallet create, or use --file)`);
      const w = WalletClass.load(file, params, walletUrl, str(args.password));
      await swapCommand(w, args._[1]);
      break;
    }
    case 'btc-sim': {
      const sub = args._[1];
      const api = (str(args['btc-api']) ?? defaultBtcApi('regtest')).replace(/\/+$/, '');
      const post = async (p, body) => {
        const r = await fetch(api + p, { method: 'POST', body: JSON.stringify(body) });
        const t = await r.text();
        if (!r.ok) throw new Error(t);
        return JSON.parse(t);
      };
      if (sub === 'pay') {
        const sats = parseBTC(args.amount);
        const r = await post('/sim/fund', { address: str(args.address), sats: sats.toString() });
        console.log(`Paid ${formatBTC(sats)} to ${args.address} (tx ${r.txid}) — confirmed in the next simulated block.`);
      } else if (sub === 'balance') {
        const r = await fetch(`${api}/address/${str(args.address)}/utxo`);
        const u = await r.json();
        console.log(`${formatBTC(u.reduce((a, x) => a + BigInt(x.value), 0n))} in ${u.length} output(s)`);
      } else if (sub === 'mine' || sub === 'minerar') {
        const r = await post('/sim/mine', { n: Number(args.blocks ?? 1), dt: args.seconds ? Number(args.seconds) : undefined });
        console.log(`height ${r.height} · block time ${new Date(r.time * 1000).toLocaleString('en-US')}`);
      } else {
        const blockMs = parseDuration(args.block ?? '10s');
        const s = await startSimBitcoin({ port: Number(args.port ?? 3002), autoMineMs: blockMs, log });
        log(`SIMULATED Bitcoin (regtest) at ${s.url} — one block every ${blockMs / 1000} s, same API as mempool.space.`);
        log('This is not real Bitcoin: it is for testing swaps without risk. Addresses start with bcrt1.');
      }
      break;
    }
    case 'web-wallet': {
      const ww = await startWebWallet({ port: Number(args.port ?? 8091), host: args.public ? '0.0.0.0' : '127.0.0.1', log });
      log('Open ' + ww.url + ' in a browser (on a phone: install it as an app from the browser menu).');
      log('The app keeps the keys encrypted on the device and talks to any light server — which never gets keys.');
      break;
    }
    case 'light-server': {
      const ls = await startLightServer({ params, rpcUrl, port: Number(args.port ?? 8090), host: args.public ? '0.0.0.0' : '127.0.0.1', log });
      log(`Light server at ${ls.url}${args.public ? ' (open on the network: put HTTPS in front)' : ''} — reading the node ${rpcUrl}`);
      log('It never receives keys; wallets use: krevo wallet balance --light ' + ls.url);
      break;
    }
    case 'explorer': {
      const ex = await startExplorer({ params, rpcUrl, port: Number(args.port ?? 8080), host: args.public ? '0.0.0.0' : '127.0.0.1', log });
      log('Block explorer at ' + ex.url + '  (reading the node ' + rpcUrl + ')');
      break;
    }
    case 'info':
      console.log(JSON.stringify(await rpc(rpcUrl, 'getinfo'), null, 2));
      break;
    case 'emission': {
      const s = emissionSchedule(params);
      console.log('year | reward/block | total issued');
      for (const r of s.rows.filter((r) => r.year <= 8 || r.year % 4 === 0).slice(0, 30)) {
        console.log(`${String(r.year).padStart(3)} | ${formatKRV(r.perBlock).padStart(18)} | ${formatKRV(r.total)}`);
      }
      console.log(`Total scheduled: ${formatKRV(s.total)} (absolute cap: 1,000,000,000 KRV)`);
      break;
    }
    case 'genesis': {
      const g = buildGenesis(params);
      console.log(`network ${params.name}\ngenesis hash: ${g.hashHex}\nmessage: ${params.genesis.message}`);
      break;
    }
    default:
      console.log(HELP);
  }
}

main().catch((e) => { console.error('error: ' + e.message); process.exit(1); });
