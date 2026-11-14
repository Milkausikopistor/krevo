#!/usr/bin/env node
// Linha de comando do Krevo.
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
Krevo (KRV) — implementação de referência

USO
  krevo no        [--rede devnet] [--dados ./dados] [--porta N] [--rpcporta N] [--par host:porta ...]
  krevo minerar   --endereco ENDEREÇO [--rpc URL] [--threads N]           mineração solo (no seu nó)
  krevo minerar   --pool HOST:PORTA --endereco ENDEREÇO [--threads N] [--trabalhador rig1]   num pool
  krevo pool      --arquivo carteira-do-pool.json [--porta 5555] [--porta-web 8081] [--taxa 1]
                  [--pagamento-minimo 1] [--intervalo 60s] [--rpc URL]      roda um pool de mineração
  krevo carteira  criar | restaurar | frase | endereco | saldo | enviar | chave-visualizacao
                  [--arquivo carteira.json] [--rpc URL] [--senha SENHA]
        criar      [--palavras 12|24] [--frase-extra TEXTO]
        restaurar  [--frase "palavra1 palavra2 …"] [--frase-extra TEXTO]   (sem --frase, ela é pedida no terminal)
        frase      mostra a frase de recuperação guardada
        enviar     --para ENDEREÇO --valor 1,5 [--de transparente|privado] [--memo "texto"]
        historico  envios e recebimentos (com memos)
        provar     --txid TXID [--mensagem "texto"]       gera prova de pagamento (krp1…)
        verificar-prova --prova krp1… --endereco krs1… [--mensagem "texto"]   (não precisa de carteira)
        cobrar     --valor 2,5 [--memo "Pedido 123"] [--rotulo "Minha Loja"] [--expira MINUTOS]
                   [--transparente] [--svg arquivo.svg] [--aguardar]      mostra QR code e link krevo:
        pagar      --uri "krevo:…" [--de transparente|privado] [--sim]    paga uma cobrança
        subendereco  [--rotulo "Cliente X"]   cria um novo endereço privado (impossível de ligar aos outros)
        subenderecos                         lista os endereços privados e quanto cada um recebeu
  krevo carteira quantica  endereco | status | migrar           proteção contra computadores quânticos
        endereco   mostra seu endereço quântico (krq1…: Schnorr + ML-DSA, as duas assinaturas são exigidas)
        status     quanto está em endereço clássico, quântico e privado
        migrar     [--incluir-privado] [--sim]   move krv1… → krq1… e liga o modo quântico (troco vai para krq1…)
  krevo nome   registrar | ver | meus | alterar | transferir | renovar | liberar | preco     nomes legíveis (@nome)
        registrar @padaria [--para privado|transparente|ENDEREÇO]   reserva o nome (compromisso + revelação)
        ver @padaria            para onde o nome aponta, dono e vencimento (qualquer um consulta)
        meus                    os nomes desta carteira
        alterar @padaria --para privado|transparente|ENDEREÇO        muda o destino (sem taxa)
        transferir @padaria --para ENDEREÇO_DO_NOVO_DONO              krv, krq ou multiassinatura (sem taxa)
        renovar @padaria        mais 1 ano (paga a taxa)   ·   liberar @padaria   devolve o depósito
        preco @padaria          taxa anual: 3 letras 100 KRV · 4 → 20 · 5 → 5 · 6 ou mais → 1 KRV
  (pagar para um nome: krevo carteira enviar --para @padaria --valor 2)
  krevo garantia  criar | importar | status | depositar | liberar | reembolsar | assinar | resgatar   contrato de garantia
        criar      --nome Pedido42 --comprador krk1… --vendedor krk1… --arbitro krk1… --valor 50 --prazo 30d
        importar   --nome Pedido42 --codigo krm1…        (as outras partes)
        depositar  --nome Pedido42                       (comprador)
        liberar    --nome Pedido42 --para ENDEREÇO_DO_VENDEDOR   ·   reembolsar --nome … --para ENDEREÇO_DO_COMPRADOR
                   cria uma proposta já assinada por você (arquivo); a outra parte usa "assinar"
        assinar    --proposta proposta.json              confere, assina e, com 2 de 3, envia
        resgatar   --nome Pedido42 [--para ENDEREÇO]     (comprador, depois do prazo, sozinho)
  krevo reservas  provar | verificar | passivos | conferir                     prova de reservas (corretoras)
        provar     --mensagem "Exchange X — 13/11/2026" [--saida reservas.json]
        verificar  --prova reservas.json [--mensagem "…"] [--passivos raiz.json]   (qualquer um, com um nó)
        passivos   --clientes clientes.csv [--saida pasta]    árvore de somas: raiz.json + uma prova por cliente
        conferir   --prova cliente.json --raiz raiz.json      (o cliente confere a própria conta)
  krevo troca  criar | aceitar | confirmar | acompanhar | avancar | status | lista     troca atômica com Bitcoin
        criar      --vender krv|btc --krv 100 --btc 0,001 --endereco-btc SEU_ENDEREÇO_BITCOIN
                   [--rede-btc regtest|testnet|signet] [--prazo 48h] [--btc-api URL | --btc-rpc URL]   gera a oferta
        aceitar    --codigo krx1… --endereco-btc SEU_ENDEREÇO_BITCOIN [--btc-api URL | --btc-rpc URL]   gera o aceite
        confirmar  --codigo krx1…      quem fez a oferta registra o aceite recebido
        acompanhar [--id ID]           conduz a troca até o fim: trava, confere, resgata ou reembolsa
        avancar    [--id ID]           só o próximo passo   ·   status [--id ID]   ·   lista
  krevo btc-simulado [--porta 3002] [--bloco 10s]     Bitcoin de teste local (mesma API do mempool.space)
        pagar --endereco bcrt1… --valor 0,001  ·  saldo --endereco bcrt1…  ·  minerar [--blocos 1] [--segundos 600]
  krevo carteira multisig  chave | criar | importar | lista | saldo | propor | assinar | enviar
        chave                                   mostra sua chave de multiassinatura (krk1…)
        criar    --nome Empresa --minimo 2 --chaves krk1…,krk1…,krk1…   (ou --descritor krm1…)
        propor   --nome Empresa --para ENDEREÇO --valor 5 [--memo "…"] [--saida proposta.json]
        assinar  --proposta proposta.json [--sim]      confere e acrescenta sua assinatura
        enviar   --proposta proposta.json [--proposta outra.json]   junta M assinaturas e envia
        (em planos de herança com vários herdeiros: propor ... --caminho 1)
  krevo carteira heranca  criar | status | renovar | enviar | importar | resgatar
        criar     --nome Vovo --herdeiros krk1…[,krk1…] [--minimo 1] --apos 365d   (d, m=meses, a=anos, h, min, s)
        status    --nome Vovo                 saldo e quando os herdeiros poderão resgatar
        renovar   --nome Vovo                 prova de vida: movimenta o saldo e zera o prazo
        enviar    --nome Vovo --para … --valor …     o dono gasta normalmente, sem espera
        importar  --nome Vovo --descritor krm1…      (herdeiro) acompanha o plano
        resgatar  --nome Vovo [--para ENDEREÇO]      (herdeiro) resgata o saldo liberado
  (cobrar usa um subendereço novo a cada cobrança; --endereco-principal para usar o principal)
  krevo info      [--rpc URL]
  krevo explorador [--porta 8080] [--rpc URL]        explorador de blocos no navegador (DAG ao vivo)
  krevo servidor-leve [--porta 8090] [--publico] [--rpc URL]   servidor para carteiras leves (não recebe chaves)
  krevo carteira-web [--porta 8091] [--publico]       app da carteira para navegador e celular (instalável)
  CARTEIRA LEVE: acrescente --leve URL_DO_SERVIDOR a carteira | nome | troca — funciona sem nó próprio
        carteira varredura local | delegada --leve URL    local = privado (padrão); delegada = o servidor vê o que você recebe
  krevo emissao   [--rede mainnet]
  krevo genesis   [--rede mainnet]

Endereços: krv1… = transparente (valores públicos)   krs1… = privado (valores e destinatário ocultos)
           krq1… = transparente resistente a computadores quânticos

English aliases: node | mine | emission
  wallet create|restore|phrase|address|balance|send|history|prove|check-proof|request|pay|subaddress|subaddresses|viewkey
  wallet multisig key|create|import|list|balance|propose|sign|send   --name --min --keys --descriptor --proposal --out --path
  wallet inheritance create|status|renew|send|import|claim            --heirs --after
  wallet quantum address|status|migrate                                --include-private
  name register|show|mine|update|transfer|renew|release|price @name  --to privado|transparente|ADDRESS
  escrow create|import|status|fund|release|refund|sign|reclaim   --buyer --seller --arbiter --amount --deadline --code --proposal
  reserves prove|verify|liabilities|check   --message --proof --liabilities --customers --root   · --light URL1,URL2 compares two servers
  light-server [--port 8090] [--publico]     · any wallet command with --light SERVER_URL · wallet scanning local|delegada
  swap create|accept|confirm|watch|step|status|list   --sell krv|btc --krv --btc --btc-address --btc-network --window --btc-api --btc-rpc --code --id
  btc-sim [pay|balance|mine]                          --port --block --address --amount --blocks --seconds
  --network --datadir --port --rpcport --peer --address --file --password --to --amount --from transparent|private
  --phrase --passphrase --words --memo --message --proof --label --expires --transparent --wait --yes --main-address
`;

// Apelidos em inglês → nomes em português usados internamente.
const OPT_ALIASES = {
  light: 'leve', buyer: 'comprador', seller: 'vendedor', arbiter: 'arbitro', deadline: 'prazo', liabilities: 'passivos', customers: 'clientes', root: 'raiz',
  network: 'rede', datadir: 'dados', port: 'porta', rpcport: 'rpcporta', peer: 'par', address: 'endereco',
  file: 'arquivo', password: 'senha', to: 'para', amount: 'valor', from: 'de',
  phrase: 'frase', passphrase: 'frase-extra', words: 'palavras', message: 'mensagem', proof: 'prova',
  label: 'rotulo', expires: 'expira', transparent: 'transparente', wait: 'aguardar', yes: 'sim',
  'main-address': 'endereco-principal', name: 'nome', min: 'minimo', keys: 'chaves', descriptor: 'descritor',
  proposal: 'proposta', out: 'saida', path: 'caminho', heirs: 'herdeiros', after: 'apos', 'include-private': 'incluir-privado',
  sell: 'vender', 'btc-address': 'endereco-btc', 'btc-network': 'rede-btc', window: 'prazo', code: 'codigo',
  blocks: 'blocos', seconds: 'segundos', block: 'bloco',
  worker: 'trabalhador', 'web-port': 'porta-web', fee: 'taxa', 'min-payout': 'pagamento-minimo', interval: 'intervalo', state: 'estado',
};
const CMD_ALIASES = { node: 'no', mine: 'minerar', wallet: 'carteira', emission: 'emissao', explorer: 'explorador', pool: 'pool', swap: 'troca', 'btc-sim': 'btc-simulado', name: 'nome', names: 'nome', 'light-server': 'servidor-leve', 'web-wallet': 'carteira-web', escrow: 'garantia', reserves: 'reservas' };
const SUB_ALIASES = {
  create: 'criar', restore: 'restaurar', phrase: 'frase', address: 'endereco', balance: 'saldo', send: 'enviar',
  viewkey: 'chave-visualizacao', history: 'historico', prove: 'provar', 'check-proof': 'verificar-prova',
  request: 'cobrar', pay: 'pagar', subaddress: 'subendereco', subaddresses: 'subenderecos', inheritance: 'heranca', scanning: 'varredura',
  quantum: 'quantica', 'quântica': 'quantica',
};
const FROM_ALIASES = { transparent: 'transparente', private: 'privado', shielded: 'privado' };

function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k0 = a.slice(2), k = OPT_ALIASES[k0] ?? k0;
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      if (o[k] === undefined) o[k] = v; else o[k] = [].concat(o[k], v);
    } else o._.push(a);
  }
  if (o._[0]) o._[0] = CMD_ALIASES[o._[0]] ?? o._[0];
  if (o._[1]) o._[1] = SUB_ALIASES[o._[1]] ?? o._[1];
  if (typeof o.de === 'string') o.de = FROM_ALIASES[o.de] ?? o.de;
  return o;
}

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];
const params = getParams(args.rede ?? args.network ?? 'devnet');
const rpcUrl = args.rpc ?? `http://127.0.0.1:${params.defaultRpcPort}`;
// Carteira leve: --leve URL_DO_SERVIDOR_LEVE — usa a Krevo sem nó próprio (o servidor não recebe chaves)
const lightUrl = typeof args.leve === 'string' ? args.leve : undefined;
const WalletClass = lightUrl ? LightWallet : Wallet;
const walletUrl = lightUrl ?? rpcUrl;
const ts = () => new Date().toISOString().slice(11, 23);
const log = (m) => console.log(`[${ts()}] ${m}`);
const str = (v) => (typeof v === 'string' ? v : undefined);

async function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try { return await rl.question(question); } finally { rl.close(); }
}

function printPhrase(mnemonic, hasPassphrase) {
  const words = mnemonic.split(' ');
  const cols = 4, rows = Math.ceil(words.length / cols);
  console.log(`\nFRASE DE RECUPERAÇÃO (${words.length} palavras):\n`);
  for (let r = 0; r < rows; r++) {
    let line = '';
    for (let c = 0; c < cols; c++) {
      const i = c * rows + r;
      if (i < words.length) line += `${String(i + 1).padStart(2)}. ${words[i].padEnd(10)}  `;
    }
    console.log('  ' + line.trimEnd());
  }
  console.log('\n  ⚠  Anote estas palavras em PAPEL, na ordem, e guarde em lugar seguro.');
  console.log('     Com elas você recupera a carteira em qualquer computador, mesmo perdendo este arquivo.');
  console.log('     Quem tiver a frase controla os fundos: nunca digite em sites, nem envie por mensagem ou foto.');
  if (hasPassphrase) console.log('     Você usou uma FRASE EXTRA: ela também é necessária para restaurar (anote separadamente).');
}

const MS_ALIASES = {
  key: 'chave', create: 'criar', import: 'importar', list: 'lista', balance: 'saldo',
  propose: 'propor', sign: 'assinar', send: 'enviar',
};

async function multisigCommand(w) {
  const cmd2 = MS_ALIASES[args._[2]] ?? args._[2];
  const groups = (w.data.multisigs ??= {});
  const group = () => {
    const name = str(args.nome);
    if (!name || !groups[name]) throw new Error(`informe --nome de um grupo existente (${Object.keys(groups).join(', ') || 'nenhum ainda'})`);
    return MultisigGroup.fromDescriptor(params, groups[name].descriptor, name);
  };
  const balanceOf = async (g) => (await groupUtxos(rpcUrl, g)).reduce((a, u) => a + BigInt(u.amount), 0n);
  const files = () => [].concat(args.proposta ?? []).filter((x) => typeof x === 'string');
  const showProposal = (d) => {
    console.log(`  grupo:   ${d.group.m} de ${d.group.n} assinaturas  (${d.group.address.slice(0, 26)}…)`);
    for (const p of d.payments) {
      console.log(`  PAGA:    ${formatKRV(p.amount)} → ${p.to.slice(0, 30)}…${p.private ? ' (privado, valor conferido)' : ''}${p.memo ? `  memo: "${p.memo}"` : ''}`);
    }
    console.log(`  troco:   ${formatKRV(d.change)} volta para o grupo`);
    console.log(`  taxa:    ${formatKRV(d.fee)}`);
    console.log(`  assinaturas: ${d.have} de ${d.need}${d.signers.length ? ` (participantes ${d.signers.map((i) => '#' + (i + 1)).join(', ')})` : ''}`);
  };
  switch (cmd2) {
    case 'chave':
      console.log(encodeMultisigKey(params, multisigKey(w.keys).P));
      console.log('Envie esta chave aos outros participantes. Ela é pública e vem da sua frase de recuperação.');
      return;
    case 'criar':
    case 'importar': {
      const name = str(args.nome);
      if (!name) throw new Error('informe --nome para o grupo (ex.: --nome Empresa)');
      let g;
      if (args.descritor) g = MultisigGroup.fromDescriptor(params, str(args.descritor), name);
      else {
        const keys = [].concat(args.chaves ?? []).flatMap((k) => String(k).split(',')).map((x) => x.trim()).filter(Boolean);
        if (!args.minimo || keys.length < 1) throw new Error('informe --minimo M e --chaves krk1…,krk1… (ou --descritor krm1…)');
        g = MultisigGroup.create(params, Number(args.minimo), keys, name);
      }
      groups[name] = { descriptor: g.descriptor, m: g.m, n: g.n, created: Date.now() };
      w.save();
      console.log(`Grupo "${name}": exige ${g.m} de ${g.n} assinaturas`);
      console.log(`Endereço do grupo (receba aqui):\n  ${g.address}`);
      console.log(`Descritor (os outros participantes importam com ele; GUARDE junto com a frase):\n  ${g.descriptor}`);
      if (g.indexOf(multisigKey(w.keys).P) < 0) console.log('⚠ Sua chave não está neste grupo: você acompanha o saldo, mas não pode assinar.');
      return;
    }
    case 'lista':
      if (!Object.keys(groups).length) console.log('Nenhum grupo. Crie com: carteira multisig criar --nome … --minimo … --chaves …');
      for (const name of Object.keys(groups)) {
        const g = MultisigGroup.fromDescriptor(params, groups[name].descriptor, name);
        console.log(`${name}: ${g.m} de ${g.n} | saldo ${formatKRV(await balanceOf(g))}\n  ${g.address}`);
      }
      return;
    case 'saldo': {
      const g = group();
      console.log(`${g.name} (${g.m} de ${g.n}): ${formatKRV(await balanceOf(g))}`);
      return;
    }
    case 'propor': {
      const g = group();
      if (!str(args.para) || !str(args.valor)) throw new Error('informe --para ENDEREÇO e --valor');
      const prop = await proposePayment({ params, rpcUrl, group: g, to: str(args.para), amount: parseKRV(args.valor), memo: str(args.memo), path: Number(args.caminho ?? 0) });
      const out = path.resolve(str(args.saida) ?? `proposta-${prop.txid.slice(0, 8)}.json`);
      fs.writeFileSync(out, JSON.stringify(prop, null, 2));
      console.log(`Proposta criada: ${out}`);
      showProposal(await checkProposalInputs(params, rpcUrl, prop));
      console.log(`\nEnvie o arquivo aos signatários. Cada um roda:\n  carteira multisig assinar --proposta ${path.basename(out)}`);
      return;
    }
    case 'assinar': {
      const file = files()[0];
      if (!file) throw new Error('informe --proposta arquivo.json');
      const prop = JSON.parse(fs.readFileSync(file, 'utf8'));
      const d = await checkProposalInputs(params, rpcUrl, prop); // confere tudo lendo a própria transação
      console.log('VOCÊ ESTÁ AUTORIZANDO:');
      showProposal(d);
      if (args.sim !== true) {
        const a = await ask('Assinar? (s/N) ');
        if (!/^(s|sim|y|yes)$/i.test(a.trim())) { console.log('Não assinado.'); return; }
      }
      const r = signProposal(params, prop, w.keys);
      const out = str(args.saida) ?? file;
      fs.writeFileSync(out, JSON.stringify(prop, null, 2));
      console.log(`Assinatura do participante #${r.index + 1} adicionada (${r.have} de ${r.need}). Arquivo: ${out}`);
      if (r.have >= r.need) console.log(`Pronta para enviar: carteira multisig enviar --proposta ${path.basename(out)}`);
      else console.log('Passe o arquivo para o próximo signatário.');
      return;
    }
    case 'enviar': {
      const fl = files();
      if (!fl.length) throw new Error('informe --proposta arquivo.json (pode repetir para juntar cópias)');
      const prop = mergeProposals(fl.map((f) => JSON.parse(fs.readFileSync(f, 'utf8'))));
      const tx = finalizeProposal(params, prop);
      const t0 = Date.now();
      const res = await rpc(rpcUrl, 'sendrawtransaction', { tx: tx.serialize().toString('hex') });
      console.log(`Enviado! txid ${res.txid}`);
      await w.waitAccepted(res.txid);
      console.log(`  confirmado em ${((Date.now() - t0) / 1000).toFixed(2)} s`);
      return;
    }
    default:
      console.log(HELP);
  }
}

// ------------------------------------------------------------------ garantia (escrow)
const ESCROW_ALIASES = { create: 'criar', import: 'importar', fund: 'depositar', release: 'liberar', refund: 'reembolsar', sign: 'assinar', reclaim: 'resgatar' };
function openWallet() {
  const file = path.resolve(args.arquivo ?? `carteira-${params.name}.json`);
  if (!fs.existsSync(file)) throw new Error(`carteira não encontrada: ${file} (crie com: krevo carteira criar, ou indique --arquivo)`);
  return Wallet.load(file, params, rpcUrl, str(args.senha));
}
function printEscrow(c, role) {
  console.log(`Garantia "${c.label}" — você é o ${role ? c.roleName(role) : '(não participa)'}`);
  console.log(`  valor: ${formatKRV(c.amount)} · prazo para o comprador reaver sozinho: ${formatWait(c.delay, params)} após o depósito`);
  console.log(`  endereço: ${c.address}`);
}
async function escrowCommand() {
  const sub = ESCROW_ALIASES[args._[1]] ?? args._[1];
  if (sub === 'assinar') {
    const w = openWallet();
    const file = str(args.proposta);
    if (!file) throw new Error('informe --proposta proposta.json');
    const prop = JSON.parse(fs.readFileSync(file, 'utf8'));
    const info = describeEscrowProposal(params, prop);
    console.log(`Proposta: ${info.kind === 'liberar' ? 'LIBERAR para o vendedor' : 'REEMBOLSAR o comprador'} — ${formatKRV(info.amount)} para ${info.to}`);
    console.log(`  já assinada por: ${info.signedBy.map((r) => info.contract.roleName(r)).join(', ')} · você: ${info.contract.roleName(myRole(info.contract, w.keys))}`);
    if (!args.sim) { console.log('Confira o destino e repita com --sim para assinar.'); return; }
    const r = await escrowSign({ params, rpcUrl, prop, walletKeys: w.keys });
    fs.writeFileSync(file, JSON.stringify(prop, null, 2));
    if (r.sent) { console.log(`Enviado com 2 de 3 assinaturas! txid ${r.txid} (taxa ${formatKRV(r.fee)})`); await w.waitAccepted(r.txid); console.log('  confirmado pela rede'); }
    else console.log(`Assinado (${r.have} de 2). Envie ${file} para outra parte assinar.`);
    return;
  }
  const w = openWallet();
  const store = (w.data.escrows ??= {});
  const name = str(args.nome);
  if (!name) throw new Error('informe --nome (um apelido para o contrato)');
  if (sub === 'criar') {
    if (!args.comprador || !args.vendedor || !args.arbitro || !args.valor) throw new Error('informe --comprador, --vendedor e --arbitro (chaves krk1…) e --valor');
    const c = EscrowContract.create(params, { buyer: str(args.comprador), seller: str(args.vendedor), arbiter: str(args.arbitro), delay: parseWait(args.prazo ?? '30d', params), amount: parseKRV(args.valor), label: name });
    store[name] = { code: c.code, created: Date.now() };
    w.save();
    printEscrow(c, myRole(c, w.keys));
    console.log(`\nEnvie este código às outras partes (elas usam: krevo garantia importar --nome ${name} --codigo …):\n\n${c.code}\n`);
    return;
  }
  if (sub === 'importar') {
    const c = EscrowContract.fromCode(params, str(args.codigo) ?? '');
    store[name] = { code: c.code, created: Date.now() };
    w.save();
    printEscrow(c, myRole(c, w.keys));
    return;
  }
  if (!store[name]) throw new Error(`nenhuma garantia chamada "${name}" nesta carteira`);
  const c = EscrowContract.fromCode(params, store[name].code);
  const role = myRole(c, w.keys);
  if (sub === 'status') {
    printEscrow(c, role);
    const st = await escrowStatus(params, rpcUrl, c);
    console.log(`  saldo no contrato: ${formatKRV(st.balance)} ${st.empty ? '(ainda sem depósito, ou já encerrado)' : st.funded ? '(depositado)' : '(depósito incompleto)'}`);
    if (!st.empty) console.log(`  o comprador pode reaver sozinho ${st.refundable ? 'JÁ' : `em ${st.refundIn}`}`);
  } else if (sub === 'depositar') {
    const r = await escrowFund(w, c);
    console.log(`Depositado ${formatKRV(c.amount)} na garantia (tx ${r.txid}, taxa ${formatKRV(r.fee)})`);
  } else if (sub === 'liberar' || sub === 'reembolsar') {
    const prop = await escrowPropose({ params, rpcUrl, contract: c, walletKeys: w.keys, kind: sub, to: str(args.para) });
    const out = path.resolve(str(args.saida) ?? `garantia-${name}-${sub}.json`);
    fs.writeFileSync(out, JSON.stringify(prop, null, 2));
    console.log(`Proposta para ${sub === 'liberar' ? 'liberar ao vendedor' : 'reembolsar o comprador'} ${formatKRV(BigInt(prop.amount))} criada e assinada por você (${c.roleName(role)}).`);
    console.log(`  Envie ${out} para outra parte rodar: krevo garantia assinar --proposta ${path.basename(out)} --sim`);
  } else if (sub === 'resgatar') {
    const r = await escrowReclaim({ params, rpcUrl, contract: c, walletKeys: w.keys, to: str(args.para) ?? w.tAddress });
    console.log(`Resgatado ${formatKRV(r.amount)} (tx ${r.txid})`);
  } else throw new Error('use: krevo garantia criar | importar | status | depositar | liberar | reembolsar | assinar | resgatar');
}

// ------------------------------------------------------------------ prova de reservas
const RES_ALIASES = { prove: 'provar', verify: 'verificar', liabilities: 'passivos', check: 'conferir' };
async function reservesCommand() {
  const sub = RES_ALIASES[args._[1]] ?? args._[1];
  if (sub === 'provar') {
    const w = openWallet();
    const proof = await proveReserves(w, str(args.mensagem));
    const out = path.resolve(str(args.saida) ?? 'reservas.json');
    fs.writeFileSync(out, JSON.stringify(proof, null, 2));
    console.log(`Prova de reservas: ${formatKRV(BigInt(proof.total))} em ${proof.transparent.length} moeda(s) transparente(s) e ${proof.private.length} privada(s)`);
    console.log(`  mensagem: "${proof.message}"\n  arquivo: ${out} (pode ser publicado)`);
  } else if (sub === 'verificar') {
    const proof = JSON.parse(fs.readFileSync(path.resolve(str(args.prova) ?? 'reservas.json'), 'utf8'));
    const r = await verifyReserves(params, rpcUrl, proof, { message: str(args.mensagem) });
    console.log(r.valid ? `✅ RESERVAS PROVADAS: ${formatKRV(r.total)}` : `❌ PROVA COM PROBLEMAS — total que de fato confere: ${formatKRV(r.total)}`);
    console.log(`  transparente ${formatKRV(r.transparent)} · privado ${formatKRV(r.private)} · ${r.coins} moeda(s) · mensagem: "${proof.message}"`);
    for (const i of r.issues) console.log(`  ⚠ ${i}`);
    if (args.passivos) {
      const root = JSON.parse(fs.readFileSync(path.resolve(str(args.passivos)), 'utf8'));
      const owed = BigInt(root.total);
      console.log(r.total >= owed
        ? `✅ SOLVENTE: reservas ${formatKRV(r.total)} ≥ devido aos clientes ${formatKRV(owed)} (${root.accounts} contas)`
        : `❌ FALTA DINHEIRO: reservas ${formatKRV(r.total)} < devido aos clientes ${formatKRV(owed)}`);
    }
    if (!r.valid) process.exitCode = 2;
  } else if (sub === 'passivos') {
    const accounts = parseAccountsCsv(fs.readFileSync(path.resolve(str(args.clientes) ?? 'clientes.csv'), 'utf8'));
    const { root, proofs } = buildLiabilities(accounts, { label: str(args.rotulo) ?? '' });
    const dir = path.resolve(str(args.saida) ?? 'passivos');
    fs.mkdirSync(path.join(dir, 'clientes'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'raiz.json'), JSON.stringify(root, null, 2));
    for (const p of proofs) fs.writeFileSync(path.join(dir, 'clientes', `${p.id.replace(/[^\w.-]/g, '_')}.json`), JSON.stringify(p, null, 2));
    console.log(`Árvore de passivos: ${root.accounts} contas, total devido ${formatKRV(BigInt(root.total))}`);
    console.log(`  publique ${path.join(dir, 'raiz.json')}; entregue a cada cliente (em particular) o arquivo dele em ${path.join(dir, 'clientes')}`);
  } else if (sub === 'conferir') {
    const proof = JSON.parse(fs.readFileSync(path.resolve(str(args.prova)), 'utf8'));
    const root = JSON.parse(fs.readFileSync(path.resolve(str(args.raiz) ?? 'raiz.json'), 'utf8'));
    const r = verifyLiability(proof, root);
    console.log(r.valid
      ? `✅ Sua conta "${proof.id}" com ${formatKRV(r.balance)} está somada no total publicado (${formatKRV(r.total)}).`
      : `❌ NÃO confere: ${r.reason}`);
    if (!r.valid) process.exitCode = 2;
  } else throw new Error('use: krevo reservas provar | verificar | passivos | conferir');
}

// ------------------------------------------------------------------ nomes (@nome)
const NAME_ALIASES = {
  register: 'registrar', show: 'ver', resolve: 'ver', mine: 'meus', list: 'meus', update: 'alterar', transfer: 'transferir',
  renew: 'renovar', release: 'liberar', price: 'preco', 'preço': 'preco', criar: 'registrar', endereco: 'ver',
};
const whenFromNow = (sec) => new Date(Date.now() + sec * 1000).toLocaleDateString('pt-BR');
const nameTypes = { t: 'transparente', s: 'privado', q: 'quântico', m: 'multiassinatura' };
function printName(info) {
  if (info.status === 'livre') { console.log(`@${info.name} está LIVRE — registrar custa ${formatKRV(BigInt(info.fee))} por ano`); return; }
  console.log(`@${info.name}  (${info.status})`);
  console.log(`  aponta para: ${info.target}  (${nameTypes[info.targetType] ?? info.targetType})`);
  console.log(`  dono:        ${info.owner}`);
  console.log(`  vence em:    ${whenFromNow(info.expiresIn)} (${formatDuration(info.expiresIn)})${info.status === 'em carência' ? ` — carência até ${whenFromNow(info.graceEndsIn)}: só o dono renova` : ''}`);
  console.log(`  depósito:    ${formatKRV(BigInt(info.deposit))} (volta ao dono se ele liberar o nome) · renovação ${formatKRV(BigInt(info.fee))}/ano`);
}

async function nameCommand() {
  const sub = NAME_ALIASES[args._[1]] ?? args._[1];
  const raw = args._[2];
  const loadWallet = () => {
    const file = path.resolve(args.arquivo ?? `carteira-${params.name}.json`);
    if (!fs.existsSync(file)) throw new Error(`carteira não encontrada: ${file} (crie com: krevo carteira criar, ou indique --arquivo)`);
    return WalletClass.load(file, params, walletUrl, str(args.senha));
  };
  const needName = () => { if (!raw) throw new Error(`informe o nome, ex.: krevo nome ${sub} @padaria`); return raw; };
  const confirm = async (w, txid, label) => {
    await w.waitAccepted(txid);
    console.log(`  ${label} confirmado (tx ${txid.slice(0, 16)}…)`);
  };
  switch (sub) {
    case 'ver':
    case 'preco': {
      printName(lightUrl ? await new LightClient(lightUrl.split(',')[0]).name(needName()) : await rpc(rpcUrl, 'resolvename', { name: needName() }));
      return;
    }
    case 'meus': {
      const w = loadWallet();
      const list = await myNames(w);
      if (!list.length) console.log('esta carteira ainda não tem nomes (registre com: krevo nome registrar @seunome)');
      for (const n of list) console.log(`@${n.name.padEnd(20)} → ${n.target.slice(0, 28)}…  ${n.status}, vence ${whenFromNow(n.expiresIn)}`);
      return;
    }
    case 'registrar': {
      const w = loadWallet();
      const name = checkName(needName());
      const pending = w.data.names?.[name]?.state === 'compromisso';
      if (!pending) {
        const r = await nameCommit(w, name, { target: str(args.para) ?? 'privado' });
        console.log(`1/2 compromisso enviado para @${name} (só um hash: ninguém sabe ainda qual nome é)`);
        console.log(`    taxa anual do nome: ${formatKRV(r.nameFee)} — vai para o Fundo de Segurança (mineradores do futuro)`);
        await confirm(w, r.txid, 'compromisso');
      } else console.log(`continuando o registro de @${name} (compromisso já feito)`);
      for (;;) {
        const wait = await nameRevealWait(w, name);
        if (wait === 0) break;
        if (wait !== null) process.stdout.write(`\r    aguardando ${Math.ceil(wait)} s (proteção contra quem tenta copiar o nome)…   `);
        await sleep(1000);
      }
      process.stdout.write('\n');
      const r = await nameReveal(w, name);
      console.log(`2/2 revelação enviada: @${name} registrado`);
      await confirm(w, r.txid, 'registro');
      printName(await w.resolveName(name));
      console.log(`\nAgora qualquer pessoa pode pagar com:  krevo carteira enviar --para @${name} --valor 1`);
      return;
    }
    case 'alterar':
    case 'transferir':
    case 'renovar':
    case 'liberar': {
      const w = loadWallet();
      const name = needName();
      let r;
      if (sub === 'alterar') {
        if (!str(args.para)) throw new Error('informe --para privado | transparente | ENDEREÇO');
        r = await nameUpdate(w, name, str(args.para));
      } else if (sub === 'transferir') {
        if (!str(args.para)) throw new Error('informe --para ENDEREÇO_DO_NOVO_DONO (krv, krq ou multiassinatura)');
        r = await nameTransfer(w, name, str(args.para));
      } else if (sub === 'renovar') r = await nameRenew(w, name);
      else r = await nameRelease(w, name);
      const what = { alterar: 'destino alterado', transferir: 'nome transferido', renovar: `renovado (taxa ${formatKRV(r.nameFee ?? 0n)})`, liberar: 'nome liberado; depósito devolvido' }[sub];
      console.log(`${what} — taxa de rede ${formatKRV(r.fee)}`);
      await confirm(w, r.txid, 'operação');
      printName(await w.resolveName(name));
      return;
    }
    default:
      throw new Error('use: krevo nome registrar | ver | meus | alterar | transferir | renovar | liberar | preco  @nome');
  }
}

// ------------------------------------------------------------------ troca atômica
const SWAP_ALIASES = { create: 'criar', accept: 'aceitar', confirm: 'confirmar', list: 'lista', step: 'avancar', watch: 'acompanhar', 'avançar': 'avancar' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function parseWindow(s) {
  const m = /^(\d+(?:[.,]\d+)?)\s*(s|min|h|d)?$/i.exec(String(s).trim());
  if (!m) throw new Error(`prazo inválido: "${s}" (ex.: 48h, 2d, 90min)`);
  return Math.round(Number(m[1].replace(',', '.')) * { s: 1, min: 60, h: 3600, d: 86400 }[(m[2] ?? 'h').toLowerCase()]);
}
const defaultBtcNet = () => (params.name === 'mainnet' ? 'mainnet' : params.name === 'testnet' ? 'testnet' : 'regtest');
function latestSwapId(w) {
  const all = Object.values(w.data.swaps ?? {});
  if (!all.length) throw new Error('nenhuma troca nesta carteira (crie com: krevo troca criar …)');
  const open = all.filter((s) => !s.status);
  return (open.length ? open : all).sort((a, b) => b.created - a.created)[0].id;
}
function printTerms(d) {
  console.log(`  você dá:      ${d.give}`);
  console.log(`  você recebe:  ${d.receive}   (${d.price})`);
  console.log(`  prazos:       iniciador ${formatDuration(d.windows.initiator)} · participante ${formatDuration(d.windows.participant)} · Bitcoin ${d.btcNet}`);
  console.log(`  seu endereço Bitcoin (recebimento/reembolso): ${d.btcPayout}`);
}
function contractLine(c, st) {
  const what = c.chain === 'krevo' ? 'Krevo  ' : 'Bitcoin';
  const amt = c.chain === 'krevo' ? formatKRV(c.amount) : formatBTC(c.amount);
  const state = st.claimed ? 'resgatado' : st.refunded ? 'reembolsado' : st.funded ? `travado · prazo em ${formatDuration(st.timeLeft ?? 0)}` : st.seen ? 'pago, aguardando confirmação' : 'ainda não travado';
  return `${what} ${amt.padEnd(16)} ${c.address}\n                     → ${state}`;
}
function printStep(r, showQr) {
  console.log(`[${new Date().toLocaleTimeString('pt-BR')}] ${r.message}`);
  if (r.action === 'pay-btc' && showQr && !r.seen) console.log('\n' + qrToTerminal(encodeQR(r.uri, 'M')) + '\n' + r.uri + '\n');
}

async function swapCommand(w, sub) {
  switch (SWAP_ALIASES[sub] ?? sub) {
    case 'criar': {
      const sell = str(args.vender)?.toLowerCase();
      if (sell !== 'krv' && sell !== 'btc') throw new Error('use --vender krv (você vende KRV e recebe BTC) ou --vender btc (vende BTC e recebe KRV)');
      if (!args.krv || !args.btc) throw new Error('informe --krv VALOR e --btc VALOR');
      const iWindow = parseWindow(args.prazo ?? '48h');
      const r = createOffer(w, {
        sell, krv: parseKRV(args.krv), btc: parseBTC(args.btc), btcNet: str(args['rede-btc']) ?? defaultBtcNet(),
        btcPayout: str(args['endereco-btc']), iWindow, pWindow: Math.round(iWindow / 2), btcApi: str(args['btc-api']) ?? null, btcRpc: str(args['btc-rpc']) ?? null,
      });
      console.log(`Oferta criada — troca ${r.id}`);
      printTerms(describeSwap(w, getSwap(w, r.id)));
      console.log(`\nEnvie este código à outra parte (não é segredo; o segredo fica só na sua carteira):\n\n${r.code}\n`);
      console.log('Quando receber o código de aceite:  krevo troca confirmar --codigo krx1…');
      return;
    }
    case 'aceitar': {
      const code = str(args.codigo);
      if (!code) throw new Error('informe --codigo krx1… (a oferta que você recebeu)');
      if (decodeSwapCode(params, code).kind !== 'offer') throw new Error('este código é um aceite, não uma oferta');
      const r = acceptOffer(w, code, { btcPayout: str(args['endereco-btc']), btcApi: str(args['btc-api']) ?? null, btcRpc: str(args['btc-rpc']) ?? null });
      console.log(`Oferta aceita — troca ${r.id}`);
      printTerms(describeSwap(w, getSwap(w, r.id)));
      console.log(`\nEnvie este código de aceite a quem fez a oferta:\n\n${r.code}\n`);
      console.log(`Depois rode:  krevo troca acompanhar --id ${r.id}   (a carteira confere tudo antes de travar o seu dinheiro)`);
      return;
    }
    case 'confirmar': {
      const s = importAcceptance(w, str(args.codigo) ?? '');
      console.log(`Aceite registrado — troca ${s.id}.\nAgora rode:  krevo troca acompanhar --id ${s.id}`);
      return;
    }
    case 'lista': {
      const l = listSwaps(w);
      if (!l.length) console.log('nenhuma troca nesta carteira');
      for (const d of l) console.log(`${d.id}  ${d.role.padEnd(12)} dá ${d.give.padEnd(20)} recebe ${d.receive.padEnd(20)} ${d.accepted ? d.status : 'aguardando aceite'}`);
      return;
    }
    case 'status': {
      const s = getSwap(w, str(args.id) ?? latestSwapId(w));
      const d = describeSwap(w, s);
      console.log(`Troca ${s.id} — você é o ${d.role}`);
      printTerms(d);
      if (!d.myContract) { console.log('\nAguardando o aceite da outra parte.'); return; }
      const r = await swapStep(w, s.id, { dryRun: true });
      console.log(`  seu contrato:      ${contractLine(d.myContract, r.my)}`);
      console.log(`  contrato do outro: ${contractLine(d.theirContract, r.their)}`);
      console.log(`\nPróximo passo: ${r.message}`);
      return;
    }
    case 'avancar': {
      const r = await swapStep(w, str(args.id) ?? latestSwapId(w));
      printStep(r, true);
      return;
    }
    case 'acompanhar': {
      const id = str(args.id) ?? latestSwapId(w);
      const every = parseDuration(args.intervalo ?? '5s');
      console.log(`Acompanhando a troca ${getSwap(w, id).id} (Ctrl+C para sair; pode voltar depois — nada se perde)`);
      let last = null, shownQr = false;
      for (;;) {
        let r;
        try { r = await swapStep(w, id); }
        catch (e) { console.log(`  (falha temporária: ${e.message} — tentando de novo)`); await sleep(every); continue; }
        const key = `${r.action}:${r.seen ?? ''}`;
        if (key !== last || ['lock', 'claim', 'refund'].includes(r.action)) { printStep(r, !shownQr); if (r.action === 'pay-btc') shownQr = true; last = key; }
        if (r.done) break;
        await sleep(every);
      }
      return;
    }
    default:
      throw new Error('use: krevo troca criar | aceitar | confirmar | acompanhar | avancar | status | lista');
  }
}

const Q_ALIASES = { address: 'endereco', status: 'status', migrate: 'migrar' };
async function quantumCommand(w) {
  const cmd2 = Q_ALIASES[args._[2]] ?? args._[2];
  switch (cmd2) {
    case 'endereco':
      console.log(`Endereço quântico: ${w.qAddress}`);
      console.log('  Para gastar, a rede exige DUAS assinaturas: Schnorr (secp256k1) E ML-DSA-44 (NIST FIPS 204).');
      console.log('  As chaves ficam escondidas atrás de um hash até o primeiro gasto e vêm da sua frase de 24 palavras.');
      return;
    case 'status': {
      const st = await w.quantumStatus();
      const total = st.classic + st.quantum + st.shielded;
      const pct = (v) => (total ? `${(Number((v * 1000n) / total) / 10).toLocaleString('pt-BR')}%` : '—');
      console.log(`Modo quântico: ${st.enabled ? 'LIGADO (troco e consolidações vão para krq1…)' : 'desligado'}`);
      console.log(`  protegido  quântico (krq1…): ${formatKRV(st.quantum).padStart(22)}  ${pct(st.quantum)}`);
      console.log(`  exposto    clássico (krv1…): ${formatKRV(st.classic).padStart(22)}  ${pct(st.classic)}   (a chave pública está no próprio endereço)`);
      console.log(`  exposto    privado  (krs1…): ${formatKRV(st.shielded).padStart(22)}  ${pct(st.shielded)}   (o pool privado usa curvas elípticas)`);
      if (st.classic > 0n) console.log('  → rode "carteira quantica migrar" para mover o saldo clássico para o endereço quântico.');
      return;
    }
    case 'migrar': {
      const inc = !!args['incluir-privado'];
      if (inc && !args.sim) {
        const st = await w.quantumStatus();
        console.log(`Atenção: ${formatKRV(st.shielded)} sairão do pool privado para ${w.qAddress.slice(0, 24)}…`);
        console.log('  Os VALORES ficam públicos (mas protegidos contra roubo quântico). Repita com --sim para confirmar.');
        return;
      }
      const r = await w.migrateQuantum({ includeShielded: inc });
      console.log(`Modo quântico ligado. Endereço: ${r.address}`);
      if (!r.txs.length) console.log('  Nada para mover agora (sem moedas clássicas maduras).');
      for (const t of r.txs) console.log(`  ${t.from.padEnd(12)} ${String(t.inputs).padStart(3)} moedas → ${formatKRV(t.amount)}  (taxa ${formatKRV(t.fee)})  tx ${t.txid.slice(0, 16)}…`);
      if (r.txs.length) console.log(`  Total movido: ${formatKRV(r.moved)}`);
      if (r.pendingClassic) console.log(`  ${r.pendingClassic} moeda(s) clássica(s) ainda imaturas ou pendentes: rode "migrar" de novo mais tarde.`);
      return;
    }
    default:
      throw new Error('use: carteira quantica endereco | status | migrar [--incluir-privado]');
  }
}

const INH_ALIASES = { create: 'criar', status: 'status', renew: 'renovar', send: 'enviar', import: 'importar', claim: 'resgatar' };

async function inheritanceCommand(w) {
  const cmd2 = INH_ALIASES[args._[2]] ?? args._[2];
  const groups = (w.data.multisigs ??= {});
  const myKey = multisigKey(w.keys).P;
  const plan = () => {
    const name = str(args.nome);
    if (!name || !groups[name]) throw new Error(`informe --nome de um plano existente (${Object.keys(groups).join(', ') || 'nenhum ainda'})`);
    const g = MultisigGroup.fromDescriptor(params, groups[name].descriptor, name);
    if (!g.isInheritance) throw new Error(`"${name}" não é um plano de herança`);
    return g;
  };
  const role = (g) => (g.indexOf(myKey, 0) >= 0 ? 'dono' : g.indexOf(myKey, 1) >= 0 ? 'herdeiro' : 'observador');
  switch (cmd2) {
    case 'criar': {
      const name = str(args.nome);
      const heirs = [].concat(args.herdeiros ?? []).flatMap((k) => String(k).split(',')).map((x) => x.trim()).filter(Boolean);
      if (!name || !heirs.length || !args.apos) throw new Error('informe --nome, --herdeiros krk1…[,krk1…] e --apos (ex.: 365d)');
      const delay = parseWait(args.apos, params);
      if (delay < 1) throw new Error('o prazo precisa ser maior que zero');
      const g = MultisigGroup.createInheritance(params, myKey, heirs, Number(args.minimo ?? 1), delay, name);
      groups[name] = { descriptor: g.descriptor, kind: 'heranca', created: Date.now() };
      w.save();
      console.log(`Plano de herança "${name}"`);
      console.log(`  você (dono) gasta quando quiser, sozinho`);
      console.log(`  ${g.paths[1].m} de ${g.paths[1].n} herdeiro(s) podem resgatar se o saldo ficar PARADO por ${formatWait(delay, params)}`);
      console.log(`Endereço do plano (deposite aqui):\n  ${g.address}`);
      console.log(`Descritor (entregue aos herdeiros; eles importam com "heranca importar"):\n  ${g.descriptor}`);
      console.log(`Importante: rode "heranca renovar" antes do prazo para provar que está vivo — isso zera a contagem.`);
      return;
    }
    case 'importar': {
      const name = str(args.nome);
      if (!name || !args.descritor) throw new Error('informe --nome e --descritor krm1…');
      const g = MultisigGroup.fromDescriptor(params, str(args.descritor), name);
      if (!g.isInheritance) throw new Error('este descritor não é de um plano de herança');
      groups[name] = { descriptor: g.descriptor, kind: 'heranca', created: Date.now() };
      w.save();
      console.log(`Plano "${name}" importado. Seu papel: ${role(g)}. Prazo: ${formatWait(g.paths[1].delay, params)} sem movimentação.`);
      console.log(`  ${g.address}`);
      return;
    }
    case 'status': {
      const g = plan();
      const s = await inheritanceStatus(params, rpcUrl, g);
      console.log(`Plano "${g.name}" — seu papel: ${role(g)}`);
      console.log(`  saldo:            ${formatKRV(s.balance)}`);
      console.log(`  prazo:            ${formatWait(s.delay, params)} sem movimentação`);
      if (!s.count) console.log('  (sem saldo no plano)');
      else if (s.claimable === s.balance) console.log(`  herdeiros:        PODEM RESGATAR TUDO agora (${formatKRV(s.claimable)})`);
      else {
        if (s.claimable > 0n) console.log(`  já liberado:      ${formatKRV(s.claimable)}`);
        console.log(`  libera em:        ${formatWait(s.nextUnlock, params)}${s.fullUnlock !== s.nextUnlock ? ` (todo o saldo em ${formatWait(s.fullUnlock, params)})` : ''}`);
      }
      return;
    }
    case 'renovar': {
      const g = plan();
      if (role(g) !== 'dono') throw new Error('só o dono pode renovar');
      const r = await spendAlone({ params, rpcUrl, group: g, path: 0, keys: w.keys, to: g.address, sweep: true });
      await w.waitAccepted(r.txid);
      console.log(`Prova de vida registrada: ${formatKRV(r.amount)} movimentados para o próprio plano (taxa ${formatKRV(r.fee)}).`);
      console.log(`O prazo dos herdeiros recomeçou: ${formatWait(g.paths[1].delay, params)}.`);
      return;
    }
    case 'enviar': {
      const g = plan();
      if (role(g) !== 'dono') throw new Error('só o dono pode gastar sem espera (herdeiros usam "resgatar")');
      const r = await spendAlone({ params, rpcUrl, group: g, path: 0, keys: w.keys, to: str(args.para), amount: parseKRV(args.valor), memo: str(args.memo) });
      await w.waitAccepted(r.txid);
      console.log(`Enviado ${formatKRV(r.amount)} (taxa ${formatKRV(r.fee)}). txid ${r.txid}`);
      return;
    }
    case 'resgatar': {
      const g = plan();
      if (role(g) !== 'herdeiro') throw new Error('só um herdeiro pode resgatar');
      const to = str(args.para) ?? w.tAddress;
      const r = await spendAlone({ params, rpcUrl, group: g, path: 1, keys: w.keys, to, sweep: true });
      await w.waitAccepted(r.txid);
      console.log(`Resgatado: ${formatKRV(r.amount)} → ${to.slice(0, 28)}… (taxa ${formatKRV(r.fee)}). txid ${r.txid}`);
      return;
    }
    default:
      console.log(HELP);
  }
}

/** Lê uma senha sem mostrá-la no terminal. */
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
 * Senha da carteira sem precisar de --senha na linha de comando (que fica no histórico do shell e
 * na lista de processos): variável KREVO_SENHA, ou pergunta escondida quando a carteira é cifrada.
 */
async function resolvePassword() {
  if (str(args.senha) !== undefined) return;
  if (process.env.KREVO_SENHA) { args.senha = process.env.KREVO_SENHA; return; }
  const file = path.resolve(args.arquivo ?? (cmd === 'pool' ? `carteira-pool-${params.name}.json` : `carteira-${params.name}.json`));
  try {
    if (!fs.existsSync(file) || !JSON.parse(fs.readFileSync(file, 'utf8')).seedEnc) return;
  } catch { return; }
  const pw = await askHidden('Senha da carteira: ');
  if (pw !== undefined) args.senha = pw;
}

async function main() {
  if (['carteira', 'garantia', 'reservas', 'nome', 'pool', 'troca'].includes(cmd) && !['criar', 'restaurar', 'verificar-prova'].includes(args._[1])) await resolvePassword();
  switch (cmd) {
    case 'no':
    case 'node': {
      const peers = [].concat(args.par ?? args.peer ?? []).filter((x) => x !== true);
      const node = new Node({
        params, datadir: args.dados ?? args.datadir ?? './dados', p2pPort: Number(args.porta ?? params.defaultP2pPort),
        rpcPort: Number(args.rpcporta ?? params.defaultRpcPort), peers, log,
      });
      await node.start();
      let last = 0;
      node.on('block', () => {
        const now = Date.now();
        if (now - last < 5000) return;
        last = now;
        const v = node.consensus.virtual;
        log(`blue score ${v.gd.blueScore} | blocos ${node.consensus.store.gd.size} | pontas ${node.consensus.tips.size} | mempool ${node.mempool.txs.size} | pares ${node.p2p.peers.size}`);
      });
      const stop = async () => { log('encerrando…'); await node.stop(); process.exit(0); };
      process.on('SIGINT', stop); process.on('SIGTERM', stop);
      break;
    }
    case 'minerar':
    case 'mine': {
      const address = args.endereco ?? args.address;
      if (!address) throw new Error('informe --endereco');
      if (args.pool) {
        log(`minerando no pool ${args.pool} para ${address}`);
        await runPoolMiner({ pool: String(args.pool), address, worker: str(args.trabalhador) ?? 'cpu', threads: Number(args.threads ?? 1), log });
        break;
      }
      log(`minerando para ${address} via ${rpcUrl}`);
      await runMiner({ rpcUrl, address, threads: Number(args.threads ?? 1), log });
      break;
    }
    case 'carteira':
    case 'wallet': {
      const sub = args._[1];
      const file = path.resolve(args.arquivo ?? `carteira-${params.name}.json`);
      if (sub === 'criar') {
        const w = WalletClass.create(file, params, walletUrl, {
          password: str(args.senha) ?? process.env.KREVO_SENHA, passphrase: str(args['frase-extra']) ?? '', words: Number(args.palavras ?? 24),
        });
        console.log(`Carteira criada: ${file}`);
        printPhrase(w.mnemonic, w.data.hasPassphrase);
        console.log(`\nEndereço transparente: ${w.tAddress}\nEndereço privado:      ${w.sAddress}\nEndereço quântico:     ${w.qAddress}`);
        return;
      }
      if (sub === 'restaurar') {
        const phrase = str(args.frase) ?? await ask('Digite a frase de recuperação (palavras separadas por espaço): ');
        const w = WalletClass.restore(file, params, walletUrl, {
          mnemonic: phrase, passphrase: str(args['frase-extra']) ?? '', password: str(args.senha),
        });
        console.log(`Carteira restaurada em ${file}\nEndereço transparente: ${w.tAddress}\nEndereço privado:      ${w.sAddress}`);
        console.log('Use "carteira saldo" para sincronizar com a rede e ver os fundos.');
        return;
      }
      if (sub === 'verificar-prova') {
        const proof = str(args.prova), address = str(args.endereco);
        if (!proof || !address) throw new Error('informe --prova krp1… e --endereco krs1… (o endereço que teria recebido)');
        const r = await Wallet.verifyProof(params, rpcUrl, { proof, address, message: str(args.mensagem) ?? '' });
        if (!r.valid) {
          console.log(`❌ PROVA INVÁLIDA: ${r.reason}`);
          process.exitCode = 2;
          return;
        }
        console.log(`✅ PROVA VÁLIDA\n  transação: ${r.txid}\n  pagou ${formatKRV(r.total)} ao endereço ${address.slice(0, 24)}…`);
        if (r.memo) console.log(`  memo: "${r.memo}"`);
        console.log(`  situação: ${r.status === 'accepted' ? `confirmada (${r.confirmations} blocos azuis acima)` : r.status}`);
        return;
      }
      const w = WalletClass.load(file, params, walletUrl, str(args.senha));
      if (sub === 'multisig') {
        await multisigCommand(w);
      } else if (sub === 'heranca') {
        await inheritanceCommand(w);
      } else if (sub === 'quantica') {
        await quantumCommand(w);
      } else if (sub === 'frase') {
        const phrase = w.revealMnemonic(str(args.senha));
        if (!phrase) throw new Error('esta carteira foi criada antes da frase de recuperação existir; não há frase guardada');
        printPhrase(phrase, w.data.hasPassphrase);
      } else if (sub === 'endereco') {
        console.log(`Transparente: ${w.tAddress}\nPrivado:      ${w.sAddress}\nQuântico:     ${w.qAddress}${w.quantum ? '   (modo quântico ligado: troco vai para cá)' : ''}`);
      } else if (sub === 'saldo') {
        await w.sync();
        const b = w.balance();
        console.log(`Transparente: ${formatKRV(b.transparent)}  (imaturo: ${formatKRV(b.transparentImmature)}, pendente: ${formatKRV(b.transparentPending)})`);
        console.log(`Privado:      ${formatKRV(b.shielded)}  (amadurecendo: ${formatKRV(b.shieldedImmature)}, pendente: ${formatKRV(b.shieldedPending)})`);
        if (lightUrl) {
          if (b.unverified > 0n) console.log(`Aguardando prova: ${formatKRV(b.unverified)}  (o servidor informou, mas ainda faltam blocos por cima — não conta nem pode ser gasto)`);
          const fraud = Object.entries(w.fraudReports);
          for (const [txid, why] of fraud) console.log(`⚠ o servidor leve enviou dados FALSOS sobre a transação ${txid.slice(0, 16)}…: ${why}`);
          const tr = w.traffic;
          for (const d of w.discrepancies) console.log(`⚠ ${d}`);
          const n = w.serverUrls.length;
          console.log(`Carteira leve · ${n > 1 ? `${n} servidores comparados${w.discrepancies.length ? '' : ' (concordam)'}` : `servidor ${lightUrl}`} · varredura ${w.light.delegate ? 'DELEGADA (o servidor vê o que você recebe)' : 'local (o servidor não vê nada)'} · ${(tr.bytes / 1024).toFixed(1).replace('.', ',')} KB baixados em ${tr.requests} consultas`);
        }
      } else if (sub === 'varredura') {
        if (!lightUrl) throw new Error('a escolha de varredura vale só para a carteira leve (use --leve URL)');
        const mode = args._[2];
        if (mode !== 'local' && mode !== 'delegada') throw new Error('use: krevo carteira varredura local | delegada --leve URL');
        w.setDelegated(mode === 'delegada');
        console.log(mode === 'delegada'
          ? 'Varredura DELEGADA: o servidor recebe sua chave de visualização e encontra seus pagamentos (economiza bateria).\n  Ele passa a ver quanto você recebe — mas continua sem poder gastar nem ver o que você gasta.'
          : 'Varredura LOCAL: seu aparelho testa as saídas; o servidor não recebe nenhuma chave.');
      } else if (sub === 'enviar') {
        const amount = parseKRV(args.valor);
        const t0 = Date.now();
        const r = await w.send({ to: args.para, amount, from: args.de ?? 'auto', memo: str(args.memo) });
        if (r.name) console.log(`@${r.name} → ${r.to}`);
        if (r.privateInputs) {
          console.log(w.privateInputs === 'fcmp'
            ? `Entrada(s) privada(s): ${r.privateInputs}, cada uma escondida entre TODAS as ${r.anonymitySet.toLocaleString('pt-BR')} saídas privadas da rede (provas em ${(r.proveMs / 1000).toFixed(1)} s${r.prover === 'nativo' ? ', provador nativo em Rust' : r.prover?.startsWith('wasm') ? ', núcleo Rust em WebAssembly' : ''})`
            : `Entrada(s) privada(s): ${r.privateInputs}, em anel de ${r.anonymitySet}`);
        }
        console.log(`Enviado! txid ${r.txid}\n  origem: ${r.from} | taxa: ${formatKRV(r.fee)} | tamanho: ${r.size} bytes`);
        const ms = await w.waitAccepted(r.txid);
        console.log(`  confirmada (aceita pelo DAG) em ${((Date.now() - t0) / 1000).toFixed(2)} s após o envio (${ms} ms após a submissão)`);
      } else if (sub === 'historico') {
        await w.sync();
        const h = w.history();
        console.log('ENVIADOS');
        if (!h.sent.length) console.log('  (nenhum)');
        for (const s of h.sent) {
          console.log(`  ${new Date(s.time).toLocaleString('pt-BR')}  -${formatKRV(s.amount)}  para ${s.to.slice(0, 20)}…  taxa ${formatKRV(s.fee)}${s.memo ? `  memo: "${s.memo}"` : ''}`);
          console.log(`      txid ${s.txid}`);
        }
        console.log('RECEBIDOS (privado)');
        if (!h.received.length) console.log('  (nenhum)');
        for (const r of h.received) {
          console.log(`  +${formatKRV(r.amount)}${r.coinbase ? '  (mineração)' : ''}${r.spent ? '  [já gasto]' : ''}${r.memo ? `  memo: "${r.memo}"` : ''}  → ${r.subLabel}   tx ${r.txid.slice(0, 16)}…`);
        }
      } else if (sub === 'subendereco') {
        const s = w.newSubaddress(str(args.rotulo) ?? '');
        console.log(`Subendereço #${s.index}${s.label ? ` (${s.label})` : ''}:
${s.address}`);
        console.log('Ninguém consegue ligar este endereço aos seus outros endereços. O dinheiro recebido entra no mesmo saldo.');
      } else if (sub === 'subenderecos') {
        await w.sync();
        for (const s of w.listSubaddresses()) {
          console.log(`#${String(s.index).padEnd(3)} ${s.label.padEnd(28).slice(0, 28)} recebido: ${formatKRV(s.received).padStart(16)} (${s.count} saídas)`);
          console.log(`     ${s.address}`);
        }
      } else if (sub === 'cobrar') {
        const transparent = args.transparente === true;
        const amount = str(args.valor) ? parseKRV(args.valor) : null;
        let memo = str(args.memo) ?? null;
        if (transparent && memo) throw new Error('memo só funciona em cobranças privadas (sem --transparente)');
        if (!transparent && !memo) memo = newOrderCode(); // identifica o pagamento quando ele chegar
        const label = str(args.rotulo) ?? null;
        const expires = args.expira ? Math.floor(Date.now() / 1000) + Number(args.expira) * 60 : null;
        // cada cobrança privada vai para um subendereço NOVO: clientes diferentes não conseguem
        // ligar suas faturas entre si nem ao endereço principal da loja
        let address = w.tAddress;
        if (!transparent) {
          address = args['endereco-principal'] ? w.sAddress
            : w.newSubaddress(`cobrança ${memo}${label ? ` — ${label}` : ''}`).address;
        }
        const uri = buildPaymentURI(params, { address, amount, memo, label, expires });
        const qr = encodeQR(uri, 'M');
        console.log(`\nCOBRANÇA${label ? ` — ${label}` : ''}`);
        console.log(`  valor:  ${amount ? formatKRV(amount) : '(o pagador escolhe)'}`);
        if (memo) console.log(`  pedido: ${memo}`);
        console.log(`  tipo:   ${transparent ? 'transparente (valor público)' : 'privado (valor e destinatário ocultos)'}`);
        if (expires) console.log(`  expira: ${new Date(expires * 1000).toLocaleString('pt-BR')}`);
        console.log('\n' + qrToTerminal(qr) + '\n');
        console.log(uri + '\n');
        if (args.svg) {
          const out = path.resolve(typeof args.svg === 'string' ? args.svg : `cobranca-${memo ?? Date.now()}.svg`);
          const caption = [label, amount ? `${formatKRV(amount)}` : null, memo ? `Pedido ${memo}` : null].filter(Boolean);
          fs.writeFileSync(out, qrToSvg(qr, { caption }));
          console.log(`QR code salvo em ${out} (abra no navegador ou imprima)`);
        }
        if (args.aguardar) {
          console.log('Aguardando pagamento… (Ctrl+C para cancelar)');
          const req = parsePaymentURI(params, uri);
          const t0 = Date.now();
          const got = await w.waitForPayment(req);
          console.log(`\n✅ PAGO! ${formatKRV(got.amount)} recebidos em ${((Date.now() - t0) / 1000).toFixed(1)} s${got.memo ? ` (pedido ${got.memo})` : ''}`);
          console.log(`   tx ${got.txid}`);
        }
      } else if (sub === 'pagar') {
        const uri = str(args.uri) ?? await ask('Cole o link de pagamento (krevo:…): ');
        const req = parsePaymentURI(params, uri);
        console.log(`\nPAGAMENTO${req.label ? ` para ${req.label}` : ''}`);
        console.log(`  endereço: ${req.address.slice(0, 28)}… (${req.type === 's' ? 'privado' : 'transparente'})`);
        console.log(`  valor:    ${req.amount ? formatKRV(req.amount) : '(não definido no link)'}`);
        if (req.memo) console.log(`  memo:     ${req.memo}`);
        if (req.expires) console.log(`  expira:   ${new Date(req.expires * 1000).toLocaleString('pt-BR')}`);
        if (isExpired(req)) throw new Error('esta cobrança expirou; peça um novo QR code');
        const amount = req.amount ?? (str(args.valor) ? parseKRV(args.valor) : null);
        if (!amount) throw new Error('o link não define o valor; informe --valor');
        if (args.sim !== true) {
          const a = await ask('Confirmar pagamento? (s/N) ');
          if (!/^(s|sim|y|yes)$/i.test(a.trim())) { console.log('Cancelado.'); return; }
        }
        const t0 = Date.now();
        const r = await w.payRequest(uri, { from: args.de ?? 'auto', amount });
        console.log(`Enviado! txid ${r.txid}\n  origem: ${r.from} | taxa: ${formatKRV(r.fee)}`);
        await w.waitAccepted(r.txid);
        console.log(`  confirmado em ${((Date.now() - t0) / 1000).toFixed(2)} s`);
      } else if (sub === 'provar') {
        const txid = str(args.txid);
        if (!txid) throw new Error('informe --txid');
        const proof = w.prove(txid, str(args.mensagem) ?? '');
        console.log(proof);
        console.log('\nEnvie esta prova junto com o endereço de quem recebeu. Qualquer pessoa verifica com:');
        console.log(`  node src/cli.js carteira verificar-prova --prova ${proof.slice(0, 16)}… --endereco ${w.data.sent[txid].to.slice(0, 16)}…${args.mensagem ? ' --mensagem "…"' : ''}`);
        console.log('Ela revela o valor e o memo DESTE pagamento, e nada mais da sua carteira.');
      } else if (sub === 'chave-visualizacao') {
        console.log(w.keys.viewKey(params));
        console.log('Quem tiver esta chave vê os valores recebidos no seu endereço privado, mas NÃO pode gastar.');
      } else console.log(HELP);
      break;
    }
    case 'pool': {
      const file = path.resolve(args.arquivo ?? `carteira-pool-${params.name}.json`);
      if (!fs.existsSync(file)) throw new Error(`carteira do pool não encontrada: ${file} (crie com: carteira criar --arquivo ${path.basename(file)})`);
      const wallet = Wallet.load(file, params, rpcUrl, str(args.senha));
      const pool = await startPool({
        params, rpcUrl, wallet, port: Number(args.porta ?? 5555), webPort: Number(args['porta-web'] ?? 8081),
        feePct: Number(String(args.taxa ?? '1').replace(',', '.')), minPayout: parseKRV(args['pagamento-minimo'] ?? '1'),
        payoutEveryMs: parseDuration(args.intervalo ?? '60s'), stateFile: path.resolve(args.estado ?? file.replace(/\.json$/, '') + '-estado.json'), log,
      });
      log(`Pool ativo | mineradores conectam em :${Number(args.porta ?? 5555)} | estatísticas em ${pool.webUrl} | recompensas chegam em ${pool.address}`);
      break;
    }
    case 'nome': {
      await nameCommand();
      break;
    }
    case 'garantia': {
      await escrowCommand();
      break;
    }
    case 'reservas': {
      await reservesCommand();
      break;
    }
    case 'troca': {
      const file = path.resolve(args.arquivo ?? `carteira-${params.name}.json`);
      if (!fs.existsSync(file)) throw new Error(`carteira não encontrada: ${file} (crie com: krevo carteira criar, ou indique --arquivo)`);
      const w = WalletClass.load(file, params, walletUrl, str(args.senha));
      await swapCommand(w, args._[1]);
      break;
    }
    case 'btc-simulado': {
      const sub = args._[1];
      const api = (str(args['btc-api']) ?? defaultBtcApi('regtest')).replace(/\/+$/, '');
      const post = async (p, body) => {
        const r = await fetch(api + p, { method: 'POST', body: JSON.stringify(body) });
        const t = await r.text();
        if (!r.ok) throw new Error(t);
        return JSON.parse(t);
      };
      if (sub === 'pagar') {
        const sats = parseBTC(args.valor);
        const r = await post('/sim/fund', { address: str(args.endereco), sats: sats.toString() });
        console.log(`Pago ${formatBTC(sats)} para ${args.endereco} (tx ${r.txid}) — confirma no próximo bloco simulado.`);
      } else if (sub === 'saldo') {
        const r = await fetch(`${api}/address/${str(args.endereco)}/utxo`);
        const u = await r.json();
        console.log(`${formatBTC(u.reduce((a, x) => a + BigInt(x.value), 0n))} em ${u.length} saída(s)`);
      } else if (sub === 'minerar' || sub === 'mine') {
        const r = await post('/sim/mine', { n: Number(args.blocos ?? 1), dt: args.segundos ? Number(args.segundos) : undefined });
        console.log(`altura ${r.height} · horário do bloco ${new Date(r.time * 1000).toLocaleString('pt-BR')}`);
      } else {
        const blockMs = parseDuration(args.bloco ?? '10s');
        const s = await startSimBitcoin({ port: Number(args.porta ?? 3002), autoMineMs: blockMs, log });
        log(`Bitcoin SIMULADO (regtest) em ${s.url} — um bloco a cada ${blockMs / 1000} s, API igual à do mempool.space.`);
        log('Não é Bitcoin de verdade: serve para testar trocas sem risco. Endereços começam com bcrt1.');
      }
      break;
    }
    case 'carteira-web': {
      const ww = await startWebWallet({ port: Number(args.porta ?? 8091), host: args.publico ? '0.0.0.0' : '127.0.0.1', log });
      log('Abra ' + ww.url + ' no navegador (no celular: instale como app pelo menu do navegador).');
      log('O app guarda as chaves cifradas no aparelho e conversa com qualquer servidor leve — que não recebe chaves.');
      break;
    }
    case 'servidor-leve': {
      const ls = await startLightServer({ params, rpcUrl, port: Number(args.porta ?? 8090), host: args.publico ? '0.0.0.0' : '127.0.0.1', log });
      log(`Servidor leve em ${ls.url}${args.publico ? ' (aberto na rede: coloque HTTPS na frente)' : ''} — lendo o nó ${rpcUrl}`);
      log('Ele não recebe chaves; carteiras usam: krevo carteira saldo --leve ' + ls.url);
      break;
    }
    case 'explorador': {
      const ex = await startExplorer({ params, rpcUrl, port: Number(args.porta ?? 8080), log });
      log('Explorador de blocos em ' + ex.url + '  (lendo o nó ' + rpcUrl + ')');
      break;
    }
    case 'info':
      console.log(JSON.stringify(await rpc(rpcUrl, 'getinfo'), null, 2));
      break;
    case 'emissao': {
      const s = emissionSchedule(params);
      console.log('ano | recompensa/bloco | emitido acumulado');
      for (const r of s.rows.filter((r) => r.year <= 8 || r.year % 4 === 0).slice(0, 30)) {
        console.log(`${String(r.year).padStart(3)} | ${formatKRV(r.perBlock).padStart(18)} | ${formatKRV(r.total)}`);
      }
      console.log(`Total programado: ${formatKRV(s.total)} (teto absoluto: 1.000.000.000 KRV)`);
      break;
    }
    case 'genesis': {
      const g = buildGenesis(params);
      console.log(`rede ${params.name}\nhash do gênesis: ${g.hashHex}\nmensagem: ${params.genesis.message}`);
      break;
    }
    default:
      console.log(HELP);
  }
}

main().catch((e) => { console.error('erro: ' + e.message); process.exit(1); });
