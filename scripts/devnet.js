// Rede local de demonstração: 3 nós, 2 mineradores, 3 carteiras.
// Executa todos os tipos de transação e mede o tempo de confirmação real.
//   node scripts/devnet.js [--segundos 90]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getParams, formatKRV, COIN } from '../src/params.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { nameCommit, nameReveal, nameRevealWait } from '../src/wallet/names.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'src', 'cli.js');
const params = getParams('devnet');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-devnet-'));
const BASE = 17100 + Math.floor(Math.random() * 500) * 10;
const nodes = [0, 1, 2].map((i) => ({ p2p: BASE + i * 3, rpc: BASE + i * 3 + 1, url: `http://127.0.0.1:${BASE + i * 3 + 1}` }));
const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();
const say = (m) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1).padStart(5)} s] ${m}`);

function start(args, name) {
  const p = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const logf = fs.createWriteStream(path.join(tmp, name + '.log'));
  p.stdout.pipe(logf); p.stderr.pipe(logf);
  procs.push(p);
  return p;
}
function cleanup() { for (const p of procs) { try { p.kill(); } catch {} } }
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(1); });

async function waitFor(fn, what, timeout = 120_000) {
  const t = Date.now();
  for (;;) {
    try { const v = await fn(); if (v) return v; } catch {}
    if (Date.now() - t > timeout) throw new Error('tempo esgotado: ' + what);
    await sleep(250);
  }
}

async function main() {
  say(`diretório temporário: ${tmp}`);
  // 1) nós em cadeia: n0 ← n1 ← n2 (n2 só fala com n1: as mensagens precisam de 2 saltos)
  nodes.forEach((n, i) => {
    const peers = i > 0 ? ['--par', `127.0.0.1:${nodes[i - 1].p2p}`] : [];
    start(['no', '--rede', 'devnet', '--dados', path.join(tmp, `n${i}`), '--porta', String(n.p2p), '--rpcporta', String(n.rpc), ...peers], `no${i}`);
  });
  for (const n of nodes) await waitFor(() => rpc(n.url, 'getinfo'), 'nó subir');
  say('3 nós ativos');

  const alice = Wallet.create(path.join(tmp, 'alice.json'), params, nodes[0].url);
  const bob = Wallet.create(path.join(tmp, 'bob.json'), params, nodes[1].url);
  const carol = Wallet.create(path.join(tmp, 'carol.json'), params, nodes[2].url);

  // 2) mineradores: Alice minera em endereço transparente (nó 0); Bob em endereço PRIVADO (nó 1)
  start(['minerar', '--rede', 'devnet', '--endereco', alice.tAddress, '--rpc', nodes[0].url], 'minerador-alice');
  start(['minerar', '--rede', 'devnet', '--endereco', bob.sAddress, '--rpc', nodes[1].url], 'minerador-bob');
  say('2 mineradores ativos (Alice → transparente, Bob → privado)');

  await waitFor(async () => { await alice.sync(); return alice.balance().transparent > 20n * COIN; }, 'saldo maduro de Alice');
  await waitFor(async () => { await bob.sync(); return bob.balance().shielded > 5n * COIN; }, 'saldo privado de Bob');
  say(`Alice: ${formatKRV(alice.balance().transparent)} transparente | Bob: ${formatKRV(bob.balance().shielded)} privado`);

  const results = [];
  async function scenario(label, wallet, to, amount, from, watcher) {
    const tSend = Date.now();
    const r = await wallet.send({ to, amount, from });
    const tSubmitted = Date.now();
    const ms = await watcher.waitAccepted(r.txid);
    const row = { label, build: tSubmitted - tSend, confirm: Date.now() - tSubmitted, fee: r.fee, size: r.size };
    results.push(row);
    say(`${label}: confirmada em ${row.confirm} ms (vista pelo nó do destinatário) | montagem ${row.build} ms | taxa ${formatKRV(r.fee)} | ${r.size} bytes`);
    return ms;
  }

  // 3) transações
  await scenario('transparente → transparente', alice, carol.tAddress, 5n * COIN, 'transparente', carol);
  await scenario('transparente → privado (blindar)', alice, carol.sAddress, 3n * COIN, 'transparente', carol);
  await scenario('privado → privado', bob, carol.sAddress, 2n * COIN, 'privado', carol);
  await waitFor(async () => { await carol.sync(); return carol.data.sOwned.filter((o) => !o.spent && o.daa > 0).length >= 2; }, 'Carol ver saídas privadas');
  await sleep(3000); // maturidade dos membros do anel (20 blocos)
  await scenario('privado → transparente (desblindar)', carol, alice.tAddress, 4n * COIN, 'privado', alice);

  // várias transparentes seguidas para estatística
  const lat = [];
  for (let i = 0; i < 8; i++) {
    const r = await alice.send({ to: carol.tAddress, amount: COIN / 10n, from: 'transparente' });
    const ts = Date.now();
    await carol.waitAccepted(r.txid);
    lat.push(Date.now() - ts);
    await sleep(300);
  }
  lat.sort((a, b) => a - b);
  say(`8 pagamentos transparentes: mediana ${lat[4]} ms, mínimo ${lat[0]} ms, máximo ${lat[7]} ms`);

  // proteção quântica: Carol migra krv → krq e paga a partir do krq (Schnorr + ML-DSA)
  const mig = await carol.migrateQuantum();
  for (const t of mig.txs) await carol.waitAccepted(t.txid);
  say(`Carol migrou ${formatKRV(mig.moved)} para ${carol.qAddress.slice(0, 22)}… em ${mig.txs.length} transação(ões), taxa ${formatKRV(mig.txs.reduce((a, t) => a + t.fee, 0n))}`);
  await scenario('quântico krq → transparente (Schnorr + ML-DSA)', carol, alice.tAddress, COIN / 2n, 'transparente', alice);

  // nomes legíveis: Carol (dona com endereço quântico) registra @loja-carol; Alice paga pelo nome
  const nc = await nameCommit(carol, '@loja-carol', { target: 'privado' });
  await carol.waitAccepted(nc.txid);
  await waitFor(async () => (await nameRevealWait(carol, 'loja-carol')) === 0, 'prazo do compromisso do nome');
  const nr = await nameReveal(carol, 'loja-carol');
  await carol.waitAccepted(nr.txid);
  say(`Carol registrou @loja-carol (compromisso + revelação, taxa ${formatKRV(nr.nameFee)} para o Fundo de Segurança)`);
  await scenario('pagamento para @loja-carol (nome → endereço privado)', alice, '@loja-carol', COIN / 2n, 'transparente', carol);
  await sleep(1000);
  const views = await Promise.all(nodes.map((n) => rpc(n.url, 'resolvename', { name: 'loja-carol' })));
  if (new Set(views.map((v) => `${v.status}|${v.outpoint}|${v.target}`)).size !== 1) throw new Error('os nós discordam sobre @loja-carol');
  say(`os 3 nós resolvem @loja-carol igual: ${views[0].status}, dono ${views[0].owner.slice(0, 16)}… (quântico), aponta para ${views[0].target.slice(0, 16)}…`);

  // 4) saldos e consistência entre nós
  await sleep(1500);
  for (const w of [alice, bob, carol]) await w.sync();
  const b = (w) => w.balance();
  say(`saldos — Alice: ${formatKRV(b(alice).transparent + b(alice).transparentImmature)} transp. | Bob: ${formatKRV(b(bob).shielded)} priv. | Carol: ${formatKRV(b(carol).transparent)} transp. + ${formatKRV(b(carol).shielded)} priv.`);
  const infos = await Promise.all(nodes.map((n) => rpc(n.url, 'getinfo')));
  infos.forEach((inf, i) => say(`nó ${i}: blocos ${inf.blocks} | blue score ${inf.virtual.blueScore} | ${inf.blocksPerSecond} blocos/s | vermelhos ${inf.redBlocks} | cunhado ${formatKRV(BigInt(inf.minted))} | fundo ${formatKRV(BigInt(inf.feePool))} | pool privado ${formatKRV(BigInt(inf.shieldedSupply))}`));

  // a viewkey de Carol permite auditar sem poder gastar
  say(`chave de visualização de Carol: ${carol.keys.viewKey(params).slice(0, 30)}…`);
  fs.writeFileSync(path.join(root, 'devnet-resultado.json'), JSON.stringify({ results, transparentLatencies: lat, nodes: infos },
    (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  say('resultado salvo em devnet-resultado.json');
}

main().then(() => { cleanup(); process.exit(0); }).catch((e) => { console.error('FALHOU: ' + e.stack); cleanup(); process.exit(1); });
