// Bitcoin Core como fonte de dados da troca atômica — alternativa à API Esplora.
//
// Vantagem: privacidade. Com o seu próprio nó, nenhum servidor de terceiros fica sabendo
// quais contratos você acompanha. A carteira Krevo usa no nó uma carteira SÓ DE OBSERVAÇÃO
// (sem chaves privadas, "krevo-swaps"), onde importa os endereços dos contratos como
// descritores addr(…). As assinaturas continuam sendo feitas pela carteira Krevo.
//
// Oferece a mesma interface do cliente Esplora: tip, utxos, txs, broadcast, feeRate.
// URL: http://usuario:senha@127.0.0.1:8332 (use um usuário RPC só para isso).

const CHAINS = { main: 'mainnet', test: 'testnet', testnet4: 'testnet', signet: 'signet', regtest: 'regtest' };
const sats = (btc) => Math.round(Number(btc) * 1e8);

export class BitcoinCore {
  /** since: horário Unix a partir do qual o nó procura transações dos contratos (reescaneamento). */
  constructor(url, { wallet = 'krevo-swaps', since = null } = {}) {
    const u = new URL(url);
    this.auth = u.username ? 'Basic ' + Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString('base64') : null;
    this.base = `${u.protocol}//${u.host}`;
    this.walletName = wallet;
    this.since = since;
  }

  async rpc(method, params = [], wallet = false) {
    const url = this.base + (wallet ? `/wallet/${encodeURIComponent(this.walletName)}` : '/');
    let r;
    try {
      r = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(this.auth ? { authorization: this.auth } : {}) },
        body: JSON.stringify({ jsonrpc: '1.0', id: 'krevo', method, params }),
      });
    } catch (e) { throw new Error(`não consegui falar com o Bitcoin Core em ${this.base} (${e.cause?.code ?? e.message})`); }
    if (r.status === 401) throw new Error('o Bitcoin Core recusou o usuário/senha do RPC');
    const text = await r.text();
    let j;
    try { j = JSON.parse(text); } catch { throw new Error(`Bitcoin Core respondeu ${r.status}: ${text.slice(0, 200)}`); }
    if (j.error) { const e = new Error(`Bitcoin Core: ${j.error.message}`); e.code = j.error.code; throw e; }
    return j.result;
  }

  /** Confere se o nó está na rede Bitcoin esperada (mainnet/testnet/signet/regtest). */
  async assertNetwork(netName) {
    if (this._net) return;
    const info = await this.rpc('getblockchaininfo');
    const chain = CHAINS[info.chain] ?? info.chain;
    if (chain !== netName) throw new Error(`o Bitcoin Core está na rede ${info.chain}, mas esta troca usa ${netName}`);
    this._net = chain;
  }

  // Consultas paralelas (saldo + histórico) não podem abrir/importar duas vezes ao mesmo tempo:
  // guardamos a promessa em andamento.
  _ensureWallet() {
    return (this._walletP ??= this._openWallet().catch((e) => { this._walletP = null; throw e; }));
  }
  _watch(address) {
    this._watchP ??= new Map();
    let p = this._watchP.get(address);
    if (!p) {
      p = this._importAddress(address).catch((e) => { this._watchP.delete(address); throw e; });
      this._watchP.set(address, p);
    }
    return p;
  }

  async _openWallet() {
    const loaded = await this.rpc('listwallets');
    if (!loaded.includes(this.walletName)) {
      try { await this.rpc('loadwallet', [this.walletName]); }
      catch (e) {
        if (!/not found|does not exist/i.test(e.message)) throw e;
        // sem chaves privadas, vazia, de descritores, carregada ao iniciar o nó
        await this.rpc('createwallet', [this.walletName, true, true, '', false, true, true]);
      }
    }
  }

  async _importAddress(address) {
    await this._ensureWallet();
    const { descriptor } = await this.rpc('getdescriptorinfo', [`addr(${address})`]);
    const ts = this.since ? Math.max(0, Math.floor(this.since)) : 'now';
    const [res] = await this.rpc('importdescriptors', [[{ desc: descriptor, timestamp: ts, label: 'krevo-swap' }]], true);
    if (!res?.success) throw new Error('o Bitcoin Core não importou o endereço do contrato: ' + JSON.stringify(res?.error ?? res));
  }

  async tip() {
    const hash = await this.rpc('getbestblockhash');
    const h = await this.rpc('getblockheader', [hash]);
    return { hash, height: h.height, time: h.time, mtp: h.mediantime };
  }

  async utxos(address) {
    await this._watch(address);
    const [height, list] = await Promise.all([this.rpc('getblockcount'), this.rpc('listunspent', [0, 9_999_999, [address], true], true)]);
    return list.map((u) => ({
      txid: u.txid, vout: u.vout, value: sats(u.amount),
      status: u.confirmations > 0 ? { confirmed: true, block_height: height - u.confirmations + 1 } : { confirmed: false },
    }));
  }

  async _decoded(txid) {
    try { return (await this.rpc('gettransaction', [txid, true, true], true)); }
    catch { return { decoded: await this.rpc('getrawtransaction', [txid, true]), confirmations: 0 }; }
  }

  /** Transações que pagam ou gastam o endereço, no formato da API Esplora (com testemunhas). */
  async txs(address) {
    await this._watch(address);
    const list = await this.rpc('listtransactions', ['*', 1000, 0, true], true);
    const out = [];
    for (const txid of [...new Set(list.map((t) => t.txid))]) {
      const t = await this._decoded(txid);
      const d = t.decoded;
      const vin = [];
      for (const i of d.vin) {
        let prevout = null;
        if (i.txid) {
          try {
            const p = (await this._decoded(i.txid)).decoded.vout[i.vout];
            prevout = { scriptpubkey: p.scriptPubKey.hex, scriptpubkey_address: p.scriptPubKey.address ?? null, value: sats(p.value) };
          } catch { /* entrada de fora da carteira e sem -txindex */ }
        }
        vin.push({ txid: i.txid, vout: i.vout, witness: i.txinwitness ?? [], prevout });
      }
      const vout = d.vout.map((o) => ({ scriptpubkey: o.scriptPubKey.hex, scriptpubkey_address: o.scriptPubKey.address ?? null, value: sats(o.value) }));
      if (!vout.some((o) => o.scriptpubkey_address === address) && !vin.some((v) => v.prevout?.scriptpubkey_address === address)) continue;
      out.push({ txid, vin, vout, status: t.confirmations > 0 ? { confirmed: true, block_height: t.blockheight } : { confirmed: false } });
    }
    return out;
  }

  broadcast(hex) { return this.rpc('sendrawtransaction', [hex]); }

  async feeRate(target = 3) {
    try {
      const r = await this.rpc('estimatesmartfee', [target]);
      return r.feerate ? Math.max(1, Math.ceil(r.feerate * 1e5)) : 2; // BTC/kvB → sat/vB
    } catch { return 2; }
  }
}
