// Esplora API client — the REST API of mempool.space and blockstream.info, which you can
// also host yourself (electrs/esplora or mempool). This is how the Krevo wallet watches
// the HTLC on Bitcoin without needing a full Bitcoin node.
//
// Privacy: the chosen server learns which HTLC addresses you query.
// To avoid depending on third parties, point --btc-api at your own instance.

const DEFAULT_APIS = {
  mainnet: 'https://mempool.space/api',
  testnet: 'https://mempool.space/testnet4/api',
  signet: 'https://mempool.space/signet/api',
  regtest: 'http://127.0.0.1:3002', // o Bitcoin simulado deste projeto (krevo btc-simulado)
};
export const defaultBtcApi = (netName) => DEFAULT_APIS[netName];

export class Esplora {
  constructor(base) {
    if (!base) throw new Error('enter the Bitcoin API (--btc-api URL of an Esplora/mempool server)');
    this.base = base.replace(/\/+$/, '');
  }

  async _req(path, { method = 'GET', body, json = true } = {}) {
    let r;
    try { r = await fetch(this.base + path, { method, body }); }
    catch (e) { throw new Error(`could not talk to the Bitcoin API at ${this.base} (${e.cause?.code ?? e.message})`); }
    const text = await r.text();
    if (!r.ok) throw new Error(`API do Bitcoin respondeu ${r.status}: ${text.slice(0, 300)}`);
    return json ? JSON.parse(text) : text.trim();
  }

  /** Most recent block: { height, time, mtp } (mtp = median of the last 11, used by CLTV). */
  async tip() {
    const hash = await this._req('/blocks/tip/hash', { json: false });
    const b = await this._req(`/block/${hash}`);
    return { hash, height: b.height, time: b.timestamp, mtp: b.mediantime ?? b.timestamp };
  }

  /** Unspent outputs of an address: [{ txid, vout, value, status: { confirmed, block_height } }]. */
  utxos(address) { return this._req(`/address/${address}/utxo`); }

  /** Transactions touching the address (with the inputs' witnesses). */
  txs(address) { return this._req(`/address/${address}/txs`); }

  tx(txid) { return this._req(`/tx/${txid}`); }

  broadcast(hex) { return this._req('/tx', { method: 'POST', body: hex, json: false }); }

  /** Suggested fee (sat/vB) to confirm within ~3 blocks; 2 sat/vB if the API does not say. */
  async feeRate(target = 3) {
    try {
      const f = await this._req('/fee-estimates');
      const v = Number(f[String(target)] ?? f['6'] ?? f['1']);
      return Number.isFinite(v) && v > 0 ? Math.max(1, Math.ceil(v)) : 2;
    } catch { return 2; }
  }
}
