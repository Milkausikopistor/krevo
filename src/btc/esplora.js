// Cliente da API Esplora — a API REST do mempool.space e do blockstream.info, que também
// pode ser hospedada por você mesmo (electrs/esplora ou mempool). É assim que a carteira
// Krevo acompanha a HTLC no Bitcoin sem precisar de um nó Bitcoin completo.
//
// Privacidade: o servidor escolhido fica sabendo quais endereços de HTLC você consulta.
// Para não depender de terceiros, aponte --btc-api para a sua própria instância.

const DEFAULT_APIS = {
  mainnet: 'https://mempool.space/api',
  testnet: 'https://mempool.space/testnet4/api',
  signet: 'https://mempool.space/signet/api',
  regtest: 'http://127.0.0.1:3002', // o Bitcoin simulado deste projeto (krevo btc-simulado)
};
export const defaultBtcApi = (netName) => DEFAULT_APIS[netName];

export class Esplora {
  constructor(base) {
    if (!base) throw new Error('informe a API do Bitcoin (--btc-api URL de um servidor Esplora/mempool)');
    this.base = base.replace(/\/+$/, '');
  }

  async _req(path, { method = 'GET', body, json = true } = {}) {
    let r;
    try { r = await fetch(this.base + path, { method, body }); }
    catch (e) { throw new Error(`não consegui falar com a API do Bitcoin em ${this.base} (${e.cause?.code ?? e.message})`); }
    const text = await r.text();
    if (!r.ok) throw new Error(`API do Bitcoin respondeu ${r.status}: ${text.slice(0, 300)}`);
    return json ? JSON.parse(text) : text.trim();
  }

  /** Bloco mais recente: { height, time, mtp } (mtp = mediana dos 11 últimos, usada pelo CLTV). */
  async tip() {
    const hash = await this._req('/blocks/tip/hash', { json: false });
    const b = await this._req(`/block/${hash}`);
    return { hash, height: b.height, time: b.timestamp, mtp: b.mediantime ?? b.timestamp };
  }

  /** Saídas não gastas de um endereço: [{ txid, vout, value, status: { confirmed, block_height } }]. */
  utxos(address) { return this._req(`/address/${address}/utxo`); }

  /** Transações que tocam o endereço (com as testemunhas das entradas). */
  txs(address) { return this._req(`/address/${address}/txs`); }

  tx(txid) { return this._req(`/tx/${txid}`); }

  broadcast(hex) { return this._req('/tx', { method: 'POST', body: hex, json: false }); }

  /** Taxa sugerida (sat/vB) para confirmar em ~3 blocos; 2 sat/vB se a API não informar. */
  async feeRate(target = 3) {
    try {
      const f = await this._req('/fee-estimates');
      const v = Number(f[String(target)] ?? f['6'] ?? f['1']);
      return Number.isFinite(v) && v > 0 ? Math.max(1, Math.ceil(v)) : 2;
    } catch { return 2; }
  }
}
