// Cliente RPC (JSON sobre HTTP).
//
// Conexões HTTP são reaproveitadas (keep-alive). Se a carteira passa vários segundos
// calculando uma prova, o servidor pode fechar a conexão ociosa exatamente quando ela é
// reutilizada (ECONNRESET). Nesse caso — e só nele — o pedido é repetido uma vez: as
// chamadas são idempotentes (retransmitir uma transação já conhecida não muda nada).
const RETRY = new Set(['ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET', 'UND_ERR_CLOSED']);
export async function fetchRetry(url, opts) {
  try { return await fetch(url, opts); } catch (e) {
    if (!RETRY.has(e.cause?.code)) throw e;
    return fetch(url, opts);
  }
}

export async function rpc(url, method, params = {}) {
  const r = await fetchRetry(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: 1, method, params }),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
