// RPC client (JSON over HTTP).
//
// HTTP connections are reused (keep-alive). If the wallet spends several seconds
// computing a proof, the server may close the idle connection exactly when it is
// reused (ECONNRESET). In that case — and only then — the request is retried once: the
// calls are idempotent (relaying an already-known transaction changes nothing).
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
