// Module hooks that imitate the BROWSER inside Node: project code that asks for
// "node:crypto" or "node:fs" gets the same versions as the web app (src/web/shims/).
const SHIM = {
  'node:crypto': new URL('../../src/web/shims/crypto.js', import.meta.url).href,
  'node:fs': new URL('../../src/web/shims/fs.js', import.meta.url).href,
};
export async function resolve(specifier, context, next) {
  const parent = context.parentURL ?? '';
  if (SHIM[specifier] && parent.includes('/src/') && !parent.includes('/src/web/shims/')) return { url: SHIM[specifier], shortCircuit: true };
  return next(specifier, context);
}
