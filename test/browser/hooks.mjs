// Ganchos de módulo que imitam o NAVEGADOR dentro do Node: o código do projeto que pedir
// "node:crypto" ou "node:fs" recebe as mesmas versões do app web (src/web/shims/).
const SHIM = {
  'node:crypto': new URL('../../src/web/shims/crypto.js', import.meta.url).href,
  'node:fs': new URL('../../src/web/shims/fs.js', import.meta.url).href,
};
export async function resolve(specifier, context, next) {
  const parent = context.parentURL ?? '';
  if (SHIM[specifier] && parent.includes('/src/') && !parent.includes('/src/web/shims/')) return { url: SHIM[specifier], shortCircuit: true };
  return next(specifier, context);
}
