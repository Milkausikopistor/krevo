// "node:fs" para o navegador: a carteira web guarda os dados cifrados no armazenamento do
// navegador (src/web/browser-wallet.js), nunca em arquivos.
const nope = () => { throw new Error('arquivos não existem no navegador'); };
export const existsSync = () => false;
export const readFileSync = nope;
export const writeFileSync = nope;
export default { existsSync, readFileSync, writeFileSync };
