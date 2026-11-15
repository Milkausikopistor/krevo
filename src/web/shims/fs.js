// "node:fs" for the browser: the web wallet keeps its data encrypted in the browser's storage
// (src/web/browser-wallet.js), never in files.
const nope = () => { throw new Error('there are no files in the browser'); };
export const existsSync = () => false;
export const readFileSync = nope;
export const writeFileSync = nope;
export default { existsSync, readFileSync, writeFileSync };
