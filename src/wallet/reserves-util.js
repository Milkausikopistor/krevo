// Pequenos auxiliares da prova de reservas.
import { toHex, fromHex, bigToBytesBE } from '../util/bytes.js';
export { toHex, fromHex };
export const scalarToBytesHex = (s) => toHex(bigToBytesBE(s, 32));
