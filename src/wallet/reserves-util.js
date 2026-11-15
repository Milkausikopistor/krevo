// Small helpers for the proof of reserves.
import { toHex, fromHex, bigToBytesBE } from '../util/bytes.js';
export { toHex, fromHex };
export const scalarToBytesHex = (s) => toHex(bigToBytesBE(s, 32));
