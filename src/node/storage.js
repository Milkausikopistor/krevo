// Simple storage: an append-only block file. On startup the node
// re-validates everything (rebuilds the state). Enough for devnet/testnet; the production
// version needs a key-value database and pruning (see the whitepaper).
import fs from 'node:fs';
import path from 'node:path';
import { Block } from '../consensus/block.js';
import { u32le } from '../util/bytes.js';

export class BlockFile {
  constructor(dir) {
    fs.mkdirSync(dir, { recursive: true });
    this.file = path.join(dir, 'blocks.dat');
    // data directories created by older versions used the Portuguese file name
    const legacy = path.join(dir, 'blocos.dat');
    if (!fs.existsSync(this.file) && fs.existsSync(legacy)) this.file = legacy;
  }
  *readAll() {
    if (!fs.existsSync(this.file)) return;
    const buf = fs.readFileSync(this.file);
    let o = 0;
    while (o + 4 <= buf.length) {
      const len = buf.readUInt32LE(o);
      if (o + 4 + len > buf.length) break; // truncated record (abrupt shutdown)
      yield Block.deserialize(buf.subarray(o + 4, o + 4 + len));
      o += 4 + len;
    }
  }
  append(block) {
    const raw = block.serialize();
    fs.appendFileSync(this.file, Buffer.concat([u32le(raw.length), raw]));
  }
}
