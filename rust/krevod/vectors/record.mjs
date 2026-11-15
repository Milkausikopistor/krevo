// Preload to RECORD the chains that the JavaScript test suite builds:
//   KREVO_RECORD_DIR=folder node --import ./rust/krevod/vectors/record.mjs --test "test/*.test.js"
// Each consensus instance (with a network's default parameters) records its accepted
// blocks, in arrival order, in the same format as the node's block file.
// Then vectors/compare.mjs reprocesses each file on both nodes and compares the state.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const { Consensus } = await import(pathToFileURL(path.join(root, 'src/consensus/consensus.js')).href);
const { getParams } = await import(pathToFileURL(path.join(root, 'src/params.js')).href);

const dir = process.env.KREVO_RECORD_DIR;
if (dir) {
  fs.mkdirSync(dir, { recursive: true });
  let seq = 0;
  const orig = Consensus.prototype.addBlock;
  Consensus.prototype.addBlock = function (block, opts) {
    const r = orig.call(this, block, opts);
    if (r.status === 'accepted' && this.params === getParams(this.params.name)) {
      this._rec ??= path.join(dir, `${process.pid}-${++seq}-${this.params.name}.dat`);
      const raw = block.serialize();
      const len = Buffer.alloc(4);
      len.writeUInt32LE(raw.length);
      fs.appendFileSync(this._rec, Buffer.concat([len, raw]));
    }
    return r;
  };
}
