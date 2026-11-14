// Armazenamento simples: arquivo de blocos só-anexação. Na inicialização o nó
// re-valida tudo (reconstrói o estado). Suficiente para devnet/testnet; a versão
// de produção precisa de banco de dados chave-valor e poda (ver whitepaper).
import fs from 'node:fs';
import path from 'node:path';
import { Block } from '../consensus/block.js';
import { u32le } from '../util/bytes.js';

export class BlockFile {
  constructor(dir) {
    fs.mkdirSync(dir, { recursive: true });
    this.file = path.join(dir, 'blocos.dat');
  }
  *readAll() {
    if (!fs.existsSync(this.file)) return;
    const buf = fs.readFileSync(this.file);
    let o = 0;
    while (o + 4 <= buf.length) {
      const len = buf.readUInt32LE(o);
      if (o + 4 + len > buf.length) break; // registro truncado (desligamento abrupto)
      yield Block.deserialize(buf.subarray(o + 4, o + 4 + len));
      o += 4 + len;
    }
  }
  append(block) {
    const raw = block.serialize();
    fs.appendFileSync(this.file, Buffer.concat([u32le(raw.length), raw]));
  }
}
