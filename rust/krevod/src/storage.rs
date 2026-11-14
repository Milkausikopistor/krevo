//! Arquivo de blocos só-anexação, no MESMO formato do nó JavaScript (u32le(tamanho) ‖ bloco):
//! um nó Rust pode abrir os dados de um nó JavaScript e vice-versa.

use crate::block::Block;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub struct BlockFile { pub file: PathBuf }

impl BlockFile {
    pub fn new(dir: &std::path::Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(BlockFile { file: dir.join("blocos.dat") })
    }
    pub fn read_all(&self) -> Vec<Block> {
        let Ok(buf) = fs::read(&self.file) else { return vec![] };
        let mut out = vec![];
        let mut o = 0usize;
        while o + 4 <= buf.len() {
            let len = u32::from_le_bytes(buf[o..o + 4].try_into().unwrap()) as usize;
            if o + 4 + len > buf.len() { break; } // registro truncado (desligamento abrupto)
            match Block::deserialize(&buf[o + 4..o + 4 + len]) { Ok(b) => out.push(b), Err(_) => break }
            o += 4 + len;
        }
        out
    }
    pub fn append(&self, b: &Block) -> std::io::Result<()> {
        let raw = b.serialize();
        let mut f = OpenOptions::new().create(true).append(true).open(&self.file)?;
        f.write_all(&(raw.len() as u32).to_le_bytes())?;
        f.write_all(&raw)
    }
}
