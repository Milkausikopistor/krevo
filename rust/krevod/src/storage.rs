//! Append-only block file, in the SAME format as the JavaScript node (u32le(length) ‖ block):
//! a Rust node can open a JavaScript node's data and vice versa (except a pruned one: see
//! `rewrite`). Next to it, `state.snap` holds a snapshot of the node's state (src/snapshot.rs).

use crate::block::Block;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub struct BlockFile { pub file: PathBuf, pub dir: PathBuf }

impl BlockFile {
    pub fn new(dir: &std::path::Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let file = dir.join("blocks.dat");
        // data directories created by older versions used the Portuguese file name
        let legacy = dir.join("blocos.dat");
        Ok(BlockFile { file: if !file.exists() && legacy.exists() { legacy } else { file }, dir: dir.to_path_buf() })
    }
    pub fn snapshot_path(&self) -> PathBuf { self.dir.join("state.snap") }
    pub fn read_all(&self) -> Vec<Block> {
        let Ok(buf) = fs::read(&self.file) else { return vec![] };
        let mut out = vec![];
        let mut o = 0usize;
        while o + 4 <= buf.len() {
            let len = u32::from_le_bytes(buf[o..o + 4].try_into().unwrap()) as usize;
            if o + 4 + len > buf.len() { break; } // truncated record (abrupt shutdown)
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
    /// Replaces the file with just these blocks (compaction after pruning), atomically: a new file
    /// is written next to it and renamed over the old one. A pruned file no longer starts at the
    /// genesis, so it only works together with its state snapshot.
    pub fn rewrite<'a>(&self, blocks: impl Iterator<Item = &'a Block>) -> std::io::Result<()> {
        let tmp = self.file.with_extension("dat.tmp");
        {
            let mut f = std::io::BufWriter::new(fs::File::create(&tmp)?);
            for b in blocks {
                let raw = b.serialize();
                f.write_all(&(raw.len() as u32).to_le_bytes())?;
                f.write_all(&raw)?;
            }
            f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        fs::rename(&tmp, &self.file)
    }
}

/// Writes `data` to `path` atomically (temporary file + rename).
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}
