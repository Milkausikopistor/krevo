//! Blocks, headers and Merkle roots (mirrors src/consensus/block.js).

use crate::bytes::*;
use crate::hash::H;
use crate::tx::Transaction;
use num_bigint::BigUint;
use std::sync::OnceLock;

#[derive(Clone, Debug, Default)]
pub struct Header {
    pub version: u16,
    pub parents: Vec<[u8; 32]>,
    pub hash_merkle_root: [u8; 32],
    pub accepted_id_merkle_root: [u8; 32],
    pub utxo_commitment: [u8; 32],
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub blue_score: u64,
    pub blue_work: BigUint,
}

impl Header {
    pub fn serialize(&self, for_pow: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.version);
        w.varint(self.parents.len() as u64);
        for p in &self.parents { w.bytes(p); }
        w.bytes(&self.hash_merkle_root).bytes(&self.accepted_id_merkle_root).bytes(&self.utxo_commitment);
        w.u64(if for_pow { 0 } else { self.timestamp });
        w.u32(self.bits);
        w.u64(if for_pow { 0 } else { self.nonce });
        w.u64(self.daa_score).u64(self.blue_score);
        let bw = if self.blue_work == BigUint::from(0u32) { vec![] } else { self.blue_work.to_bytes_be() };
        w.varbytes(&bw);
        w.done()
    }
    pub fn read(r: &mut Reader) -> Res<Self> {
        let mut h = Header { version: r.u16()?, ..Default::default() };
        let n = r.varint(64)?;
        for _ in 0..n { h.parents.push(r.arr()?); }
        h.hash_merkle_root = r.arr()?;
        h.accepted_id_merkle_root = r.arr()?;
        h.utxo_commitment = r.arr()?;
        h.timestamp = r.u64()?;
        h.bits = r.u32()?;
        h.nonce = r.u64()?;
        h.daa_score = r.u64()?;
        h.blue_score = r.u64()?;
        let bw = r.varbytes(64)?;
        if !bw.is_empty() && bw[0] == 0 { return Err("non-canonical blueWork".into()); }
        h.blue_work = BigUint::from_bytes_be(bw);
        Ok(h)
    }
    pub fn deserialize(buf: &[u8]) -> Res<Self> { let mut r = Reader::new(buf); let h = Self::read(&mut r)?; r.end()?; Ok(h) }
    pub fn hash(&self) -> [u8; 32] { H::new("block/hash").b(&self.serialize(false)).d32() }
    pub fn pre_pow_hash(&self) -> [u8; 32] { H::new("block/prepow").b(&self.serialize(true)).d32() }
}

#[derive(Debug)]
pub struct Block { pub header: Header, pub txs: Vec<Transaction>, hash: OnceLock<[u8; 32]> }

impl Clone for Block {
    fn clone(&self) -> Self { Block { header: self.header.clone(), txs: self.txs.clone(), hash: OnceLock::new() } }
}

impl Block {
    pub fn new(header: Header, txs: Vec<Transaction>) -> Self { Block { header, txs, hash: OnceLock::new() } }
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.serialize(false));
        w.varint(self.txs.len() as u64);
        for tx in &self.txs { w.varbytes(&tx.serialize()); }
        w.done()
    }
    pub fn deserialize(buf: &[u8]) -> Res<Self> {
        let mut r = Reader::new(buf);
        let header = Header::read(&mut r)?;
        let n = r.varint(100_000)?;
        let mut txs = Vec::with_capacity(n as usize);
        for _ in 0..n { txs.push(Transaction::deserialize(r.varbytes(4_000_000)?)?); }
        r.end()?;
        Ok(Block::new(header, txs))
    }
    pub fn hash(&self) -> [u8; 32] { *self.hash.get_or_init(|| self.header.hash()) }
    pub fn hash_hex(&self) -> String { to_hex(&self.hash()) }
    pub fn reset_hash(&mut self) { self.hash = OnceLock::new(); }
}

/// Merkle root without duplicating the last node (avoids CVE-2012-2459).
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() { return [0u8; 32]; }
    let mut level: Vec<[u8; 32]> = hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for i in (0..level.len()).step_by(2) {
            next.push(if i + 1 < level.len() { H::new("merkle").b(&level[i]).b(&level[i + 1]).d32() } else { level[i] });
        }
        level = next;
    }
    H::new("merkle/root").b(&level[0]).n(hashes.len() as u64).d32()
}

/// Inclusion proof: { index, count, path: [hex | null] }.
pub fn merkle_proof(hashes: &[[u8; 32]], index: usize) -> serde_json::Value {
    let mut path = vec![];
    let mut level: Vec<[u8; 32]> = hashes.to_vec();
    let mut i = index;
    while level.len() > 1 {
        let sib = i ^ 1;
        path.push(if sib < level.len() { serde_json::Value::String(to_hex(&level[sib])) } else { serde_json::Value::Null });
        let mut next = vec![];
        for k in (0..level.len()).step_by(2) {
            next.push(if k + 1 < level.len() { H::new("merkle").b(&level[k]).b(&level[k + 1]).d32() } else { level[k] });
        }
        level = next;
        i >>= 1;
    }
    serde_json::json!({ "index": index, "count": hashes.len(), "path": path })
}
