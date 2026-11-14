//! Transação (espelha src/consensus/tx.js): um formato para os dois mundos.
//! txid = hash do CORPO (sem assinaturas/provas); as assinaturas não alteram o id.

use crate::bytes::*;
use crate::hash::H;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct TIn { pub txid: [u8; 32], pub index: u32, pub sig: Vec<u8> }

#[derive(Clone, Debug)]
pub struct SIn {
    pub ring: Vec<([u8; 32], u32)>,
    /// FCMP: árvore com as `anchor` primeiras saídas privadas (só quando ring é vazio)
    pub anchor: u64,
    pub pseudo: [u8; 33],
    pub key_image: [u8; 33],
    pub clsag: Vec<u8>,
    pub fcmp: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TOut { pub amount: u64, pub lock: Vec<u8> }

#[derive(Clone, Debug)]
pub struct SOut { pub r: [u8; 33], pub p: [u8; 33], pub c: [u8; 33], pub enc_amount: [u8; 8], pub view_tag: u8 }

#[derive(Debug, Default)]
pub struct Transaction {
    pub version: u16,
    pub t_in: Vec<TIn>,
    pub s_in: Vec<SIn>,
    pub t_out: Vec<TOut>,
    pub s_out: Vec<SOut>,
    pub fee: u64,
    pub mass: u64,
    pub payload: Vec<u8>,
    pub range_proof: Vec<u8>,
    pub binding_sig: Option<[u8; 64]>,
    id: OnceLock<[u8; 32]>,
    hash: OnceLock<[u8; 32]>,
    size: OnceLock<usize>,
}

impl Clone for Transaction {
    fn clone(&self) -> Self {
        Transaction {
            version: self.version, t_in: self.t_in.clone(), s_in: self.s_in.clone(), t_out: self.t_out.clone(),
            s_out: self.s_out.clone(), fee: self.fee, mass: self.mass, payload: self.payload.clone(),
            range_proof: self.range_proof.clone(), binding_sig: self.binding_sig,
            id: OnceLock::new(), hash: OnceLock::new(), size: OnceLock::new(),
        }
    }
}

impl Transaction {
    pub fn new() -> Self { Transaction { version: 1, ..Default::default() } }
    pub fn is_coinbase(&self) -> bool { self.t_in.is_empty() && self.s_in.is_empty() }

    pub fn serialize_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.version);
        w.varint(self.t_in.len() as u64);
        for i in &self.t_in { w.bytes(&i.txid).u32(i.index); }
        w.varint(self.s_in.len() as u64);
        for i in &self.s_in {
            w.varint(i.ring.len() as u64);
            if i.ring.is_empty() { w.varint(i.anchor); }
            for (t, x) in &i.ring { w.bytes(t).u32(*x); }
            w.bytes(&i.pseudo).bytes(&i.key_image);
        }
        w.varint(self.t_out.len() as u64);
        for o in &self.t_out { w.u64(o.amount).varbytes(&o.lock); }
        w.varint(self.s_out.len() as u64);
        for o in &self.s_out { w.bytes(&o.r).bytes(&o.p).bytes(&o.c).bytes(&o.enc_amount).u8(o.view_tag); }
        w.u64(self.fee).u64(self.mass).varbytes(&self.payload);
        w.done()
    }

    pub fn serialize_witness(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for i in &self.t_in { w.varbytes(&i.sig); }
        for i in &self.s_in { w.varbytes(if i.ring.is_empty() { &i.fcmp } else { &i.clsag }); }
        w.varbytes(&self.range_proof);
        match &self.binding_sig { Some(b) => { w.u8(1).bytes(b); } None => { w.u8(0); } }
        w.done()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v = self.serialize_body();
        v.extend(self.serialize_witness());
        v
    }

    pub fn read(r: &mut Reader) -> Res<Self> {
        let mut tx = Transaction::new();
        tx.version = r.u16()?;
        let nt = r.varint(10_000)?;
        for _ in 0..nt { tx.t_in.push(TIn { txid: r.arr()?, index: r.u32()?, sig: vec![] }); }
        let ns = r.varint(1_000)?;
        for _ in 0..ns {
            let n = r.varint(128)?;
            let anchor = if n == 0 { r.varint(1u64 << 40)? } else { 0 };
            let mut ring = Vec::with_capacity(n as usize);
            for _ in 0..n { ring.push((r.arr()?, r.u32()?)); }
            tx.s_in.push(SIn { ring, anchor, pseudo: r.arr()?, key_image: r.arr()?, clsag: vec![], fcmp: vec![] });
        }
        let nto = r.varint(10_000)?;
        for _ in 0..nto { tx.t_out.push(TOut { amount: r.u64()?, lock: r.varbytes(255)?.to_vec() }); }
        let nso = r.varint(1_000)?;
        for _ in 0..nso {
            tx.s_out.push(SOut { r: r.arr()?, p: r.arr()?, c: r.arr()?, enc_amount: r.arr()?, view_tag: r.u8()? });
        }
        tx.fee = r.u64()?;
        let mass = r.u64()?;
        if mass > 0xffff_ffff { return Err("massa inválida".into()); }
        tx.mass = mass;
        tx.payload = r.varbytes(10_000)?.to_vec();
        for i in tx.t_in.iter_mut() { i.sig = r.varbytes(8192)?.to_vec(); }
        for i in tx.s_in.iter_mut() {
            if i.ring.is_empty() { i.fcmp = r.varbytes(16_384)?.to_vec(); } else { i.clsag = r.varbytes(32 + 32 * 128 + 33)?.to_vec(); }
        }
        tx.range_proof = r.varbytes(4_000)?.to_vec();
        let has_b = r.u8()?;
        if has_b > 1 { return Err("flag inválida".into()); }
        tx.binding_sig = if has_b == 1 { Some(r.arr()?) } else { None };
        Ok(tx)
    }

    pub fn deserialize(buf: &[u8]) -> Res<Self> {
        let mut r = Reader::new(buf);
        let tx = Self::read(&mut r)?;
        r.end()?;
        Ok(tx)
    }

    pub fn id(&self) -> [u8; 32] { *self.id.get_or_init(|| H::new("tx/id").b(&self.serialize_body()).d32()) }
    pub fn id_hex(&self) -> String { to_hex(&self.id()) }
    pub fn hash(&self) -> [u8; 32] {
        *self.hash.get_or_init(|| {
            let wh = H::new("tx/witness").b(&self.serialize_witness()).d32();
            H::new("tx/hash").b(&self.id()).b(&wh).d32()
        })
    }
    pub fn hash_hex(&self) -> String { to_hex(&self.hash()) }
    pub fn size(&self) -> usize { *self.size.get_or_init(|| self.serialize().len()) }
    pub fn sighash(&self) -> [u8; 32] { H::new("tx/sighash").b(&self.id()).d32() }
    /// Depois de mudar campos à mão (montagem de modelos).
    pub fn invalidate(&mut self) { self.id = OnceLock::new(); self.hash = OnceLock::new(); self.size = OnceLock::new(); }
}

pub fn outpoint_key(txid: &[u8; 32], index: u32) -> String { format!("{}:{}", to_hex(txid), index) }
pub fn parse_outpoint_key(k: &str) -> Option<([u8; 32], u32)> {
    let (h, i) = k.split_once(':')?;
    Some((from_hex32(h).ok()?, i.parse().ok()?))
}
