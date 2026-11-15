//! UTXO state (mirrors src/consensus/utxo.js): transparent coins, private outputs
//! (never removed), key images and the curve tree over the private outputs.
//! The materialized state lives at a chain block (the "base") and moves by applying/reverting diffs.

use crate::bytes::Writer;
use crate::fcmp::{CurveTree, Root};
use crate::rules::name_of_lock;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

pub type Op = ([u8; 32], u32);

#[derive(Clone, Debug)]
pub struct TEntry { pub amount: u64, pub lock: Vec<u8>, pub daa: u64, pub coinbase: bool }

#[derive(Clone, Debug)]
pub struct SEntry { pub p: [u8; 33], pub c: [u8; 33], pub enc_amount: [u8; 8], pub view_tag: u8, pub r: [u8; 33], pub j: u32, pub daa: u64, pub coinbase: bool }

pub fn encode_t_entry(k: &Op, e: &TEntry) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x54).bytes(&k.0).u32(k.1).u64(e.amount).varbytes(&e.lock).u64(e.daa).u8(e.coinbase as u8);
    w.done()
}
pub fn encode_s_entry(k: &Op, e: &SEntry) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x53).bytes(&k.0).u32(k.1).bytes(&e.p).bytes(&e.c).bytes(&e.enc_amount).u8(e.view_tag).bytes(&e.r).u32(e.j).u64(e.daa).u8(e.coinbase as u8);
    w.done()
}
pub fn encode_ki(ki: &[u8; 33]) -> Vec<u8> { let mut v = vec![0x4b]; v.extend_from_slice(ki); v }

#[derive(Clone, Default, Debug)]
pub struct UtxoDiff {
    pub add_t: HashMap<Op, TEntry>,
    pub rem_t: HashMap<Op, TEntry>,
    pub add_s: Vec<(Op, SEntry)>,
    pub add_s_map: HashMap<Op, usize>,
    pub add_ki: Vec<[u8; 33]>,
    pub add_ki_set: HashSet<[u8; 33]>,
    pub names: HashMap<String, Vec<Op>>,
}

pub struct UtxoSet {
    pub t: HashMap<Op, TEntry>,
    pub s: HashMap<Op, SEntry>,
    pub ki: HashSet<[u8; 33]>,
    pub s_list: Vec<Op>,
    pub by_lock: HashMap<Vec<u8>, Vec<Op>>,
    pub by_name: HashMap<String, Vec<Op>>,
    pub tree: RefCell<CurveTree>,
}

fn vec_remove(v: &mut Vec<Op>, k: &Op) { if let Some(i) = v.iter().position(|x| x == k) { v.remove(i); } }

impl UtxoSet {
    pub fn new(branch: usize) -> Self {
        UtxoSet { t: HashMap::new(), s: HashMap::new(), ki: HashSet::new(), s_list: vec![], by_lock: HashMap::new(), by_name: HashMap::new(), tree: RefCell::new(CurveTree::new(branch)) }
    }
    fn idx_add(&mut self, k: &Op, e: &TEntry) {
        self.by_lock.entry(e.lock.clone()).or_default().push(*k);
        if let Some(n) = name_of_lock(&e.lock) { self.by_name.entry(n).or_default().push(*k); }
    }
    fn idx_del(&mut self, k: &Op, e: &TEntry) {
        if let Some(v) = self.by_lock.get_mut(&e.lock) { vec_remove(v, k); if v.is_empty() { self.by_lock.remove(&e.lock); } }
        if let Some(n) = name_of_lock(&e.lock) {
            if let Some(v) = self.by_name.get_mut(&n) { vec_remove(v, k); if v.is_empty() { self.by_name.remove(&n); } }
        }
    }
    /// Inserts a transparent coin with its indexes (loading a state snapshot).
    pub fn insert_t(&mut self, k: Op, e: TEntry) { self.idx_add(&k, &e); self.t.insert(k, e); }
    pub fn apply(&mut self, d: &UtxoDiff) {
        for (k, e) in &d.rem_t { self.t.remove(k); self.idx_del(k, e); }
        for (k, e) in &d.add_t { self.t.insert(*k, e.clone()); self.idx_add(k, e); }
        for (k, e) in &d.add_s { self.s.insert(*k, e.clone()); self.s_list.push(*k); }
        for ki in &d.add_ki { self.ki.insert(*ki); }
    }
    pub fn revert(&mut self, d: &UtxoDiff) {
        for ki in &d.add_ki { self.ki.remove(ki); }
        for (k, _) in d.add_s.iter().rev() {
            self.s.remove(k);
            let last = self.s_list.pop();
            assert_eq!(last.as_ref(), Some(k), "inconsistent private output order");
        }
        if !d.add_s.is_empty() { self.tree.borrow_mut().truncate(self.s_list.len() as u64); }
        for (k, e) in &d.add_t { self.t.remove(k); self.idx_del(k, e); }
        for (k, e) in &d.rem_t { self.t.insert(*k, e.clone()); self.idx_add(k, e); }
    }
    /// Root of the tree with the first n private outputs.
    pub fn tree_root(&self, n: u64) -> Root {
        let leaf = |i: u64| { let k = self.s_list[i as usize]; let e = &self.s[&k]; (op_key32(&k), e.p, e.c) };
        self.tree.borrow_mut().root(&leaf, n)
    }
    pub fn tree_path(&self, n: u64, chunk: u64) -> Option<Vec<(u32, u64, Vec<[u64; 4]>)>> {
        let leaf = |i: u64| { let k = self.s_list[i as usize]; let e = &self.s[&k]; (op_key32(&k), e.p, e.c) };
        self.tree.borrow_mut().path_for_chunk(&leaf, n, chunk)
    }
}

/// Compact key (32 bytes) of an outpoint for the leaf memo.
pub fn op_key32(k: &Op) -> [u8; 32] {
    let mut h = crate::hash::H::new("leafkey").b(&k.0).n(k.1 as u64).d32();
    h[0] ^= 0; // (just a local identifier)
    h
}

/// View = base + diff (read only) — used to validate transactions in sequence.
pub struct UtxoView<'a> { pub base: &'a UtxoSet, pub diff: &'a UtxoDiff }

impl<'a> UtxoView<'a> {
    pub fn get_t(&self, k: &Op) -> Option<&'a TEntry> {
        if let Some(a) = self.diff.add_t.get(k) { return Some(a); }
        if self.diff.rem_t.contains_key(k) { return None; }
        self.base.t.get(k)
    }
    pub fn get_s(&self, k: &Op) -> Option<&'a SEntry> {
        if let Some(&i) = self.diff.add_s_map.get(k) { return Some(&self.diff.add_s[i].1); }
        self.base.s.get(k)
    }
    pub fn has_ki(&self, ki: &[u8; 33]) -> bool { self.diff.add_ki_set.contains(ki) || self.base.ki.contains(ki) }
    /// (Unspent) records of a name, including expired ones.
    pub fn name_entries(&self, name: &str) -> Vec<(Op, &'a TEntry)> {
        let mut keys: Vec<Op> = self.base.by_name.get(name).cloned().unwrap_or_default();
        for k in self.diff.names.get(name).into_iter().flatten() { if !keys.contains(k) { keys.push(*k); } }
        keys.into_iter().filter_map(|k| self.get_t(&k).map(|e| (k, e))).collect()
    }
    pub fn all_names(&self) -> HashSet<String> {
        self.base.by_name.keys().chain(self.diff.names.keys()).cloned().collect()
    }
    pub fn s_count(&self) -> usize { self.base.s_list.len() + self.diff.add_s.len() }
    pub fn s_at(&self, i: usize) -> Option<Op> {
        let n = self.base.s_list.len();
        if i < n { Some(self.base.s_list[i]) } else { self.diff.add_s.get(i - n).map(|x| x.0) }
    }
}

impl UtxoDiff {
    pub fn spend_t(&mut self, k: Op, e: &TEntry) {
        if self.add_t.remove(&k).is_none() { self.rem_t.insert(k, e.clone()); }
    }
    pub fn add_t(&mut self, k: Op, e: TEntry) {
        if let Some(n) = name_of_lock(&e.lock) { self.names.entry(n).or_default().push(k); }
        self.add_t.insert(k, e);
    }
    pub fn add_s(&mut self, k: Op, e: SEntry) { self.add_s_map.insert(k, self.add_s.len()); self.add_s.push((k, e)); }
    pub fn add_ki(&mut self, ki: [u8; 33]) { self.add_ki.push(ki); self.add_ki_set.insert(ki); }
}
