//! State snapshot (`state.snap`): everything the consensus engine knows, so that a restart does not
//! re-validate the whole chain.
//!
//! Restarting used to replay `blocks.dat` from the genesis through full validation (every signature,
//! range proof and membership proof checked again). Now the node periodically writes this file;
//! on startup it loads it, re-reads the block bodies it needs from `blocks.dat` WITHOUT validating
//! them again (they were validated before being written), and only validates the blocks that
//! arrived after the snapshot.
//!
//! What it holds: per block (in arrival order) the header, the GHOSTDAG data, status, miner data
//! and the UTXO diff of chain blocks; the materialized UTXO set at the "base" block; the tips and the
//! acceptance/reward indexes; and, for a pruned node, the pruning point. Block bodies are not in it.
//!
//! Integrity: a BLAKE2b checksum over the whole file, every header is re-hashed and must match its
//! key, and the UTXO set is re-committed with MuHash and must equal the commitment that the chain
//! itself carries for the base block (the same `utxoCommitment` every block header has) — a
//! corrupted or tampered snapshot is refused, and the node falls back to a full replay.

use crate::block::{Block, Header};
use crate::bytes::*;
use crate::consensus::{Acc, Consensus, RewardInfo, Status};
use crate::crypto::MuHash;
use crate::dag::*;
use crate::hash::H;
use crate::params::Params;
use crate::utxo::*;
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"KRVSNAP1";
const BIG: u64 = 1 << 40; // bound for list lengths while reading (the checksum already protects the file)

fn w_big(w: &mut Writer, x: &BigUint) { w.varbytes(&x.to_bytes_le()); }
fn r_big(r: &mut Reader) -> Res<BigUint> { Ok(BigUint::from_bytes_le(r.varbytes(4096)?)) }
fn w_hashes(w: &mut Writer, v: &[Hash]) { w.varint(v.len() as u64); for h in v { w.bytes(h); } }
fn r_hashes(r: &mut Reader) -> Res<Vec<Hash>> { let n = r.varint(BIG)?; (0..n).map(|_| r.arr()).collect() }
pub(crate) fn w_op(w: &mut Writer, k: &Op) { w.bytes(&k.0).u32(k.1); }
pub(crate) fn r_op(r: &mut Reader) -> Res<Op> { Ok((r.arr()?, r.u32()?)) }

fn w_gd(w: &mut Writer, g: &GhostdagData) {
    match g.selected_parent { Some(h) => { w.u8(1).bytes(&h); } None => { w.u8(0); } }
    w_hashes(w, &g.mergeset_blues);
    w_hashes(w, &g.mergeset_reds);
    let mut sizes: Vec<(&Hash, &usize)> = g.blues_anticone_sizes.iter().collect();
    sizes.sort();
    w.varint(sizes.len() as u64);
    for (h, s) in sizes { w.bytes(h).varint(*s as u64); }
    w.u64(g.blue_score).u64(g.daa_score);
    w_big(w, &g.blue_work);
    w_hashes(w, &g.mergeset_asc);
}
fn r_gd(r: &mut Reader) -> Res<GhostdagData> {
    let selected_parent = if r.u8()? == 1 { Some(r.arr()?) } else { None };
    let mergeset_blues = r_hashes(r)?;
    let mergeset_reds = r_hashes(r)?;
    let n = r.varint(BIG)?;
    let mut blues_anticone_sizes = HashMap::new();
    for _ in 0..n { let h: Hash = r.arr()?; blues_anticone_sizes.insert(h, r.varint(BIG)? as usize); }
    let blue_score = r.u64()?;
    let daa_score = r.u64()?;
    let blue_work = r_big(r)?;
    let mergeset_asc = r_hashes(r)?;
    Ok(GhostdagData { selected_parent, mergeset_blues, mergeset_reds, blues_anticone_sizes, blue_score, blue_work, daa_score, mergeset_asc })
}

pub(crate) fn w_t(w: &mut Writer, e: &TEntry) { w.u64(e.amount).varbytes(&e.lock).u64(e.daa).u8(e.coinbase as u8); }
pub(crate) fn r_t(r: &mut Reader) -> Res<TEntry> { Ok(TEntry { amount: r.u64()?, lock: r.varbytes(BIG)?.to_vec(), daa: r.u64()?, coinbase: r.u8()? == 1 }) }
pub(crate) fn w_s(w: &mut Writer, e: &SEntry) { w.bytes(&e.p).bytes(&e.c).bytes(&e.enc_amount).u8(e.view_tag).bytes(&e.r).u32(e.j).u64(e.daa).u8(e.coinbase as u8); }
pub(crate) fn r_s(r: &mut Reader) -> Res<SEntry> {
    Ok(SEntry { p: r.arr()?, c: r.arr()?, enc_amount: r.arr()?, view_tag: r.u8()?, r: r.arr()?, j: r.u32()?, daa: r.u64()?, coinbase: r.u8()? == 1 })
}

fn w_diff(w: &mut Writer, d: &UtxoDiff) {
    let mut add: Vec<_> = d.add_t.iter().collect(); add.sort_by_key(|x| *x.0);
    w.varint(add.len() as u64); for (k, e) in add { w_op(w, k); w_t(w, e); }
    let mut rem: Vec<_> = d.rem_t.iter().collect(); rem.sort_by_key(|x| *x.0);
    w.varint(rem.len() as u64); for (k, e) in rem { w_op(w, k); w_t(w, e); }
    w.varint(d.add_s.len() as u64); for (k, e) in &d.add_s { w_op(w, k); w_s(w, e); }
    w.varint(d.add_ki.len() as u64); for ki in &d.add_ki { w.bytes(ki); }
    let mut names: Vec<_> = d.names.iter().collect(); names.sort_by(|a, b| a.0.cmp(b.0));
    w.varint(names.len() as u64);
    for (n, ops) in names { w.varbytes(n.as_bytes()).varint(ops.len() as u64); for k in ops { w_op(w, k); } }
}
fn r_diff(r: &mut Reader) -> Res<UtxoDiff> {
    let mut d = UtxoDiff::default();
    for _ in 0..r.varint(BIG)? { let k = r_op(r)?; d.add_t.insert(k, r_t(r)?); }
    for _ in 0..r.varint(BIG)? { let k = r_op(r)?; d.rem_t.insert(k, r_t(r)?); }
    for _ in 0..r.varint(BIG)? { let k = r_op(r)?; let e = r_s(r)?; d.add_s(k, e); }
    for _ in 0..r.varint(BIG)? { d.add_ki(r.arr()?); }
    for _ in 0..r.varint(BIG)? {
        let n = String::from_utf8(r.varbytes(256)?.to_vec()).map_err(|_| "invalid name")?;
        let ops = (0..r.varint(BIG)?).map(|_| r_op(r)).collect::<Res<Vec<Op>>>()?;
        d.names.insert(n, ops);
    }
    Ok(d)
}

fn w_acc(w: &mut Writer, a: &Acc) {
    w_diff(w, &a.diff);
    w.bytes(&a.muhash.to_state()).u64(a.pool).u64(a.minted);
    w_hashes(w, &a.accepted);
    w.varint(a.rewards.len() as u64); for (h, x) in &a.rewards { w.bytes(h).u64(*x); }
    w_hashes(w, &a.reds);
    w.bytes(&a.shielded.to_le_bytes()).u64(a.cb_shielded);
}
fn r_acc(r: &mut Reader) -> Res<Acc> {
    let diff = r_diff(r)?;
    let muhash = MuHash::from_state(r.bytes(768)?).ok_or("invalid MuHash state")?;
    let pool = r.u64()?;
    let minted = r.u64()?;
    let accepted = r_hashes(r)?;
    let rewards = (0..r.varint(BIG)?).map(|_| Ok((r.arr()?, r.u64()?))).collect::<Res<Vec<(Hash, u64)>>>()?;
    let reds = r_hashes(r)?;
    let shielded = i128::from_le_bytes(r.arr()?);
    let cb_shielded = r.u64()?;
    Ok(Acc { diff, muhash, pool, minted, accepted, rewards, reds, shielded, cb_shielded })
}

/// Serializes the engine's state (see the module notes).
pub fn encode(c: &Consensus) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(MAGIC).varbytes(c.params.name.as_bytes()).bytes(&c.genesis_hash);
    match c.pruning_point { Some(pp) => { w.u8(1).bytes(&pp).u64(c.prune_cutoff); } None => { w.u8(0); } }
    w.u64(c.blocks_count).u64(c.reds_count).bytes(&c.base_hash);
    w.varint(c.order.len() as u64);
    for h in &c.order {
        w.varbytes(&c.headers[h].serialize(false));
        w.u64(c.store.height[h]);
        w_gd(&mut w, &c.store.gd[h]);
        w_big(&mut w, &c.store.work[h]);
        w_hashes(&mut w, &c.store.parents[h]);
        w.u8(match c.status.get(h) { None => 0, Some(Status::Chain) => 1, Some(Status::Disq) => 2 });
        w.varbytes(c.miner_data.get(h).map(|v| v.as_slice()).unwrap_or(&[]));
        w.u8(c.chain_ok.get(h).copied().unwrap_or(false) as u8);
        w.u8(c.blocks.contains_key(h) as u8);
        match c.acc.get(h) { Some(a) => { w.u8(1); w_acc(&mut w, a); } None => { w.u8(0); } }
    }
    let mut tips: Vec<Hash> = c.tips.iter().copied().collect(); tips.sort();
    w_hashes(&mut w, &tips);
    let mut t: Vec<_> = c.utxo.t.iter().collect(); t.sort_by_key(|x| *x.0);
    w.varint(t.len() as u64); for (k, e) in t { w_op(&mut w, k); w_t(&mut w, e); }
    w.varint(c.utxo.s_list.len() as u64); for k in &c.utxo.s_list { w_op(&mut w, k); w_s(&mut w, &c.utxo.s[k]); }
    let mut ki: Vec<_> = c.utxo.ki.iter().collect(); ki.sort();
    w.varint(ki.len() as u64); for k in ki { w.bytes(k); }
    let mut txi: Vec<_> = c.tx_index.iter().collect(); txi.sort();
    w.varint(txi.len() as u64); for (id, h) in txi { w.bytes(id).bytes(h); }
    let mut rw: Vec<_> = c.reward_index.iter().collect(); rw.sort_by_key(|x| *x.0);
    w.varint(rw.len() as u64); for (h, i) in rw { w.bytes(h).u64(i.amount).bytes(&i.paid_by).u8(i.red as u8); }
    let mut out = w.done();
    let sum = H::new("snapshot/checksum").b(&out).d32();
    out.extend_from_slice(&sum);
    out
}

/// What a snapshot expects to find in `blocks.dat`: the blocks whose bodies it did not drop.
pub struct Loaded { pub c: Consensus, pub bodies_expected: HashSet<Hash> }

impl Loaded {
    /// How many of the bodies this snapshot needs are absent from `blocks`.
    pub fn missing_bodies(&self, blocks: &[Block]) -> usize {
        let present: HashSet<Hash> = blocks.iter().map(|b| b.hash()).collect();
        self.bodies_expected.iter().filter(|h| !present.contains(*h)).count()
    }
    /// Attaches the bodies (from blocks.dat: they were fully validated when first received, so they
    /// are not validated again) and finishes the engine. Returns it together with the blocks the
    /// snapshot does not know yet, in file order — those still go through full validation.
    pub fn finish(self, blocks: Vec<Block>) -> (Consensus, Vec<Block>) {
        let Loaded { mut c, bodies_expected } = self;
        let mut later = vec![];
        for b in blocks {
            let h = b.hash();
            if !c.store.has(&h) { later.push(b); } else if bodies_expected.contains(&h) { c.blocks.entry(h).or_insert_with(|| Arc::new(b)); }
        }
        c.rebuild_body_indexes();
        c.resolve_virtual();
        (c, later)
    }
}

/// Reads and checks a snapshot. The bodies must then be attached (Node::load) before use.
pub fn decode(params: &Params, buf: &[u8]) -> Result<Loaded, String> {
    if buf.len() < MAGIC.len() + 32 || &buf[..8] != MAGIC { return Err("not a Krevo state snapshot (or an older format)".into()); }
    let (body, sum) = buf.split_at(buf.len() - 32);
    if H::new("snapshot/checksum").b(body).d32() != sum { return Err("checksum mismatch (damaged file)".into()); }
    let mut r = Reader::new(&body[8..]);
    let name = String::from_utf8(r.varbytes(64)?.to_vec()).map_err(|_| "invalid network name")?;
    if name != params.name { return Err(format!("snapshot of the {name} network")); }
    let mut c = Consensus::new(params.clone());
    let genesis: Hash = r.arr()?;
    if genesis != c.genesis_hash { return Err("snapshot of another genesis".into()); }
    if r.u8()? == 1 { c.pruning_point = Some(r.arr()?); c.prune_cutoff = r.u64()?; }
    c.blocks_count = r.u64()?;
    c.reds_count = r.u64()?;
    c.base_hash = r.arr()?;
    // start from an empty engine (except for the genesis body: it is built, never stored in blocks.dat)
    let genesis_body = c.blocks[&c.genesis_hash].clone();
    c.store = DagStore::default();
    c.headers.clear(); c.blocks.clear(); c.miner_data.clear(); c.status.clear(); c.acc.clear(); c.tips.clear();
    c.order.clear(); c.chain_ok.clear(); c.tx_index.clear(); c.tx_block.clear(); c.lock_txs.clear(); c.reward_index.clear();
    c.utxo = UtxoSet::new(params.fcmp_branch);
    let mut bodies_expected = HashSet::new();
    for _ in 0..r.varint(BIG)? {
        let header = Header::deserialize(r.varbytes(1 << 20)?)?;
        let h = header.hash();
        let height = r.u64()?;
        let gd = r_gd(&mut r)?;
        let work = r_big(&mut r)?;
        let parents = r_hashes(&mut r)?;
        for p in &parents { if !c.store.gd.contains_key(p) { return Err("block listed before its parent".into()); } }
        if let Some(sp) = gd.selected_parent { if !c.store.gd.contains_key(&sp) && c.pruning_point.is_none() { return Err("unknown selected parent".into()); } }
        match r.u8()? { 1 => { c.status.insert(h, Status::Chain); } 2 => { c.status.insert(h, Status::Disq); } _ => {} }
        c.miner_data.insert(h, r.varbytes(256)?.to_vec());
        c.chain_ok.insert(h, r.u8()? == 1);
        if r.u8()? == 1 {
            if h == genesis { c.blocks.insert(h, genesis_body.clone()); } else { bodies_expected.insert(h); }
        }
        if r.u8()? == 1 { c.acc.insert(h, r_acc(&mut r)?); }
        for p in &parents { if let Some(ch) = c.store.children.get_mut(p) { ch.push(h); } }
        c.store.children.insert(h, vec![]);
        c.store.parents.insert(h, parents);
        c.store.height.insert(h, height);
        c.store.gd.insert(h, gd);
        c.store.work.insert(h, work);
        c.headers.insert(h, header);
        c.order.push(h);
    }
    for t in r_hashes(&mut r)? { if !c.store.has(&t) { return Err("unknown tip".into()); } c.tips.insert(t); }
    for _ in 0..r.varint(BIG)? { let k = r_op(&mut r)?; let e = r_t(&mut r)?; c.utxo.insert_t(k, e); }
    for _ in 0..r.varint(BIG)? { let k = r_op(&mut r)?; let e = r_s(&mut r)?; c.utxo.s.insert(k, e); c.utxo.s_list.push(k); }
    for _ in 0..r.varint(BIG)? { c.utxo.ki.insert(r.arr()?); }
    for _ in 0..r.varint(BIG)? { let id: [u8; 32] = r.arr()?; let h: Hash = r.arr()?; c.tx_index.insert(id, h); }
    for _ in 0..r.varint(BIG)? {
        let h: Hash = r.arr()?;
        let amount = r.u64()?;
        let paid_by: Hash = r.arr()?;
        let red = r.u8()? == 1;
        c.reward_index.insert(h, RewardInfo { amount, paid_by, red });
    }
    r.end()?;
    // consistency: the base and the pruning point must be known chain blocks with their totals
    if !c.store.has(&c.base_hash) || !c.acc.contains_key(&c.base_hash) { return Err("snapshot without its base block".into()); }
    if let Some(pp) = c.pruning_point { if !c.store.has(&pp) || !c.acc.contains_key(&pp) { return Err("snapshot without its pruning point".into()); } }
    if c.tips.is_empty() { return Err("snapshot without tips".into()); }
    // the UTXO set must re-commit to what the chain says (the base block's MuHash commitment)
    let mut mh = MuHash::new();
    for (k, e) in &c.utxo.t { mh.add(&encode_t_entry(k, e)); }
    for k in &c.utxo.s_list { mh.add(&encode_s_entry(k, &c.utxo.s[k])); }
    for ki in &c.utxo.ki { mh.add(&encode_ki(ki)); }
    let mut expected = c.acc[&c.base_hash].muhash.clone();
    if mh.digest() != expected.digest() { return Err("the UTXO set does not match the chain's commitment".into()); }
    if c.utxo.s.len() != c.utxo.s_list.len() { return Err("repeated private output".into()); }
    Ok(Loaded { c, bodies_expected })
}

/// Writes the snapshot (atomically: a crash leaves the previous one intact); returns its size.
pub fn save(c: &Consensus, path: &std::path::Path) -> std::io::Result<usize> {
    let data = encode(c);
    crate::storage::write_atomic(path, &data)?;
    Ok(data.len())
}
