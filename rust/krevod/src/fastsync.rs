//! Fast sync for new nodes (`krevod node --fast-sync`): headers first, then the state at a sync point.
//!
//! A new node normally downloads every block and validates every transaction since the genesis. With
//! fast sync it:
//!  1. downloads and validates **every header** since the genesis (PoW, parents, GHOSTDAG, difficulty,
//!     timestamps, merge depth) — so it knows the heaviest chain with the full security of its work —
//!     while keeping only a recent window of them in memory (`HeaderChain`);
//!  2. picks a *sync point* S on that chain, `sync_depth` blue score below its tip;
//!  3. asks its peers for the state at S: the UTXO set (transparent coins, private outputs, key images)
//!     plus S's block. The UTXO set must re-commit to the MuHash commitment in S's header, and the
//!     coins minted up to S must match what the headers imply;
//!  4. starts its engine from there (as a node pruned at S) and downloads and fully validates the
//!     blocks after S.
//!
//! Two totals are not in any header: the Security Fund balance and the private-pool total (and the
//! private part of S's coinbase). They come from the peers: every peer asked must agree (otherwise the
//! node falls back to a full sync), and they are then checked by the validation of the following
//! blocks — a wrong value makes the next coinbases or acceptance roots disagree with the chain.
//!
//! Not a Kaspa-style pruning proof: that needs a logarithmic subset of headers, which needs
//! per-level parents in the header format (a consensus change). Headers are small, but a node still
//! needs a peer that keeps all of them (an archival node).

use crate::block::{Block, Header};
use crate::bytes::*;
use crate::consensus::*;
use crate::crypto::MuHash;
use crate::dag::*;
use crate::hash::H;
use crate::params::Params;
use crate::pow::calc_work;
use crate::snapshot::{r_op, r_s, r_t, w_op, w_s, w_t};
use crate::utxo::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Blue score covered by one `headers` message (the server's choice: the reply says where to go on).
pub const HEADER_PAGE: u64 = 2_000;
/// Bytes of state per `state` message (hex in JSON: about twice this, under the 8 MB message limit).
pub const STATE_CHUNK: usize = 2 << 20;
pub const MAX_STATE_PARTS: u64 = 1024;
pub const HEADER_TIMEOUT_MS: u64 = 20_000;
pub const STATE_TIMEOUT_MS: u64 = 60_000;
/// Peers asked for the state (all must agree).
pub const STATE_PEERS: usize = 3;
const STATE_MAGIC: &[u8; 8] = b"KRVSTAT1";

/// Depth of the sync point below the tip: the deepest validation window. It is at most half the
/// smallest pruning depth, so every peer (pruned or not) still has the diffs to rebuild that state.
pub fn sync_depth(p: &Params) -> u64 { p.merge_depth.max(p.daa_window_size as u64).max(p.past_median_time_window as u64).max(100) }
/// DAG data needed below the sync point: the pruning margin, plus one merge depth for blocks in its
/// anticone that later blocks may still merge (their own parents reach that far down).
pub fn engine_margin(p: &Params) -> u64 { prune_margin(p) + p.merge_depth }

// ===================================================================== headers
pub enum HeaderResult { Added, Known, Orphan, Invalid(String) }

/// Header-only DAG: validates headers exactly as the engine does, without bodies, and forgets what
/// is far below its tip (a rolling window), so memory stays bounded however long the chain is.
pub struct HeaderChain {
    pub params: Params,
    pub store: DagStore,
    pub headers: HashMap<Hash, Header>,
    ghostdag: Ghostdag,
    pow_limit_bits: u32,
    pub genesis: Hash,
    pub tips: HashSet<Hash>,
    pub order: Vec<Hash>,
    /// coins minted up to each block's acceptance (header data only)
    pub minted: HashMap<Hash, u64>,
    /// headers validated (beyond the genesis), including forgotten ones
    pub count: u64,
    pub reds: u64,
    pub cutoff: u64,
    orphans: HashMap<Hash, Header>,
    invalid: HashSet<Hash>,
}

impl HeaderChain {
    pub fn new(params: Params) -> Self {
        let g = build_genesis(&params);
        let h = g.hash();
        let mut store = DagStore::default();
        store.add(h, vec![], genesis_ghostdag(), calc_work(g.header.bits));
        HeaderChain {
            ghostdag: Ghostdag { k: params.ghostdag_k }, pow_limit_bits: params.genesis_bits, genesis: h,
            headers: HashMap::from([(h, g.header.clone())]), tips: HashSet::from([h]), order: vec![h], minted: HashMap::from([(h, 0)]),
            store, count: 0, reds: 0, cutoff: 0, orphans: HashMap::new(), invalid: HashSet::new(), params,
        }
    }
    pub fn best(&self) -> Hash { *self.tips.iter().max_by(|a, b| self.store.cmp(a, b)).unwrap() }
    pub fn best_score(&self) -> u64 { self.store.gd[&self.best()].blue_score }

    pub fn add(&mut self, h: Header, now: u64) -> HeaderResult {
        let hash = h.hash();
        if self.store.has(&hash) || self.orphans.contains_key(&hash) { return HeaderResult::Known; }
        if self.invalid.contains(&hash) { return HeaderResult::Invalid("known invalid header".into()); }
        if h.timestamp > now + self.params.max_future_ms { return HeaderResult::Known; } // (our clock may lag: skipped, not punished; the block comes later)
        if h.parents.iter().any(|p| !self.store.has(p)) {
            if h.blue_score < self.cutoff { return HeaderResult::Known; } // (below the window: already forgotten)
            if self.orphans.len() < 20_000 { self.orphans.insert(hash, h); }
            return HeaderResult::Orphan;
        }
        if let Err(e) = self.insert(hash, h) { return HeaderResult::Invalid(e); }
        // headers that were waiting for this one
        while !self.orphans.is_empty() {
            let ready: Vec<Hash> = self.orphans.iter().filter(|(_, o)| o.parents.iter().all(|p| self.store.has(p))).map(|(k, _)| *k).collect();
            if ready.is_empty() { break; }
            for k in ready { let o = self.orphans.remove(&k).unwrap(); let _ = self.insert(k, o); }
        }
        HeaderResult::Added
    }

    fn insert(&mut self, hash: Hash, h: Header) -> Result<(), String> {
        let gd = match check_header(&self.params, &self.store, &self.headers, &self.ghostdag, self.pow_limit_bits, &h) {
            Ok(gd) => gd,
            Err(e) => { if self.invalid.len() > 10_000 { self.invalid.clear(); } self.invalid.insert(hash); return Err(e); }
        };
        let sp = gd.selected_parent.unwrap();
        let minted = minted_after(&self.params, &self.store, &self.genesis, self.minted[&sp], &gd);
        self.reds += gd.mergeset_reds.len() as u64;
        for p in &h.parents { self.tips.remove(p); }
        self.tips.insert(hash);
        self.store.add(hash, h.parents.clone(), gd, calc_work(h.bits));
        self.headers.insert(hash, h);
        self.minted.insert(hash, minted);
        self.order.push(hash);
        self.count += 1;
        Ok(())
    }

    /// Forgets the headers more than `keep` blue score below the tip (they can never be needed to
    /// validate new headers, nor to start the engine from the sync point).
    pub fn prune(&mut self, keep: u64) {
        let cut = self.best_score().saturating_sub(keep);
        if cut <= self.cutoff { return; }
        let forget: HashSet<Hash> = self.order.iter().filter(|h| self.store.gd[*h].blue_score < cut).copied().collect();
        for h in &forget {
            self.headers.remove(h); self.minted.remove(h); self.tips.remove(h);
            self.store.parents.remove(h); self.store.children.remove(h); self.store.height.remove(h);
            self.store.gd.remove(h); self.store.work.remove(h);
        }
        for list in self.store.parents.values_mut() { list.retain(|p| !forget.contains(p)); }
        for list in self.store.children.values_mut() { list.retain(|p| !forget.contains(p)); }
        self.order.retain(|h| !forget.contains(h));
        self.orphans.retain(|_, o| o.blue_score >= cut);
        self.cutoff = cut;
    }
    pub fn window(&self) -> u64 { sync_depth(&self.params) + engine_margin(&self.params) + 100 }

    /// The sync point: the selected-chain block `sync_depth` below the tip (None while the chain is
    /// too short for fast sync to be worth it — a normal sync is quick then).
    pub fn sync_point(&self) -> Option<Hash> {
        let p = &self.params;
        let best = self.best();
        let top = self.store.gd[&best].blue_score;
        if top <= 2 * sync_depth(p) { return None; }
        let target = top - sync_depth(p);
        let mut x = best;
        while self.store.gd[&x].blue_score > target {
            match self.store.gd[&x].selected_parent { Some(sp) if self.store.has(&sp) => x = sp, _ => return None }
        }
        let bs = self.store.gd[&x].blue_score;
        if self.cutoff > 0 && bs < self.cutoff + engine_margin(p) { return None; }
        Some(x)
    }
}

// ======================================================================= state
/// What a peer sends for the sync point S (all of it checked before use).
pub struct StateData {
    pub hash: Hash,
    pub block: Block,
    pub pool: u64,
    pub minted: u64,
    pub shielded: i128,
    pub cb_shielded: u64,
    pub utxo: UtxoSet,
    pub muhash: MuHash,
}

/// Server side: the state at chain block `s` (canonical bytes: every honest node sends the same).
/// Err is a short code for the reply: "unknown", "not-chain" or "pruned".
pub fn encode_state(c: &mut Consensus, s: &Hash) -> Result<Vec<u8>, &'static str> {
    if !c.store.has(s) { return Err("unknown"); }
    if c.status.get(s) != Some(&Status::Chain) || !c.acc.contains_key(s) { return Err("not-chain"); }
    if !c.chain_ok.get(s).copied().unwrap_or(false) || !c.blocks.contains_key(s) { return Err("pruned"); }
    c.move_base(s);
    let a = &c.acc[s];
    let mut w = Writer::new();
    w.bytes(STATE_MAGIC).bytes(s).u64(a.pool).u64(a.minted).bytes(&a.shielded.to_le_bytes()).u64(a.cb_shielded);
    w.varbytes(&c.blocks[s].serialize());
    let mut t: Vec<_> = c.utxo.t.iter().collect();
    t.sort_by_key(|x| *x.0);
    w.varint(t.len() as u64);
    for (k, e) in t { w_op(&mut w, k); w_t(&mut w, e); }
    w.varint(c.utxo.s_list.len() as u64);
    for k in &c.utxo.s_list { w_op(&mut w, k); w_s(&mut w, &c.utxo.s[k]); }
    let mut ki: Vec<_> = c.utxo.ki.iter().collect();
    ki.sort();
    w.varint(ki.len() as u64);
    for k in ki { w.bytes(k); }
    let out = w.done();
    c.ensure_virtual_base(); // (the materialized state goes back to the virtual's selected parent)
    Ok(out)
}

pub fn state_digest(buf: &[u8]) -> [u8; 32] { H::new("fastsync/state").b(buf).d32() }

/// Requester side: parses a state and checks it against the validated headers — S's block must be
/// the header we have, the UTXO set must re-commit to S's MuHash commitment, and the coins minted
/// must be what the headers imply.
pub fn decode_state(hc: &HeaderChain, buf: &[u8]) -> Result<StateData, String> {
    const BIG: u64 = 1 << 40;
    let mut r = Reader::new(buf);
    if r.bytes(8)? != &STATE_MAGIC[..] { return Err("not a state message".into()); }
    let hash: Hash = r.arr()?;
    let pool = r.u64()?;
    let minted = r.u64()?;
    let shielded = i128::from_le_bytes(r.arr()?);
    let cb_shielded = r.u64()?;
    let block = Block::deserialize(r.varbytes(1 << 26)?)?;
    let mut utxo = UtxoSet::new(hc.params.fcmp_branch);
    let mut mh = MuHash::new();
    for _ in 0..r.varint(BIG)? {
        let k = r_op(&mut r)?;
        let e = r_t(&mut r)?;
        mh.add(&encode_t_entry(&k, &e));
        if utxo.t.contains_key(&k) { return Err("repeated coin".into()); }
        utxo.insert_t(k, e);
    }
    for _ in 0..r.varint(BIG)? {
        let k = r_op(&mut r)?;
        let e = r_s(&mut r)?;
        mh.add(&encode_s_entry(&k, &e));
        if utxo.s.insert(k, e).is_some() { return Err("repeated private output".into()); }
        utxo.s_list.push(k);
    }
    for _ in 0..r.varint(BIG)? {
        let ki: [u8; 33] = r.arr()?;
        mh.add(&encode_ki(&ki));
        if !utxo.ki.insert(ki) { return Err("repeated key image".into()); }
    }
    r.end()?;
    let header = hc.headers.get(&hash).ok_or("state for a block whose header we do not have")?;
    if block.hash() != hash || block.header.serialize(false) != header.serialize(false) { return Err("the block does not match its header".into()); }
    mh.normalize();
    if mh.clone().digest() != header.utxo_commitment { return Err("the UTXO set does not match the commitment in the header".into()); }
    if hc.minted.get(&hash) != Some(&minted) { return Err("coins minted do not match the headers".into()); }
    Ok(StateData { hash, block, pool, minted, shielded, cb_shielded, utxo, muhash: mh })
}

/// Starts an engine at the sync point: the DAG data of the past of S within `engine_margin` (from the
/// validated headers), S's block and the verified state; S is its pruning point. The blocks after S
/// are then added normally (full validation).
pub fn build_engine(hc: &HeaderChain, st: StateData) -> Result<Consensus, String> {
    let p = hc.params.clone();
    let s = st.hash;
    let s_bs = hc.store.gd.get(&s).ok_or("sync point not in the header window")?.blue_score;
    let cutoff = s_bs.saturating_sub(engine_margin(&p));
    if hc.cutoff > cutoff { return Err("the header window does not reach far enough below the sync point".into()); }
    let mut keep: HashSet<Hash> = HashSet::from([s]);
    let mut stack = vec![s];
    while let Some(x) = stack.pop() {
        for q in &hc.store.parents[&x] {
            if hc.store.gd[q].blue_score >= cutoff && keep.insert(*q) { stack.push(*q); }
        }
    }
    let mut c = Consensus::new(p.clone());
    let md = c.check_body(&st.block)?;
    c.store = DagStore::default();
    c.headers.clear(); c.blocks.clear(); c.miner_data.clear(); c.status.clear(); c.acc.clear(); c.tips.clear();
    c.order.clear(); c.chain_ok.clear(); c.tx_index.clear(); c.tx_block.clear(); c.lock_txs.clear(); c.reward_index.clear();
    for h in hc.order.iter().filter(|h| keep.contains(*h)) {
        let parents: Vec<Hash> = hc.store.parents[h].iter().filter(|q| keep.contains(*q)).copied().collect();
        for q in &parents { c.store.children.get_mut(q).unwrap().push(*h); }
        c.store.children.insert(*h, vec![]);
        c.store.parents.insert(*h, parents);
        c.store.height.insert(*h, hc.store.height[h]);
        c.store.gd.insert(*h, hc.store.gd[h].clone());
        c.store.work.insert(*h, hc.store.work[h].clone());
        c.headers.insert(*h, hc.headers[h].clone());
        c.chain_ok.insert(*h, *h == s);
        c.order.push(*h);
    }
    // counters (shown by getinfo): what the headers covered, minus the blocks that will come again
    let again: Vec<&Hash> = hc.order.iter().filter(|h| !keep.contains(*h) && hc.store.gd[*h].blue_score >= cutoff).collect();
    c.blocks_count = hc.count - again.len() as u64;
    c.reds_count = hc.reds - again.iter().map(|h| hc.store.gd[*h].mergeset_reds.len() as u64).sum::<u64>();
    c.pruning_point = Some(s);
    c.prune_cutoff = cutoff;
    c.status.insert(s, Status::Chain);
    c.miner_data.insert(s, md);
    c.blocks.insert(s, Arc::new(st.block));
    c.acc.insert(s, Acc {
        diff: UtxoDiff::default(), muhash: st.muhash, pool: st.pool, minted: st.minted, accepted: vec![], rewards: vec![], reds: vec![],
        shielded: st.shielded, cb_shielded: st.cb_shielded,
    });
    c.utxo = st.utxo;
    c.base_hash = s;
    c.tips.insert(s);
    c.rebuild_body_indexes();
    c.resolve_virtual();
    Ok(c)
}

// ================================================================ the process
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Stage { Headers, State }

pub struct Parts { pub total: u64, pub digest: [u8; 32], pub got: Vec<Option<Vec<u8>>>, pub n: u64 }

/// Progress of a fast sync (driven by Node: messages and its maintenance tick).
pub struct FastSync {
    pub hc: HeaderChain,
    pub stage: Stage,
    pub header_peer: Option<u64>,
    pub next_from: u64,
    pub last_progress: u64,
    pub tried: HashSet<u64>,
    pub peer_scores: HashMap<u64, u64>,
    pub target: Option<Hash>,
    pub asked: HashSet<u64>,
    pub answered: HashSet<u64>,
    pub parts: HashMap<u64, Parts>,
    pub verified: Vec<(u64, [u8; 32], StateData)>,
    pub disagreement: bool,
    pub state_since: u64,
}

impl FastSync {
    pub fn new(params: Params, now: u64) -> Self {
        FastSync {
            hc: HeaderChain::new(params), stage: Stage::Headers, header_peer: None, next_from: 0, last_progress: now,
            tried: HashSet::new(), peer_scores: HashMap::new(), target: None, asked: HashSet::new(), answered: HashSet::new(),
            parts: HashMap::new(), verified: vec![], disagreement: false, state_since: now,
        }
    }
    /// One `state` message from `peer`; the whole state once every part arrived (checked against the digest).
    pub fn add_part(&mut self, peer: u64, part: u64, total: u64, digest: [u8; 32], data: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        if total == 0 || total > MAX_STATE_PARTS || part >= total { return Err("invalid state part".into()); }
        let e = self.parts.entry(peer).or_insert_with(|| Parts { total, digest, got: vec![None; total as usize], n: 0 });
        if e.total != total || e.digest != digest { return Err("inconsistent state parts".into()); }
        if e.got[part as usize].is_none() { e.got[part as usize] = Some(data); e.n += 1; }
        if e.n < e.total { return Ok(None); }
        let e = self.parts.remove(&peer).unwrap();
        let buf: Vec<u8> = e.got.into_iter().flatten().flatten().collect();
        if state_digest(&buf) != e.digest { return Err("state does not match its digest".into()); }
        Ok(Some(buf))
    }
}
