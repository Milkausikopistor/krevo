//! Full node: consensus + mempool + P2P + RPC + storage (mirrors node.js and p2p.js).
//!
//! P2P: TCP with [magic u32][length u32][JSON] messages — the same protocol as the JavaScript node,
//! so Rust and JavaScript nodes form a single network. DAG synchronization by inventory;
//! blocks with unknown parents become orphans and the parents are requested from the same peer.
//! Dandelion++: a new transaction walks along the "stem" (one peer at a time) before it "fluffs".

use crate::block::Block;
use crate::bytes::{from_hex, from_hex32, to_hex};
use crate::consensus::{AddResult, Consensus};
use crate::dag::Hash;
use crate::block::Header;
use crate::fastsync::*;
use crate::mempool::{now_ms, Mempool};
use crate::params::Params;
use crate::storage::BlockFile;
use crate::tx::Transaction;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

const PROTOCOL_VERSION: u64 = 1;
const MAX_MSG: usize = 8 * 1024 * 1024;
const STEM_PROBABILITY: f64 = 0.9;
/// A state snapshot (and, on a pruned node, a pruning round) every max(this many new blocks, a
/// quarter of the blocks the engine keeps). The snapshot is rewritten whole (~1.6 KB per kept block),
/// so a growing interval bounds the disk writes to ~4× its size per its own size in new blocks, and a
/// restart never re-validates more than about a quarter of what the node keeps.
const SNAPSHOT_EVERY_BLOCKS: u64 = 6_000;

pub struct Peer { pub id: u64, pub addr: String, pub outbound: bool, pub ready: bool, pub score: i32, pub listen: Option<String>, tx: Sender<Vec<u8>>, sock: TcpStream }

pub struct Node {
    pub params: Params,
    pub c: Consensus,
    pub mempool: Mempool,
    pub orphans: HashMap<Hash, (Block, HashSet<Hash>)>,
    pub waiting: HashMap<Hash, HashSet<Hash>>,
    pub future: HashMap<Hash, (Block, Option<u64>)>,
    pub stem: HashMap<[u8; 32], (Arc<Transaction>, u64)>,
    pub storage: Option<BlockFile>,
    pub block_times: VecDeque<u64>,
    pub started_at: u64,
    pub peers: HashMap<u64, Peer>,
    next_peer: u64,
    pub known: Vec<String>,
    requested: HashMap<String, u64>,
    stem_peer: Option<u64>,
    stem_since: u64,
    embargo: HashMap<[u8; 32], u64>,
    nonce: String,
    pub port: u16,
    pub rpc_host: String,
    pub rpc_port: u16,
    max_peers: usize,
    pub template_cache: HashMap<String, Value>,
    rng: u64,
    pub to_connect: Vec<String>,
    /// Pruning depth (blue score) when the node prunes (`--prune`); None = archival node.
    pub prune_depth: Option<u64>,
    snap_blocks: u64,
    /// `--fast-sync`: an empty node starts from headers + a verified state (fastsync.rs)
    pub fast_sync: bool,
    /// the fast sync in progress (None: normal operation)
    pub fast: Option<FastSync>,
    /// blue score per `headers` reply this node serves
    pub header_page: u64,
}

pub type Shared = Arc<(Mutex<Node>, Condvar)>;

pub fn log(m: &str) {
    let t = now_ms() % 86_400_000;
    eprintln!("[{:02}:{:02}:{:02}] {m}", t / 3_600_000, t / 60_000 % 60, t / 1000 % 60);
}

/// Locks the node state. If some thread panicked while holding the lock, it carries on with the
/// state (like the JavaScript node, which catches the exception and continues): a hostile peer
/// cannot bring the whole node down by "poisoning" the lock.
pub fn lock_node(m: &Mutex<Node>) -> MutexGuard<'_, Node> { m.lock().unwrap_or_else(|e| e.into_inner()) }

/// Runs `f` catching panics — defense in depth: a programming error triggered by
/// hostile data becomes an ordinary error (the peer is disconnected), not a node crash.
pub fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(p) => {
            let why = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
            Err(format!("{INTERNAL}: {why}"))
        }
    }
}
pub const INTERNAL: &str = "internal failure";

impl Node {
    pub fn new(params: Params, storage: Option<BlockFile>, port: u16, rpc_host: String, rpc_port: u16) -> Self {
        let mut seed = [0u8; 16];
        let _ = getrandom::fill(&mut seed);
        Node {
            c: Consensus::new(params.clone()), mempool: Mempool::new(), params,
            orphans: HashMap::new(), waiting: HashMap::new(), future: HashMap::new(), stem: HashMap::new(), storage,
            block_times: VecDeque::new(), started_at: now_ms(), peers: HashMap::new(), next_peer: 1, known: vec![],
            requested: HashMap::new(), stem_peer: None, stem_since: 0, embargo: HashMap::new(),
            nonce: to_hex(&seed[..8]), port, rpc_host, rpc_port, max_peers: 24, template_cache: HashMap::new(),
            rng: u64::from_le_bytes(seed[8..].try_into().unwrap()) | 1, to_connect: vec![],
            prune_depth: None, snap_blocks: 0, fast_sync: false, fast: None, header_page: HEADER_PAGE,
        }
    }

    // ------------------------------------------------------------ fast sync
    /// Starts a fast sync if it was asked for and this node has nothing yet.
    pub fn start_fast_sync(&mut self) {
        if !self.fast_sync || self.c.blocks_count > 0 || self.fast.is_some() { return; }
        log("fast sync: downloading and validating the headers first, then the state at a recent block");
        self.fast = Some(FastSync::new(self.params.clone(), now_ms()));
        self.fast_request_headers();
    }

    /// Asks the next peer for headers (the one that announced the most work and has not failed).
    fn fast_request_headers(&mut self) {
        let Some(f) = &self.fast else { return };
        if f.stage != Stage::Headers || f.header_peer.is_some() { return; }
        let ready: Vec<u64> = self.peers.values().filter(|p| p.ready).map(|p| p.id).collect();
        let pick = ready.iter().filter(|id| !f.tried.contains(id)).max_by_key(|id| (f.peer_scores.get(id).copied().unwrap_or(0), u64::MAX - **id)).copied();
        match pick {
            Some(peer) => {
                let from = f.next_from;
                let f = self.fast.as_mut().unwrap();
                f.header_peer = Some(peer);
                f.last_progress = now_ms();
                self.send(peer, &json!({ "t": "getheaders", "from": from }));
            }
            None if !ready.is_empty() => self.fast_fallback("no peer answered with the headers from the genesis — they come from archival Rust nodes"),
            None => {} // (no peers yet)
        }
    }

    fn fast_on_headers(&mut self, peer: u64, m: &Value) {
        let now = now_ms();
        let Some(f) = &mut self.fast else { return };
        if f.stage != Stage::Headers || f.header_peer != Some(peer) || m["from"].as_u64() != Some(f.next_from) { return; }
        f.header_peer = None;
        if let Some(e) = m["error"].as_str() {
            log(&format!("fast sync: peer {peer} does not serve these headers ({e}); asking another"));
            f.tried.insert(peer);
            return self.fast_request_headers();
        }
        let mut bad = None;
        let list = m["headers"].as_array().map(|v| v.as_slice()).unwrap_or(&[]);
        // every page of an honest chain holds headers (blue score never jumps a whole page): an empty
        // one ends the download, so a peer cannot keep us asking for pages forever
        let last_page = list.is_empty();
        for x in list {
            let Some(h) = x.as_str().and_then(|s| from_hex(s).ok()).and_then(|b| Header::deserialize(&b).ok()) else { bad = Some("malformed header".to_string()); break };
            if let HeaderResult::Invalid(e) = f.hc.add(h, now) { bad = Some(e); break; }
        }
        if let Some(e) = bad {
            f.tried.insert(peer);
            log(&format!("fast sync: invalid header from peer {peer}: {e}"));
            self.misbehave(peer, 50, &e);
            return self.fast_request_headers();
        }
        let window = f.hc.window();
        f.hc.prune(window);
        f.last_progress = now;
        match m["next"].as_u64() {
            Some(next) if next > f.next_from && !last_page => {
                f.next_from = next;
                if f.hc.count % 50_000 < 2_500 { log(&format!("fast sync: {} headers validated (blue score {})", f.hc.count, f.hc.best_score())); }
                self.fast_request_headers();
            }
            _ => self.fast_headers_done(),
        }
    }

    fn fast_headers_done(&mut self) {
        let Some(f) = &mut self.fast else { return };
        let Some(s) = f.hc.sync_point() else { return self.fast_fallback("the chain is still short: a normal sync is quick") };
        let s_bs = f.hc.store.gd[&s].blue_score;
        log(&format!("fast sync: {} headers validated, tip at blue score {}; asking for the state at {} (blue score {s_bs})",
            f.hc.count, f.hc.best_score(), &to_hex(&s)[..12]));
        f.stage = Stage::State;
        f.target = Some(s);
        f.state_since = now_ms();
        let mut cand: Vec<u64> = self.peers.values().filter(|p| p.ready).map(|p| p.id).collect();
        cand.sort_by_key(|id| std::cmp::Reverse(f.peer_scores.get(id).copied().unwrap_or(0)));
        cand.truncate(STATE_PEERS);
        f.asked = cand.iter().copied().collect();
        for id in cand { self.send(id, &json!({ "t": "getstate", "hash": to_hex(&s) })); }
        self.fast_decide(false);
    }

    fn fast_on_state(&mut self, peer: u64, m: &Value) -> Result<(), String> {
        let Some(f) = &mut self.fast else { return Ok(()) };
        if f.stage != Stage::State || !f.asked.contains(&peer) || f.answered.contains(&peer) { return Ok(()); }
        if m["hash"].as_str() != f.target.map(|h| to_hex(&h)).as_deref() { return Ok(()); }
        if let Some(e) = m["error"].as_str() {
            if e == "not-chain" { f.disagreement = true; } // (it has that block, but not as a valid chain block)
            f.answered.insert(peer);
            self.fast_decide(false);
            return Ok(());
        }
        let digest = from_hex32(m["digest"].as_str().unwrap_or(""))?;
        let data = from_hex(m["data"].as_str().unwrap_or(""))?;
        let got = f.add_part(peer, m["part"].as_u64().unwrap_or(u64::MAX), m["parts"].as_u64().unwrap_or(0), digest, data);
        let buf = match got {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(()),
            Err(e) => { f.answered.insert(peer); f.parts.remove(&peer); self.fast_decide(false); return Err(e); }
        };
        f.answered.insert(peer);
        match decode_state(&f.hc, &buf) {
            Ok(st) => f.verified.push((peer, digest, st)),
            Err(e) => { log(&format!("fast sync: state from peer {peer} refused: {e}")); self.misbehave(peer, 100, &e); }
        }
        self.fast_decide(false);
        Ok(())
    }

    /// Once every peer asked has answered (or on timeout): all the states received must be the same.
    fn fast_decide(&mut self, timeout: bool) {
        let Some(f) = &mut self.fast else { return };
        if f.stage != Stage::State { return; }
        let pending = f.asked.iter().filter(|id| !f.answered.contains(id) && self.peers.contains_key(id)).count();
        if pending > 0 && !timeout { return; }
        let digests: HashSet<[u8; 32]> = f.verified.iter().map(|x| x.1).collect();
        if f.disagreement || digests.len() > 1 { return self.fast_fallback("peers disagree about the state at the sync point"); }
        if f.verified.is_empty() { return self.fast_fallback("no peer could provide the state at the sync point"); }
        let n = f.verified.len();
        let mut f = self.fast.take().unwrap();
        let (_, _, st) = f.verified.swap_remove(0);
        let body = st.block.clone();
        match build_engine(&f.hc, st) {
            Ok(c) => {
                self.c = c;
                self.orphans.clear(); self.waiting.clear(); self.future.clear(); self.requested.clear();
                if let Some(storage) = &self.storage { if let Err(e) = storage.append(&body) { log(&format!("error writing block: {e}")); } }
                let s = self.c.pruning_point.unwrap();
                log(&format!("fast sync: state at {} verified ({n} peer(s) in agreement{}); now downloading and validating the blocks after it",
                    &to_hex(&s)[..12], if n < 2 { " — the Security Fund and private-pool totals were not cross-checked" } else { "" }));
                self.checkpoint(true);
                let from = self.c.prune_cutoff;
                let ids: Vec<u64> = self.peers.values().filter(|p| p.ready).map(|p| p.id).collect();
                for id in ids { self.send(id, &json!({ "t": "getdag", "from": from })); }
            }
            Err(e) => { self.fast = Some(f); self.fast_fallback(&format!("could not start from the state: {e}")); }
        }
    }

    /// Gives up the fast sync: a normal sync from the genesis (always possible, just slower).
    fn fast_fallback(&mut self, why: &str) {
        if self.fast.take().is_none() { return; }
        log(&format!("fast sync abandoned ({why}): syncing normally from the genesis"));
        let ids: Vec<u64> = self.peers.values().filter(|p| p.ready).map(|p| p.id).collect();
        for id in ids { self.send(id, &json!({ "t": "getdag", "from": 0 })); }
    }

    /// Timeouts of the fast sync (from the maintenance tick).
    pub fn fast_tick(&mut self, now: u64) {
        let Some(f) = &mut self.fast else { return };
        match f.stage {
            Stage::Headers => {
                if let Some(p) = f.header_peer {
                    if !self.peers.contains_key(&p) || now.saturating_sub(f.last_progress) > HEADER_TIMEOUT_MS { f.tried.insert(p); f.header_peer = None; }
                }
                self.fast_request_headers();
            }
            Stage::State => { if now.saturating_sub(f.state_since) > STATE_TIMEOUT_MS { self.fast_decide(true); } else { self.fast_decide(false); } }
        }
    }

    /// Serves `getheaders`: the headers with blue score in [from, from + page), parents first.
    fn serve_headers(&mut self, peer: u64, m: &Value) {
        let from = m["from"].as_u64().unwrap_or(0);
        if self.fast.is_some() { return self.send(peer, &json!({ "t": "headers", "from": from, "error": "syncing" })); }
        if self.c.pruning_point.is_some() && from < self.c.prune_cutoff { return self.send(peer, &json!({ "t": "headers", "from": from, "error": "pruned" })); }
        let end = from.saturating_add(self.header_page.max(1));
        let mut top = 0;
        let mut hs: Vec<(&num_bigint::BigUint, &Hash)> = vec![];
        for (h, g) in &self.c.store.gd {
            top = top.max(g.blue_score);
            if g.blue_score >= from && g.blue_score < end { hs.push((&g.blue_work, h)); }
        }
        hs.sort(); // (blue work grows from parent to child: parents first)
        let list: Vec<String> = hs.iter().filter_map(|(_, h)| self.c.headers.get(*h)).map(|x| to_hex(&x.serialize(false))).collect();
        let next = if top >= end { json!(end) } else { Value::Null };
        self.send(peer, &json!({ "t": "headers", "from": from, "headers": list, "next": next }));
    }

    /// Serves `getstate`: the state at a chain block, in parts.
    fn serve_state(&mut self, peer: u64, m: &Value) -> Result<(), String> {
        let hx = m["hash"].as_str().unwrap_or("").to_string();
        let h = from_hex32(&hx)?;
        let res = if self.fast.is_some() { Err("syncing") } else { encode_state(&mut self.c, &h) };
        let buf = match res { Ok(b) => b, Err(e) => { self.send(peer, &json!({ "t": "state", "hash": hx, "error": e })); return Ok(()); } };
        let digest = to_hex(&state_digest(&buf));
        let chunks: Vec<&[u8]> = buf.chunks(STATE_CHUNK).collect();
        for (i, ch) in chunks.iter().enumerate() {
            self.send(peer, &json!({ "t": "state", "hash": hx, "part": i, "parts": chunks.len(), "digest": digest, "data": to_hex(ch) }));
        }
        Ok(())
    }
    fn rand(&mut self) -> f64 {
        self.rng ^= self.rng << 13; self.rng ^= self.rng >> 7; self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Reloads the node from disk. With a state snapshot (`state.snap`): loads it, attaches the block
    /// bodies it needs from `blocks.dat` without validating them again, and validates only the blocks
    /// that arrived after it. Without one (or with an unusable one): validates `blocks.dat` from the
    /// genesis, as the JavaScript node does, and then writes a snapshot. Ok(true): it started from the snapshot.
    pub fn load(&mut self) -> Result<bool, String> {
        let Some(st) = &self.storage else { return Ok(false) };
        let t = now_ms();
        let blocks = st.read_all();
        let path = st.snapshot_path();
        let resync = format!("Delete {} to sync again from peers.", st.dir.display());
        let snap = if path.exists() {
            match std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| crate::snapshot::decode(&self.params, &b)) {
                Ok(l) => Some(l),
                Err(e) => { log(&format!("ignoring the state snapshot ({e}): validating blocks.dat from the start")); None }
            }
        } else { None };
        if let Some(l) = snap {
            let missing = l.missing_bodies(&blocks);
            if missing == 0 {
                let (c, later) = l.finish(blocks);
                self.c = c;
                let mut n = 0;
                for b in later { if let AddResult::Accepted { .. } = self.c.add_block(b, now_ms(), true) { n += 1; } }
                log(&format!("state snapshot loaded ({} blocks{}) + {n} newer block(s) validated, in {:.1} s",
                    self.c.store.gd.len(), if self.c.pruning_point.is_some() { ", pruned" } else { "" }, (now_ms() - t) as f64 / 1000.0));
                self.snap_blocks = self.c.blocks_count - n;
                self.after_change();
                return Ok(true);
            }
            if l.c.pruning_point.is_some() {
                return Err(format!("the data folder is inconsistent: blocks.dat lacks {missing} block(s) that the pruned state snapshot needs, and a pruned folder cannot be rebuilt from the start. {resync}"));
            }
            log(&format!("the state snapshot needs {missing} block(s) that blocks.dat lacks: validating blocks.dat from the start"));
        }
        let (mut n, mut orphans) = (0, 0);
        for b in blocks {
            match self.c.add_block(b, now_ms(), true) {
                AddResult::Accepted { .. } => n += 1,
                AddResult::Orphan { .. } => orphans += 1,
                _ => {}
            }
        }
        // blocks are appended only after their parents, so a full file never has orphans: this one
        // was compacted by pruning, and without its state snapshot it cannot be used
        if orphans > 0 {
            self.c = Consensus::new(self.params.clone());
            return Err(format!("blocks.dat belongs to a pruned node ({orphans} block(s) without their parents) and its state snapshot is missing or unusable. {resync}"));
        }
        if n > 0 { log(&format!("{n} blocks reloaded from disk in {:.1} s", (now_ms() - t) as f64 / 1000.0)); }
        self.after_change();
        if n > 0 { self.checkpoint(true); } // the next restart starts from here
        Ok(false)
    }

    /// Writes a state snapshot when due (or when forced); on a pruned node, prunes first and then
    /// compacts blocks.dat. Order matters for crash safety: the new snapshot is on disk before
    /// blocks.dat loses the bodies the old one needed.
    pub fn checkpoint(&mut self, force: bool) {
        let Some(st) = &self.storage else { return };
        let now = now_ms();
        let new_blocks = self.c.blocks_count.saturating_sub(self.snap_blocks);
        if !force && new_blocks < SNAPSHOT_EVERY_BLOCKS.max(self.c.store.gd.len() as u64 / 4) { return; }
        let pruned = match self.prune_depth { Some(d) => self.c.prune(d), None => None };
        match crate::snapshot::save(&self.c, &st.snapshot_path()) {
            Ok(bytes) => log(&format!("state snapshot written: {} blocks, {:.1} MB, in {:.1} s", self.c.store.gd.len(), bytes as f64 / 1e6, (now_ms() - now) as f64 / 1000.0)),
            Err(e) => { log(&format!("could not write the state snapshot: {e}")); return; }
        }
        if let Some(r) = pruned {
            let kept: Vec<&Block> = self.c.order.iter().filter_map(|h| self.c.blocks.get(h).map(|b| b.as_ref())).collect();
            let n = kept.len();
            match st.rewrite(kept.into_iter()) {
                Ok(()) => log(&format!("pruned: pruning point {} (blue score {}), {} block(s) forgotten, {} body(ies) dropped; blocks.dat now holds {n}",
                    &to_hex(&r.pruning_point)[..12], self.c.store.gd[&r.pruning_point].blue_score, r.forgotten, r.bodies_dropped)),
                Err(e) => log(&format!("could not compact blocks.dat: {e}")),
            }
        }
        self.snap_blocks = self.c.blocks_count;
    }

    fn after_change(&mut self) {
        for (h, r) in std::mem::take(&mut self.c.disqualified) { log(&format!("block {} disqualified: {r}", &to_hex(&h)[..12])); }
        let mut mp = std::mem::replace(&mut self.mempool, Mempool::new());
        mp.revalidate(&mut self.c);
        self.mempool = mp;
    }

    // ------------------------------------------------------------ blocks
    /// Block from the network or from RPC: (status, hash, reason).
    pub fn receive_block(&mut self, block: Block, peer: Option<u64>) -> (String, Hash, Option<String>) {
        let res = self.c.add_block(block.clone(), now_ms(), false);
        let out = match res {
            AddResult::Accepted { hash, .. } => {
                self.on_accepted(&hash, peer);
                self.resolve_orphans(hash);
                ("accepted".to_string(), hash, None)
            }
            AddResult::Orphan { hash, missing } => {
                if self.orphans.len() < 50_000 {
                    self.orphans.insert(hash, (block, missing.iter().copied().collect()));
                    for m in &missing { self.waiting.entry(*m).or_default().insert(hash); }
                    if let Some(p) = peer { self.request_blocks(p, missing.iter().map(|h| to_hex(h)).collect()); }
                }
                ("orphan".to_string(), hash, None)
            }
            AddResult::Future(hash) => { self.future.insert(hash, (block, peer)); ("future".to_string(), hash, None) }
            AddResult::Invalid { hash, reason } => {
                log(&format!("invalid block {}: {reason}", &to_hex(&hash)[..12]));
                if let Some(p) = peer { self.misbehave(p, 50, &reason); }
                ("invalid".to_string(), hash, Some(reason))
            }
            AddResult::Known(hash) => ("known".to_string(), hash, None),
        };
        self.after_change();
        out
    }

    fn on_accepted(&mut self, hash: &Hash, peer: Option<u64>) {
        if let Some(st) = &self.storage {
            if let Err(e) = st.append(&self.c.blocks[hash]) { log(&format!("error writing block: {e}")); }
        }
        self.broadcast(&json!({ "t": "inv", "blocks": [to_hex(hash)] }), peer);
        let now = now_ms();
        self.block_times.push_back(now);
        while let Some(&f) = self.block_times.front() { if now - f > 60_000 { self.block_times.pop_front(); } else { break; } }
    }

    fn resolve_orphans(&mut self, hash: Hash) {
        let mut queue = VecDeque::from([hash]);
        while let Some(h) = queue.pop_front() {
            let Some(kids) = self.waiting.remove(&h) else { continue };
            for k in kids {
                let ready = match self.orphans.get_mut(&k) { Some(o) => { o.1.remove(&h); o.1.is_empty() } None => false };
                if !ready { continue; }
                let (b, _) = self.orphans.remove(&k).unwrap();
                if let AddResult::Accepted { .. } = self.c.add_block(b, now_ms(), false) { self.on_accepted(&k, None); queue.push_back(k); }
            }
        }
    }

    fn retry_future(&mut self) {
        let now = now_ms();
        let ready: Vec<Hash> = self.future.iter().filter(|(_, (b, _))| b.header.timestamp <= now + self.params.max_future_ms).map(|(h, _)| *h).collect();
        for h in ready { let (b, p) = self.future.remove(&h).unwrap(); self.receive_block(b, p); }
    }

    /// Inputs and key images already committed by transactions in the stem phase.
    pub fn stem_spends(&mut self) -> (HashSet<(Hash, u32)>, HashSet<[u8; 33]>) {
        let now = now_ms();
        self.stem.retain(|_, (_, at)| now - *at <= 60_000);
        let (mut outs, mut kis) = (HashSet::new(), HashSet::new());
        for (tx, _) in self.stem.values() {
            for i in &tx.t_in { outs.insert((i.txid, i.index)); }
            for s in &tx.s_in { kis.insert(s.key_image); }
        }
        (outs, kis)
    }

    // ------------------------------------------------------------ P2P
    fn send(&self, peer: u64, msg: &Value) {
        let Some(p) = self.peers.get(&peer) else { return };
        let body = serde_json::to_vec(msg).unwrap();
        let mut frame = Vec::with_capacity(8 + body.len());
        frame.extend_from_slice(&self.params.p2p_magic.to_le_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend(body);
        let _ = p.tx.send(frame);
    }
    fn broadcast(&self, msg: &Value, except: Option<u64>) {
        let ids: Vec<u64> = self.peers.values().filter(|p| p.ready && Some(p.id) != except).map(|p| p.id).collect();
        for id in ids { self.send(id, msg); }
    }
    pub fn misbehave(&mut self, peer: u64, n: i32, why: &str) {
        let ban = match self.peers.get_mut(&peer) { Some(p) => { p.score += n; p.score >= 100 } None => false };
        if ban { self.ban(peer, why); }
    }
    fn ban(&mut self, peer: u64, why: &str) {
        if let Some(p) = self.peers.remove(&peer) {
            log(&format!("disconnecting {}: {why}", p.addr));
            let _ = p.sock.shutdown(Shutdown::Both);
        }
        if self.stem_peer == Some(peer) { self.stem_peer = None; }
    }
    fn recently_requested(&mut self, h: &str) -> bool {
        let now = now_ms();
        if let Some(&t) = self.requested.get(h) { if now - t < 10_000 { return true; } }
        self.requested.insert(h.to_string(), now);
        false
    }
    pub fn request_blocks(&mut self, peer: u64, hashes: Vec<String>) {
        let mut want = vec![];
        for h in hashes {
            let Ok(hb) = from_hex32(&h) else { continue };
            if self.c.has(&hb) || self.orphans.contains_key(&hb) || self.recently_requested(&h) { continue; }
            want.push(h);
        }
        for ch in want.chunks(500) { self.send(peer, &json!({ "t": "getblocks", "hashes": ch })); }
    }

    pub(crate) fn handle(&mut self, peer: u64, m: &Value) -> Result<(), String> {
        let t = m["t"].as_str().unwrap_or("");
        let ready = self.peers.get(&peer).map(|p| p.ready).unwrap_or(false);
        if !ready && t != "hello" { return Ok(()); }
        match t {
            "hello" => {
                if m["nonce"].as_str() == Some(&self.nonce) { self.ban(peer, "connection to itself"); return Ok(()); }
                if m["network"].as_str() != Some(self.params.name) || m["genesis"].as_str() != Some(&to_hex(&self.c.genesis_hash)) {
                    self.ban(peer, "different network"); return Ok(());
                }
                let listen_port = m["listen"].as_u64().unwrap_or(0);
                let Some(p) = self.peers.get_mut(&peer) else { return Ok(()) };
                p.ready = true;
                let host = p.addr.rsplit_once(':').map(|x| x.0).unwrap_or("").replace("::ffff:", "").trim_matches(|c| c == '[' || c == ']').to_string();
                let listen = format!("{host}:{listen_port}");
                p.listen = Some(listen.clone());
                let dir = if p.outbound { "outbound" } else { "inbound" };
                if !self.known.contains(&listen) { self.known.push(listen.clone()); }
                log(&format!("peer connected: {listen} ({dir})"));
                if let Some(f) = &mut self.fast {
                    // fast sync: headers first (no blocks until the state at the sync point is in)
                    f.peer_scores.insert(peer, m["blueScore"].as_u64().unwrap_or(0));
                    self.fast_request_headers();
                } else {
                    let from = self.c.virt().gd.blue_score.saturating_sub(300);
                    self.send(peer, &json!({ "t": "getdag", "from": from }));
                }
                self.send(peer, &json!({ "t": "getaddr" }));
            }
            "getheaders" => self.serve_headers(peer, m),
            "headers" => self.fast_on_headers(peer, m),
            "getstate" => self.serve_state(peer, m)?,
            "state" => self.fast_on_state(peer, m)?,
            "getdag" => {
                let from = m["from"].as_u64().unwrap_or(0);
                let mut hashes: Vec<(u64, String)> = self.c.store.gd.iter()
                    .filter(|(h, g)| g.blue_score >= from && self.c.blocks.contains_key(*h)) // (a pruned node only offers what it can send)
                    .map(|(h, g)| (g.blue_score, to_hex(h))).collect();
                hashes.sort();
                for ch in hashes.chunks(2000) {
                    let v: Vec<&String> = ch.iter().map(|x| &x.1).collect();
                    self.send(peer, &json!({ "t": "inv", "blocks": v }));
                }
            }
            "inv" | "block" | "tx" if self.fast.is_some() => {} // (during a fast sync: nothing to build on yet)
            "inv" => {
                if let Some(b) = m["blocks"].as_array() {
                    let hs: Vec<String> = b.iter().filter_map(|x| x.as_str().map(String::from)).collect();
                    self.request_blocks(peer, hs);
                }
                if let Some(t) = m["txs"].as_array() {
                    let mut want = vec![];
                    for id in t.iter().filter_map(|x| x.as_str()) {
                        let Ok(idb) = from_hex32(id) else { continue };
                        if self.mempool.txs.contains_key(&idb) || self.recently_requested(id) { continue; }
                        want.push(id.to_string());
                    }
                    want.truncate(1000);
                    if !want.is_empty() { self.send(peer, &json!({ "t": "gettxs", "txids": want })); }
                }
            }
            "getblocks" => {
                for h in m["hashes"].as_array().map(|v| v.iter().take(1000).collect::<Vec<_>>()).unwrap_or_default() {
                    let Some(hb) = h.as_str().and_then(|s| from_hex32(s).ok()) else { continue };
                    if let Some(b) = self.c.blocks.get(&hb) { let d = to_hex(&b.serialize()); self.send(peer, &json!({ "t": "block", "data": d })); }
                }
            }
            "block" => {
                let raw = from_hex(m["data"].as_str().unwrap_or(""))?;
                let b = Block::deserialize(&raw)?;
                self.requested.remove(&b.hash_hex());
                self.receive_block(b, Some(peer));
            }
            "gettxs" => {
                for id in m["txids"].as_array().map(|v| v.iter().take(1000).collect::<Vec<_>>()).unwrap_or_default() {
                    let Some(idb) = id.as_str().and_then(|s| from_hex32(s).ok()) else { continue };
                    if let Some(e) = self.mempool.txs.get(&idb) { let d = to_hex(&e.tx.serialize()); self.send(peer, &json!({ "t": "tx", "data": d, "stem": false })); }
                }
            }
            "tx" => {
                let raw = from_hex(m["data"].as_str().unwrap_or(""))?;
                let tx = Transaction::deserialize(&raw)?;
                self.requested.remove(&tx.id_hex());
                let stem = m["stem"].as_bool().unwrap_or(false);
                self.receive_tx(Arc::new(tx), Some(peer), stem);
            }
            "getaddr" => {
                let a: Vec<&String> = self.known.iter().take(100).collect();
                self.send(peer, &json!({ "t": "addr", "addrs": a }));
            }
            "addr" => {
                for a in m["addrs"].as_array().map(|v| v.iter().take(100).collect::<Vec<_>>()).unwrap_or_default() {
                    if let Some(s) = a.as_str() {
                        let ok = s.rsplit_once(':').map(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok() && h.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))).unwrap_or(false);
                        if ok && !self.known.iter().any(|k| k == s) { self.known.push(s.to_string()); }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ------------------------------------------------------- Dandelion++
    fn pick_stem(&mut self, except: Option<u64>) -> Option<u64> {
        let now = now_ms();
        let ok: Vec<u64> = self.peers.values().filter(|p| p.ready && Some(p.id) != except).map(|p| p.id).collect();
        let valid = self.stem_peer.map(|s| self.peers.contains_key(&s) && Some(s) != except).unwrap_or(false);
        if !valid || now - self.stem_since > 600_000 {
            self.stem_peer = if ok.is_empty() { None } else { let i = (self.rand() * ok.len() as f64) as usize; Some(ok[i.min(ok.len() - 1)]) };
            self.stem_since = now;
        }
        self.stem_peer.filter(|s| Some(*s) != except)
    }

    /// Transaction created locally (RPC) or received from a peer. Returns the response JSON.
    pub fn receive_tx(&mut self, tx: Arc<Transaction>, from: Option<u64>, stem: bool) -> Value {
        let id = tx.id();
        if self.mempool.txs.contains_key(&id) { return json!({ "ok": true, "txid": to_hex(&id), "duplicate": true }); }
        if stem {
            if let Err(e) = self.mempool.check(&mut self.c, &tx) {
                if let Some(f) = from { self.misbehave(f, 5, &e); }
                return json!({ "ok": false, "txid": to_hex(&id), "reason": e });
            }
            let next = if self.rand() < STEM_PROBABILITY { self.pick_stem(from) } else { None };
            if let Some(n) = next {
                let d = to_hex(&tx.serialize());
                self.send(n, &json!({ "t": "tx", "data": d, "stem": true }));
                self.stem.insert(id, (tx.clone(), now_ms()));
                if !self.embargo.contains_key(&id) {
                    let delay = 2000.0 + self.rand() * 2000.0;
                    self.embargo.insert(id, now_ms() + delay as u64);
                }
                return json!({ "ok": true, "txid": to_hex(&id), "phase": "haste" });
            }
        }
        self.fluff(tx, from)
    }

    fn fluff(&mut self, tx: Arc<Transaction>, from: Option<u64>) -> Value {
        let id = tx.id();
        self.stem.remove(&id);
        self.embargo.remove(&id);
        let mut mp = std::mem::replace(&mut self.mempool, Mempool::new());
        let (ok, dup, reason) = mp.add(&mut self.c, tx);
        self.mempool = mp;
        if ok && !dup { self.broadcast(&json!({ "t": "inv", "txs": [to_hex(&id)] }), from); }
        else if !ok { if let Some(f) = from { self.misbehave(f, 1, &reason); } }
        let mut r = json!({ "ok": ok, "txid": to_hex(&id), "phase": "flor" });
        if dup { r["duplicate"] = json!(true); }
        if !ok { r["reason"] = json!(reason); }
        r
    }

    fn tick(&mut self, last_maint: &mut u64) {
        let now = now_ms();
        let due: Vec<[u8; 32]> = self.embargo.iter().filter(|(_, d)| **d <= now).map(|(k, _)| *k).collect();
        for id in due {
            self.embargo.remove(&id);
            if let Some((tx, _)) = self.stem.get(&id).cloned() { self.fluff(tx, None); }
        }
        self.retry_future();
        if now - *last_maint >= 5000 {
            *last_maint = now;
            let outbound = self.peers.values().filter(|p| p.outbound).count();
            if outbound < 8 {
                let connected: HashSet<String> = self.peers.values().map(|p| p.listen.clone().unwrap_or(p.addr.clone())).collect();
                let me = format!("127.0.0.1:{}", self.port);
                let cand: Vec<String> = self.known.iter().filter(|a| !connected.contains(*a) && **a != me).take(8 - outbound).cloned().collect();
                self.to_connect.extend(cand);
            }
            self.requested.retain(|_, t| now - *t <= 60_000);
            self.checkpoint(false);
            self.fast_tick(now);
        }
    }
}

#[cfg(test)]
impl Node {
    /// A "ready" peer attached to a local socket (tests with hostile messages).
    pub fn test_peer(&mut self) -> u64 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        std::mem::forget(b);
        let (tx, rx) = channel();
        std::mem::forget(rx);
        let id = self.next_peer;
        self.next_peer += 1;
        self.peers.insert(id, Peer { id, addr: "127.0.0.1:1".into(), outbound: false, ready: true, score: 0, listen: None, tx, sock: a });
        id
    }

    /// A peer reached through an in-memory channel (tests of the protocol between nodes): returns its
    /// id on this node and the frames this node sends to it; the hello goes out first, as in `attach`.
    pub fn test_link(&mut self) -> (u64, std::sync::mpsc::Receiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        std::mem::forget(b);
        let (tx, rx) = channel();
        let id = self.next_peer;
        self.next_peer += 1;
        self.peers.insert(id, Peer { id, addr: format!("127.0.0.1:{}", 30_000 + id), outbound: true, ready: false, score: 0, listen: None, tx, sock: a });
        let hello = json!({
            "t": "hello", "version": PROTOCOL_VERSION, "network": self.params.name, "genesis": to_hex(&self.c.genesis_hash),
            "nonce": self.nonce, "listen": self.port, "blueScore": self.c.virt().gd.blue_score,
        });
        self.send(id, &hello);
        (id, rx)
    }
}

// ================================================================ network threads
fn attach(shared: &Shared, sock: TcpStream, outbound: bool, addr: String) {
    let (lock, _) = &**shared;
    let (tx, rx) = channel::<Vec<u8>>();
    let id;
    {
        let mut n = lock_node(lock);
        if n.peers.len() >= n.max_peers { let _ = sock.shutdown(Shutdown::Both); return; }
        id = n.next_peer;
        n.next_peer += 1;
        let _ = sock.set_nodelay(true);
        n.peers.insert(id, Peer { id, addr: addr.clone(), outbound, ready: false, score: 0, listen: None, tx, sock: sock.try_clone().unwrap() });
        let hello = json!({
            "t": "hello", "version": PROTOCOL_VERSION, "network": n.params.name, "genesis": to_hex(&n.c.genesis_hash),
            "nonce": n.nonce, "listen": n.port, "blueScore": n.c.virt().gd.blue_score,
        });
        n.send(id, &hello);
    }
    let mut w = sock.try_clone().unwrap();
    std::thread::spawn(move || { for frame in rx { if w.write_all(&frame).is_err() { break; } } });
    let sh = shared.clone();
    let mut r = sock;
    std::thread::spawn(move || {
        let (lock, cv) = &*sh;
        let magic = lock_node(lock).params.p2p_magic;
        loop {
            let mut head = [0u8; 8];
            if r.read_exact(&mut head).is_err() { break; }
            if u32::from_le_bytes(head[..4].try_into().unwrap()) != magic { lock_node(lock).ban(id, "wrong magic"); break; }
            let len = u32::from_le_bytes(head[4..].try_into().unwrap()) as usize;
            if len > MAX_MSG { lock_node(lock).ban(id, "message too large"); break; }
            let mut body = vec![0u8; len];
            if r.read_exact(&mut body).is_err() { break; }
            let Ok(msg) = serde_json::from_slice::<Value>(&body) else { lock_node(lock).ban(id, "invalid JSON"); break };
            let mut n = lock_node(lock);
            if !n.peers.contains_key(&id) { break; }
            let v0 = n.c.virtual_version;
            match guarded(|| n.handle(id, &msg)) {
                Ok(()) => {}
                Err(e) if e.starts_with(INTERNAL) => { log(&format!("message from peer {id} caused {e}")); n.ban(id, "message caused an internal failure"); }
                Err(e) => n.misbehave(id, 10, &e),
            }
            let changed = n.c.virtual_version != v0;
            let pending = std::mem::take(&mut n.to_connect);
            drop(n);
            if changed { cv.notify_all(); }
            for a in pending { connect(&sh, a); }
        }
        let mut n = lock_node(lock);
        n.peers.remove(&id);
        if n.stem_peer == Some(id) { n.stem_peer = None; }
    });
}

pub fn connect(shared: &Shared, addr: String) {
    {
        let n = lock_node(&shared.0);
        if n.peers.values().any(|p| p.addr == addr || p.listen.as_deref() == Some(&addr)) { return; }
    }
    let sh = shared.clone();
    std::thread::spawn(move || {
        let Ok(mut it) = std::net::ToSocketAddrs::to_socket_addrs(addr.as_str()) else { return };
        let Some(sa) = it.next() else { return };
        if let Ok(s) = TcpStream::connect_timeout(&sa, Duration::from_secs(5)) { attach(&sh, s, true, addr); }
    });
}

/// Starts the node: loads the disk, opens P2P and RPC and runs maintenance.
pub fn run(shared: Shared, seeds: Vec<String>) -> std::io::Result<()> {
    let (port, rpc_host, rpc_port, name, genesis) = {
        let mut n = lock_node(&shared.0);
        n.load().map_err(std::io::Error::other)?;
        n.start_fast_sync();
        for s in &seeds { if !n.known.contains(s) { n.known.push(s.clone()); } }
        (n.port, n.rpc_host.clone(), n.rpc_port, n.params.name, to_hex(&n.c.genesis_hash))
    };
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    let sh = shared.clone();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let addr = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            attach(&sh, s, false, addr);
        }
    });
    crate::rpc::start(shared.clone(), &rpc_host, rpc_port)?;
    for s in seeds { connect(&shared, s); }
    log(&format!("Krevo {name} (Rust node) | P2P :{port} | RPC http://{rpc_host}:{rpc_port} | genesis {}…", &genesis[..16]));
    let mut last_maint = now_ms();
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let (lock, cv) = &*shared;
        let mut n = lock_node(lock);
        let v0 = n.c.virtual_version;
        n.tick(&mut last_maint);
        let changed = n.c.virtual_version != v0;
        let pending = std::mem::take(&mut n.to_connect);
        drop(n);
        if changed { cv.notify_all(); }
        for a in pending { connect(&shared, a); }
    }
}
