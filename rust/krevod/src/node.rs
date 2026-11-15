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
        }
    }
    fn rand(&mut self) -> f64 {
        self.rng ^= self.rng << 13; self.rng ^= self.rng >> 7; self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Reloads the blocks from disk (the same file as the JavaScript node).
    pub fn load(&mut self) {
        let Some(st) = &self.storage else { return };
        let t = now_ms();
        let blocks = st.read_all();
        let mut n = 0;
        for b in blocks { if let AddResult::Accepted { .. } = self.c.add_block(b, now_ms(), true) { n += 1; } }
        if n > 0 { log(&format!("{n} blocks reloaded from disk in {:.1} s", (now_ms() - t) as f64 / 1000.0)); }
        self.after_change();
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
                let from = self.c.virt().gd.blue_score.saturating_sub(300);
                self.send(peer, &json!({ "t": "getdag", "from": from }));
                self.send(peer, &json!({ "t": "getaddr" }));
            }
            "getdag" => {
                let from = m["from"].as_u64().unwrap_or(0);
                let mut hashes: Vec<(u64, String)> = self.c.store.gd.iter().filter(|(_, g)| g.blue_score >= from).map(|(h, g)| (g.blue_score, to_hex(h))).collect();
                hashes.sort();
                for ch in hashes.chunks(2000) {
                    let v: Vec<&String> = ch.iter().map(|x| &x.1).collect();
                    self.send(peer, &json!({ "t": "inv", "blocks": v }));
                }
            }
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
        n.load();
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
