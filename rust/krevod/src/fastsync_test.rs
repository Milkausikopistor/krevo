//! Fast sync (issue #8), with real nodes talking the P2P protocol through in-memory links:
//!  • a new node syncs from headers + the state at a sync point and then agrees with an archival node
//!    on everything (state, template), and keeps following the chain in both directions;
//!  • headers come from an archival peer (a pruned one says so), the state from every peer asked;
//!  • a peer with a forged UTXO set is refused; peers disagreeing on the totals → full sync instead;
//!  • invalid headers, silent peers (e.g. the JavaScript node, which ignores these messages) and short
//!    chains all end in a correct node;
//!  • the fast-synced node restarts from its own snapshot.

use crate::consensus::Consensus;
use crate::fastsync::*;
use crate::mempool::now_ms;
use crate::node::Node;
use crate::snapshot_test::{fingerprint, mine, miners, params, reload, tmpdir, Sim};
use crate::storage::BlockFile;
use serde_json::Value;
use std::sync::mpsc::Receiver;

struct Link { to: usize, to_peer: u64, rx: Receiver<Vec<u8>>, tamper: Option<fn(&mut Value) -> bool> }
/// `hold`: messages matching it are kept back (delivered by `release`).
struct Net { nodes: Vec<Node>, links: Vec<Link>, hold: Option<fn(&Value) -> bool>, held: Vec<(usize, u64, Value)> }

impl Net {
    fn new(nodes: Vec<Node>) -> Self { Net { nodes, links: vec![], hold: None, held: vec![] } }
    fn release(&mut self) {
        self.hold = None;
        for (to, peer, msg) in std::mem::take(&mut self.held) {
            let n = &mut self.nodes[to];
            if n.peers.contains_key(&peer) { if let Err(e) = n.handle(peer, &msg) { n.misbehave(peer, 10, &e); } }
        }
        self.pump();
    }
    /// Connects a and b; `tamper` edits (or drops, returning false) what a sends to b.
    fn connect(&mut self, a: usize, b: usize, tamper: Option<fn(&mut Value) -> bool>) {
        let (a_sees_b, a_to_b) = self.nodes[a].test_link();
        let (b_sees_a, b_to_a) = self.nodes[b].test_link();
        self.links.push(Link { to: b, to_peer: b_sees_a, rx: a_to_b, tamper });
        self.links.push(Link { to: a, to_peer: a_sees_b, rx: b_to_a, tamper: None });
    }
    /// Delivers messages until the network is quiet (as the reading thread of `attach` does).
    fn pump(&mut self) {
        for _ in 0..100_000 {
            let mut moved = 0;
            for i in 0..self.links.len() {
                let frames: Vec<Vec<u8>> = self.links[i].rx.try_iter().collect();
                let (to, peer, tamper) = (self.links[i].to, self.links[i].to_peer, self.links[i].tamper);
                for f in frames {
                    let mut msg: Value = serde_json::from_slice(&f[8..]).unwrap();
                    if let Some(t) = tamper { if !t(&mut msg) { continue; } }
                    if self.hold.map(|h| h(&msg)).unwrap_or(false) { self.held.push((to, peer, msg)); continue; }
                    let n = &mut self.nodes[to];
                    if !n.peers.contains_key(&peer) { continue; } // (disconnected)
                    if let Err(e) = n.handle(peer, &msg) { n.misbehave(peer, 10, &e); }
                    moved += 1;
                }
            }
            if moved == 0 { return; }
        }
        panic!("the network never went quiet");
    }
}

fn node(c: Option<Consensus>) -> Node {
    let mut n = Node::new(params(), None, 0, "127.0.0.1".into(), 0);
    if let Some(c) = c { n.c = c; }
    n.header_page = 150; // (several pages, so that paging and the rolling header window are exercised)
    n
}
fn fresh(storage: Option<BlockFile>) -> Node {
    let mut n = Node::new(params(), storage, 0, "127.0.0.1".into(), 0);
    n.fast_sync = true;
    n.start_fast_sync();
    n
}
/// A chain with parallel blocks, reorganizations, red blocks and private coinbases.
fn chain(steps: usize) -> Sim {
    let mut s = Sim::new(0x5eed_f00d);
    for _ in 0..steps { s.step(); }
    s
}
/// Mines `n` blocks on node `i` and lets them propagate.
fn grow(net: &mut Net, i: usize, n: usize, ts: &mut u64) {
    let md = miners();
    for k in 0..n {
        *ts += 100;
        let b = mine(&mut net.nodes[i].c, &md[k % 3], &format!("g{i}-{k}-{ts}"), *ts);
        let (st, _, why) = net.nodes[i].receive_block(b, None);
        assert_eq!(st, "accepted", "{why:?}");
        net.pump();
    }
}
fn same(net: &mut Net, a: usize, b: usize) {
    let fa = fingerprint(&mut net.nodes[a].c);
    let fb = fingerprint(&mut net.nodes[b].c);
    assert_eq!(fa, fb);
}

#[test]
fn new_node_fast_syncs_and_follows_the_chain() {
    let s = chain(400);
    let mut ts = s.ts;
    let archival = s.a;
    let total = archival.store.gd.len();
    let mut net = Net::new(vec![node(Some(archival)), fresh(None)]);
    net.connect(0, 1, None);
    net.pump();
    let b = &net.nodes[1];
    assert!(b.fast.is_none(), "the fast sync must be over");
    let s_point = b.c.pruning_point.expect("started from a sync point");
    assert!(b.c.store.gd.len() < total / 2, "it keeps only the window around the sync point: {} of {total}", b.c.store.gd.len());
    let st = &net.nodes[0].c.status;
    assert!(st.get(&s_point) == Some(&crate::consensus::Status::Chain));
    same(&mut net, 0, 1);
    // it follows new blocks, and its own blocks are valid for the archival node
    grow(&mut net, 0, 25, &mut ts);
    same(&mut net, 0, 1);
    grow(&mut net, 1, 25, &mut ts);
    same(&mut net, 0, 1);
    // and its state survives a snapshot round trip like any pruned engine
    let r = reload(&net.nodes[1].c);
    net.nodes[1].c = r;
    same(&mut net, 0, 1);
}

#[test]
fn nothing_is_downloaded_before_the_state() {
    let s = chain(300);
    let mut ts = s.ts;
    let mut net = Net::new(vec![node(Some(s.a)), fresh(None)]);
    net.hold = Some(|m| m["t"] == "state");
    net.connect(0, 1, None);
    net.pump();
    assert_eq!(net.nodes[1].fast.as_ref().map(|f| f.stage), Some(Stage::State));
    // new blocks meanwhile: B hears of them but builds on nothing yet (no orphans, no blocks)
    grow(&mut net, 0, 5, &mut ts);
    assert!(net.nodes[1].c.blocks_count == 0 && net.nodes[1].orphans.is_empty());
    net.release();
    assert!(net.nodes[1].fast.is_none() && net.nodes[1].c.pruning_point.is_some());
    same(&mut net, 0, 1);
}

#[test]
fn headers_from_an_archival_peer_state_from_all() {
    let mut s = chain(300);
    let depth = s.p.min_prune_depth();
    s.p.prune(depth);
    assert!(s.p.pruning_point.is_some());
    let pruned = reload(&s.p);
    let mut ts = s.ts;
    // the pruned peer comes first and announces the same work: it is asked first and says "pruned"
    let mut net = Net::new(vec![node(Some(pruned)), node(Some(s.a)), fresh(None)]);
    net.connect(0, 2, None);
    net.connect(1, 2, None);
    net.pump();
    assert!(net.nodes[2].fast.is_none() && net.nodes[2].c.pruning_point.is_some());
    same(&mut net, 1, 2);
    same(&mut net, 0, 2);
    grow(&mut net, 0, 10, &mut ts);
    same(&mut net, 1, 2);
}

#[test]
fn forged_state_is_refused() {
    let s = chain(300);
    let mut liar = reload(&s.a);
    // a coin that does not exist in the real UTXO set (the MuHash commitment will not match); an old
    // one, so that it is still there once the liar rewinds its state to the sync point
    let k = *liar.utxo.t.iter().min_by_key(|(k, e)| (e.daa, **k)).unwrap().0;
    liar.utxo.t.get_mut(&k).unwrap().amount += 1;
    let mut net = Net::new(vec![node(Some(liar)), node(Some(s.a)), fresh(None)]);
    net.connect(0, 2, None);
    net.connect(1, 2, None);
    net.pump();
    let b = &net.nodes[2];
    assert!(b.fast.is_none() && b.c.pruning_point.is_some(), "the honest peer's state is used");
    assert!(b.peers.len() == 1, "the liar was disconnected");
    same(&mut net, 1, 2);

    // a supply that is not what the headers imply (coins minted: computable from headers alone)
    let s = chain(300);
    let mut liar = reload(&s.a);
    for a in liar.acc.values_mut() { a.minted += 1; }
    let mut net = Net::new(vec![node(Some(liar)), node(Some(s.a)), fresh(None)]);
    net.connect(0, 2, None);
    net.connect(1, 2, None);
    net.pump();
    let b = &net.nodes[2];
    assert!(b.c.pruning_point.is_some() && b.peers.len() == 1);
    same(&mut net, 1, 2);
}

#[test]
fn peers_disagreeing_on_the_totals_mean_a_full_sync() {
    let s = chain(300);
    let mut liar = reload(&s.a);
    for a in liar.acc.values_mut() { a.pool += 1; } // (a Security Fund balance off by one grain: not in any header)
    let mut net = Net::new(vec![node(Some(liar)), node(Some(s.a)), fresh(None)]);
    net.connect(0, 2, None);
    net.connect(1, 2, None);
    net.pump();
    let b = &net.nodes[2];
    assert!(b.fast.is_none());
    assert!(b.c.pruning_point.is_none(), "it fell back to a full sync from the genesis");
    same(&mut net, 1, 2);
}

#[test]
fn invalid_headers_silent_peers_and_short_chains() {
    // a peer whose headers are corrupted on the way: banned, the next peer serves them
    fn corrupt(m: &mut Value) -> bool {
        if m["t"] == "headers" {
            if let Some(h) = m["headers"].as_array_mut().and_then(|v| v.last_mut()) {
                let mut s = h.as_str().unwrap().to_string();
                let last = s.pop().unwrap();
                s.push(if last == '0' { '1' } else { '0' }); // (the nonce: the proof of work fails)
                *h = Value::String(s);
            }
        }
        true
    }
    let s = chain(300);
    let copy = reload(&s.a);
    let mut net = Net::new(vec![node(Some(copy)), node(Some(s.a)), fresh(None)]);
    net.connect(0, 2, Some(corrupt));
    net.connect(1, 2, None);
    net.pump();
    assert!(net.nodes[2].fast.is_none() && net.nodes[2].c.pruning_point.is_some());
    same(&mut net, 1, 2);

    // a peer that ignores the new messages (the JavaScript node does): after the timeout, a full sync
    fn silent(m: &mut Value) -> bool { !matches!(m["t"].as_str(), Some("headers" | "state")) }
    let s = chain(300);
    let mut net = Net::new(vec![node(Some(s.a)), fresh(None)]);
    net.connect(0, 1, Some(silent));
    net.pump();
    assert!(net.nodes[1].fast.is_some(), "still waiting for headers");
    net.nodes[1].fast_tick(now_ms() + HEADER_TIMEOUT_MS + 1);
    net.pump();
    assert!(net.nodes[1].fast.is_none() && net.nodes[1].c.pruning_point.is_none(), "full sync");
    same(&mut net, 0, 1);

    // a peer that answers with empty pages that never end: the download stops at the first one
    fn endless(m: &mut Value) -> bool {
        if m["t"] == "headers" && m.get("error").is_none() {
            let from = m["from"].as_u64().unwrap();
            m["headers"] = Value::Array(vec![]);
            m["next"] = Value::from(from + 150);
        }
        true
    }
    let s = chain(300);
    let mut net = Net::new(vec![node(Some(s.a)), fresh(None)]);
    net.connect(0, 1, Some(endless));
    net.pump();
    assert!(net.nodes[1].fast.is_none() && net.nodes[1].c.pruning_point.is_none(), "gave up the fast sync: full sync");
    same(&mut net, 0, 1);

    // a chain too short for a sync point: a normal sync
    let s = chain(20);
    let mut net = Net::new(vec![node(Some(s.a)), fresh(None)]);
    net.connect(0, 1, None);
    net.pump();
    assert!(net.nodes[1].fast.is_none() && net.nodes[1].c.pruning_point.is_none());
    same(&mut net, 0, 1);
}

#[test]
fn fast_synced_node_restarts_from_disk() {
    let mut s = chain(300);
    let mut ts = s.ts;
    let dir = tmpdir("fastsync");
    let mut net = Net::new(vec![node(Some(std::mem::replace(&mut s.a, Consensus::new(params())))), fresh(Some(BlockFile::new(&dir).unwrap()))]);
    net.connect(0, 1, None);
    net.pump();
    assert!(net.nodes[1].c.pruning_point.is_some());
    grow(&mut net, 0, 15, &mut ts);
    let fp = fingerprint(&mut net.nodes[1].c);
    let mut b = Node::new(params(), Some(BlockFile::new(&dir).unwrap()), 0, "127.0.0.1".into(), 0);
    b.fast_sync = true;
    assert!(b.load().unwrap(), "restarts from its state snapshot");
    b.start_fast_sync();
    assert!(b.fast.is_none(), "nothing to fast-sync: it already has a chain");
    assert_eq!(fingerprint(&mut b.c), fp);
    let _ = std::fs::remove_dir_all(&dir);
}
