//! State snapshots and pruning (issue #2).
//!
//! • a snapshot reloads to exactly the same engine (and re-encodes to the same bytes);
//! • a pruned engine validates every new block exactly like an archival one, through parallel
//!   blocks, reorganizations, red blocks, shielded coinbases and repeated snapshot reloads;
//! • a pruned node keeps finality: a chain that forks off below its pruning point is refused;
//! • a node restarts from disk (snapshot + newer blocks), survives a crash between the snapshot
//!   and the compaction of blocks.dat, falls back to a full replay when the snapshot is unusable,
//!   and refuses a pruned folder it cannot rebuild;
//! • damaged or tampered snapshots are refused without panicking.

use crate::block::Block;
use crate::bytes::to_hex;
use crate::consensus::{AddResult, Consensus, Status};
use crate::crypto::hash_to_point_secp;
use crate::dag::Hash;
use crate::hash::H;
use crate::node::Node;
use crate::params::{get_params, Params};
use crate::pow::check_pow;
use crate::snapshot;
use crate::storage::BlockFile;
use serde_json::{json, Value};
use std::path::PathBuf;

/// simnet with small windows, so that pruning starts after a few hundred blocks
pub(crate) fn params() -> Params {
    let mut p = get_params("simnet").unwrap();
    p.merge_depth = 30;
    p.daa_window_size = 30;
    p.past_median_time_window = 11;
    p.ghostdag_k = 8;
    p
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

fn point(tag: &str, part: &str) -> [u8; 33] { hash_to_point_secp(H::new("test/miner").s(tag).s(part)).to_bytes() }
/// the three kinds of miner: transparent key, shielded address (private coinbase), lock hash
pub(crate) fn miners() -> Vec<Vec<u8>> {
    let mut t = vec![0x00]; t.extend(point("alice", "t"));
    let mut s = vec![0x01]; s.extend(point("bob", "a")); s.extend(point("bob", "b"));
    let mut m = vec![0x03]; m.extend(H::new("test/miner").s("carol").d32());
    vec![t, s, m]
}

fn solve(mut b: Block) -> Block {
    while !check_pow(&b.header) { b.header.nonce += 1; }
    Block::new(b.header, b.txs)
}
pub(crate) fn mine(c: &mut Consensus, md: &[u8], extra: &str, ts: u64) -> Block {
    solve(c.build_template(md, vec![], extra.as_bytes(), ts).expect("template"))
}

fn res(r: &AddResult) -> String {
    match r {
        AddResult::Accepted { hash, chain_valid } => format!("accepted {} {chain_valid}", to_hex(hash)),
        AddResult::Known(h) => format!("known {}", to_hex(h)),
        AddResult::Orphan { hash, .. } => format!("orphan {}", to_hex(hash)),
        AddResult::Future(h) => format!("future {}", to_hex(h)),
        AddResult::Invalid { hash, reason } => format!("invalid {} {reason}", to_hex(hash)),
    }
}

/// Everything a node's behaviour depends on, as seen from the virtual: the state summary, the tips
/// and the exact block template it would hand to a miner.
pub(crate) fn fingerprint(c: &mut Consensus) -> Value {
    let probe = c.build_template(&miners()[2], vec![], b"probe", 0).expect("template");
    let mut s = crate::replay::summary(c);
    let o = s.as_object_mut().unwrap();
    for k in ["blocks", "chain", "disq", "statusDigest"] { o.remove(k); } // (these count forgotten blocks too)
    let mut tips: Vec<String> = c.tips.iter().map(|h| to_hex(h)).collect();
    tips.sort();
    o.insert("tips".into(), json!(tips));
    o.insert("template".into(), json!(to_hex(&probe.serialize())));
    s
}

/// The pruned engine agrees with the archival one on everything it still keeps.
fn same_view(a: &mut Consensus, p: &mut Consensus) {
    assert_eq!(fingerprint(a), fingerprint(p));
    for h in &p.order {
        assert_eq!(a.status.get(h), p.status.get(h), "status of {}", to_hex(h));
        assert_eq!(a.store.gd[h].blue_score, p.store.gd[h].blue_score);
    }
    for (id, h) in &p.tx_index { assert_eq!(a.tx_index.get(id), Some(h)); }
    for (id, h) in &a.tx_index { if p.store.has(h) { assert_eq!(p.tx_index.get(id), Some(h), "tx index of {}", to_hex(id)); } }
    for (r, i) in &p.reward_index {
        let x = a.reward_index.get(r).expect("reward known to the archival engine");
        assert_eq!((x.amount, x.paid_by, x.red), (i.amount, i.paid_by, i.red));
    }
    for (r, i) in &a.reward_index {
        if p.store.has(r) && p.store.has(&i.paid_by) { assert!(p.reward_index.contains_key(r), "reward of {}", to_hex(r)); }
    }
    // transaction → block index (RPC lookups): the same for every body the pruned engine keeps
    for (id, h) in &p.tx_block { assert_eq!(a.tx_block.get(id), Some(h)); }
    for (id, h) in &a.tx_block { if p.blocks.contains_key(h) { assert_eq!(p.tx_block.get(id), Some(h)); } }
    assert_eq!(a.reds_count, p.reds_count);
    assert_eq!(a.blocks_count, p.blocks_count);
}

/// The transaction → block index of a reloaded engine equals the original's (with a readable report).
fn same_tx_block(re: &Consensus, c: &Consensus) {
    let describe = |id: &[u8; 32], h: &Hash| {
        let pos = c.order.iter().position(|x| x == h);
        let txs: Vec<String> = c.blocks.get(h).map(|b| b.txs.iter().map(|t| to_hex(&t.id())[..8].to_string()).collect()).unwrap_or_default();
        format!("{} in {} (order {pos:?}, body {}, genesis {}, txs {txs:?})", &to_hex(id)[..8], &to_hex(h)[..8], c.blocks.contains_key(h), *h == c.genesis_hash)
    };
    let extra: Vec<String> = re.tx_block.iter().filter(|(k, v)| c.tx_block.get(*k) != Some(*v)).map(|(k, v)| describe(k, v)).collect();
    let lost: Vec<String> = c.tx_block.iter().filter(|(k, v)| re.tx_block.get(*k) != Some(*v)).map(|(k, v)| describe(k, v)).collect();
    assert!(extra.is_empty() && lost.is_empty(), "tx index after reload ({} vs {} entries, pruned {}): only after reload {extra:?}; only before {lost:?}",
        re.tx_block.len(), c.tx_block.len(), c.pruning_point.is_some());
}

/// Snapshot → bytes → engine: the reloaded engine re-encodes to exactly the same bytes.
pub(crate) fn reload(c: &Consensus) -> Consensus {
    let bytes = snapshot::encode(c);
    let l = snapshot::decode(&c.params, &bytes).expect("decode");
    let blocks: Vec<Block> = c.order.iter().filter_map(|h| c.blocks.get(h).map(|b| (**b).clone())).collect();
    assert_eq!(l.missing_bodies(&blocks), 0);
    let (c2, later) = l.finish(blocks);
    assert!(later.is_empty());
    assert!(snapshot::encode(&c2) == bytes, "re-encoding a reloaded snapshot changed it");
    // and, compared with the original engine itself (also what the snapshot rebuilds rather than stores)
    assert_eq!(c2.tx_index, c.tx_index);
    same_tx_block(&c2, c);
    assert_eq!(c2.lock_txs, c.lock_txs);
    let rewards = |x: &Consensus| { let mut v: Vec<_> = x.reward_index.iter().map(|(r, i)| (*r, i.amount, i.paid_by, i.red)).collect(); v.sort(); v };
    assert_eq!(rewards(&c2), rewards(c));
    let bodies = |x: &Consensus| { let mut v: Vec<Hash> = x.blocks.keys().copied().collect(); v.sort(); v };
    assert_eq!(bodies(&c2), bodies(c));
    assert_eq!((&c2.status, &c2.chain_ok, &c2.tips, &c2.order), (&c.status, &c.chain_ok, &c.tips, &c.order));
    assert_eq!((c2.pruning_point, c2.prune_cutoff, c2.blocks_count, c2.reds_count), (c.pruning_point, c.prune_cutoff, c.blocks_count, c.reds_count));
    c2
}

pub(crate) struct Sim { pub a: Consensus, pub p: Consensus, side: Consensus, pub ts: u64, rng: Rng, miners: Vec<Vec<u8>>, n: u64, prunes: usize, forgotten: usize, reorgs: usize }

impl Sim {
    pub(crate) fn new(seed: u64) -> Self {
        let p = params();
        let ts = p.genesis_timestamp + 100;
        Sim { a: Consensus::new(p.clone()), p: Consensus::new(p.clone()), side: Consensus::new(p), ts, rng: Rng(seed), miners: miners(), n: 0, prunes: 0, forgotten: 0, reorgs: 0 }
    }
    fn tick(&mut self) -> u64 { self.ts += 100; self.ts }
    fn miner(&mut self) -> Vec<u8> { let i = self.rng.below(3) as usize; self.miners[i].clone() }
    fn feed(&mut self, b: &Block, side_too: bool) {
        let ra = self.a.add_block(b.clone(), u64::MAX / 2, false);
        let rp = self.p.add_block(b.clone(), u64::MAX / 2, false);
        assert!(matches!(ra, AddResult::Accepted { chain_valid: true, .. }), "{}", res(&ra));
        assert_eq!(res(&ra), res(&rp));
        if side_too { assert!(matches!(self.side.add_block(b.clone(), u64::MAX / 2, false), AddResult::Accepted { .. } | AddResult::Known(_))); }
    }
    /// one step: a block, a few parallel blocks, or a private branch released later
    pub(crate) fn step(&mut self) {
        let r = self.rng.below(100);
        if r < 60 {
            let (md, ts) = (self.miner(), self.tick());
            let b = mine(&mut self.a, &md, &format!("b{}", self.n), ts);
            self.feed(&b, true);
        } else if r < 90 {
            // 2–4 blocks on the same template (same parents): they merge in the next block
            let ts = self.tick();
            let k = 2 + self.rng.below(3);
            let bs: Vec<Block> = (0..k).map(|i| { let md = self.miner(); mine(&mut self.a, &md, &format!("p{}-{i}", self.n), ts) }).collect();
            for b in &bs { self.feed(b, true); }
        } else {
            // a private branch (4–16 blocks) while the public DAG grows 2–10 blocks: either a
            // reorganization or a batch of blocks merged late (often red: k = 8)
            let (sl, ml) = (4 + self.rng.below(13), 2 + self.rng.below(9));
            let mut private = vec![];
            for i in 0..sl {
                let (md, ts) = (self.miner(), self.tick());
                let b = mine(&mut self.side, &md, &format!("s{}-{i}", self.n), ts);
                assert!(matches!(self.side.add_block(b.clone(), u64::MAX / 2, false), AddResult::Accepted { .. }));
                private.push(b);
            }
            let mut public = vec![];
            for i in 0..ml {
                let (md, ts) = (self.miner(), self.tick());
                let b = mine(&mut self.a, &md, &format!("m{}-{i}", self.n), ts);
                self.feed(&b, false);
                public.push(b);
            }
            let mid = self.a.virt().gd.selected_parent;
            for b in &private { self.feed(b, false); }
            for b in &public { self.side.add_block(b.clone(), u64::MAX / 2, false); }
            if self.a.virt().gd.selected_parent != mid { self.reorgs += 1; }
        }
        self.n += 1;
    }
}

#[test]
fn snapshot_roundtrip_and_pruned_equivalence() {
    let mut s = Sim::new(0x9e3779b97f4a7c15);
    let depth = s.p.min_prune_depth();
    assert!(depth >= 200);
    let t = std::time::Instant::now();
    for i in 0..700 {
        s.step();
        if let Some(r) = s.p.prune(depth) {
            s.prunes += 1;
            s.forgotten += r.forgotten;
            assert!(s.p.blocks.contains_key(&r.pruning_point), "the pruning point keeps its body");
        }
        same_view(&mut s.a, &mut s.p);
        if i % 60 == 59 {
            s.p = reload(&s.p);
            s.a = reload(&s.a);
            same_view(&mut s.a, &mut s.p);
        }
    }
    let (a, p) = (&s.a, &s.p);
    eprintln!("{} blocks, blue score {}, {} reorganizations, {} reds; pruned engine: {} prunes, {} blocks forgotten, keeps {} blocks / {} bodies; {:.1} s",
        a.store.gd.len(), a.virt().gd.blue_score, s.reorgs, a.reds_count, s.prunes, s.forgotten, p.store.gd.len(), p.blocks.len(), t.elapsed().as_secs_f64());
    assert!(s.reorgs > 0 && a.reds_count > 0, "the scenario must exercise reorganizations and red blocks");
    assert!(p.virt().acceptance.shielded > 0, "and shielded coinbases");
    assert!(s.forgotten > 0 && p.store.gd.len() < a.store.gd.len() / 2, "the pruned engine must actually forget");
    let pp = p.pruning_point.unwrap();
    let vbs = p.virt().gd.blue_score;
    assert!(vbs - p.store.gd[&pp].blue_score >= depth);
    // what it keeps is bounded by the depth and the margin, not by the length of the chain
    let low = p.order.iter().map(|h| p.store.gd[h].blue_score).min().unwrap();
    assert!(vbs - low <= depth + p.prune_margin() + 50);
    assert!(p.order.iter().all(|h| p.store.gd[h].blue_score >= p.prune_cutoff || *h == pp));
}

#[test]
fn pruned_node_keeps_finality() {
    let prm = params();
    let (mut a, mut p, mut x) = (Consensus::new(prm.clone()), Consensus::new(prm.clone()), Consensus::new(prm.clone()));
    let depth = p.min_prune_depth();
    let md = miners();
    let mut ts = prm.genesis_timestamp;
    let feed = |c: &mut Consensus, b: &Block| c.add_block(b.clone(), u64::MAX / 2, false);
    for i in 0..150 {
        ts += 100;
        let b = mine(&mut a, &md[i % 3], &format!("c{i}"), ts);
        for c in [&mut a, &mut p, &mut x] { assert!(matches!(feed(c, &b), AddResult::Accepted { .. })); }
    }
    let fork = a.virt().gd.selected_parent.unwrap();
    // the public chain grows 300 more blocks; the pruned engine prunes along the way
    for i in 0..300 {
        ts += 100;
        let b = mine(&mut a, &md[i % 3], &format!("d{i}"), ts);
        for c in [&mut a, &mut p] { assert!(matches!(feed(c, &b), AddResult::Accepted { .. })); }
        p.prune(depth);
    }
    let pp = p.pruning_point.expect("pruned");
    assert!(p.store.gd[&pp].blue_score > p.store.gd[&fork].blue_score && p.store.has(&fork), "the fork point is kept, below the pruning point");
    let tip = p.virt().gd.selected_parent;
    // an attacker had been mining a longer chain in private since `fork`
    let mut ts2 = prm.genesis_timestamp + 150 * 100;
    let mut private = vec![];
    for i in 0..340 {
        ts2 += 100;
        let b = mine(&mut x, &md[0], &format!("x{i}"), ts2);
        assert!(matches!(feed(&mut x, &b), AddResult::Accepted { .. }));
        private.push(b);
    }
    p.disqualified.clear();
    for b in &private {
        assert!(matches!(feed(&mut a, b), AddResult::Accepted { .. }));
        assert!(matches!(feed(&mut p, b), AddResult::Accepted { chain_valid: false, .. }));
    }
    // the archival engine follows the heavier chain; the pruned one does not reorganize below its pruning point
    assert_eq!(a.virt().gd.selected_parent, x.virt().gd.selected_parent);
    assert_eq!(p.virt().gd.selected_parent, tip);
    assert!(private.iter().all(|b| p.status.get(&b.hash()) == Some(&Status::Disq)));
    assert!(p.disqualified.iter().any(|(_, r)| r == "forks off below the pruning point"));
    // and keeps extending its own chain
    ts += 100;
    let b = mine(&mut p, &md[1], "after", ts);
    assert!(matches!(feed(&mut p, &b), AddResult::Accepted { chain_valid: true, .. }));
}

// ------------------------------------------------------------------------------- node on disk
pub(crate) fn tmpdir(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("krevo-test-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}
fn open(dir: &PathBuf, prune: Option<u64>) -> Node {
    let mut n = Node::new(params(), Some(BlockFile::new(dir).unwrap()), 0, "127.0.0.1".into(), 0);
    n.prune_depth = prune;
    n
}
fn grow(n: &mut Node, count: usize, ts: &mut u64, tag: &str) {
    let md = miners();
    for i in 0..count {
        *ts += 100;
        let b = mine(&mut n.c, &md[i % 3], &format!("{tag}{i}"), *ts);
        let (st, _, why) = n.receive_block(b, None);
        assert_eq!(st, "accepted", "{why:?}");
    }
}

#[test]
fn archival_node_restarts_from_its_snapshot() {
    let dir = tmpdir("archival");
    let mut ts = params().genesis_timestamp;
    let mut n = open(&dir, None);
    assert!(!n.load().unwrap(), "full validation");
    grow(&mut n, 200, &mut ts, "a");
    n.checkpoint(true);
    grow(&mut n, 150, &mut ts, "b");
    n.checkpoint(true);
    grow(&mut n, 25, &mut ts, "c"); // newer than the snapshot: validated again on restart
    let fp = fingerprint(&mut n.c);
    let blocks = n.c.store.gd.len();
    drop(n);
    let snap = BlockFile::new(&dir).unwrap().snapshot_path();
    // 1. from the snapshot
    let mut n = open(&dir, None);
    assert!(n.load().unwrap(), "must start from the state snapshot");
    assert_eq!(fingerprint(&mut n.c), fp);
    assert_eq!(n.c.store.gd.len(), blocks);
    drop(n);
    // 2. without a snapshot: full replay (which writes a new snapshot)
    std::fs::remove_file(&snap).unwrap();
    let mut n = open(&dir, None);
    assert!(!n.load().unwrap(), "full validation");
    assert_eq!(fingerprint(&mut n.c), fp);
    assert!(snap.exists());
    drop(n);
    // 3. damaged snapshots: refused, full replay
    let good = std::fs::read(&snap).unwrap();
    for bad in [good[..good.len() / 2].to_vec(), { let mut b = good.clone(); let i = b.len() / 3; b[i] ^= 1; b }, b"garbage".to_vec()] {
        std::fs::write(&snap, &bad).unwrap();
        let mut n = open(&dir, None);
        assert!(!n.load().unwrap(), "the damaged snapshot must be refused");
        assert_eq!(fingerprint(&mut n.c), fp);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pruned_node_restarts_compacts_and_survives_a_crash() {
    let dir = tmpdir("pruned");
    let depth = Consensus::new(params()).min_prune_depth();
    let bf = BlockFile::new(&dir).unwrap();
    let mut ts = params().genesis_timestamp;
    let mut n = open(&dir, Some(depth));
    assert!(!n.load().unwrap(), "full validation");
    grow(&mut n, 300, &mut ts, "a");
    n.checkpoint(true);
    grow(&mut n, 300, &mut ts, "b");
    // a crash between writing the new snapshot and compacting blocks.dat: the old, longer file stays
    let uncompacted = std::fs::read(&bf.file).unwrap();
    n.checkpoint(true);
    assert!(n.c.pruning_point.is_some());
    let compacted = std::fs::read(&bf.file).unwrap();
    assert!(compacted.len() < uncompacted.len() / 2, "blocks.dat must shrink: {} -> {}", uncompacted.len(), compacted.len());
    assert_eq!(bf.read_all().len(), n.c.blocks.len());
    grow(&mut n, 20, &mut ts, "c");
    let fp = fingerprint(&mut n.c);
    let kept = n.c.store.gd.len();
    let after: Vec<Block> = bf.read_all().into_iter().skip(n.c.blocks.len() - 20).collect();
    drop(n);
    // 1. normal restart
    let mut n = open(&dir, Some(depth));
    assert!(n.load().unwrap(), "must start from the state snapshot");
    assert_eq!(fingerprint(&mut n.c), fp);
    assert_eq!(n.c.store.gd.len(), kept);
    grow(&mut n, 10, &mut ts, "d"); // and it goes on
    let fp2 = fingerprint(&mut n.c);
    drop(n);
    // 2. the crash: blocks.dat still holds the forgotten blocks (they are ignored)
    let mut crashed = uncompacted.clone();
    for b in &after { let raw = b.serialize(); crashed.extend_from_slice(&(raw.len() as u32).to_le_bytes()); crashed.extend_from_slice(&raw); }
    let compacted_now = std::fs::read(&bf.file).unwrap();
    std::fs::write(&bf.file, &crashed).unwrap();
    let mut n = open(&dir, Some(depth));
    assert!(n.load().unwrap(), "must start from the state snapshot");
    assert_eq!(fingerprint(&mut n.c), fp);
    drop(n);
    std::fs::write(&bf.file, &compacted_now).unwrap();
    // 3. a pruned folder cannot be rebuilt without its snapshot, nor with bodies missing
    let snap = std::fs::read(bf.snapshot_path()).unwrap();
    std::fs::remove_file(bf.snapshot_path()).unwrap();
    let err = open(&dir, Some(depth)).load().unwrap_err();
    assert!(err.contains("pruned node"), "{err}");
    std::fs::write(bf.snapshot_path(), &snap).unwrap();
    std::fs::write(&bf.file, &compacted_now[..compacted_now.len() / 3]).unwrap();
    let err = open(&dir, Some(depth)).load().unwrap_err();
    assert!(err.contains("inconsistent"), "{err}");
    // 4. back to the right files: all good again
    std::fs::write(&bf.file, &compacted_now).unwrap();
    let mut n = open(&dir, Some(depth));
    assert!(n.load().unwrap(), "must start from the state snapshot");
    assert_eq!(fingerprint(&mut n.c), fp2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ----------------------------------------------------------------------------- hostile input
fn checksum(body: &[u8]) -> [u8; 32] { H::new("snapshot/checksum").b(body).d32() }

#[test]
fn damaged_or_tampered_snapshots_are_refused() {
    let mut s = Sim::new(7);
    for _ in 0..60 { s.step(); }
    let good = snapshot::encode(&s.a);
    assert!(snapshot::decode(&s.a.params, &good).is_ok());
    assert!(snapshot::decode(&get_params("devnet").unwrap(), &good).err().unwrap().contains("simnet"), "another network");
    // any change, any truncation: the checksum
    let mut rng = Rng(99);
    for _ in 0..300 {
        let mut b = good.clone();
        let i = rng.below(b.len() as u64) as usize;
        b[i] ^= 1 << rng.below(8);
        assert!(snapshot::decode(&s.a.params, &b).is_err());
    }
    for cut in [0, 7, 8, 40, good.len() / 2, good.len() - 1] { assert!(snapshot::decode(&s.a.params, &good[..cut]).is_err()); }
    // changes with a recomputed checksum (as a deliberate edit would have): never a panic
    let body = &good[..good.len() - 32];
    for _ in 0..400 {
        let mut b = body.to_vec();
        for _ in 0..1 + rng.below(3) { let i = 8 + rng.below((b.len() - 8) as u64) as usize; b[i] = rng.next() as u8; }
        let sum = checksum(&b);
        b.extend_from_slice(&sum);
        let _ = snapshot::decode(&s.a.params, &b);
    }
    // a UTXO set that is not the one the chain committed to
    let k = *s.a.utxo.t.keys().next().unwrap();
    s.a.utxo.t.get_mut(&k).unwrap().amount += 1;
    let err = snapshot::decode(&s.a.params, &snapshot::encode(&s.a)).err().unwrap();
    assert!(err.contains("commitment"), "{err}");
}

/// Informational: restart time with and without the state snapshot (cargo test --release
/// restart_speed -- --ignored --nocapture). Coinbase-only blocks are cheaper to validate than real
/// traffic (signatures, range and membership proofs), so the real gain is larger.
#[test]
#[ignore]
fn restart_speed() {
    let dir = tmpdir("speed");
    let mut ts = params().genesis_timestamp;
    let mut n = open(&dir, None);
    n.load().unwrap();
    grow(&mut n, 3000, &mut ts, "s");
    let fp = fingerprint(&mut n.c);
    drop(n);
    let snap = BlockFile::new(&dir).unwrap().snapshot_path();
    let _ = std::fs::remove_file(&snap);
    let t = std::time::Instant::now();
    let mut n = open(&dir, None);
    assert!(!n.load().unwrap()); // full validation (and writes the snapshot)
    let full = t.elapsed().as_secs_f64();
    assert_eq!(fingerprint(&mut n.c), fp);
    drop(n);
    let t = std::time::Instant::now();
    let mut n = open(&dir, None);
    assert!(n.load().unwrap());
    let fast = t.elapsed().as_secs_f64();
    assert_eq!(fingerprint(&mut n.c), fp);
    eprintln!("3,000 blocks: full validation {full:.2} s (including writing the snapshot), from the snapshot {fast:.2} s ({:.0}x); snapshot {:.1} MB",
        full / fast, std::fs::metadata(&snap).unwrap().len() as f64 / 1e6);
    let _ = std::fs::remove_dir_all(&dir);
}
