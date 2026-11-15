//! Consensus engine (mirrors src/consensus/consensus.js).
//!  1. header: PoW, parents (antichain), GHOSTDAG, difficulty, timestamp, merge depth
//!  2. body: well-formed coinbase, transactions valid in isolation, Merkle, mass
//!  3. UTXO state: the block accepts the transactions of its mergeset on top of the selected
//!     parent's state; the MuHash commitment and the coinbase must match (otherwise: disqualified)
//!  4. virtual: the hypothetical block on top of all tips = the current state of the network

use crate::block::{merkle_root, Block, Header};
use crate::bytes::*;
use crate::crypto::{hash_to_scalar, make_coinbase_shielded_output, MuHash};
use crate::dag::*;
use crate::hash::H;
use crate::params::Params;
use crate::pow::{calc_work, check_pow, compact_to_target};
use crate::rules::{capped_subsidy, parse_address_data, Addr};
use crate::tx::{SOut, TOut, Transaction};
use crate::txvalidation::*;
use crate::utxo::*;
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status { Chain, Disq }

#[derive(Clone)]
pub struct Acc {
    pub diff: UtxoDiff,
    pub muhash: MuHash,
    pub pool: u64,
    pub minted: u64,
    pub accepted: Vec<[u8; 32]>,
    pub rewards: Vec<(Hash, u64)>,
    pub reds: Vec<Hash>,
    pub shielded: i128,
    pub cb_shielded: u64,
}

#[derive(Clone)]
pub struct Acceptance {
    pub diff: UtxoDiff,
    pub muhash: MuHash,
    pub accepted: Vec<[u8; 32]>,
    pub accepted_set: HashSet<[u8; 32]>,
    pub accepted_root: [u8; 32],
    pub pool: u64,
    pub minted: u64,
    pub blue_rewards: Vec<(Hash, u64)>,
    pub red_reward: u64,
    pub fee_total: u64,
    pub shielded: i128,
    pub name_fees: u64,
}

pub struct Virtual { pub parents: Vec<Hash>, pub gd: GhostdagData, pub acceptance: Acceptance, pub version: u64, pub bits: u32, pub pmt: u64 }

#[derive(Clone, Copy)]
pub struct RewardInfo { pub amount: u64, pub paid_by: Hash, pub red: bool }

pub enum AddResult {
    Accepted { hash: Hash, chain_valid: bool },
    Known(Hash),
    Orphan { hash: Hash, missing: Vec<Hash> },
    Future(Hash),
    Invalid { hash: Hash, reason: String },
}

pub struct Consensus {
    pub params: Params,
    pub store: DagStore,
    pub ghostdag: Ghostdag,
    pub headers: HashMap<Hash, Header>,
    pub blocks: HashMap<Hash, Arc<Block>>,
    pub miner_data: HashMap<Hash, Vec<u8>>,
    pub status: HashMap<Hash, Status>,
    pub acc: HashMap<Hash, Acc>,
    pub invalid: HashMap<Hash, String>,
    pub tips: HashSet<Hash>,
    pub utxo: UtxoSet,
    pub base_hash: Hash,
    pub tx_index: HashMap<[u8; 32], Hash>,
    pub tx_block: HashMap<[u8; 32], Hash>,
    pub lock_txs: HashMap<Vec<u8>, Vec<[u8; 32]>>,
    pub reward_index: HashMap<Hash, RewardInfo>,
    pub order: Vec<Hash>,
    pub pow_limit_bits: u32,
    pub virt: Option<Virtual>,
    pub virtual_version: u64,
    pub genesis_hash: Hash,
    pub blocks_count: u64,
    pub reds_count: u64,
    /// disqualified blocks (hash, reason) since the last query — for the node's log
    pub disqualified: Vec<(Hash, String)>,
    /// Pruning (optional node policy, see `prune`): the pruning point, below which this node no
    /// longer follows reorganizations, and the blue score under which it forgot everything.
    pub pruning_point: Option<Hash>,
    pub prune_cutoff: u64,
    /// "The pruning point is on this block's selected chain" (always true before any pruning).
    pub chain_ok: HashMap<Hash, bool>,
}

/// What `prune` did.
pub struct PruneReport { pub pruning_point: Hash, pub forgotten: usize, pub bodies_dropped: usize }

pub fn coinbase_payload(blue_score: u64, miner_data: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(blue_score).varbytes(miner_data).varbytes(extra);
    w.done()
}
pub fn parse_coinbase_payload(buf: &[u8]) -> Res<(u64, Vec<u8>, Vec<u8>)> {
    let mut r = Reader::new(buf);
    let bs = r.u64()?;
    let md = r.varbytes(100)?.to_vec();
    let extra = r.varbytes(200)?.to_vec();
    r.end()?;
    Ok((bs, md, extra))
}

/// Header rules (everything that needs no block body): PoW, parents, GHOSTDAG, difficulty, timestamp
/// and merge depth, against the DAG data in `store`/`headers`. Shared by the engine and by the
/// header-first sync of new nodes (fastsync.rs).
pub fn check_header(p: &Params, store: &DagStore, headers: &HashMap<Hash, Header>, ghostdag: &Ghostdag, pow_limit_bits: u32, h: &Header) -> Result<GhostdagData, String> {
    let parents = &h.parents;
    if h.version != 1 { return Err("unknown header version".into()); }
    if parents.is_empty() || parents.len() > p.max_parents { return Err("invalid number of parents".into()); }
    for i in 1..parents.len() { if parents[i - 1] >= parents[i] { return Err("parents out of order or repeated".into()); } }
    let target = compact_to_target(h.bits)?;
    if target > compact_to_target(pow_limit_bits)? { return Err("target above the limit".into()); }
    if !check_pow(h) { return Err("insufficient proof of work".into()); }
    for i in 0..parents.len() {
        for j in 0..parents.len() {
            if i != j && store.is_ancestor(&parents[i], &parents[j]) { return Err("parents do not form an antichain".into()); }
        }
    }
    let gd = ghostdag.run(store, parents);
    if gd.mergeset_blues.len() + gd.mergeset_reds.len() > p.mergeset_size_limit { return Err("mergeset too large".into()); }
    if h.blue_score != gd.blue_score || h.blue_work != gd.blue_work || h.daa_score != gd.daa_score { return Err("header GHOSTDAG data does not match".into()); }
    if h.bits != required_bits(p, store, headers, &gd, pow_limit_bits) { return Err("incorrect difficulty".into()); }
    if h.timestamp < past_median_time(p, store, headers, &gd) { return Err("timestamp before the past median time".into()); }
    for x in &gd.mergeset_asc {
        if gd.blue_score.saturating_sub(store.gd[x].blue_score) > p.merge_depth { return Err("block too old in the mergeset (merge depth limit)".into()); }
    }
    Ok(gd)
}

/// How far below a pruning point the DAG data must be kept (see `Consensus::prune`).
pub fn prune_margin(p: &Params) -> u64 {
    p.merge_depth + p.daa_window_size as u64 + p.past_median_time_window as u64 + 4 * p.ghostdag_k as u64 + 100
}

/// Coins minted up to and including the acceptance of a block with this GHOSTDAG data, from the
/// selected parent's total — the same loop as `compute_acceptance`, which needs only header data.
pub fn minted_after(p: &Params, store: &DagStore, genesis: &Hash, sp_minted: u64, gd: &GhostdagData) -> u64 {
    let sp = gd.selected_parent.expect("not the genesis");
    let mut minted = sp_minted;
    for x in std::iter::once(&sp).chain(gd.mergeset_asc.iter()) {
        if x == genesis { continue; }
        minted += capped_subsidy(store.gd[x].daa_score, minted, p);
    }
    minted
}

pub fn build_genesis(p: &Params) -> Block {
    let mut cb = Transaction::new();
    cb.payload = coinbase_payload(0, &[], p.genesis_message.as_bytes());
    let header = Header {
        version: 1, parents: vec![], hash_merkle_root: merkle_root(&[cb.hash()]), accepted_id_merkle_root: [0; 32],
        utxo_commitment: MuHash::new().digest(), timestamp: p.genesis_timestamp, bits: p.genesis_bits, nonce: 0,
        daa_score: 0, blue_score: 0, blue_work: BigUint::from(0u32),
    };
    Block::new(header, vec![cb])
}

fn apply_tx(base: &UtxoSet, diff: &mut UtxoDiff, mh: &mut MuHash, tx: &Transaction, daa: u64, coinbase: bool) {
    for i in &tx.t_in {
        let k = (i.txid, i.index);
        let e = UtxoView { base, diff }.get_t(&k).cloned().expect("validated input");
        mh.remove(&encode_t_entry(&k, &e));
        diff.spend_t(k, &e);
    }
    for si in &tx.s_in { diff.add_ki(si.key_image); mh.add(&encode_ki(&si.key_image)); }
    let id = tx.id();
    for (i, o) in tx.t_out.iter().enumerate() {
        let k = (id, i as u32);
        let e = TEntry { amount: o.amount, lock: o.lock.clone(), daa, coinbase };
        mh.add(&encode_t_entry(&k, &e));
        diff.add_t(k, e);
    }
    for (j, o) in tx.s_out.iter().enumerate() {
        let k = (id, (tx.t_out.len() + j) as u32);
        let e = SEntry { p: o.p, c: o.c, enc_amount: o.enc_amount, view_tag: o.view_tag, r: o.r, j: j as u32, daa, coinbase };
        mh.add(&encode_s_entry(&k, &e));
        diff.add_s(k, e);
    }
}

impl Consensus {
    pub fn new(params: Params) -> Self {
        let g = build_genesis(&params);
        let h = g.hash();
        let mut c = Consensus {
            ghostdag: Ghostdag { k: params.ghostdag_k },
            store: DagStore::default(),
            headers: HashMap::new(), blocks: HashMap::new(), miner_data: HashMap::new(), status: HashMap::new(),
            acc: HashMap::new(), invalid: HashMap::new(), tips: HashSet::new(),
            utxo: UtxoSet::new(params.fcmp_branch), base_hash: h,
            tx_index: HashMap::new(), tx_block: HashMap::new(), lock_txs: HashMap::new(), reward_index: HashMap::new(),
            order: vec![], pow_limit_bits: params.genesis_bits, virt: None, virtual_version: 0, genesis_hash: h,
            blocks_count: 0, reds_count: 0, disqualified: vec![], params,
            pruning_point: None, prune_cutoff: 0, chain_ok: HashMap::new(),
        };
        c.chain_ok.insert(h, true);
        c.headers.insert(h, g.header.clone());
        c.miner_data.insert(h, vec![]);
        c.store.add(h, vec![], genesis_ghostdag(), calc_work(g.header.bits));
        c.blocks.insert(h, Arc::new(g));
        c.status.insert(h, Status::Chain);
        c.acc.insert(h, Acc { diff: UtxoDiff::default(), muhash: MuHash::new(), pool: 0, minted: 0, accepted: vec![], rewards: vec![], reds: vec![], shielded: 0, cb_shielded: 0 });
        c.tips.insert(h);
        c.order.push(h);
        c.resolve_virtual();
        c
    }

    pub fn has(&self, h: &Hash) -> bool { self.store.has(h) }
    pub fn virt(&self) -> &Virtual { self.virt.as_ref().unwrap() }

    /// View of the virtual's state (moves the base to the virtual's selected parent if needed).
    pub fn ensure_virtual_base(&mut self) { let sp = self.virt().gd.selected_parent.unwrap(); self.move_base(&sp); }
    pub fn virtual_view(&self) -> UtxoView<'_> { UtxoView { base: &self.utxo, diff: &self.virt().acceptance.diff } }

    // ------------------------------------------------------------ input
    pub fn add_block(&mut self, block: Block, now: u64, trusted: bool) -> AddResult {
        let hash = block.hash();
        if self.store.has(&hash) { return AddResult::Known(hash); }
        if let Some(r) = self.invalid.get(&hash) { return AddResult::Invalid { hash, reason: r.clone() }; }
        let h = &block.header;
        let mut missing: Vec<Hash> = vec![];
        for p in &h.parents { if !self.store.has(p) && !missing.contains(p) { missing.push(*p); } }
        // a pruned node already forgot everything this far down: nothing to fetch or validate
        if !missing.is_empty() && self.pruning_point.is_some() && h.blue_score < self.prune_cutoff { return AddResult::Known(hash); }
        if !missing.is_empty() { return AddResult::Orphan { hash, missing }; }
        if !trusted && h.timestamp > now + self.params.max_future_ms { return AddResult::Future(hash); }
        let res = self.validate_header(&block).and_then(|gd| self.validate_body(&block).map(|md| (gd, md)));
        let (gd, md) = match res {
            Ok(x) => x,
            Err(reason) => {
                if self.invalid.len() > 10_000 { self.invalid.clear(); }
                self.invalid.insert(hash, reason.clone());
                return AddResult::Invalid { hash, reason };
            }
        };
        let parents = h.parents.clone();
        self.headers.insert(hash, h.clone());
        self.miner_data.insert(hash, md);
        self.blocks_count += 1;
        self.reds_count += gd.mergeset_reds.len() as u64;
        let sp = gd.selected_parent.unwrap();
        self.chain_ok.insert(hash, self.pruning_point == Some(hash) || self.chain_ok.get(&sp).copied().unwrap_or(false));
        self.store.add(hash, parents.clone(), gd, calc_work(h.bits));
        for p in &parents { self.tips.remove(p); }
        self.tips.insert(hash);
        self.order.push(hash);
        let block = Arc::new(block);
        for tx in &block.txs {
            let id = tx.id();
            if self.tx_block.contains_key(&id) { continue; }
            self.tx_block.insert(id, hash);
            self.index_locks(tx, id);
        }
        self.blocks.insert(hash, block);
        let chain_valid = self.validate_utxo(&hash);
        self.resolve_virtual();
        AddResult::Accepted { hash, chain_valid }
    }

    fn validate_header(&self, block: &Block) -> Result<GhostdagData, String> {
        check_header(&self.params, &self.store, &self.headers, &self.ghostdag, self.pow_limit_bits, &block.header)
    }

    /// Context-free checks of a block body (coinbase form, Merkle root, mass…); returns the miner data.
    pub fn check_body(&self, block: &Block) -> Result<Vec<u8>, String> { self.validate_body(block) }

    fn validate_body(&self, block: &Block) -> Result<Vec<u8>, String> {
        let p = &self.params;
        let txs = &block.txs;
        if txs.is_empty() { return Err("block without coinbase".into()); }
        let cb = &txs[0];
        if !cb.is_coinbase() || cb.version != 1 { return Err("first transaction is not a coinbase".into()); }
        if cb.fee != 0 || cb.mass != 0 || !cb.range_proof.is_empty() || cb.binding_sig.is_some() { return Err("malformed coinbase".into()); }
        if cb.payload.len() > p.max_coinbase_payload { return Err("coinbase payload too large".into()); }
        let (bs, md, _) = parse_coinbase_payload(&cb.payload).map_err(|_| "invalid coinbase payload".to_string())?;
        if bs != block.header.blue_score { return Err("coinbase blue score does not match".into()); }
        let a = parse_address_data(&md).ok_or("invalid miner address")?;
        if !matches!(a.kind(), 't' | 's' | 'm' | 'q') { return Err("invalid miner address (must be krv, krs, krq or multisig)".into()); }
        let mut mass = 0u64;
        let mut ids = HashSet::from([cb.id()]);
        for tx in &txs[1..] {
            if tx.is_coinbase() { return Err("extra coinbase".into()); }
            validate_tx_stateless(tx, p)?;
            if !ids.insert(tx.id()) { return Err("transaction repeated in the block".into()); }
            mass += tx.mass;
        }
        if mass > p.max_block_mass { return Err("block mass above the limit".into()); }
        let hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.hash()).collect();
        if merkle_root(&hashes) != block.header.hash_merkle_root { return Err("incorrect Merkle root".into()); }
        Ok(md)
    }

    fn validate_utxo(&mut self, hash: &Hash) -> bool {
        let gd = self.store.gd[hash].clone();
        let sp = gd.selected_parent.unwrap();
        if self.status.get(&sp) != Some(&Status::Chain) { self.status.insert(*hash, Status::Disq); return false; }
        if !self.chain_ok.get(hash).copied().unwrap_or(false) {
            // finality of a pruned node: its state below the pruning point is gone, so it cannot follow
            // a chain that forks off below it (the same trade-off as a pruned Bitcoin node)
            self.status.insert(*hash, Status::Disq);
            self.disqualified.push((*hash, "forks off below the pruning point".to_string()));
            return false;
        }
        let parents = self.store.parents[hash].clone();
        let reuse = self.virt.as_ref().map(|v| v.parents == parents).unwrap_or(false);
        let mut res = if reuse {
            self.virt().acceptance.clone()
        } else {
            self.move_base(&sp);
            self.compute_acceptance(&gd)
        };
        let block = self.blocks[hash].clone();
        let h = &block.header;
        let mut reason = None;
        let mut cb_shielded = 0;
        if h.utxo_commitment != res.muhash.digest() { reason = Some("incorrect UTXO commitment"); }
        else if h.accepted_id_merkle_root != res.accepted_root { reason = Some("incorrect accepted transactions root"); }
        else {
            let actual = &block.txs[0];
            let extra = parse_coinbase_payload(&actual.payload).map(|x| x.2).unwrap_or_default();
            match self.build_coinbase(&res, &gd, &parents, &self.miner_data[hash], &extra) {
                Some((expected, sh)) => {
                    if expected.serialize_body() != actual.serialize_body() { reason = Some("coinbase does not match the rewards due"); }
                    cb_shielded = sh;
                }
                None => reason = Some("coinbase does not match the rewards due"),
            }
        }
        if let Some(r) = reason {
            self.status.insert(*hash, Status::Disq);
            self.disqualified.push((*hash, r.to_string()));
            return false;
        }
        self.acc.insert(*hash, Acc {
            diff: res.diff, muhash: res.muhash, pool: res.pool, minted: res.minted, accepted: res.accepted,
            rewards: res.blue_rewards, reds: gd.mergeset_reds.clone(), shielded: res.shielded, cb_shielded,
        });
        self.status.insert(*hash, Status::Chain);
        true
    }

    /// Moves the materialized state to block `target` by reverting/applying diffs.
    pub fn move_base(&mut self, target: &Hash) {
        if self.base_hash == *target { return; }
        let (mut a, mut b) = (self.base_hash, *target);
        let (mut revert, mut apply) = (vec![], vec![]);
        while a != b {
            if self.store.cmp(&a, &b).is_gt() { revert.push(a); a = self.store.gd[&a].selected_parent.unwrap(); }
            else { apply.push(b); b = self.store.gd[&b].selected_parent.unwrap(); }
        }
        for h in &revert {
            let acc = self.acc.remove(h).unwrap();
            self.utxo.revert(&acc.diff);
            for id in &acc.accepted { if self.tx_index.get(id) == Some(h) { self.tx_index.remove(id); } }
            for (r, _) in &acc.rewards { if self.reward_index.get(r).map(|x| x.paid_by) == Some(*h) { self.reward_index.remove(r); } }
            for r in &acc.reds { if self.reward_index.get(r).map(|x| x.paid_by) == Some(*h) { self.reward_index.remove(r); } }
            self.acc.insert(*h, acc);
        }
        for h in apply.iter().rev() {
            let acc = self.acc.remove(h).expect("chain block without state");
            self.utxo.apply(&acc.diff);
            for id in &acc.accepted { self.tx_index.insert(*id, *h); }
            for (r, amount) in &acc.rewards { self.reward_index.insert(*r, RewardInfo { amount: *amount, paid_by: *h, red: false }); }
            for r in &acc.reds { self.reward_index.insert(*r, RewardInfo { amount: 0, paid_by: *h, red: true }); }
            self.acc.insert(*h, acc);
        }
        self.base_hash = *target;
    }

    /// Acceptance of a block (or of the virtual) with this GHOSTDAG data. Precondition: base = selected parent.
    fn compute_acceptance(&self, gd: &GhostdagData) -> Acceptance {
        let p = &self.params;
        let sp = gd.selected_parent.unwrap();
        assert_eq!(self.base_hash, sp, "base out of position");
        let sp_acc = &self.acc[&sp];
        let mut diff = UtxoDiff::default();
        let mut mh = sp_acc.muhash.clone();
        let daa = gd.daa_score;
        let sp_cb = &self.blocks[&sp].txs[0];
        apply_tx(&self.utxo, &mut diff, &mut mh, sp_cb, daa, true);
        let mut shielded = sp_acc.shielded + sp_acc.cb_shielded as i128;
        let mut accepted = vec![sp_cb.id()];
        let mut seen: HashSet<[u8; 32]> = accepted.iter().copied().collect();
        let mut fees: HashMap<Hash, u64> = HashMap::new();
        let mut name_fees = 0u64;
        let order: Vec<Hash> = std::iter::once(sp).chain(gd.mergeset_asc.iter().copied()).collect();
        for x in &order {
            let mut f = 0u64;
            let blk = self.blocks[x].clone();
            for tx in &blk.txs[1..] {
                let id = tx.id();
                if seen.contains(&id) { continue; }
                let r = match validate_tx_in_context(tx, &UtxoView { base: &self.utxo, diff: &diff }, daa, p) { Ok(r) => r, Err(_) => continue };
                let delta = shielded_delta(tx, r.t_in);
                if shielded + delta < 0 { continue; }
                shielded += delta;
                apply_tx(&self.utxo, &mut diff, &mut mh, tx, daa, false);
                seen.insert(id);
                accepted.push(id);
                f += tx.fee - r.name_fee;
                name_fees += r.name_fee;
            }
            fees.insert(*x, f);
        }
        let mut minted = sp_acc.minted;
        let mut pool = sp_acc.pool as i128;
        let release = (sp_acc.pool / p.fee_pool_decay) as i128;
        let reds: HashSet<Hash> = gd.mergeset_reds.iter().copied().collect();
        let mut blue_rewards = vec![];
        let mut red_reward = 0u64;
        for x in &order {
            if *x == self.genesis_hash { continue; }
            let sub = capped_subsidy(self.store.gd[x].daa_score, minted, p);
            minted += sub;
            let fee = fees[x];
            let to_pool = fee * p.fee_pool_share_num / p.fee_pool_share_den;
            pool += to_pool as i128 - release;
            let reward = (sub as i128 + (fee - to_pool) as i128 + release) as u64;
            if reds.contains(x) { red_reward += reward; } else { blue_rewards.push((*x, reward)); }
        }
        pool += name_fees as i128;
        let fee_total = fees.values().sum();
        mh.normalize();
        Acceptance {
            accepted_root: merkle_root(&accepted), accepted_set: seen, accepted, diff, muhash: mh, pool: pool as u64, minted,
            blue_rewards, red_reward, fee_total, shielded, name_fees,
        }
    }

    fn miner_addr(&self, h: &Hash) -> Option<Addr> { parse_address_data(&self.miner_data[h]) }

    /// Required coinbase (and the amount it puts into the private pool).
    pub fn build_coinbase(&self, res: &Acceptance, gd: &GhostdagData, parents: &[Hash], miner_data: &[u8], extra: &[u8]) -> Option<(Transaction, u64)> {
        let mut recipients: Vec<(Addr, u64)> = vec![];
        for (h, amount) in &res.blue_rewards { recipients.push((self.miner_addr(h)?, *amount)); }
        if res.red_reward > 0 { recipients.push((parse_address_data(miner_data)?, res.red_reward)); }
        let mut tx = Transaction::new();
        let mut shielded_total = 0u64;
        for (addr, amount) in recipients {
            if amount == 0 { continue; }
            match &addr {
                Addr::S { a, b, .. } => {
                    shielded_total += amount;
                    let j = tx.s_out.len() as u64;
                    let mut hh = H::new("coinbase/r");
                    for p in parents { hh = hh.b(p); }
                    let r = hash_to_scalar(hh.n(gd.blue_score).n(j));
                    let o = make_coinbase_shielded_output(a, b, &r, j, amount);
                    tx.s_out.push(SOut { r: o.r.to_bytes(), p: o.p.to_bytes(), c: o.c.to_bytes(), enc_amount: o.enc_amount, view_tag: o.view_tag });
                }
                other => tx.t_out.push(TOut { amount, lock: other.data().to_vec() }),
            }
        }
        tx.payload = coinbase_payload(gd.blue_score, miner_data, extra);
        Some((tx, shielded_total))
    }

    // ------------------------------------------------------------- virtual
    pub fn resolve_virtual(&mut self) {
        let p = self.params.clone();
        let mut tips: Vec<Hash> = self.tips.iter().copied().collect();
        tips.sort_by(|a, b| self.store.cmp(b, a));
        let mut cand = tips.clone();
        let mut seen: HashSet<Hash> = cand.iter().copied().collect();
        let mut selected = None;
        while !cand.is_empty() {
            cand.sort_by(|a, b| self.store.cmp(b, a));
            let c = cand.remove(0);
            if self.status.get(&c) == Some(&Status::Chain) { selected = Some(c); break; }
            for par in &self.store.parents[&c] { if seen.insert(*par) { cand.push(*par); } }
        }
        let selected = selected.expect("no chain block");
        let mut vparents = vec![selected];
        for t in &tips {
            if vparents.len() >= p.max_parents { break; }
            if *t == selected || self.status.get(t) != Some(&Status::Chain) { continue; }
            if vparents.iter().any(|v| self.store.is_ancestor(v, t) || self.store.is_ancestor(t, v)) { continue; }
            vparents.push(*t);
        }
        let gd = loop {
            let gd = self.ghostdag.run(&self.store, &vparents);
            let size = gd.mergeset_blues.len() + gd.mergeset_reds.len();
            let too_deep = gd.mergeset_asc.iter().any(|x| gd.blue_score.saturating_sub(self.store.gd[x].blue_score) > p.merge_depth);
            if (size <= p.mergeset_size_limit && !too_deep) || vparents.len() == 1 { break gd; }
            vparents.pop();
        };
        assert_eq!(gd.selected_parent, Some(selected), "virtual: inconsistent selected parent");
        self.move_base(&selected);
        let acceptance = self.compute_acceptance(&gd);
        let mut parents = vparents.clone();
        parents.sort();
        self.virtual_version += 1;
        let bits = required_bits(&p, &self.store, &self.headers, &gd, self.pow_limit_bits);
        let pmt = past_median_time(&p, &self.store, &self.headers, &gd);
        self.virt = Some(Virtual { parents, gd, acceptance, version: self.virtual_version, bits, pmt });
    }

    /// Block template for mining (the virtual with the chosen transactions).
    pub fn build_template(&mut self, miner_data: &[u8], txs: Vec<Transaction>, extra: &[u8], now: u64) -> Option<Block> {
        parse_address_data(miner_data)?;
        self.ensure_virtual_base();
        let v = self.virt();
        let (cb, _) = self.build_coinbase(&v.acceptance, &v.gd, &v.parents, miner_data, extra)?;
        let mut all = vec![cb];
        all.extend(txs);
        let hashes: Vec<[u8; 32]> = all.iter().map(|t| t.hash()).collect();
        let mut mh = v.acceptance.muhash.clone();
        let header = Header {
            version: 1, parents: v.parents.clone(), hash_merkle_root: merkle_root(&hashes),
            accepted_id_merkle_root: v.acceptance.accepted_root, utxo_commitment: mh.digest(),
            timestamp: now.max(v.pmt), bits: v.bits, nonce: 0,
            daa_score: v.gd.daa_score, blue_score: v.gd.blue_score, blue_work: v.gd.blue_work.clone(),
        };
        Some(Block::new(header, all))
    }

    // ----------------------------------------------------------- queries
    pub fn tx_status(&self, txid: &[u8; 32]) -> serde_json::Value {
        let v = self.virt();
        if v.acceptance.accepted_set.contains(txid) {
            return serde_json::json!({ "status": "accepted", "confirmations": 0, "blueScore": v.gd.blue_score });
        }
        if let Some(h) = self.tx_index.get(txid) {
            let bs = self.store.gd[h].blue_score;
            return serde_json::json!({ "status": "accepted", "acceptingBlock": to_hex(h), "confirmations": v.gd.blue_score - bs, "blueScore": bs });
        }
        serde_json::json!({ "status": "unknown" })
    }

    fn index_locks(&mut self, tx: &Transaction, id: [u8; 32]) {
        let mut locks: Vec<Vec<u8>> = tx.t_out.iter().map(|o| o.lock.clone()).collect();
        for i in &tx.t_in {
            if let Some(prev) = self.find_tx(&i.txid) {
                if let Some(o) = prev.t_out.get(i.index as usize) { locks.push(o.lock.clone()); }
            }
        }
        for l in locks {
            let a = self.lock_txs.entry(l).or_default();
            if a.last() != Some(&id) { a.push(id); if a.len() > 5000 { a.remove(0); } }
        }
    }

    pub fn find_tx(&self, txid: &[u8; 32]) -> Option<&Transaction> {
        let h = self.tx_block.get(txid)?;
        self.blocks.get(h)?.txs.iter().find(|t| t.id() == *txid)
    }

    /// Transparent coins of a lock in the virtual's state.
    pub fn utxos_by_lock(&self, lock: &[u8]) -> Vec<(Op, TEntry)> {
        let v = self.virtual_view();
        let mut keys: Vec<Op> = self.utxo.by_lock.get(lock).cloned().unwrap_or_default();
        for (k, e) in &v.diff.add_t { if e.lock == lock && !keys.contains(k) { keys.push(*k); } }
        keys.into_iter().filter_map(|k| v.get_t(&k).map(|e| (k, e.clone()))).collect()
    }

    pub fn selected_chain(&self, limit: usize) -> Vec<Hash> {
        let mut out = vec![];
        let mut h = self.virt().gd.selected_parent;
        while let Some(x) = h {
            if out.len() >= limit { break; }
            let Some(g) = self.store.gd.get(&x) else { break }; // (forgotten by pruning)
            out.push(x);
            h = g.selected_parent;
        }
        out
    }

    // ----------------------------------------------------------- pruning
    /// How far below the pruning point the DAG data must be kept: the difficulty and median-time
    /// windows, the merge depth and the GHOSTDAG walks of new blocks never reach further down.
    pub fn prune_margin(&self) -> u64 { prune_margin(&self.params) }
    /// Smallest pruning depth accepted (blue score between the virtual and the pruning point): twice
    /// the deepest window a new block's validation looks into, so it never reaches the pruning point
    /// (the margin below it is a further cushion, e.g. for side blocks that fork off near it).
    pub fn min_prune_depth(&self) -> u64 {
        let p = &self.params;
        2 * p.merge_depth.max(p.daa_window_size as u64).max(p.past_median_time_window as u64).max(100)
    }

    /// Pruning (optional node policy). The pruning point PP is the selected-chain block about
    /// `depth` blue score below the virtual. Afterwards this node:
    ///  • never adopts a chain that forks off below PP (finality: its state down there is gone);
    ///  • drops the bodies of the blocks in the past of PP (no future block can merge them), and the
    ///    UTXO diffs below PP (no reorganization can reach them) — PP keeps its body and totals;
    ///  • forgets every trace of the blocks more than `prune_margin()` blue score below PP.
    /// What it keeps is enough to validate every new block exactly as an archival node does.
    pub fn prune(&mut self, depth: u64) -> Option<PruneReport> {
        let vsp = self.virt().gd.selected_parent?;
        let vbs = self.store.gd[&vsp].blue_score;
        if vbs < depth { return None; }
        let target = vbs - depth;
        let mut pp = vsp;
        while self.store.gd[&pp].blue_score > target {
            match self.store.gd[&pp].selected_parent { Some(sp) if self.store.has(&sp) => pp = sp, _ => break }
        }
        let pp_bs = self.store.gd[&pp].blue_score;
        if let Some(old) = self.pruning_point { if pp == old || pp_bs <= self.store.gd.get(&old).map(|g| g.blue_score).unwrap_or(0) { return None; } }
        let cutoff = pp_bs.saturating_sub(self.prune_margin());
        self.ensure_virtual_base(); // the materialized state stays above PP
        // the past of PP (within what is kept): these bodies can never be merged again
        let mut past: HashSet<Hash> = HashSet::from([pp]);
        let mut stack = vec![pp];
        while let Some(x) = stack.pop() {
            for p in self.store.parents.get(&x).cloned().unwrap_or_default() {
                if self.store.gd.get(&p).map(|g| g.blue_score >= cutoff).unwrap_or(false) && past.insert(p) { stack.push(p); }
            }
        }
        let forget: HashSet<Hash> = self.order.iter().filter(|h| **h != pp && self.store.gd[*h].blue_score < cutoff).copied().collect();
        let drop_tx_index = |c: &mut Self, b: &Block, h: &Hash| {
            for tx in &b.txs { let id = tx.id(); if c.tx_block.get(&id) == Some(h) { c.tx_block.remove(&id); } }
        };
        let mut bodies = 0;
        for h in &forget {
            if let Some(b) = self.blocks.remove(h) { drop_tx_index(self, &b, h); bodies += 1; }
            self.acc.remove(h);
            self.headers.remove(h); self.miner_data.remove(h); self.status.remove(h); self.chain_ok.remove(h); self.tips.remove(h);
            self.store.parents.remove(h); self.store.children.remove(h); self.store.height.remove(h);
            self.store.gd.remove(h); self.store.work.remove(h);
        }
        for h in &past {
            if *h == pp { continue; }
            if let Some(b) = self.blocks.remove(h) { drop_tx_index(self, &b, h); bodies += 1; }
        }
        for h in past.iter() { if let Some(a) = self.acc.get_mut(h) { a.diff = UtxoDiff::default(); } } // no revert below PP
        for list in self.store.parents.values_mut() { list.retain(|p| !forget.contains(p)); }
        for list in self.store.children.values_mut() { list.retain(|p| !forget.contains(p)); }
        self.tx_index.retain(|_, h| !forget.contains(h));
        self.reward_index.retain(|r, info| !forget.contains(r) && !forget.contains(&info.paid_by));
        let known: HashSet<[u8; 32]> = self.tx_block.keys().copied().collect();
        self.lock_txs.retain(|_, ids| { ids.retain(|id| known.contains(id)); !ids.is_empty() });
        self.order.retain(|h| !forget.contains(h));
        self.pruning_point = Some(pp);
        self.prune_cutoff = cutoff;
        self.recompute_chain_ok();
        Some(PruneReport { pruning_point: pp, forgotten: forget.len(), bodies_dropped: bodies })
    }

    /// chain_ok for every kept block: does its selected chain pass through the pruning point?
    pub fn recompute_chain_ok(&mut self) {
        self.chain_ok.clear();
        let Some(pp) = self.pruning_point else { for h in &self.order { self.chain_ok.insert(*h, true); } return };
        for h in self.order.clone() {
            let ok = h == pp || self.store.gd[&h].selected_parent.and_then(|sp| self.chain_ok.get(&sp).copied()).unwrap_or(false);
            self.chain_ok.insert(h, ok);
        }
    }

    /// Indexes of the transactions in the loaded block bodies (after reading a state snapshot).
    pub fn rebuild_body_indexes(&mut self) {
        self.tx_block.clear();
        self.lock_txs.clear();
        for h in self.order.clone() {
            if h == self.genesis_hash { continue; } // (never indexed, as in `new`)
            let Some(b) = self.blocks.get(&h).cloned() else { continue };
            for tx in &b.txs {
                let id = tx.id();
                if self.tx_block.contains_key(&id) { continue; }
                self.tx_block.insert(id, h);
                self.index_locks(tx, id);
            }
        }
    }
}
