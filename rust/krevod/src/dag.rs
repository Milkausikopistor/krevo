//! GHOSTDAG and difficulty adjustment (mirrors ghostdag.js and difficulty.js).

use crate::block::Header;
use crate::params::Params;
use crate::pow::{compact_to_target, target_to_compact};
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet, VecDeque};

pub type Hash = [u8; 32];

#[derive(Clone, Debug, Default)]
pub struct GhostdagData {
    pub selected_parent: Option<Hash>,
    pub mergeset_blues: Vec<Hash>,
    pub mergeset_reds: Vec<Hash>,
    pub blues_anticone_sizes: HashMap<Hash, usize>,
    pub blue_score: u64,
    pub blue_work: BigUint,
    pub daa_score: u64,
    /// mergeset without the selected parent, in increasing blue-work order
    pub mergeset_asc: Vec<Hash>,
}

#[derive(Default)]
pub struct DagStore {
    pub parents: HashMap<Hash, Vec<Hash>>,
    pub children: HashMap<Hash, Vec<Hash>>,
    pub height: HashMap<Hash, u64>,
    pub gd: HashMap<Hash, GhostdagData>,
    pub work: HashMap<Hash, BigUint>,
    anc_cache: std::cell::RefCell<HashMap<(Hash, Hash), bool>>,
}

impl DagStore {
    pub fn has(&self, h: &Hash) -> bool { self.gd.contains_key(h) }
    pub fn add(&mut self, h: Hash, parents: Vec<Hash>, gd: GhostdagData, work: BigUint) {
        for p in &parents { self.children.get_mut(p).unwrap().push(h); }
        let height = parents.iter().map(|p| self.height[p] + 1).max().unwrap_or(0);
        self.height.insert(h, height);
        self.parents.insert(h, parents);
        self.children.insert(h, vec![]);
        self.gd.insert(h, gd);
        self.work.insert(h, work);
    }
    /// a ∈ past(b) ∪ {b}?
    pub fn is_ancestor(&self, a: &Hash, b: &Hash) -> bool {
        if a == b { return true; }
        let (ha, hb) = (self.height[a], self.height[b]);
        if ha >= hb { return false; }
        if let Some(&c) = self.anc_cache.borrow().get(&(*a, *b)) { return c; }
        let mut seen: HashSet<Hash> = HashSet::from([*b]);
        let mut stack = vec![*b];
        let mut found = false;
        'outer: while let Some(x) = stack.pop() {
            for p in &self.parents[&x] {
                if p == a { found = true; break 'outer; }
                if !seen.contains(p) && self.height[p] > ha { seen.insert(*p); stack.push(*p); }
            }
        }
        let mut c = self.anc_cache.borrow_mut();
        if c.len() > 500_000 { c.clear(); }
        c.insert((*a, *b), found);
        found
    }
    /// Order by blue work and, on a tie, by hash.
    pub fn cmp(&self, a: &Hash, b: &Hash) -> std::cmp::Ordering {
        let (wa, wb) = (&self.gd[a].blue_work, &self.gd[b].blue_work);
        wa.cmp(wb).then_with(|| a.cmp(b))
    }
}

pub fn genesis_ghostdag() -> GhostdagData { GhostdagData::default() }

pub struct Ghostdag { pub k: usize }

impl Ghostdag {
    pub fn selected_parent(&self, s: &DagStore, parents: &[Hash]) -> Hash {
        let mut best = parents[0];
        for p in &parents[1..] { if s.cmp(p, &best).is_gt() { best = *p; } }
        best
    }

    fn ordered_mergeset_without_sp(&self, s: &DagStore, sp: &Hash, parents: &[Hash]) -> Vec<Hash> {
        let mut queue: VecDeque<Hash> = parents.iter().filter(|p| *p != sp).copied().collect();
        let mut mergeset: HashSet<Hash> = queue.iter().copied().collect();
        let mut sp_past: HashSet<Hash> = HashSet::new();
        while let Some(cur) = queue.pop_front() {
            for p in &s.parents[&cur] {
                if mergeset.contains(p) || sp_past.contains(p) { continue; }
                if s.is_ancestor(p, sp) { sp_past.insert(*p); continue; }
                mergeset.insert(*p);
                queue.push_back(*p);
            }
        }
        let mut v: Vec<Hash> = mergeset.into_iter().collect();
        v.sort_by(|a, b| s.cmp(a, b));
        v
    }

    fn blue_anticone_size(&self, s: &DagStore, block: &Hash, ctx: &GhostdagData) -> usize {
        if let Some(&x) = ctx.blues_anticone_sizes.get(block) { return x; }
        let mut cur = ctx.selected_parent.expect("block outside the context's blue set");
        loop {
            let d = &s.gd[&cur];
            if let Some(&x) = d.blues_anticone_sizes.get(block) { return x; }
            cur = d.selected_parent.expect("block outside the context's blue set");
        }
    }

    fn check_blue_candidate(&self, s: &DagStore, new: &GhostdagData, cand: &Hash) -> Option<(usize, Vec<(Hash, usize)>)> {
        if new.mergeset_blues.len() == self.k + 1 { return None; }
        let mut sizes: Vec<(Hash, usize)> = vec![];
        let mut cand_anticone = 0usize;
        let mut chain_hash: Option<Hash> = None;
        let mut chain_data: &GhostdagData = new;
        loop {
            if let Some(ch) = chain_hash { if s.is_ancestor(&ch, cand) { return Some((cand_anticone, sizes)); } }
            for b in &chain_data.mergeset_blues {
                if s.is_ancestor(b, cand) { continue; }
                let sz = self.blue_anticone_size(s, b, new);
                if let Some(e) = sizes.iter_mut().find(|e| e.0 == *b) { e.1 = sz; } else { sizes.push((*b, sz)); }
                cand_anticone += 1;
                if cand_anticone > self.k { return None; }
                if sz == self.k { return None; }
            }
            match chain_data.selected_parent {
                None => return Some((cand_anticone, sizes)),
                Some(h) => { chain_hash = Some(h); chain_data = &s.gd[&h]; }
            }
        }
    }

    pub fn run(&self, s: &DagStore, parents: &[Hash]) -> GhostdagData {
        let sp = self.selected_parent(s, parents);
        let sp_data = &s.gd[&sp];
        let mut data = GhostdagData {
            selected_parent: Some(sp),
            mergeset_blues: vec![sp],
            blues_anticone_sizes: HashMap::from([(sp, 0)]),
            ..Default::default()
        };
        let mergeset = self.ordered_mergeset_without_sp(s, &sp, parents);
        for cand in &mergeset {
            match self.check_blue_candidate(s, &data, cand) {
                Some((anticone, sizes)) => {
                    data.mergeset_blues.push(*cand);
                    data.blues_anticone_sizes.insert(*cand, anticone);
                    for (b, sz) in sizes { data.blues_anticone_sizes.insert(b, sz + 1); }
                }
                None => data.mergeset_reds.push(*cand),
            }
        }
        data.blue_score = sp_data.blue_score + data.mergeset_blues.len() as u64;
        let mut added = BigUint::from(0u32);
        for b in &data.mergeset_blues { added += &s.work[b]; }
        data.blue_work = &sp_data.blue_work + added;
        data.daa_score = sp_data.daa_score + (data.mergeset_blues.len() + data.mergeset_reds.len()) as u64;
        data.mergeset_asc = mergeset;
        data
    }
}

// ------------------------------------------------------------------ difficulty
pub fn daa_window(s: &DagStore, gd: &GhostdagData, size: usize) -> Vec<Hash> {
    let mut out = vec![];
    let mut cur = gd;
    while out.len() < size {
        let mut ms: Vec<Hash> = cur.mergeset_blues.iter().chain(&cur.mergeset_reds).copied().collect();
        ms.sort_by(|a, b| s.cmp(b, a));
        for h in ms { out.push(h); if out.len() >= size { break; } }
        match cur.selected_parent { Some(sp) => cur = &s.gd[&sp], None => break }
    }
    out
}

pub fn required_bits(p: &Params, s: &DagStore, headers: &HashMap<Hash, Header>, gd: &GhostdagData, pow_limit_bits: u32) -> u32 {
    let win = daa_window(s, gd, p.daa_window_size);
    if win.len() < p.daa_min_window { return pow_limit_bits; }
    let mut ts: Vec<u64> = win.iter().map(|h| headers[h].timestamp).collect();
    ts.sort_unstable();
    let cut = (win.len() as f64 * 0.05).floor() as usize;
    let (lo, hi) = (cut, win.len() - 1 - cut);
    let span = BigUint::from((ts[hi] as i64 - ts[lo] as i64).max(1) as u64);
    let expected = BigUint::from(((hi - lo) as u64) * p.target_time_ms);
    let mut sum = BigUint::from(0u32);
    for h in &win { sum += compact_to_target(headers[h].bits).unwrap_or_default(); }
    let avg = &sum / BigUint::from(win.len() as u64);
    let mut next = (&avg * span) / expected;
    let hi4 = &avg * 4u32;
    let lo4 = &avg / 4u32;
    if next > hi4 { next = hi4; }
    if next < lo4 { next = lo4; }
    let limit = compact_to_target(pow_limit_bits).unwrap();
    if next > limit { next = limit; }
    if next < BigUint::from(1u32) { next = BigUint::from(1u32); }
    target_to_compact(&next)
}

pub fn past_median_time(p: &Params, s: &DagStore, headers: &HashMap<Hash, Header>, gd: &GhostdagData) -> u64 {
    let win = daa_window(s, gd, p.past_median_time_window);
    let mut ts: Vec<u64> = win.iter().map(|h| headers[h].timestamp).collect();
    ts.sort_unstable();
    if ts.is_empty() { 0 } else { ts[ts.len() / 2] }
}
