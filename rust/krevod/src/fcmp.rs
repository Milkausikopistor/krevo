//! Verification of full-chain membership proofs (FCMP) and the curve tree.
//! Mirrors src/fcmp/{bp,circuit,tree,fcmp}.js — the circuit is rebuilt constraint by
//! constraint in the same order, because the weights z^q depend on each constraint's position.

use crate::crypto::{hash_point_for_key_image, hash_to_scalar, mul_g, Sc};
use crate::ct::{ct_msm, ct_mul};
use crate::curve::*;
use crate::field::*;
use crate::hash::H;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

// ====================================================================== generators
/// hashToPoint from src/fcmp/curve.js: H(domain, curve name, parts…, u32le(ctr)).
fn hash_to_point_named<C: Curve>(domain: &str, f: impl Fn(H) -> H) -> Pt<C> {
    Pt::<C>::hash_to_point(|ctr| f(H::new(domain).s(C::NAME)).b(&ctr.to_le_bytes()).d32()).normalize()
}
pub fn gen<C: Curve>(label: &str) -> Pt<C> { hash_to_point_named::<C>("fcmp/gen", |h| h.s(label)) }

pub struct Gens<C: Curve> { pub g: Vec<Pt<C>>, pub h: Vec<Pt<C>>, pub gb: Pt<C>, pub hb: Pt<C>, pub ub: Pt<C> }

pub trait FcmpCurve: Curve {
    fn gens_cell() -> &'static OnceLock<Mutex<Gens<Self>>>;
}
impl FcmpCurve for Secp {
    fn gens_cell() -> &'static OnceLock<Mutex<Gens<Self>>> { static C: OnceLock<Mutex<Gens<Secp>>> = OnceLock::new(); &C }
}
impl FcmpCurve for Secq {
    fn gens_cell() -> &'static OnceLock<Mutex<Gens<Self>>> { static C: OnceLock<Mutex<Gens<Secq>>> = OnceLock::new(); &C }
}

/// Generators of the circuit Bulletproofs (the first n G and H, plus g, h, u).
pub fn gens<C: FcmpCurve>(n: usize) -> (Vec<Pt<C>>, Vec<Pt<C>>, Pt<C>, Pt<C>, Pt<C>) {
    let cell = C::gens_cell().get_or_init(|| Mutex::new(Gens { g: vec![], h: vec![], gb: gen::<C>("bp/g"), hb: gen::<C>("bp/h"), ub: gen::<C>("bp/u") }));
    let mut gs = cell.lock().unwrap();
    while gs.g.len() < n {
        let i = (gs.g.len() as u32).to_le_bytes();
        let a = hash_to_point_named::<C>("fcmp/bp/G", |h| h.b(&i));
        let b = hash_to_point_named::<C>("fcmp/bp/H", |h| h.b(&i));
        gs.g.push(a);
        gs.h.push(b);
    }
    (gs.g[..n].to_vec(), gs.h[..n].to_vec(), gs.gb, gs.hb, gs.ub)
}
fn gen_at<C: FcmpCurve>(i: usize) -> Pt<C> { gens::<C>(i + 1).0[i] }
fn h_base<C: FcmpCurve>() -> Pt<C> { gens::<C>(0).3 }

// ====================================================================== transcript
pub enum Tx<'a> { N(u64), S(&'a str), B(&'a [u8]) }
pub struct Transcript([u8; 32]);
impl Transcript {
    pub fn new(label: &str) -> Self { Transcript(H::new("fcmp/transcript").s(label).d32()) }
    pub fn add(&mut self, label: &str, xs: &[Tx]) {
        let mut h = H::new("fcmp/transcript").b(&self.0).s(label);
        for x in xs { h = match x { Tx::N(n) => h.n(*n), Tx::S(s) => h.s(s), Tx::B(b) => h.b(b) }; }
        self.0 = h.d32();
    }
    pub fn ch<M: Modulus>(&mut self, label: &str) -> Fe<M> {
        for ctr in 0u64.. {
            let c = Fe::<M>::from_be_bytes_wide(&H::new("fcmp/challenge").b(&self.0).s(label).n(ctr).d64());
            if !c.is_zero() { self.add("ch", &[Tx::S(label), Tx::B(&c.to_be_bytes())]); return c; }
        }
        unreachable!()
    }
    pub fn ch128<M: Modulus>(&mut self, label: &str) -> Fe<M> {
        for ctr in 0u64.. {
            let d = H::new("fcmp/challenge128").b(&self.0).s(label).n(ctr).d32();
            let mut b = [0u8; 32];
            b[16..].copy_from_slice(&d[..16]);
            if b != [0u8; 32] {
                self.add("ch128", &[Tx::S(label), Tx::B(&b)]);
                return Fe::<M>::from_be_bytes_reduce(&b);
            }
        }
        unreachable!()
    }
}

// ====================================================================== circuit
const BIG: i64 = 1 << 24;
pub fn wire_l(i: usize) -> i64 { 3 * i as i64 }
pub fn wire_r(i: usize) -> i64 { 3 * i as i64 + 1 }
pub fn wire_o(i: usize) -> i64 { 3 * i as i64 + 2 }
pub fn vc_var(k: usize, pos: usize) -> i64 { -1 - (k as i64 * BIG + pos as i64) }

#[derive(Clone, Debug)]
pub struct Lc<M: Modulus> { pub t: BTreeMap<i64, Fe<M>>, pub c: Fe<M> }

impl<M: Modulus> Lc<M> {
    pub fn v(var: i64) -> Self { Lc { t: BTreeMap::from([(var, Fe::ONE)]), c: Fe::ZERO } }
    pub fn k(c: Fe<M>) -> Self { Lc { t: BTreeMap::new(), c } }
    pub fn add_scaled(&self, o: &Self, s: Fe<M>) -> Self {
        let mut r = self.clone();
        for (v, c) in &o.t {
            let nc = r.t.get(v).copied().unwrap_or(Fe::ZERO) + *c * s;
            if nc.is_zero() { r.t.remove(v); } else { r.t.insert(*v, nc); }
        }
        r.c = r.c + o.c * s;
        r
    }
    pub fn add(&self, o: &Self) -> Self { self.add_scaled(o, Fe::ONE) }
    pub fn sub(&self, o: &Self) -> Self { self.add_scaled(o, -Fe::ONE) }
    pub fn scale(&self, s: Fe<M>) -> Self {
        let mut r = Lc { t: BTreeMap::new(), c: self.c * s };
        if !s.is_zero() { for (v, c) in &self.t { r.t.insert(*v, *c * s); } }
        r
    }
    pub fn plus(&self, k: Fe<M>) -> Self { let mut r = self.clone(); r.c = r.c + k; r }
}

pub struct Gate<M: Modulus> { pub l: Lc<M>, pub r: Lc<M>, pub o: Lc<M> }

/// Constraint system. In prove mode (`prover`) it also keeps the gate values and the
/// openings of the vector commitments; in verify mode, only the structure.
pub struct Cs<M: Modulus> {
    pub n_gates: usize, pub cons: Vec<Lc<M>>, pub n_vcs: usize, pub n: usize,
    pub prover: bool, pub al: Vec<Fe<M>>, pub ar: Vec<Fe<M>>, pub ao: Vec<Fe<M>>,
    pub vc_vals: Vec<HashMap<usize, Fe<M>>>, pub gammas: Vec<Fe<M>>,
}

impl<M: Modulus> Cs<M> {
    pub fn new() -> Self { Self::with_prover(false) }
    pub fn with_prover(prover: bool) -> Self {
        Cs { n_gates: 0, cons: vec![], n_vcs: 0, n: 0, prover, al: vec![], ar: vec![], ao: vec![], vc_vals: vec![], gammas: vec![] }
    }
    /// Declares a vector commitment (with its opening, for the prover).
    pub fn add_vc_with(&mut self, entries: HashMap<usize, Fe<M>>, gamma: Fe<M>) -> usize {
        self.vc_vals.push(entries);
        self.gammas.push(gamma);
        self.n_vcs += 1;
        self.n_vcs - 1
    }
    pub fn add_vc(&mut self) -> usize { self.add_vc_with(HashMap::new(), Fe::ZERO) }
    pub fn vc(&self, k: usize, pos: usize) -> Lc<M> { Lc::v(vc_var(k, pos)) }
    pub fn value(&self, v: i64) -> Fe<M> {
        if v >= 0 {
            let (kind, i) = (v % 3, (v / 3) as usize);
            match kind { 0 => self.al[i], 1 => self.ar[i], _ => self.ao[i] }
        } else {
            let u = -1 - v;
            self.vc_vals[(u / BIG) as usize].get(&((u % BIG) as usize)).copied().unwrap_or(Fe::ZERO)
        }
    }
    pub fn eval(&self, lc: &Lc<M>) -> Fe<M> {
        let mut s = lc.c;
        for (v, c) in &lc.t { s = s + *c * self.value(*v); }
        s
    }
    /// Gate with free inputs (new witnesses); the values only matter to the prover.
    pub fn mul_free_v(&mut self, va: Fe<M>, vb: Fe<M>) -> Gate<M> {
        let i = self.n_gates;
        self.n_gates += 1;
        if self.prover { self.al.push(va); self.ar.push(vb); self.ao.push(va * vb); }
        Gate { l: Lc::v(wire_l(i)), r: Lc::v(wire_r(i)), o: Lc::v(wire_o(i)) }
    }
    pub fn mul_free(&mut self) -> Gate<M> { self.mul_free_v(Fe::ZERO, Fe::ZERO) }
    pub fn mul(&mut self, a: &Lc<M>, b: &Lc<M>) -> Gate<M> {
        let (va, vb) = if self.prover { (self.eval(a), self.eval(b)) } else { (Fe::ZERO, Fe::ZERO) };
        let g = self.mul_free_v(va, vb);
        self.constrain(g.l.sub(a));
        self.constrain(g.r.sub(b));
        g
    }
    pub fn constrain(&mut self, lc: Lc<M>) { if !lc.t.is_empty() || !lc.c.is_zero() { self.cons.push(lc); } }
    /// Checks (prover) that all constraints hold.
    pub fn check(&self) -> Result<(), String> {
        for (q, lc) in self.cons.iter().enumerate() { if !self.eval(lc).is_zero() { return Err(format!("constraint {q} not satisfied")); } }
        Ok(())
    }

    /// Weights with powers of z (z¹ … z^Q): wL, wR, wO, wC[k] (pos → weight), wc.
    pub fn weights(&self, z: Fe<M>, n: usize) -> (Vec<Fe<M>>, Vec<Fe<M>>, Vec<Fe<M>>, Vec<HashMap<usize, Fe<M>>>, Fe<M>) {
        let mut wl = vec![Fe::ZERO; n];
        let mut wr = vec![Fe::ZERO; n];
        let mut wo = vec![Fe::ZERO; n];
        let mut wcm: Vec<HashMap<usize, Fe<M>>> = (0..self.n_vcs).map(|_| HashMap::new()).collect();
        let mut zq = Fe::ONE;
        let mut wc = Fe::ZERO;
        for lc in &self.cons {
            zq = zq * z;
            wc = wc - zq * lc.c;
            for (v, c) in &lc.t {
                let w = zq * *c;
                if *v >= 0 {
                    let kind = v % 3;
                    let i = ((v - kind) / 3) as usize;
                    let arr = match kind { 0 => &mut wl, 1 => &mut wr, _ => &mut wo };
                    arr[i] = arr[i] + w;
                } else {
                    let u = -1 - v;
                    let (k, pos) = ((u / BIG) as usize, (u % BIG) as usize);
                    let e = wcm[k].entry(pos).or_insert(Fe::ZERO);
                    *e = *e + w;
                }
            }
        }
        (wl, wr, wo, wcm, wc)
    }
}

fn bit_of(r: &[u64; 4], i: usize) -> u64 { if i >= 256 { 0 } else { (r[i / 64] >> (i % 64)) & 1 } }

fn bits_gadget<M: Modulus>(cs: &mut Cs<M>, value: &[u64; 4], nbits: usize) -> Vec<Lc<M>> {
    (0..nbits).map(|i| {
        let b = Fe::from_u64(bit_of(value, i));
        let g = cs.mul_free_v(b, b);
        cs.constrain(g.r.sub(&g.l));
        cs.constrain(g.o.sub(&g.l));
        g.l
    }).collect()
}
fn windows_gadget<M: Modulus>(cs: &mut Cs<M>, bits: &[Lc<M>]) -> Vec<[Lc<M>; 7]> {
    bits.chunks(3).map(|b| {
        let p01 = cs.mul(&b[0], &b[1]).o;
        let p02 = cs.mul(&b[0], &b[2]).o;
        let p12 = cs.mul(&b[1], &b[2]).o;
        let p012 = cs.mul(&p01, &b[2]).o;
        [b[0].clone(), b[1].clone(), b[2].clone(), p01, p02, p12, p012]
    }).collect()
}
fn select8<M: Modulus>(win: &[Lc<M>; 7], t: &[Fe<M>; 8]) -> Lc<M> {
    let c = [
        t[0], t[1] - t[0], t[2] - t[0], t[4] - t[0],
        t[3] - t[2] - t[1] + t[0], t[5] - t[4] - t[1] + t[0], t[6] - t[4] - t[2] + t[0],
        t[7] - t[6] - t[5] - t[3] + t[4] + t[2] + t[1] - t[0],
    ];
    Lc::k(c[0]).add_scaled(&win[0], c[1]).add_scaled(&win[1], c[2]).add_scaled(&win[2], c[3])
        .add_scaled(&win[3], c[4]).add_scaled(&win[4], c[5]).add_scaled(&win[5], c[6]).add_scaled(&win[6], c[7])
}
struct LcPt<M: Modulus> { x: Lc<M>, y: Lc<M> }
type Val<M> = (Fe<M>, Fe<M>);
/// Incomplete addition A + S (3 gates). `vals` = values (A, S) for the prover; returns those of A + S.
fn add_gadget<M: Modulus>(cs: &mut Cs<M>, a: &LcPt<M>, s: &LcPt<M>, vals: Option<(Val<M>, Val<M>)>) -> (LcPt<M>, Option<Val<M>>) {
    let (lam, dx, v3) = match vals {
        Some(((xa, ya), (xs, ys))) => {
            let lam = (ys - ya) * (xs - xa).invert();
            let x3 = lam.square() - xa - xs;
            (lam, xs - xa, Some((x3, lam * (xa - x3) - ya)))
        }
        None => (Fe::ZERO, Fe::ZERO, None),
    };
    let g1 = cs.mul_free_v(lam, dx);
    cs.constrain(g1.r.sub(&s.x.sub(&a.x)));
    cs.constrain(g1.o.sub(&s.y.sub(&a.y)));
    let g2 = cs.mul(&g1.l, &g1.l);
    let two = Fe::<M>::from_u64(2);
    let three = Fe::<M>::from_u64(3);
    let x3 = g2.o.add(&g1.r).sub(&s.x.scale(two));
    let g3 = cs.mul(&g1.l, &s.x.scale(three).sub(&g1.r.scale(two)).sub(&g2.o));
    let y3 = g3.o.sub(&s.y).add(&g1.o);
    (LcPt { x: x3, y: y3 }, v3)
}

pub const W: usize = 86;
pub struct Table<M: Modulus> { tbl: Vec<[(Fe<M>, Fe<M>); 8]>, offset: (Fe<M>, Fe<M>) }

/// T_j[d] = d·8^j·B + 2^j·Ω ; offset = (2^W − 1)·Ω.  (PC: the points' curve; field = circuit.)
fn fixed_base_table<PC: Curve>(b: &Pt<PC>, omega: &Pt<PC>) -> Table<PC::F> {
    let mut js = Vec::with_capacity(8 * W);
    let (mut bj, mut oj) = (*b, *omega);
    for _ in 0..W {
        let mut acc = oj;
        js.push(acc);
        for _ in 1..8 { acc = acc.add(&bj); js.push(acc); }
        bj = bj.dbl().dbl().dbl();
        oj = oj.dbl();
    }
    let aff = batch_affine(&js);
    let tbl = (0..W).map(|j| {
        let mut row = [(Fe::ZERO, Fe::ZERO); 8];
        for d in 0..8 { row[d] = aff[8 * j + d].expect("degenerate fixed-base table"); }
        row
    }).collect();
    // (2^W − 1)·Ω
    let mut off = Pt::<PC>::inf();
    let mut p = *omega;
    for _ in 0..W { off = off.add(&p); p = p.dbl(); }
    Table { tbl, offset: off.affine().unwrap() }
}

/// Window table lookup without access that depends on the secret digit.
fn lookup8<M: Modulus>(row: &[(Fe<M>, Fe<M>); 8], d: usize) -> (Fe<M>, Fe<M>) {
    let mut r = (Fe::ZERO, Fe::ZERO);
    for (i, e) in row.iter().enumerate() {
        let m = ct_mask(nonzero_bit((i ^ d) as u64) ^ 1);
        r = (Fe::select(&r.0, &e.0, m), Fe::select(&r.1, &e.1, m));
    }
    r
}

/// C = Ĉ − r·B with the bits of r in the circuit. `r` only matters to the prover (values).
fn unblind_gadget<PC: Curve>(cs: &mut Cs<PC::F>, wins: &[[Lc<PC::F>; 7]], table: &Table<PC::F>, chat: &Pt<PC>, r: &[u64; 4]) -> Result<(LcPt<PC::F>, Option<Val<PC::F>>), String> {
    let col = |j: usize, which: usize| -> [Fe<PC::F>; 8] { let mut r = [Fe::ZERO; 8]; for d in 0..8 { r[d] = if which == 0 { table.tbl[j][d].0 } else { table.tbl[j][d].1 }; } r };
    let pv = cs.prover;
    let dig = |j: usize| -> usize { (bit_of(r, 3 * j) + 2 * bit_of(r, 3 * j + 1) + 4 * bit_of(r, 3 * j + 2)) as usize };
    let mut a = LcPt { x: select8(&wins[0], &col(0, 0)), y: select8(&wins[0], &col(0, 1)) };
    let mut va = if pv { Some(lookup8(&table.tbl[0], dig(0))) } else { None };
    for j in 1..W {
        let s = LcPt { x: select8(&wins[j], &col(j, 0)), y: select8(&wins[j], &col(j, 1)) };
        let vs = if pv { lookup8(&table.tbl[j], dig(j)) } else { (Fe::ZERO, Fe::ZERO) };
        let (na, nv) = add_gadget(cs, &a, &s, va.map(|x| (x, vs)));
        a = na;
        va = nv;
    }
    let k = chat.add_aff(&table.offset.0, &table.offset.1).affine().ok_or("degenerate public point")?;
    let kl = LcPt { x: Lc::k(k.0), y: Lc::k(k.1) };
    let neg_a = LcPt { x: a.x.clone(), y: a.y.scale(-Fe::ONE) };
    let vneg = va.map(|(x, y)| (x, -y));
    let gi = match vneg {
        Some((xn, _)) => { let d = xn - k.0; if d.is_zero() { return Err("exceptional addition".into()); } cs.mul_free_v(d.invert(), d) }
        None => cs.mul_free(),
    };
    cs.constrain(gi.r.sub(&neg_a.x.sub(&kl.x)));
    cs.constrain(gi.o.plus(-Fe::ONE));
    Ok(add_gadget(cs, &kl, &neg_a, vneg.map(|v| (k, v))))
}
fn permissible_gadget<M: Modulus>(cs: &mut Cs<M>, y: &Lc<M>, yv: Option<Fe<M>>) -> Result<(), String> {
    let w = match yv { Some(y) => (y + Fe::ONE).sqrt_ct().ok_or("point not permissible")?, None => Fe::ZERO };
    let g = cs.mul_free_v(w, w);
    cs.constrain(g.r.sub(&g.l));
    cs.constrain(g.o.sub(&y.plus(Fe::ONE)));
    Ok(())
}
fn select_gadget<M: Modulus>(cs: &mut Cs<M>, entries: &[Lc<M>], x: &Lc<M>) {
    if entries.len() == 1 { cs.constrain(entries[0].sub(x)); return; }
    let mut acc = cs.mul(&entries[0].sub(x), &entries[1].sub(x)).o;
    for e in &entries[2..] { acc = cs.mul(&acc, &e.sub(x)).o; }
    cs.constrain(acc);
}

// ====================================================================== tree
pub const LEAF_WIDTH: usize = 6;
pub const LEAF_BLIND: usize = 6;

#[derive(Clone, Copy)]
pub struct Segment { pub odd: bool, pub off: usize, pub blind: usize }
pub fn segment(l: usize, b: usize) -> Segment {
    if l % 2 == 1 { let o = ((l - 1) / 2) * (b + 1); Segment { odd: true, off: o, blind: o + b } }
    else { let o = LEAF_BLIND + 1 + ((l - 2) / 2) * (b + 1); Segment { odd: false, off: o, blind: o + b } }
}
pub fn depth_for(n: u64, b: usize) -> u32 {
    let (mut d, mut cap) = (1u32, b as u128);
    while cap < n as u128 { d += 1; cap *= b as u128; }
    d
}
pub fn is_permissible<C: Curve>(p: &Pt<C>) -> bool {
    match p.affine() {
        None => false,
        Some((_, y)) => (y + Fe::ONE).is_square() && !(Fe::ONE - y).is_square(),
    }
}
pub fn make_permissible<C: Curve>(raw: &Pt<C>, h: &Pt<C>) -> (u64, Pt<C>) {
    let mut pt = *raw;
    for k in 0..4096u64 {
        if is_permissible(&pt) { return (k, pt.normalize()); }
        pt = pt.add(h);
    }
    panic!("no permissible offset");
}

fn leaf_tables() -> &'static Vec<FixedBase<Secq>> {
    static T: OnceLock<Vec<FixedBase<Secq>>> = OnceLock::new();
    T.get_or_init(|| gens::<Secq>(LEAF_BLIND + 1).0[..LEAF_WIDTH].iter().map(FixedBase::new).collect())
}
/// Leaf of an output: coordinates (P, I = Hp(P), C), permissible point and offset k.
pub struct LeafData { pub p: P1, pub i: P1, pub c: P1, pub coords: [Fe<ModP>; 6], pub k: u64, pub point: P2, pub x: [u64; 4] }

pub fn leaf_data(p: &[u8; 33], c: &[u8; 33]) -> Option<LeafData> {
    let pp = P1::from_bytes(p)?;
    let cc = P1::from_bytes(c)?;
    let ii = hash_point_for_key_image(&pp);
    let (px, py) = pp.affine()?;
    let (ix, iy) = ii.affine()?;
    let (cx, cy) = cc.affine()?;
    let coords = [px, py, ix, iy, cx, cy];
    let t = leaf_tables();
    let mut raw = P2::inf();
    for (i, v) in coords.iter().enumerate() { raw = raw.add(&t[i].mul_limbs(&v.to_limbs())); }
    let (k, pt) = make_permissible(&raw, &h_base::<Secq>());
    let x = pt.affine()?.0.to_limbs();
    Some(LeafData { p: pp, i: ii, c: cc, coords, k, point: pt, x })
}

/// x of an output's permissible leaf (P, C as bytes), as an integer (a scalar of E1).
pub fn leaf_x(p: &[u8; 33], c: &[u8; 33]) -> [u64; 4] { leaf_data(p, c).expect("invalid private output").x }

#[derive(Clone)]
pub enum NodePt { E1(P1), E2(P2) }
#[derive(Clone)]
pub struct NodeRec { pub entries: Vec<[u64; 4]>, pub raw: NodePt, pub x: [u64; 4] }
#[derive(Clone)]
pub struct Root { pub depth: u32, pub point: NodePt, pub count: usize }

/// Tree over the private outputs in global order (the leaves come from outside, on demand).
pub struct CurveTree {
    pub branch: usize,
    cache: HashMap<(u32, u64), NodeRec>,
    max_idx: HashMap<u32, u64>,
    roots: HashMap<u64, Root>,
    leaf_memo: HashMap<[u8; 32], [u64; 4]>,
}

impl CurveTree {
    pub fn new(branch: usize) -> Self { CurveTree { branch, cache: HashMap::new(), max_idx: HashMap::new(), roots: HashMap::new(), leaf_memo: HashMap::new() } }

    fn leaf(&mut self, leaf: &dyn Fn(u64) -> ([u8; 32], [u8; 33], [u8; 33]), i: u64) -> [u64; 4] {
        let (key, p, c) = leaf(i);
        if let Some(x) = self.leaf_memo.get(&key) { return *x; }
        let x = leaf_x(&p, &c);
        if self.leaf_memo.len() > 2_000_000 { self.leaf_memo.clear(); }
        self.leaf_memo.insert(key, x);
        x
    }

    pub fn node_at(&mut self, leaf: &dyn Fn(u64) -> ([u8; 32], [u8; 33], [u8; 33]), level: u32, idx: u64, n: u64) -> Option<NodeRec> {
        let b = self.branch as u64;
        let span = b.pow(level);
        let start = idx * span;
        if start >= n { return None; }
        let complete = start + span <= n;
        if complete { if let Some(c) = self.cache.get(&(level, idx)) { return Some(c.clone()); } }
        let mut entries = vec![];
        for j in 0..b {
            if level == 1 {
                if start + j >= n { break; }
                entries.push(self.leaf(leaf, start + j));
            } else {
                match self.node_at(leaf, level - 1, idx * b + j, n) { Some(ch) => entries.push(ch.x), None => break }
            }
        }
        let seg = segment(level as usize, self.branch);
        let rec = if seg.odd {
            let (g, _, _, hb, _) = gens::<Secp>(seg.blind + 1);
            let ks: Vec<Fe<ModN>> = entries.iter().map(|e| Fe::from_limbs(*e)).collect();
            let raw = msm(&ks, &g[seg.off..seg.off + entries.len()]);
            let (_, pt) = make_permissible(&raw, &hb);
            NodeRec { x: pt.affine().unwrap().0.to_limbs(), entries, raw: NodePt::E1(raw) }
        } else {
            let (g, _, _, hb, _) = gens::<Secq>(seg.blind + 1);
            let ks: Vec<Fe<ModP>> = entries.iter().map(|e| Fe::from_limbs(*e)).collect();
            let raw = msm(&ks, &g[seg.off..seg.off + entries.len()]);
            let (_, pt) = make_permissible(&raw, &hb);
            NodeRec { x: pt.affine().unwrap().0.to_limbs(), entries, raw: NodePt::E2(raw) }
        };
        if complete {
            self.cache.insert((level, idx), rec.clone());
            let m = self.max_idx.entry(level).or_insert(idx);
            if *m < idx { *m = idx; }
        }
        Some(rec)
    }

    pub fn root(&mut self, leaf: &dyn Fn(u64) -> ([u8; 32], [u8; 33], [u8; 33]), n: u64) -> Root {
        if let Some(r) = self.roots.get(&n) { return r.clone(); }
        let depth = depth_for(n, self.branch);
        let rec = self.node_at(leaf, depth, 0, n).expect("root");
        let r = Root { depth, point: rec.raw, count: rec.entries.len() };
        if self.roots.len() > 10_000 { self.roots.clear(); }
        self.roots.insert(n, r.clone());
        r
    }

    /// Entries of each node on the path of chunk `chunk`, from level 1 up to the root.
    pub fn path_for_chunk(&mut self, leaf: &dyn Fn(u64) -> ([u8; 32], [u8; 33], [u8; 33]), n: u64, chunk: u64) -> Option<Vec<(u32, u64, Vec<[u64; 4]>)>> {
        let d = depth_for(n, self.branch);
        let mut out = vec![];
        let mut idx = chunk;
        for l in 1..=d {
            let rec = self.node_at(leaf, l, idx, n)?;
            out.push((l, idx, rec.entries));
            idx /= self.branch as u64;
        }
        Some(out)
    }

    pub fn truncate(&mut self, n: u64) {
        let b = self.branch as u64;
        for (l, max) in self.max_idx.iter_mut() {
            let span = b.pow(*l);
            let from = n / span;
            let mut idx = from;
            while idx <= *max { self.cache.remove(&(*l, idx)); idx += 1; }
            *max = if from == 0 { 0 } else { (*max).min(from - 1) };
        }
        self.roots.retain(|k, _| *k <= n);
    }
}

// ====================================================================== Bulletproofs (verification)
pub fn t_powers(k: usize) -> (Vec<i64>, Vec<i64>, Vec<i64>) {
    let mut lp = vec![1i64, 2, 3];
    let mut rp = vec![0i64, 1, 3];
    for j in 0..k as i64 { lp.push(4 + j); rp.push(-2 - j); }
    let mut s: Vec<i64> = vec![];
    for i in &lp { for j in &rp { if i + j != 2 && !s.contains(&(i + j)) { s.push(i + j); } } }
    s.sort();
    (lp, rp, s)
}
pub fn bp_proof_size(n: usize, k: usize) -> usize { (3 + t_powers(k).2.len() + 2 * n.trailing_zeros() as usize) * 33 + 5 * 32 }

pub struct BpProof<C: Curve> { ai: Pt<C>, ao: Pt<C>, s: Pt<C>, t: Vec<Pt<C>>, taux: Scalar<C>, mu: Scalar<C>, that: Scalar<C>, l: Vec<Pt<C>>, r: Vec<Pt<C>>, a: Scalar<C>, b: Scalar<C> }

fn decode_bp<C: Curve>(buf: &[u8], n: usize, k: usize) -> Option<BpProof<C>> {
    if buf.len() != bp_proof_size(n, k) { return None; }
    let mut o = 0usize;
    let pt = |o: &mut usize| -> Option<Pt<C>> { let p = Pt::<C>::from_bytes(&buf[*o..*o + 33]); *o += 33; p };
    let sc = |o: &mut usize| -> Option<Scalar<C>> { let v = Fe::from_be_bytes(&buf[*o..*o + 32]); *o += 32; v };
    let ai = pt(&mut o)?; let ao = pt(&mut o)?; let s = pt(&mut o)?;
    let mut t = vec![];
    for _ in 0..t_powers(k).2.len() { t.push(pt(&mut o)?); }
    let taux = sc(&mut o)?; let mu = sc(&mut o)?; let that = sc(&mut o)?;
    let (mut l, mut r) = (vec![], vec![]);
    for _ in 0..n.trailing_zeros() { l.push(pt(&mut o)?); r.push(pt(&mut o)?); }
    let a = sc(&mut o)?; let b = sc(&mut o)?;
    Some(BpProof { ai, ao, s, t, taux, mu, that, l, r, a, b })
}

pub struct BpBatch<C: Curve> { n: usize, g: Vec<Scalar<C>>, h: Vec<Scalar<C>>, gb: Scalar<C>, hb: Scalar<C>, ub: Scalar<C>, extra: Vec<(Scalar<C>, Pt<C>)> }

impl<C: FcmpCurve> BpBatch<C> {
    pub fn new() -> Self { BpBatch { n: 0, g: vec![], h: vec![], gb: Fe::ZERO, hb: Fe::ZERO, ub: Fe::ZERO, extra: vec![] } }
    fn grow(&mut self, n: usize) { while self.g.len() < n { self.g.push(Fe::ZERO); self.h.push(Fe::ZERO); } self.n = self.n.max(n); }
    pub fn check(&self) -> bool {
        let (g, h, gb, hb, ub) = gens::<C>(self.n);
        let mut ks: Vec<Scalar<C>> = self.g.clone();
        ks.extend(&self.h);
        ks.extend([self.gb, self.hb, self.ub]);
        let mut ps = g;
        ps.extend(h);
        ps.extend([gb, hb, ub]);
        for (k, p) in &self.extra { ks.push(*k); ps.push(*p); }
        msm(&ks, &ps).is_inf()
    }
}

fn xpow<M: Modulus>(x: Fe<M>, e: i64) -> Fe<M> {
    let base = if e >= 0 { x } else { x.invert() };
    base.pow_limbs(&[e.unsigned_abs(), 0, 0, 0])
}

/// Adds a proof's equations to the batch (cs = the circuit in verify mode).
fn bp_verify_into<C: FcmpCurve>(batch: &mut BpBatch<C>, cs: &Cs<C::S>, vcs: &[Pt<C>], pf: &BpProof<C>, tr: &mut Transcript) -> Result<(), String> {
    let n = cs.n;
    let rounds = n.trailing_zeros() as usize;
    let k = vcs.len();
    let (_, _, tpow) = t_powers(k);
    if pf.t.len() != tpow.len() || pf.l.len() != rounds { return Err("bp: proof with the wrong size".into()); }
    tr.add("AI", &[Tx::B(&pf.ai.to_bytes())]);
    tr.add("AO", &[Tx::B(&pf.ao.to_bytes())]);
    tr.add("S", &[Tx::B(&pf.s.to_bytes())]);
    let y: Scalar<C> = tr.ch("y");
    let z: Scalar<C> = tr.ch("z");
    for (i, e) in tpow.iter().enumerate() { tr.add("T", &[Tx::S(&e.to_string()), Tx::B(&pf.t[i].to_bytes())]); }
    let x: Scalar<C> = tr.ch("x");
    tr.add("taux", &[Tx::B(&pf.taux.to_be_bytes())]);
    tr.add("mu", &[Tx::B(&pf.mu.to_be_bytes())]);
    tr.add("that", &[Tx::B(&pf.that.to_be_bytes())]);
    let w: Scalar<C> = tr.ch("w");
    let mut us = vec![];
    for j in 0..rounds {
        tr.add("L", &[Tx::B(&pf.l[j].to_bytes())]);
        tr.add("R", &[Tx::B(&pf.r[j].to_bytes())]);
        us.push(tr.ch128::<C::S>("u"));
    }
    let (wl, wr, wo, wcm, wc) = cs.weights(z, n);
    let yinv = y.invert();
    let mut yp = vec![Fe::ONE; n];
    let mut yi = vec![Fe::ONE; n];
    for i in 1..n { yp[i] = yp[i - 1] * y; yi[i] = yi[i - 1] * yinv; }
    let mut delta = Fe::ZERO;
    for i in 0..n { if !wr[i].is_zero() && !wl[i].is_zero() { delta = delta + yi[i] * wr[i] * wl[i]; } }
    // batch weights: randomness + hash of the proof itself (still unpredictable with a broken generator)
    let c1 = Fe::random() + tr.ch::<C::S>("batch/c1");
    let c2 = Fe::random() + tr.ch::<C::S>("batch/c2");
    batch.grow(n);
    let x2 = xpow(x, 2);
    batch.gb = batch.gb + c1 * (pf.that - x2 * (wc + delta));
    batch.hb = batch.hb + c1 * pf.taux;
    for (i, e) in tpow.iter().enumerate() { batch.extra.push((-(c1 * xpow(x, *e)), pf.t[i])); }
    let mut up = Fe::ONE;
    for u in &us { up = up * *u; }
    let k2 = c2 * up;
    batch.extra.push((k2 * x, pf.ai));
    batch.extra.push((k2 * x2, pf.ao));
    batch.extra.push((k2 * xpow(x, 3), pf.s));
    for (j, p) in vcs.iter().enumerate() { batch.extra.push((k2 * xpow(x, 4 + j as i64), *p)); }
    batch.hb = batch.hb - k2 * pf.mu;
    batch.ub = batch.ub + c2 * (up * pf.that - pf.a * pf.b) * w;
    let mut suffix = Fe::ONE;
    for j in (0..rounds).rev() {
        batch.extra.push((c2 * suffix * us[j].square(), pf.l[j]));
        batch.extra.push((c2 * suffix, pf.r[j]));
        suffix = suffix * us[j];
    }
    let mut s = vec![Fe::ONE];
    let mut sp = vec![Fe::ONE];
    for j in (0..rounds).rev() {
        let s2: Vec<Scalar<C>> = s.iter().map(|v| *v * us[j]).collect();
        s.extend(s2);
        let mut sp2: Vec<Scalar<C>> = sp.iter().map(|v| *v * us[j]).collect();
        sp2.extend(sp.iter().copied());
        sp = sp2;
    }
    let xneg: Vec<Scalar<C>> = (0..k).map(|j| xpow(x, -2 - j as i64)).collect();
    for i in 0..n {
        let gi = k2 * x * yi[i] * wr[i] - c2 * pf.a * s[i];
        let mut hr = wo[i] - yp[i] + x * wl[i];
        for j in 0..k { if let Some(wk) = wcm[j].get(&i) { hr = hr + xneg[j] * *wk; } }
        let hi = k2 * yi[i] * hr - c2 * pf.b * sp[i] * yi[i];
        batch.g[i] = batch.g[i] + gi;
        batch.h[i] = batch.h[i] + hi;
    }
    Ok(())
}

// ====================================================================== FCMP
const SCALAR_GATES: usize = 7 * W;
const UNBLIND_GATES: usize = 3 * W + 1;

pub struct Sizes { pub n1: usize, pub n2: usize, pub k1: usize, pub k2: usize }
pub fn circuit_sizes(d: u32, b: usize) -> Sizes {
    let d = d as usize;
    let sel = UNBLIND_GATES + 1 + (b - 1);
    let g2 = SCALAR_GATES + 3 * UNBLIND_GATES + (d / 2) * sel;
    let g1 = SCALAR_GATES + (1 + (d - 1) / 2) * sel;
    let (mut p1, mut p2) = (0usize, LEAF_BLIND);
    for l in 1..=d { let s = segment(l, b); if l % 2 == 1 { p1 = p1.max(s.blind); } else { p2 = p2.max(s.blind); } }
    Sizes { n1: g1.max(p1 + 1).next_power_of_two(), n2: g2.max(p2 + 1).next_power_of_two(), k1: d.div_ceil(2), k2: 1 + d / 2 }
}
pub fn fcmp_proof_size(n: u64, b: usize) -> usize {
    let d = depth_for(n, b);
    let s = circuit_sizes(d, b);
    4 * 33 + (d as usize - 1) * 33 + bp_proof_size(s.n1, s.k1) + bp_proof_size(s.n2, s.k2) + 7 * 32
}

struct Bases { t: P1, ti: P1, tc: P1, o1: P1, o2: P2 }
fn bases() -> &'static Bases {
    static B: OnceLock<Bases> = OnceLock::new();
    B.get_or_init(|| Bases { t: gen("fcmp/T"), ti: gen("fcmp/TI"), tc: gen("fcmp/TC"), o1: gen("fcmp/Omega"), o2: gen("fcmp/Omega") })
}
fn table1(base: &P1) -> std::sync::Arc<Table<ModP>> {
    static T: OnceLock<Mutex<HashMap<[u8; 33], std::sync::Arc<Table<ModP>>>>> = OnceLock::new();
    let m = T.get_or_init(|| Mutex::new(HashMap::new()));
    let key = base.to_bytes();
    if let Some(t) = m.lock().unwrap().get(&key) { return t.clone(); }
    let t = std::sync::Arc::new(fixed_base_table(base, &bases().o1));
    m.lock().unwrap().insert(key, t.clone());
    t
}
fn table2(base: &P2) -> std::sync::Arc<Table<ModN>> {
    static T: OnceLock<Mutex<HashMap<[u8; 33], std::sync::Arc<Table<ModN>>>>> = OnceLock::new();
    let m = T.get_or_init(|| Mutex::new(HashMap::new()));
    let key = base.to_bytes();
    if let Some(t) = m.lock().unwrap().get(&key) { return t.clone(); }
    let t = std::sync::Arc::new(fixed_base_table(base, &bases().o2));
    m.lock().unwrap().insert(key, t.clone());
    t
}

struct Statement { b: usize, n: u64, d: u32, root: NodePt, root_count: usize, phat: P1, ihat: P1, chat: P1, lhat: P2, hats1: HashMap<u32, P1>, hats2: HashMap<u32, P2> }

fn transcript_for(label: &str, st: &Statement) -> Transcript {
    let mut tr = Transcript::new(&format!("fcmp/{label}"));
    let root = match &st.root { NodePt::E1(p) => p.to_bytes(), NodePt::E2(p) => p.to_bytes() };
    tr.add("st", &[Tx::N(st.b as u64), Tx::N(st.n), Tx::N(st.d as u64), Tx::B(&root), Tx::N(st.root_count as u64),
        Tx::B(&st.phat.to_bytes()), Tx::B(&st.ihat.to_bytes()), Tx::B(&st.chat.to_bytes()), Tx::B(&st.lhat.to_bytes())]);
    for l in 1..st.d {
        let h = if l % 2 == 1 { st.hats1[&l].to_bytes() } else { st.hats2[&l].to_bytes() };
        tr.add("hat", &[Tx::N(l as u64), Tx::B(&h)]);
    }
    tr
}

fn select_in_parent<M: Modulus>(cs: &mut Cs<M>, st: &Statement, parent_level: u32, vc_idx: usize, x: &Lc<M>) {
    let seg = segment(parent_level as usize, st.b);
    let count = if parent_level == st.d { st.root_count } else { st.b };
    let entries: Vec<Lc<M>> = (0..count).map(|j| cs.vc(vc_idx, seg.off + j)).collect();
    select_gadget(cs, &entries, x);
}

/// Prover's witness: blindings, leaf coordinates and the entries of each node on the path.
pub struct Witness { pub r1: Fe<ModN>, pub r2: Fe<ModP>, pub coords: [Fe<ModP>; 6], pub k_l: u64, pub levels: HashMap<u32, (Vec<[u64; 4]>, u64)> }

/// Vector commitment of a node on the path (with the opening, if there is a witness).
fn add_node_vc<M: Modulus>(cs: &mut Cs<M>, st: &Statement, w: Option<&Witness>, l: u32) -> usize {
    let Some(w) = w else { return cs.add_vc() };
    let seg = segment(l as usize, st.b);
    let (entries, k) = &w.levels[&l];
    let mut e: HashMap<usize, Fe<M>> = entries.iter().enumerate().map(|(j, v)| (seg.off + j, Fe::from_limbs(*v))).collect();
    if l == st.d { return cs.add_vc_with(e, Fe::ZERO); }
    let r = if l % 2 == 1 { w.r1.to_limbs() } else { w.r2.to_limbs() };
    e.insert(seg.blind, Fe::from_limbs(r));
    cs.add_vc_with(e, Fe::from_u64(*k))
}

/// Circuit over E2 (field F_p): points of E1 are unblinded with r1. Returns (cs, commitments).
fn build_e2(st: &Statement, w: Option<&Witness>) -> Result<(Cs<ModP>, Vec<P2>), String> {
    let bs = bases();
    let mut cs = Cs::<ModP>::with_prover(w.is_some());
    let mut vcs = vec![];
    match w {
        Some(w) => {
            let mut e: HashMap<usize, Fe<ModP>> = w.coords.iter().enumerate().map(|(i, v)| (i, *v)).collect();
            e.insert(LEAF_BLIND, w.r2);
            cs.add_vc_with(e, Fe::from_u64(w.k_l));
        }
        None => { cs.add_vc(); }
    }
    vcs.push(st.lhat);
    let mut vc_of = HashMap::new();
    let mut l = 2;
    while l <= st.d {
        let p = if l == st.d { match &st.root { NodePt::E2(p) => *p, _ => return Err("root on the wrong curve".into()) } } else { st.hats2[&l] };
        vc_of.insert(l, add_node_vc(&mut cs, st, w, l)); vcs.push(p);
        l += 2;
    }
    let r = w.map(|w| w.r1.to_limbs()).unwrap_or([0; 4]);
    let bits = bits_gadget(&mut cs, &r, 3 * W);
    let wins = windows_gadget(&mut cs, &bits);
    for (pt, base, i) in [(st.phat, bs.t, 0usize), (st.ihat, bs.ti, 2), (st.chat, bs.tc, 4)] {
        let (res, _) = unblind_gadget::<Secp>(&mut cs, &wins, &table1(&base), &pt, &r)?;
        cs.constrain(res.x.sub(&cs.vc(0, i)));
        cs.constrain(res.y.sub(&cs.vc(0, i + 1)));
    }
    let mut l = 1;
    while l < st.d {
        let seg = segment(l as usize, st.b);
        let base = gen_at::<Secp>(seg.blind);
        let (res, v) = unblind_gadget::<Secp>(&mut cs, &wins, &table1(&base), &st.hats1[&l], &r)?;
        permissible_gadget(&mut cs, &res.y, v.map(|x| x.1))?;
        select_in_parent(&mut cs, st, l + 1, vc_of[&(l + 1)], &res.x);
        l += 2;
    }
    Ok((cs, vcs))
}

/// Circuit over E1 (field F_n): the leaf and the E2 nodes are unblinded with r2.
fn build_e1(st: &Statement, w: Option<&Witness>) -> Result<(Cs<ModN>, Vec<P1>), String> {
    let mut cs = Cs::<ModN>::with_prover(w.is_some());
    let mut vcs = vec![];
    let mut vc_of = HashMap::new();
    let mut l = 1;
    while l <= st.d {
        let p = if l == st.d { match &st.root { NodePt::E1(p) => *p, _ => return Err("root on the wrong curve".into()) } } else { st.hats1[&l] };
        vc_of.insert(l, add_node_vc(&mut cs, st, w, l)); vcs.push(p);
        l += 2;
    }
    let r = w.map(|w| w.r2.to_limbs()).unwrap_or([0; 4]);
    let bits = bits_gadget(&mut cs, &r, 3 * W);
    let wins = windows_gadget(&mut cs, &bits);
    let leaf_base = gen_at::<Secq>(LEAF_BLIND);
    let (res, v) = unblind_gadget::<Secq>(&mut cs, &wins, &table2(&leaf_base), &st.lhat, &r)?;
    permissible_gadget(&mut cs, &res.y, v.map(|x| x.1))?;
    select_in_parent(&mut cs, st, 1, vc_of[&1], &res.x);
    let mut l = 2;
    while l < st.d {
        let seg = segment(l as usize, st.b);
        let base = gen_at::<Secq>(seg.blind);
        let (res, v) = unblind_gadget::<Secq>(&mut cs, &wins, &table2(&base), &st.hats2[&l], &r)?;
        permissible_gadget(&mut cs, &res.y, v.map(|x| x.1))?;
        select_in_parent(&mut cs, st, l + 1, vc_of[&(l + 1)], &res.x);
        l += 2;
    }
    Ok((cs, vcs))
}

fn gsp_verify(ctx: &[u8; 32], phat: &P1, ihat: &P1, d: &P1, ki: &P1, buf: &[u8]) -> bool {
    let bs = bases();
    let mut v = vec![];
    for i in 0..7 { match Sc::from_be_bytes(&buf[32 * i..32 * i + 32]) { Some(x) => v.push(x), None => return false } }
    let (e, sp, st, sq, sy, sa, sb) = (v[0], v[1], v[2], v[3], v[4], v[5], v[6]);
    let r1 = mul_g(&sp).add(&bs.t.mul(&st)).add(&phat.mul(&-e));
    let r2 = phat.mul(&sp).add(&mul_g(&-sq)).add(&bs.t.mul(&-sy));
    let r3 = ihat.mul(&sp).add(&bs.ti.mul(&-sy)).add(&ki.mul(&-e));
    let r4 = mul_g(&sa).add(&bs.tc.mul(&sb)).add(&d.mul(&-e));
    hash_to_scalar(H::new("fcmp/gsp").b(ctx).b(&r1.to_bytes()).b(&r2.to_bytes()).b(&r3.to_bytes()).b(&r4.to_bytes())) == e
}

pub struct FcmpBatch { pub e1: BpBatch<Secp>, pub e2: BpBatch<Secq> }
impl FcmpBatch {
    pub fn new() -> Self { FcmpBatch { e1: BpBatch::new(), e2: BpBatch::new() } }
    pub fn check(&self) -> bool { self.e1.check() && self.e2.check() }
}

/// Checks an input's proof and adds the Bulletproofs equations to the batch.
pub fn fcmp_verify_into(batch: &mut FcmpBatch, branch: usize, n: u64, root: &Root, proof: &[u8], key_image: &P1, pseudo: &P1, msg: &[u8]) -> Result<(), String> {
    let d = depth_for(n, branch);
    let sizes = circuit_sizes(d, branch);
    if proof.len() != fcmp_proof_size(n, branch) { return Err("fcmp: proof size".into()); }
    if key_image.is_inf() { return Err("fcmp: invalid key image".into()); }
    let mut o = 0usize;
    let bad = || "invalid point".to_string();
    let e1 = |o: &mut usize| -> Result<P1, String> { let p = P1::from_bytes(&proof[*o..*o + 33]).ok_or_else(bad); *o += 33; p };
    let phat = e1(&mut o)?; let ihat = e1(&mut o)?; let chat = e1(&mut o)?;
    let lhat = P2::from_bytes(&proof[o..o + 33]).ok_or_else(bad)?; o += 33;
    let (mut hats1, mut hats2) = (HashMap::new(), HashMap::new());
    for l in 1..d {
        if l % 2 == 1 { hats1.insert(l, e1(&mut o)?); } else { hats2.insert(l, P2::from_bytes(&proof[o..o + 33]).ok_or_else(bad)?); o += 33; }
    }
    let head_len = o;
    let (s1, s2) = (bp_proof_size(sizes.n1, sizes.k1), bp_proof_size(sizes.n2, sizes.k2));
    let pr1 = decode_bp::<Secp>(&proof[o..o + s1], sizes.n1, sizes.k1).ok_or("bp: malformed proof")?; o += s1;
    let pr2 = decode_bp::<Secq>(&proof[o..o + s2], sizes.n2, sizes.k2).ok_or("bp: malformed proof")?; o += s2;
    let gsp = &proof[o..];
    let dpt = chat.sub(pseudo);
    let ctx = H::new("fcmp/ctx").b(msg).b(&proof[..head_len]).b(&proof[head_len..head_len + s1 + s2]).b(&pseudo.to_bytes()).b(&key_image.to_bytes()).d32();
    if !gsp_verify(&ctx, &phat, &ihat, &dpt, key_image, gsp) { return Err("fcmp: invalid ownership/key image proof".into()); }
    let st = Statement { b: branch, n, d, root: root.point.clone(), root_count: root.count, phat, ihat, chat, lhat, hats1, hats2 };
    let (mut cs2, vcs2) = build_e2(&st, None)?;
    cs2.n = sizes.n2;
    let (mut cs1, vcs1) = build_e1(&st, None)?;
    cs1.n = sizes.n1;
    if cs2.n_gates > cs2.n || cs1.n_gates > cs1.n { return Err("fcmp: circuit larger than expected".into()); }
    bp_verify_into(&mut batch.e2, &cs2, &vcs2, &pr2, &mut transcript_for("E2", &st))?;
    bp_verify_into(&mut batch.e1, &cs1, &vcs1, &pr1, &mut transcript_for("E1", &st))?;
    Ok(())
}

// ====================================================================== PROVER
/// Proving job for ONE input (it comes from the JavaScript wallet): the path in the tree, the output
/// and the already chosen blindings (r1, r2) — the wallet uses the same ones in the statement and in the GSP.
pub struct ProveJob {
    pub branch: usize,
    pub n: u64,
    pub path: Vec<(u32, u64, Vec<[u64; 4]>)>,
    pub leaf_pos: usize,
    pub p: [u8; 33],
    pub c: [u8; 33],
    pub r1: Fe<ModN>,
    pub r2: Fe<ModP>,
}

/// Public statement + witness (mirrors setup() from src/fcmp/fcmp.js).
fn setup(job: &ProveJob) -> Result<(Statement, Witness), String> {
    let b = job.branch;
    let d = depth_for(job.n, b);
    if job.path.len() != d as usize { return Err("fcmp: path with the wrong depth".into()); }
    let leaf = leaf_data(&job.p, &job.c).ok_or("fcmp: invalid output")?;
    if job.path[0].2.get(job.leaf_pos) != Some(&leaf.x) { return Err("fcmp: the output is not at that position in the tree".into()); }
    let mut levels: HashMap<u32, (Vec<[u64; 4]>, u64)> = HashMap::new();
    let mut points1: HashMap<u32, P1> = HashMap::new();
    let mut points2: HashMap<u32, P2> = HashMap::new();
    let mut root = None;
    let mut child_x = leaf.x;
    for l in 1..=d {
        let entries = &job.path[l as usize - 1].2;
        let pos = if l == 1 { job.leaf_pos } else { (job.path[l as usize - 2].1 % b as u64) as usize };
        if entries.get(pos) != Some(&child_x) { return Err(format!("fcmp: inconsistent path at level {l}")); }
        let seg = segment(l as usize, b);
        let k;
        if seg.odd {
            let (g, _, _, hb, _) = gens::<Secp>(seg.blind + 1);
            let ks: Vec<Fe<ModN>> = entries.iter().map(|e| Fe::from_limbs(*e)).collect();
            let raw = msm(&ks, &g[seg.off..seg.off + entries.len()]);
            let (kk, pt) = if l < d { make_permissible(&raw, &hb) } else { (0, raw) };
            k = kk;
            child_x = pt.affine().ok_or("degenerate node")?.0.to_limbs();
            if l == d { root = Some(NodePt::E1(raw)); } else { points1.insert(l, pt); }
        } else {
            let (g, _, _, hb, _) = gens::<Secq>(seg.blind + 1);
            let ks: Vec<Fe<ModP>> = entries.iter().map(|e| Fe::from_limbs(*e)).collect();
            let raw = msm(&ks, &g[seg.off..seg.off + entries.len()]);
            let (kk, pt) = if l < d { make_permissible(&raw, &hb) } else { (0, raw) };
            k = kk;
            child_x = pt.affine().ok_or("degenerate node")?.0.to_limbs();
            if l == d { root = Some(NodePt::E2(raw)); } else { points2.insert(l, pt); }
        }
        levels.insert(l, (entries.clone(), k));
    }
    let bs = bases();
    let (r1, r2) = (job.r1, job.r2);
    let mut hats1 = HashMap::new();
    let mut hats2 = HashMap::new();
    for l in 1..d {
        let seg = segment(l as usize, b);
        // r1 and r2 are secrets (they would reveal the spent coin): constant-time multiplications
        if seg.odd { hats1.insert(l, points1[&l].add(&ct_mul(&gen_at::<Secp>(seg.blind), &r1))); }
        else { hats2.insert(l, points2[&l].add(&ct_mul(&gen_at::<Secq>(seg.blind), &r2))); }
    }
    let st = Statement {
        b, n: job.n, d, root: root.unwrap(), root_count: job.path[d as usize - 1].2.len(),
        phat: leaf.p.add(&ct_mul(&bs.t, &r1)), ihat: leaf.i.add(&ct_mul(&bs.ti, &r1)), chat: leaf.c.add(&ct_mul(&bs.tc, &r1)),
        lhat: leaf.point.add(&ct_mul(&gen_at::<Secq>(LEAF_BLIND), &r2)), hats1, hats2,
    };
    Ok((st, Witness { r1, r2, coords: leaf.coords, k_l: leaf.k, levels }))
}

/// Inner product WITHOUT skipping zeros: the prover's vectors carry the witness (bits of the
/// blindings, position in the tree) and skipping the zeros made the timing depend on it.
fn inner<M: Modulus>(a: &[Fe<M>], b: &[Fe<M>]) -> Fe<M> {
    let mut s = Fe::ZERO;
    for i in 0..a.len() { s = s + a[i] * b[i]; }
    s
}

fn to_points<C: Curve>(v: Vec<Pt<C>>) -> Vec<Pt<C>> {
    batch_affine(&v).into_iter().map(|p| p.map(|(x, y)| Pt::from_affine(x, y)).unwrap_or_else(Pt::inf)).collect()
}

/// Circuit Bulletproofs with vector commitments (mirrors bpProve from src/fcmp/bp.js).
fn bp_prove<C: FcmpCurve>(cs: &Cs<C::S>, tr: &mut Transcript) -> Result<BpProof<C>, String> {
    let n = cs.n;
    let k = cs.n_vcs;
    if cs.n_gates > n { return Err("bp: too many gates for n".into()); }
    cs.check()?;
    let (g, h, gb, hb, ub) = gens::<C>(n);
    let pad = |a: &Vec<Scalar<C>>| { let mut r = vec![Fe::ZERO; n]; r[..a.len()].copy_from_slice(a); r };
    let (al, ar, ao) = (pad(&cs.al), pad(&cs.ar), pad(&cs.ao));
    // "Hedged" nonces: seed = H(witness ‖ 32 random bytes). With a broken random
    // generator, the blindings stay unpredictable (they depend on the secret witness).
    let mut sh = H::new("fcmp/bp/seed");
    for v in cs.al.iter().chain(&cs.ar).chain(&cs.gammas) { sh = sh.b(&v.to_be_bytes()); }
    let mut rnd = [0u8; 32];
    getrandom::fill(&mut rnd).map_err(|_| "randomness unavailable")?;
    let seed = sh.b(&rnd).d32();
    let nonce = |tag: &str, i: usize| -> Scalar<C> { Fe::from_be_bytes_wide(&H::new("fcmp/bp/nonce").b(&seed).s(tag).n(i as u64).d64()) };
    let (alpha, beta, rho) = (nonce("alpha", 0), nonce("beta", 0), nonce("rho", 0));
    let sl: Vec<Scalar<C>> = (0..n).map(|i| nonce("sL", i)).collect();
    let sr: Vec<Scalar<C>> = (0..n).map(|i| nonce("sR", i)).collect();
    let cat = |x: Scalar<C>, a: &[Scalar<C>], b: &[Scalar<C>]| { let mut v = vec![x]; v.extend_from_slice(a); v.extend_from_slice(b); v };
    let mut gh = vec![hb]; gh.extend_from_slice(&g); gh.extend_from_slice(&h);
    let mut g1 = vec![hb]; g1.extend_from_slice(&g);
    // aL, aR, aO carry the witness (bits of r, position on the path): constant-time commitments
    let ai = ct_msm(&cat(alpha, &al, &ar), &gh);
    let ao_pt = ct_msm(&cat(beta, &ao, &[]), &g1);
    let s = msm(&cat(rho, &sl, &sr), &gh);
    tr.add("AI", &[Tx::B(&ai.to_bytes())]);
    tr.add("AO", &[Tx::B(&ao_pt.to_bytes())]);
    tr.add("S", &[Tx::B(&s.to_bytes())]);
    let y: Scalar<C> = tr.ch("y");
    let z: Scalar<C> = tr.ch("z");
    let (wl, wr, wo, wcm, wc) = cs.weights(z, n);
    let yinv = y.invert();
    let mut yp = vec![Fe::ONE; n];
    let mut yi = vec![Fe::ONE; n];
    for i in 1..n { yp[i] = yp[i - 1] * y; yi[i] = yi[i - 1] * yinv; }
    let (lp, rp, tpow) = t_powers(k);
    let mut lv: HashMap<i64, Vec<Scalar<C>>> = HashMap::new();
    let mut rv: HashMap<i64, Vec<Scalar<C>>> = HashMap::new();
    lv.insert(1, (0..n).map(|i| al[i] + yi[i] * wr[i]).collect());
    lv.insert(2, ao.clone());
    lv.insert(3, sl.clone());
    rv.insert(0, (0..n).map(|i| wo[i] - yp[i]).collect());
    rv.insert(1, (0..n).map(|i| yp[i] * ar[i] + wl[i]).collect());
    rv.insert(3, (0..n).map(|i| yp[i] * sr[i]).collect());
    for j in 0..k {
        let mut c = vec![Fe::ZERO; n];
        for (pos, v) in &cs.vc_vals[j] { if *pos >= n { return Err("bp: commitment out of range".into()); } c[*pos] = *v; }
        let mut wv = vec![Fe::ZERO; n];
        for (pos, v) in &wcm[j] { if *pos >= n { return Err("bp: constraint out of range".into()); } wv[*pos] = *v; }
        lv.insert(4 + j as i64, c);
        rv.insert(-2 - j as i64, wv);
    }
    let mut t: HashMap<i64, Scalar<C>> = HashMap::new();
    for i in &lp { for jj in &rp { let e = t.entry(i + jj).or_insert(Fe::ZERO); *e = *e + inner(&lv[i], &rv[jj]); } }
    let mut delta = Fe::ZERO;
    for i in 0..n { if !wr[i].is_zero() && !wl[i].is_zero() { delta = delta + yi[i] * wr[i] * wl[i]; } }
    if t[&2] != wc + delta { return Err("bp: t2 does not match (inconsistent circuit)".into()); }
    let mut tau: HashMap<i64, Scalar<C>> = HashMap::new();
    let mut ts = vec![];
    for e in &tpow {
        let te = nonce("tau", (*e + 1000) as usize);
        tau.insert(*e, te);
        let tp = ct_msm(&[t.get(e).copied().unwrap_or(Fe::ZERO), te], &[gb, hb]);
        tr.add("T", &[Tx::S(&e.to_string()), Tx::B(&tp.to_bytes())]);
        ts.push(tp);
    }
    let x: Scalar<C> = tr.ch("x");
    let mut l = vec![Fe::ZERO; n];
    let mut r = vec![Fe::ZERO; n];
    // no branching on witness values
    for (e, v) in &lv { let xe = xpow(x, *e); for i in 0..n { l[i] = l[i] + v[i] * xe; } }
    for (e, v) in &rv { let xe = xpow(x, *e); for i in 0..n { r[i] = r[i] + v[i] * xe; } }
    let that = inner(&l, &r);
    let mut taux = Fe::ZERO;
    for e in &tpow { taux = taux + tau[e] * xpow(x, *e); }
    let mut mu = alpha * x + beta * x * x + rho * xpow(x, 3);
    for j in 0..k { mu = mu + cs.gammas[j] * xpow(x, 4 + j as i64); }
    tr.add("taux", &[Tx::B(&taux.to_be_bytes())]);
    tr.add("mu", &[Tx::B(&mu.to_be_bytes())]);
    tr.add("that", &[Tx::B(&that.to_be_bytes())]);
    let w: Scalar<C> = tr.ch("w");
    let q = ub.mul(&w);
    // inner-product argument; H'_i = y^-i·H_i kept as the weight cw_i
    let (mut a, mut b) = (l, r);
    let (mut gv, mut hv, mut cw) = (g, h, yi);
    let (mut ls, mut rs) = (vec![], vec![]);
    while a.len() > 1 {
        let hh = a.len() / 2;
        let cl = inner(&a[..hh], &b[hh..]);
        let cr = inner(&a[hh..], &b[..hh]);
        let mut ks: Vec<Scalar<C>> = a[..hh].to_vec();
        ks.extend((0..hh).map(|i| b[hh + i] * cw[i]));
        ks.push(cl);
        let mut ps: Vec<Pt<C>> = gv[hh..].to_vec();
        ps.extend_from_slice(&hv[..hh]);
        ps.push(q);
        let lk = msm(&ks, &ps);
        let mut ks: Vec<Scalar<C>> = a[hh..].to_vec();
        ks.extend((0..hh).map(|i| b[i] * cw[hh + i]));
        ks.push(cr);
        let mut ps: Vec<Pt<C>> = gv[..hh].to_vec();
        ps.extend_from_slice(&hv[hh..]);
        ps.push(q);
        let rk = msm(&ks, &ps);
        tr.add("L", &[Tx::B(&lk.to_bytes())]);
        tr.add("R", &[Tx::B(&rk.to_bytes())]);
        ls.push(lk);
        rs.push(rk);
        let u: Scalar<C> = tr.ch128("u");
        a = (0..hh).map(|i| a[i] * u + a[hh + i]).collect();
        b = (0..hh).map(|i| b[i] + b[hh + i] * u).collect();
        let su = u * y.pow_limbs(&[hh as u64, 0, 0, 0]);
        let (ul, sul) = (u.to_limbs(), su.to_limbs());
        gv = to_points((0..hh).map(|i| gv[i].add(&gv[hh + i].mul_limbs(&ul))).collect());
        hv = to_points((0..hh).map(|i| hv[hh + i].add(&hv[i].mul_limbs(&sul))).collect());
        cw = cw[hh..].to_vec();
    }
    Ok(BpProof { ai, ao: ao_pt, s, t: ts, taux, mu, that, l: ls, r: rs, a: a[0], b: b[0] })
}

fn encode_bp<C: Curve>(p: &BpProof<C>) -> Vec<u8> {
    let mut v = vec![];
    for pt in [&p.ai, &p.ao, &p.s] { v.extend_from_slice(&pt.to_bytes()); }
    for t in &p.t { v.extend_from_slice(&t.to_bytes()); }
    for s in [&p.taux, &p.mu, &p.that] { v.extend_from_slice(&s.to_be_bytes()); }
    for i in 0..p.l.len() { v.extend_from_slice(&p.l[i].to_bytes()); v.extend_from_slice(&p.r[i].to_bytes()); }
    v.extend_from_slice(&p.a.to_be_bytes());
    v.extend_from_slice(&p.b.to_be_bytes());
    v
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Half { E1, E2 }

/// One of an input's two Bulletproofs, already encoded (the same as proveHalf in JS).
pub fn prove_half(job: &ProveJob, half: Half) -> Result<Vec<u8>, String> {
    let (st, w) = setup(job)?;
    let sizes = circuit_sizes(st.d, st.b);
    match half {
        Half::E1 => {
            let (mut cs, _) = build_e1(&st, Some(&w))?;
            cs.n = sizes.n1;
            Ok(encode_bp(&bp_prove::<Secp>(&cs, &mut transcript_for("E1", &st))?))
        }
        Half::E2 => {
            let (mut cs, _) = build_e2(&st, Some(&w))?;
            cs.n = sizes.n2;
            Ok(encode_bp(&bp_prove::<Secq>(&cs, &mut transcript_for("E2", &st))?))
        }
    }
}

/// Checks the two halves produced for a job (the prover's self-check).
pub fn verify_halves(job: &ProveJob, e1: &[u8], e2: &[u8]) -> Result<bool, String> {
    let (st, _) = setup(job)?;
    let sizes = circuit_sizes(st.d, st.b);
    let pr1 = decode_bp::<Secp>(e1, sizes.n1, sizes.k1).ok_or("malformed E1 half")?;
    let pr2 = decode_bp::<Secq>(e2, sizes.n2, sizes.k2).ok_or("malformed E2 half")?;
    let (mut cs2, vcs2) = build_e2(&st, None)?;
    cs2.n = sizes.n2;
    let (mut cs1, vcs1) = build_e1(&st, None)?;
    cs1.n = sizes.n1;
    let mut batch = FcmpBatch::new();
    bp_verify_into(&mut batch.e2, &cs2, &vcs2, &pr2, &mut transcript_for("E2", &st))?;
    bp_verify_into(&mut batch.e1, &cs1, &vcs1, &pr1, &mut transcript_for("E1", &st))?;
    Ok(batch.check())
}

/// Proof header (P̂, Î, Ĉ, L̂ and the blinded nodes of the path), equal to JS's encodeHead.
pub fn head_bytes(job: &ProveJob) -> Result<Vec<u8>, String> {
    let (st, _) = setup(job)?;
    let mut v = vec![];
    for p in [&st.phat, &st.ihat, &st.chat] { v.extend_from_slice(&p.to_bytes()); }
    v.extend_from_slice(&st.lhat.to_bytes());
    for l in 1..st.d { v.extend_from_slice(&if l % 2 == 1 { st.hats1[&l].to_bytes() } else { st.hats2[&l].to_bytes() }); }
    Ok(v)
}

/// Prover's statement: header, P̂, Î, Ĉ and the root (for the self-check).
pub fn prover_statement(job: &ProveJob) -> Result<(Vec<u8>, P1, P1, P1, Root), String> {
    let head = head_bytes(job)?;
    let (st, _) = setup(job)?;
    let root = Root { depth: st.d, point: st.root.clone(), count: st.root_count };
    Ok((head, st.phat, st.ihat, st.chat, root))
}

/// FCMP generalized Schnorr proof (mirrors gspProve from JS) with "hedged" nonces and all
/// multiplications by secrets in constant time. w = [p, t, q, y, a, b].
pub fn gsp_prove(ctx: &[u8; 32], phat: &P1, ihat: &P1, d: &P1, w: [Sc; 6]) -> Result<Vec<u8>, String> {
    use crate::wallet_ops::{hedged, mul_g_ct};
    let bs = bases();
    let secret: Vec<u8> = w.iter().flat_map(|s| s.to_be_bytes()).collect();
    let k: Vec<Sc> = (0..6).map(|i| hedged(&format!("fcmp/gsp/nonce/{i}"), &[&secret], ctx)).collect();
    let r1 = mul_g_ct(&k[0]).add(&ct_mul(&bs.t, &k[1]));
    let r2 = ct_mul(phat, &k[0]).sub(&mul_g_ct(&k[2])).sub(&ct_mul(&bs.t, &k[3]));
    let r3 = ct_mul(ihat, &k[0]).sub(&ct_mul(&bs.ti, &k[3]));
    let r4 = mul_g_ct(&k[4]).add(&ct_mul(&bs.tc, &k[5]));
    let e = hash_to_scalar(H::new("fcmp/gsp").b(ctx).b(&r1.to_bytes()).b(&r2.to_bytes()).b(&r3.to_bytes()).b(&r4.to_bytes()));
    let mut out = e.to_be_bytes().to_vec();
    for i in 0..6 { out.extend_from_slice(&(k[i] + e * w[i]).to_be_bytes()); }
    if !gsp_verify(ctx, phat, ihat, d, &ct_mul(ihat, &w[0]).sub(&ct_mul(&bs.ti, &w[3])), &out) {
        return Err("ownership proof failed (self-check)".into());
    }
    Ok(out)
}
