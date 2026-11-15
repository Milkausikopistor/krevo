//! The y² = x³ + 7 curves of the secp256k1 / secq256k1 cycle, generic over the field.
//!   Secp: field p, order n (the usual curve)      Secq: field n, order p (the "twin")
//! Jacobian coordinates; multiplication in 4-bit windows; Pippenger multi-exponentiation
//! with mixed additions (points normalized to affine with a single inversion).

use crate::field::*;
use std::fmt::Debug;

pub trait Curve: Copy + Clone + Send + Sync + 'static + Debug + PartialEq + Eq {
    type F: Modulus;
    type S: Modulus;
    const NAME: &'static str;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Secp;
impl Curve for Secp { type F = ModP; type S = ModN; const NAME: &'static str = "secp256k1"; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Secq;
impl Curve for Secq { type F = ModN; type S = ModP; const NAME: &'static str = "secq256k1"; }

pub type Base<C> = Fe<<C as Curve>::F>;
pub type Scalar<C> = Fe<<C as Curve>::S>;

#[derive(Clone, Copy, Debug)]
pub struct Pt<C: Curve> { pub x: Base<C>, pub y: Base<C>, pub z: Base<C> }

pub type P1 = Pt<Secp>;
pub type P2 = Pt<Secq>;

impl<C: Curve> Pt<C> {
    pub fn inf() -> Self { Pt { x: Fe::ZERO, y: Fe::ONE, z: Fe::ZERO } }
    #[inline(always)]
    pub fn is_inf(&self) -> bool { self.z.is_zero() }
    pub fn from_affine(x: Base<C>, y: Base<C>) -> Self { Pt { x, y, z: Fe::ONE } }
    pub fn on_curve(x: &Base<C>, y: &Base<C>) -> bool { y.square() == x.square() * *x + Fe::from_u64(7) }

    pub fn affine(&self) -> Option<(Base<C>, Base<C>)> {
        if self.is_inf() { return None; }
        if self.z == Fe::ONE { return Some((self.x, self.y)); }
        let zi = self.z.invert();
        let zi2 = zi.square();
        Some((self.x * zi2, self.y * zi2 * zi))
    }
    pub fn normalize(&self) -> Self {
        match self.affine() { Some((x, y)) => Pt::from_affine(x, y), None => Pt::inf() }
    }

    #[inline]
    pub fn dbl(&self) -> Self {
        if self.is_inf() || self.y.is_zero() { return Pt::inf(); }
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = ((self.x + b).square() - a - c).double();
        let e = a.double() + a;
        let f = e.square();
        let x3 = f - d.double();
        let c8 = c.double().double().double();
        let y3 = e * (d - x3) - c8;
        let z3 = (self.y * self.z).double();
        Pt { x: x3, y: y3, z: z3 }
    }

    #[inline]
    pub fn add_aff(&self, x2: &Base<C>, y2: &Base<C>) -> Self {
        if self.is_inf() { return Pt::from_affine(*x2, *y2); }
        let z1z1 = self.z.square();
        let u2 = *x2 * z1z1;
        let s2 = *y2 * self.z * z1z1;
        let h = u2 - self.x;
        let r = s2 - self.y;
        if h.is_zero() { return if r.is_zero() { self.dbl() } else { Pt::inf() }; }
        let h2 = h.square();
        let h3 = h * h2;
        let u1h2 = self.x * h2;
        let x3 = r.square() - h3 - u1h2.double();
        let y3 = r * (u1h2 - x3) - self.y * h3;
        Pt { x: x3, y: y3, z: self.z * h }
    }

    pub fn add(&self, q: &Self) -> Self {
        if self.is_inf() { return *q; }
        if q.is_inf() { return *self; }
        if q.z == Fe::ONE { return self.add_aff(&q.x, &q.y); }
        if self.z == Fe::ONE { return q.add_aff(&self.x, &self.y); }
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        let u1 = self.x * z2z2;
        let u2 = q.x * z1z1;
        let s1 = self.y * q.z * z2z2;
        let s2 = q.y * self.z * z1z1;
        let h = u2 - u1;
        let r = s2 - s1;
        if h.is_zero() { return if r.is_zero() { self.dbl() } else { Pt::inf() }; }
        let h2 = h.square();
        let h3 = h * h2;
        let u1h2 = u1 * h2;
        let x3 = r.square() - h3 - u1h2.double();
        let y3 = r * (u1h2 - x3) - s1 * h3;
        Pt { x: x3, y: y3, z: self.z * q.z * h }
    }
    pub fn neg(&self) -> Self { Pt { x: self.x, y: -self.y, z: self.z } }
    pub fn sub(&self, q: &Self) -> Self { self.add(&q.neg()) }

    /// k·P with a canonical integer k (limbs).
    pub fn mul_limbs(&self, k: &[u64; 4]) -> Self {
        if self.is_inf() || *k == [0; 4] { return Pt::inf(); }
        let mut tbl = [Pt::inf(); 16];
        tbl[1] = *self;
        for i in 2..16 { tbl[i] = tbl[i - 1].add(self); }
        let mut acc = Pt::inf();
        for i in (0..4).rev() {
            for nib in (0..16).rev() {
                if !acc.is_inf() { acc = acc.dbl().dbl().dbl().dbl(); }
                let d = ((k[i] >> (4 * nib)) & 15) as usize;
                if d != 0 { acc = acc.add(&tbl[d]); }
            }
        }
        acc
    }
    pub fn mul(&self, k: &Scalar<C>) -> Self { self.mul_limbs(&k.to_limbs()) }

    pub fn eq(&self, q: &Self) -> bool {
        if self.is_inf() || q.is_inf() { return self.is_inf() && q.is_inf(); }
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        self.x * z2z2 == q.x * z1z1 && self.y * q.z * z2z2 == q.y * self.z * z1z1
    }

    /// 33 compressed bytes; infinity becomes 33 zeros (as in JavaScript).
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        if let Some((x, y)) = self.affine() {
            out[0] = if y.is_odd() { 3 } else { 2 };
            out[1..].copy_from_slice(&x.to_be_bytes());
        }
        out
    }
    pub fn lift_x(x: Base<C>, odd: bool) -> Option<Self> {
        let rhs = x.square() * x + Fe::from_u64(7);
        let mut y = rhs.sqrt()?;
        if y.is_odd() != odd { y = -y; }
        Some(Pt::from_affine(x, y))
    }
    /// Decodes 33 bytes; rejects infinity, x ≥ field and points not on the curve.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 33 || (b[0] != 2 && b[0] != 3) { return None; }
        let x = Fe::from_be_bytes(&b[1..])?;
        Self::lift_x(x, b[0] == 3)
    }
    /// Try-and-increment: `h(ctr)` gives 32 bytes; x = big-endian integer; even y.
    pub fn hash_to_point(h: impl Fn(u32) -> [u8; 32]) -> Self {
        for ctr in 0..1000u32 {
            let b = h(ctr);
            if let Some(x) = Fe::<C::F>::from_be_bytes(&b) {
                if let Some(p) = Self::lift_x(x, false) { return p; }
            }
        }
        panic!("hash_to_point failed");
    }
}

/// Normalizes several points to affine with a single inversion.
pub fn batch_affine<C: Curve>(ps: &[Pt<C>]) -> Vec<Option<(Base<C>, Base<C>)>> {
    let mut zs: Vec<Base<C>> = ps.iter().map(|p| p.z).collect();
    batch_invert(&mut zs);
    ps.iter().zip(zs).map(|(p, zi)| {
        if p.is_inf() { None } else { let zi2 = zi.square(); Some((p.x * zi2, p.y * zi2 * zi)) }
    }).collect()
}

/// Σ ks[i]·ps[i].
pub fn msm<C: Curve>(ks: &[Scalar<C>], ps: &[Pt<C>]) -> Pt<C> {
    assert_eq!(ks.len(), ps.len());
    let mut k2 = Vec::with_capacity(ks.len());
    let mut p2 = Vec::with_capacity(ks.len());
    for (k, p) in ks.iter().zip(ps) {
        if k.is_zero() || p.is_inf() { continue; }
        k2.push(k.to_limbs());
        p2.push(*p);
    }
    if k2.is_empty() { return Pt::inf(); }
    if k2.len() < 8 {
        let mut acc = Pt::inf();
        for (k, p) in k2.iter().zip(&p2) { acc = acc.add(&p.mul_limbs(k)); }
        return acc;
    }
    pippenger(&k2, &p2)
}

fn pippenger<C: Curve>(ks: &[[u64; 4]], ps: &[Pt<C>]) -> Pt<C> {
    let n = ks.len();
    let c: usize = if n < 32 { 3 } else if n < 128 { 5 } else if n < 512 { 7 } else if n < 2048 { 8 } else if n < 8192 { 10 } else { 12 };
    let windows = 256usize.div_ceil(c);
    let aff = batch_affine(ps);
    let digit = |k: &[u64; 4], w: usize| -> usize {
        let bit = w * c;
        let limb = bit / 64;
        let off = bit % 64;
        if limb >= 4 { return 0; }
        let mut v = k[limb] >> off;
        if off + c > 64 && limb + 1 < 4 { v |= k[limb + 1] << (64 - off); }
        (v as usize) & ((1 << c) - 1)
    };
    let mut acc = Pt::<C>::inf();
    let mut buckets = vec![Pt::<C>::inf(); 1 << c];
    for w in (0..windows).rev() {
        if !acc.is_inf() { for _ in 0..c { acc = acc.dbl(); } }
        for b in buckets.iter_mut() { *b = Pt::inf(); }
        for i in 0..n {
            let d = digit(&ks[i], w);
            if d != 0 {
                if let Some((x, y)) = &aff[i] { buckets[d] = buckets[d].add_aff(x, y); }
            }
        }
        let mut run = Pt::<C>::inf();
        let mut sum = Pt::<C>::inf();
        for d in (1..buckets.len()).rev() {
            run = run.add(&buckets[d]);
            sum = sum.add(&run);
        }
        acc = acc.add(&sum);
    }
    acc
}

/// Fixed-base table (4-bit windows, 64 × 15 affine points).
pub struct FixedBase<C: Curve> { tbl: Vec<[(Base<C>, Base<C>); 15]> }

impl<C: Curve> FixedBase<C> {
    pub fn new(p: &Pt<C>) -> Self {
        let mut flat = Vec::with_capacity(64 * 15);
        let mut base = *p;
        for _ in 0..64 {
            let mut acc = base;
            flat.push(acc);
            for _ in 2..16 { acc = acc.add(&base); flat.push(acc); }
            base = base.dbl().dbl().dbl().dbl();
        }
        let aff = batch_affine(&flat);
        let mut tbl = Vec::with_capacity(64);
        for i in 0..64 {
            let mut row = [(Fe::ZERO, Fe::ZERO); 15];
            for j in 0..15 { row[j] = aff[i * 15 + j].expect("degenerate table"); }
            tbl.push(row);
        }
        FixedBase { tbl }
    }
    pub fn mul_limbs(&self, k: &[u64; 4]) -> Pt<C> {
        let mut acc = Pt::inf();
        for i in 0..64 {
            let d = ((k[i / 16] >> (4 * (i % 16))) & 15) as usize;
            if d != 0 { let (x, y) = &self.tbl[i][d - 1]; acc = acc.add_aff(x, y); }
        }
        acc
    }
    pub fn mul(&self, k: &Scalar<C>) -> Pt<C> { self.mul_limbs(&k.to_limbs()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::H;

    #[test]
    fn cycle_and_msm() {
        let g2 = P2::hash_to_point(|c| H::new("test").b(&c.to_le_bytes()).d32());
        let p_as_scalar_minus1 = Fe::<ModP>::ZERO - Fe::<ModP>::ONE; // order of secq = p
        // (p−1)·G + G = O
        assert!(g2.mul(&p_as_scalar_minus1).add(&g2).is_inf());
        let g1 = P1::hash_to_point(|c| H::new("test").b(&c.to_le_bytes()).d32());
        let n_minus1 = Fe::<ModN>::ZERO - Fe::<ModN>::ONE;
        assert!(g1.mul(&n_minus1).add(&g1).is_inf());
        // msm == naive sum
        let pts: Vec<P1> = (0..300u64).map(|i| g1.mul(&Fe::from_u64(i * 7919 + 1))).collect();
        let ks: Vec<Fe<ModN>> = (0..300u64).map(|i| Fe::from_u64(i * i + 11).invert()).collect();
        let mut naive = P1::inf();
        for (k, p) in ks.iter().zip(&pts) { naive = naive.add(&p.mul(k)); }
        assert!(msm(&ks, &pts).eq(&naive));
        let fb = FixedBase::new(&g1);
        assert!(fb.mul(&ks[5]).eq(&g1.mul(&ks[5])));
        let enc = pts[9].to_bytes();
        assert!(P1::from_bytes(&enc).unwrap().eq(&pts[9]));
    }
}
