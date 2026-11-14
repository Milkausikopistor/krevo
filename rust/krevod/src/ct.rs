//! Aritmética de curva em TEMPO CONSTANTE para operações com segredos.
//!
//! O código de verificação (dados públicos) usa as rotinas rápidas de `curve.rs`, que têm
//! desvios e acessos à memória dependentes dos dados. Aqui não: nada depende do escalar
//! secreto além dos próprios valores calculados.
//!   • coordenadas projetivas (X:Y:Z) com as fórmulas COMPLETAS de Renes–Costello–Batina
//!     (2016, alg. 7 e 9, a = 0): sem casos especiais para identidade, dobra ou P + (−P);
//!   • multiplicação em janelas fixas de 4 bits: sempre 4 dobras + 1 soma por janela;
//!   • consulta de tabela que percorre TODAS as entradas e escolhe por máscara;
//!   • escalares em Montgomery sem desvios (field.rs).

use crate::curve::*;
use crate::field::*;

#[derive(Clone, Copy, Debug)]
pub struct PP<C: Curve> { pub x: Base<C>, pub y: Base<C>, pub z: Base<C> }

impl<C: Curve> PP<C> {
    pub fn identity() -> Self { PP { x: Fe::ZERO, y: Fe::ONE, z: Fe::ZERO } }
    /// A partir de um ponto (Jacobiano) — usado com pontos PÚBLICOS (bases).
    pub fn from_pt(p: &Pt<C>) -> Self {
        match p.affine() { Some((x, y)) => PP { x, y, z: Fe::ONE }, None => Self::identity() }
    }
    #[inline(always)]
    fn b3() -> Base<C> { Fe::from_limbs([21, 0, 0, 0]) }

    /// Soma completa (alg. 7, a = 0, b3 = 3·7).
    pub fn add(&self, q: &Self) -> Self {
        let b3 = Self::b3();
        let (x1, y1, z1, x2, y2, z2) = (self.x, self.y, self.z, q.x, q.y, q.z);
        let mut t0 = x1 * x2;
        let mut t1 = y1 * y2;
        let mut t2 = z1 * z2;
        let mut t3 = x1 + y1;
        let mut t4 = x2 + y2;
        t3 = t3 * t4;
        t4 = t0 + t1;
        t3 = t3 - t4;
        t4 = y1 + z1;
        let mut x3 = y2 + z2;
        t4 = t4 * x3;
        x3 = t1 + t2;
        t4 = t4 - x3;
        x3 = x1 + z1;
        let mut y3 = x2 + z2;
        x3 = x3 * y3;
        y3 = t0 + t2;
        y3 = x3 - y3;
        x3 = t0 + t0;
        t0 = x3 + t0;
        t2 = b3 * t2;
        let mut z3 = t1 + t2;
        t1 = t1 - t2;
        y3 = b3 * y3;
        x3 = t4 * y3;
        t2 = t3 * t1;
        x3 = t2 - x3;
        y3 = y3 * t0;
        t1 = t1 * z3;
        y3 = t1 + y3;
        t0 = t0 * t3;
        z3 = z3 * t4;
        z3 = z3 + t0;
        PP { x: x3, y: y3, z: z3 }
    }

    /// Dobra completa (alg. 9, a = 0).
    pub fn dbl(&self) -> Self {
        let b3 = Self::b3();
        let (x, y, z) = (self.x, self.y, self.z);
        let mut t0 = y * y;
        let mut z3 = t0 + t0;
        z3 = z3 + z3;
        z3 = z3 + z3;
        let mut t1 = y * z;
        let mut t2 = z * z;
        t2 = b3 * t2;
        let mut x3 = t2 * z3;
        let mut y3 = t0 + t2;
        z3 = t1 * z3;
        t1 = t2 + t2;
        t2 = t1 + t2;
        t0 = t0 - t2;
        y3 = t0 * y3;
        y3 = x3 + y3;
        t1 = x * y;
        x3 = t0 * t1;
        x3 = x3 + x3;
        PP { x: x3, y: y3, z: z3 }
    }

    pub fn neg(&self) -> Self { PP { x: self.x, y: -self.y, z: self.z } }

    #[inline(always)]
    pub fn select(a: &Self, b: &Self, mask: u64) -> Self {
        PP { x: Fe::select(&a.x, &b.x, mask), y: Fe::select(&a.y, &b.y, mask), z: Fe::select(&a.z, &b.z, mask) }
    }

    /// De volta a um ponto comum (inversão de Fermat: expoente público, tempo constante).
    pub fn to_pt(&self) -> Pt<C> {
        let zi = self.z.invert();
        let inf = self.z.ct_eq(&Fe::ZERO);
        let p = Pt::from_affine(self.x * zi, self.y * zi);
        if inf != 0 { Pt::inf() } else { p }
    }
}

/// Consulta tbl[idx] percorrendo todas as entradas (sem acesso dependente do segredo).
#[inline(always)]
fn lookup<C: Curve>(tbl: &[PP<C>], idx: u64) -> PP<C> {
    let mut r = PP::identity();
    for (i, e) in tbl.iter().enumerate() {
        let m = ct_mask(nonzero_bit(i as u64 ^ idx) ^ 1);
        r = PP::select(&r, e, m);
    }
    r
}

#[inline(always)]
fn nibble(k: &[u64; 4], i: usize) -> u64 { (k[i / 16] >> (4 * (i % 16))) & 15 }

/// k·P em tempo constante (P público, k secreto).
pub fn ct_mul<C: Curve>(p: &Pt<C>, k: &Scalar<C>) -> Pt<C> { ct_mul_pp(&PP::from_pt(p), k).to_pt() }

pub fn ct_mul_pp<C: Curve>(p: &PP<C>, k: &Scalar<C>) -> PP<C> {
    let kl = k.to_limbs();
    let mut tbl = [PP::identity(); 16];
    tbl[1] = *p;
    for i in 2..16 { tbl[i] = tbl[i - 1].add(p); }
    let mut acc = PP::identity();
    for i in (0..64).rev() {
        acc = acc.dbl().dbl().dbl().dbl();
        acc = acc.add(&lookup(&tbl, nibble(&kl, i)));
    }
    acc
}

/// Base fixa em tempo constante: 64 janelas × 16 múltiplos pré-calculados, uma soma por janela.
pub struct CtFixed<C: Curve> { tbl: Vec<[PP<C>; 16]> }

impl<C: Curve> CtFixed<C> {
    pub fn new(p: &Pt<C>) -> Self {
        let mut tbl = Vec::with_capacity(64);
        let mut base = PP::from_pt(p);
        for _ in 0..64 {
            let mut row = [PP::identity(); 16];
            for d in 1..16 { row[d] = row[d - 1].add(&base); }
            // normaliza para Z = 1 (pontos públicos)
            for d in 1..16 { row[d] = PP::from_pt(&row[d].to_pt()); }
            tbl.push(row);
            base = base.dbl().dbl().dbl().dbl();
        }
        CtFixed { tbl }
    }
    pub fn mul(&self, k: &Scalar<C>) -> Pt<C> {
        let kl = k.to_limbs();
        let mut acc = PP::identity();
        for i in 0..64 { acc = acc.add(&lookup(&self.tbl[i], nibble(&kl, i))); }
        acc.to_pt()
    }
}

/// Σ ks[i]·ps[i] em tempo constante (Straus, janelas de 4 bits, consultas mascaradas).
/// Para compromissos de provas com testemunhas secretas.
pub fn ct_msm<C: Curve>(ks: &[Scalar<C>], ps: &[Pt<C>]) -> Pt<C> {
    assert_eq!(ks.len(), ps.len());
    let aff = batch_affine(ps);
    let tbls: Vec<[PP<C>; 16]> = aff.iter().map(|a| {
        let p = match a { Some((x, y)) => PP { x: *x, y: *y, z: Fe::ONE }, None => PP::identity() };
        let mut t = [PP::identity(); 16];
        t[1] = p;
        for i in 2..16 { t[i] = t[i - 1].add(&p); }
        t
    }).collect();
    let kls: Vec<[u64; 4]> = ks.iter().map(|k| k.to_limbs()).collect();
    let mut acc = PP::identity();
    for i in (0..64).rev() {
        acc = acc.dbl().dbl().dbl().dbl();
        for (t, k) in tbls.iter().zip(&kls) { acc = acc.add(&lookup(t, nibble(k, i))); }
    }
    acc.to_pt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::H;

    fn check<C: Curve>() {
        let g = Pt::<C>::hash_to_point(|c| H::new("ct").b(&c.to_le_bytes()).d32());
        let ks: Vec<Scalar<C>> = vec![Fe::ZERO, Fe::ONE, -Fe::ONE, Fe::from_u64(15), Fe::from_u64(16), Fe::random(), Fe::random()];
        for k in &ks { assert!(ct_mul(&g, k).eq(&g.mul(k)), "{} k·G", C::NAME); }
        // fórmulas completas: P + P, P + (−P), P + O
        let p = PP::from_pt(&g);
        assert!(p.add(&p).to_pt().eq(&g.dbl()));
        assert!(p.add(&p.neg()).to_pt().is_inf());
        assert!(p.add(&PP::identity()).to_pt().eq(&g));
        assert!(PP::<C>::identity().dbl().to_pt().is_inf());
        let fb = CtFixed::new(&g);
        for k in &ks { assert!(fb.mul(k).eq(&g.mul(k))); }
        let ps: Vec<Pt<C>> = (1..40u64).map(|i| g.mul(&Fe::from_u64(i * 7 + 3))).collect();
        let kk: Vec<Scalar<C>> = (0..39).map(|_| Fe::random()).collect();
        assert!(ct_msm(&kk, &ps).eq(&msm(&kk, &ps)));
    }

    #[test]
    fn constant_time_matches_reference() { check::<Secp>(); check::<Secq>(); }

    #[test]
    fn sqrt_ct_matches() {
        for _ in 0..200 {
            let a = Fe::<ModN>::random();
            let s = a.square();
            let r = s.sqrt_ct().unwrap();
            assert_eq!(r.square(), s);
            let b = Fe::<ModP>::random().square();
            assert_eq!(b.sqrt_ct().unwrap().square(), b);
            let nonres = Fe::<ModN>::from_u64(5) * a.square();
            assert!(nonres.sqrt_ct().is_none() || a.is_zero());
        }
    }
}
