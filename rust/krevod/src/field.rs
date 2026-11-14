//! Corpos primos de 256 bits em forma de Montgomery (4 limbs de 64 bits).
//!
//! Dois módulos bastam para tudo: p (campo de secp256k1 = ordem de secq256k1) e
//! n (ordem de secp256k1 = campo de secq256k1). Os valores ficam sempre reduzidos
//! (< módulo), então a representação é única e a igualdade é por limbs.

use num_bigint::BigUint;
use std::fmt;
use std::marker::PhantomData;

pub trait Modulus: Copy + Clone + Send + Sync + 'static + fmt::Debug + PartialEq + Eq {
    const M: [u64; 4];
    /// −M⁻¹ mod 2⁶⁴
    const INV: u64;
    /// 2²⁵⁶ mod M (o "1" em Montgomery)
    const R: [u64; 4];
    /// 2⁵¹² mod M
    const R2: [u64; 4];
    /// não-resíduo quadrático (para Tonelli–Shanks quando M ≡ 1 mod 4)
    const NONRES: u64;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModP;
impl Modulus for ModP {
    const M: [u64; 4] = [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
    const INV: u64 = 0xd838091dd2253531;
    const R: [u64; 4] = [0x1000003d1, 0, 0, 0];
    const R2: [u64; 4] = [0x7a2000e90a1, 0x1, 0, 0];
    const NONRES: u64 = 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModN;
impl Modulus for ModN {
    const M: [u64; 4] = [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    const INV: u64 = 0x4b0dff665588b13f;
    const R: [u64; 4] = [0x402da1732fc9bebf, 0x4551231950b75fc4, 0x1, 0];
    const R2: [u64; 4] = [0x896cf21467d7d140, 0x741496c20e7cf878, 0xe697f5e45bcd07c6, 0x9d671cd581c69bc5];
    const NONRES: u64 = 5;
}

#[inline(always)]
fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (acc as u128) + (a as u128) * (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, ((t >> 64) as u64) & 1)
}

/// a − b em 256 bits; devolve (diferença, borrow).
#[inline(always)]
pub fn sub4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let (r0, c) = sbb(a[0], b[0], 0);
    let (r1, c) = sbb(a[1], b[1], c);
    let (r2, c) = sbb(a[2], b[2], c);
    let (r3, c) = sbb(a[3], b[3], c);
    ([r0, r1, r2, r3], c)
}
#[inline(always)]
pub fn add4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let (r0, c) = adc(a[0], b[0], 0);
    let (r1, c) = adc(a[1], b[1], c);
    let (r2, c) = adc(a[2], b[2], c);
    let (r3, c) = adc(a[3], b[3], c);
    ([r0, r1, r2, r3], c)
}
/// 1 se x ≠ 0, senão 0 — sem desvio.
#[inline(always)]
pub fn nonzero_bit(x: u64) -> u64 { (x | x.wrapping_neg()) >> 63 }
/// Bit (0/1) → máscara (0/!0) atrás de uma BARREIRA de otimização. Sem ela, o LLVM percebe que a
/// máscara só pode ser 0 ou !0 e troca a seleção por um desvio condicional — que o preditor de
/// desvios aprende, e o tempo passa a depender do segredo. A medição estatística (ct_timing_test)
/// pegou exatamente isso na consulta de tabela da multiplicação por escalar.
#[inline(always)]
pub fn ct_mask(bit: u64) -> u64 { std::hint::black_box(bit).wrapping_neg() }
/// Seleção sem desvio: mask = 0 → a; mask = !0 → b.
#[inline(always)]
pub fn sel4(a: &[u64; 4], b: &[u64; 4], mask: u64) -> [u64; 4] {
    [(a[0] & !mask) | (b[0] & mask), (a[1] & !mask) | (b[1] & mask), (a[2] & !mask) | (b[2] & mask), (a[3] & !mask) | (b[3] & mask)]
}
pub fn lt4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fe<M: Modulus>(pub(crate) [u64; 4], PhantomData<M>);

impl<M: Modulus> fmt::Debug for Fe<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex(&self.to_be_bytes()))
    }
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

impl<M: Modulus> Fe<M> {
    pub const ZERO: Self = Fe([0; 4], PhantomData);
    pub const ONE: Self = Fe(M::R, PhantomData);

    #[inline(always)]
    fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let m = &M::M;
        let mut t = [0u64; 5];
        for i in 0..4 {
            let mut c = 0u64;
            for j in 0..4 {
                let (lo, hi) = mac(t[j], a[j], b[i], c);
                t[j] = lo;
                c = hi;
            }
            let (t4, t5) = adc(t[4], c, 0);
            let k = t[0].wrapping_mul(M::INV);
            let (_, mut c) = mac(t[0], k, m[0], 0);
            for j in 1..4 {
                let (lo, hi) = mac(t[j], k, m[j], c);
                t[j - 1] = lo;
                c = hi;
            }
            let (lo, hi) = adc(t4, c, 0);
            t[3] = lo;
            t[4] = t5 + hi;
        }
        let low = [t[0], t[1], t[2], t[3]];
        let (r, borrow) = sub4(&low, m);
        // tempo constante: escolhe sem desvio entre low e low − M
        let use_r = nonzero_bit(t[4]) | (borrow ^ 1);
        sel4(&low, &r, ct_mask(use_r))
    }

    /// Inteiro canônico (< 2²⁵⁶, qualquer) → elemento (reduz módulo M).
    pub fn from_limbs(x: [u64; 4]) -> Self {
        Fe(Self::mont_mul(&x, &M::R2), PhantomData)
    }
    pub fn from_u64(v: u64) -> Self { Self::from_limbs([v, 0, 0, 0]) }
    /// Elemento → inteiro canônico (< M).
    pub fn to_limbs(&self) -> [u64; 4] { Self::mont_mul(&self.0, &[1, 0, 0, 0]) }

    pub fn from_be_bytes_reduce(b: &[u8; 32]) -> Self { Self::from_limbs(be_to_limbs(b)) }
    /// Só aceita a codificação canônica (< M).
    pub fn from_be_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 32 { return None; }
        let l = be_to_limbs(b.try_into().unwrap());
        if !lt4(&l, &M::M) { return None; }
        Some(Self::from_limbs(l))
    }
    /// 64 bytes big-endian → elemento (512 bits módulo M, como o `% N` do JavaScript).
    pub fn from_be_bytes_wide(b: &[u8; 64]) -> Self {
        let hi = Self::from_limbs(be_to_limbs(b[..32].try_into().unwrap()));
        let lo = Self::from_limbs(be_to_limbs(b[32..].try_into().unwrap()));
        let two256 = Self::from_limbs(M::R); // 2²⁵⁶ mod M
        hi * two256 + lo
    }
    pub fn to_be_bytes(&self) -> [u8; 32] { limbs_to_be(&self.to_limbs()) }
    pub fn from_biguint(v: &BigUint) -> Self {
        let m = BigUint::from_bytes_be(&limbs_to_be(&M::M));
        let r = v % m;
        let mut b = [0u8; 32];
        let rb = r.to_bytes_be();
        b[32 - rb.len()..].copy_from_slice(&rb);
        Self::from_be_bytes_reduce(&b)
    }
    pub fn to_biguint(&self) -> BigUint { BigUint::from_bytes_be(&self.to_be_bytes()) }
    pub fn modulus_biguint() -> BigUint { BigUint::from_bytes_be(&limbs_to_be(&M::M)) }

    #[inline(always)]
    pub fn is_zero(&self) -> bool { self.0 == [0; 4] }
    pub fn is_odd(&self) -> bool { self.to_limbs()[0] & 1 == 1 }
    #[inline(always)]
    pub fn square(&self) -> Self { Fe(Self::mont_mul(&self.0, &self.0), PhantomData) }
    pub fn double(&self) -> Self { *self + *self }

    pub fn pow_limbs(&self, e: &[u64; 4]) -> Self {
        let mut r = Self::ONE;
        for i in (0..4).rev() {
            for bit in (0..64).rev() {
                r = r.square();
                if (e[i] >> bit) & 1 == 1 { r = r * *self; }
            }
        }
        r
    }
    /// Inverso (Fermat). Zero → zero.
    pub fn invert(&self) -> Self {
        let (e, _) = sub4(&M::M, &[2, 0, 0, 0]);
        self.pow_limbs(&e)
    }
    pub fn is_square(&self) -> bool {
        if self.is_zero() { return true; }
        let (m1, _) = sub4(&M::M, &[1, 0, 0, 0]);
        self.pow_limbs(&shr(&m1, 1)) == Self::ONE
    }
    /// Raiz quadrada (uma das duas) ou None.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() { return Some(Self::ZERO); }
        if M::M[0] & 3 == 3 {
            let (e, _) = add4(&M::M, &[1, 0, 0, 0]);
            let y = self.pow_limbs(&shr(&e, 2));
            return if y.square() == *self { Some(y) } else { None };
        }
        if !self.is_square() { return None; }
        // Tonelli–Shanks
        let (m1, _) = sub4(&M::M, &[1, 0, 0, 0]);
        let mut s = 0u32;
        let mut q = m1;
        while q[0] & 1 == 0 { q = shr(&q, 1); s += 1; }
        let z = Self::from_u64(M::NONRES);
        let mut mm = s;
        let mut c = z.pow_limbs(&q);
        let mut t = self.pow_limbs(&q);
        let (q1, _) = add4(&q, &[1, 0, 0, 0]);
        let mut r = self.pow_limbs(&shr(&q1, 1));
        while t != Self::ONE {
            let mut i = 0u32;
            let mut t2 = t;
            while t2 != Self::ONE { t2 = t2.square(); i += 1; }
            let mut b = c;
            for _ in 0..(mm - i - 1) { b = b.square(); }
            mm = i;
            c = b.square();
            t = t * c;
            r = r * b;
        }
        Some(r)
    }
    /// Máscara !0 se iguais, 0 se diferentes — tempo constante.
    #[inline(always)]
    pub fn ct_eq(&self, o: &Self) -> u64 {
        let d = (self.0[0] ^ o.0[0]) | (self.0[1] ^ o.0[1]) | (self.0[2] ^ o.0[2]) | (self.0[3] ^ o.0[3]);
        ct_mask(nonzero_bit(d) ^ 1)
    }
    /// mask = 0 → a; mask = !0 → b (tempo constante).
    #[inline(always)]
    pub fn select(a: &Self, b: &Self, mask: u64) -> Self { Fe(sel4(&a.0, &b.0, mask), PhantomData) }

    /// Raiz quadrada em TEMPO CONSTANTE (para valores secretos): Tonelli–Shanks com número
    /// fixo de passos e escolhas por máscara. Só o resultado final (existe ou não) é revelado.
    pub fn sqrt_ct(&self) -> Option<Self> {
        let r = if M::M[0] & 3 == 3 {
            let (e, _) = add4(&M::M, &[1, 0, 0, 0]);
            self.pow_limbs(&shr(&e, 2))
        } else {
            let (m1, _) = sub4(&M::M, &[1, 0, 0, 0]);
            let (mut s, mut q) = (0u32, m1);
            while q[0] & 1 == 0 { q = shr(&q, 1); s += 1; } // depende só do módulo (público)
            let mut c = Self::from_u64(M::NONRES).pow_limbs(&q);
            let mut t = self.pow_limbs(&q);
            let (q1, _) = add4(&q, &[1, 0, 0, 0]);
            let mut r = self.pow_limbs(&shr(&q1, 1));
            for i in (1..s).rev() {
                let mut b = t;
                for _ in 0..(i - 1) { b = b.square(); }
                let flip = !b.ct_eq(&Self::ONE);
                r = Self::select(&r, &(r * c), flip);
                c = c.square();
                t = Self::select(&t, &(t * c), flip);
            }
            r
        };
        if r.square().ct_eq(self) != 0 { Some(r) } else { None }
    }

    pub fn random() -> Self {
        let mut b = [0u8; 64];
        getrandom::fill(&mut b).expect("aleatoriedade do sistema");
        Self::from_be_bytes_wide(&b)
    }
}

pub fn shr(a: &[u64; 4], k: u32) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        r[i] = a[i] >> k;
        if i < 3 { r[i] |= a[i + 1] << (64 - k); }
    }
    r
}
pub fn be_to_limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for i in 0..4 {
        l[3 - i] = u64::from_be_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
    }
    l
}
pub fn limbs_to_be(l: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 { b[8 * i..8 * i + 8].copy_from_slice(&l[3 - i].to_be_bytes()); }
    b
}

impl<M: Modulus> std::ops::Add for Fe<M> {
    type Output = Self;
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        let (s, carry) = add4(&self.0, &o.0);
        let (d, borrow) = sub4(&s, &M::M);
        Fe(sel4(&s, &d, ct_mask(carry | (borrow ^ 1))), PhantomData)
    }
}
impl<M: Modulus> std::ops::Sub for Fe<M> {
    type Output = Self;
    #[inline(always)]
    fn sub(self, o: Self) -> Self {
        let (d, borrow) = sub4(&self.0, &o.0);
        let mask = ct_mask(borrow);
        let m = M::M;
        Fe(add4(&d, &[m[0] & mask, m[1] & mask, m[2] & mask, m[3] & mask]).0, PhantomData)
    }
}
impl<M: Modulus> std::ops::Neg for Fe<M> {
    type Output = Self;
    fn neg(self) -> Self { Self::ZERO - self }
}
impl<M: Modulus> std::ops::Mul for Fe<M> {
    type Output = Self;
    #[inline(always)]
    fn mul(self, o: Self) -> Self { Fe(Self::mont_mul(&self.0, &o.0), PhantomData) }
}

pub type FeP = Fe<ModP>;
pub type FeN = Fe<ModN>;

/// Inversão de muitos elementos com uma só inversão (truque de Montgomery). Zeros ficam zero.
pub fn batch_invert<M: Modulus>(v: &mut [Fe<M>]) {
    let mut acc = Vec::with_capacity(v.len());
    let mut run = Fe::<M>::ONE;
    for x in v.iter() {
        acc.push(run);
        if !x.is_zero() { run = run * *x; }
    }
    let mut inv = run.invert();
    for i in (0..v.len()).rev() {
        if v[i].is_zero() { continue; }
        let t = inv * acc[i];
        inv = inv * v[i];
        v[i] = t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn rnd_big(m: &BigUint, seed: u64) -> BigUint {
        let mut x = BigUint::from(seed).pow(17u32) * BigUint::from(0x9e3779b97f4a7c15u64) + BigUint::from(seed);
        x %= m;
        x
    }

    fn check<M: Modulus>() {
        let m = Fe::<M>::modulus_biguint();
        for s in 1..200u64 {
            let a = rnd_big(&m, s);
            let b = rnd_big(&m, s * 7 + 3);
            let (fa, fb) = (Fe::<M>::from_biguint(&a), Fe::<M>::from_biguint(&b));
            assert_eq!((fa * fb).to_biguint(), (&a * &b) % &m);
            assert_eq!((fa + fb).to_biguint(), (&a + &b) % &m);
            assert_eq!((fa - fb).to_biguint(), ((&a + &m) - &b) % &m);
            if !fa.is_zero() { assert_eq!((fa * fa.invert()), Fe::<M>::ONE); }
            let sq = fa.square();
            let r = sq.sqrt().expect("quadrado tem raiz");
            assert_eq!(r.square(), sq);
        }
        // extremos
        let mm1 = Fe::<M>::from_biguint(&(&m - 1u32));
        assert_eq!((mm1 + Fe::<M>::ONE), Fe::<M>::ZERO);
        assert_eq!((mm1 * mm1), Fe::<M>::ONE);
        let mut w = [0xffu8; 64];
        w[0] = 0xfe;
        let big = BigUint::from_bytes_be(&w) % &m;
        assert_eq!(Fe::<M>::from_be_bytes_wide(&w).to_biguint(), big);
    }

    #[test]
    fn fields() { check::<ModP>(); check::<ModN>(); }
}
