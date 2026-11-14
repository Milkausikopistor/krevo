//! Criptografia de consenso sobre secp256k1 (espelha src/crypto/*.js):
//! geradores "nada na manga", Schnorr, Pedersen, imagens de chave, CLSAG, Bulletproofs de
//! intervalo, MuHash3072, saídas furtivas da coinbase e ML-DSA-44.

use crate::curve::*;
use crate::field::*;
use crate::hash::{shake256, H};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub type Sc = Fe<ModN>;

// ------------------------------------------------------------------ geradores
pub fn g() -> P1 {
    static G: OnceLock<P1> = OnceLock::new();
    *G.get_or_init(|| {
        let x = FeP::from_be_bytes(&crate::bytes::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()).unwrap();
        let y = FeP::from_be_bytes(&crate::bytes::from_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap()).unwrap();
        P1::from_affine(x, y)
    })
}
fn g_table() -> &'static FixedBase<Secp> {
    static T: OnceLock<FixedBase<Secp>> = OnceLock::new();
    T.get_or_init(|| FixedBase::new(&g()))
}
pub fn mul_g(k: &Sc) -> P1 { g_table().mul(k) }

/// hashToPoint de src/crypto/secp256k1.js: H(domínio, partes…, u32le(ctr)).
pub fn hash_to_point_secp(base: H) -> P1 {
    P1::hash_to_point(|ctr| base.clone().b(&ctr.to_le_bytes()).d32())
}
/// hashToScalar: H64(…) big-endian mod n.
pub fn hash_to_scalar(h: H) -> Sc { Sc::from_be_bytes_wide(&h.d64()) }

/// Gerador de valor das quantias (Pedersen).
pub fn hv() -> P1 {
    static HV: OnceLock<P1> = OnceLock::new();
    *HV.get_or_init(|| hash_to_point_secp(H::new("pedersen/H").s("gerador de valor do Krevo")).normalize())
}
fn hv_table() -> &'static FixedBase<Secp> {
    static T: OnceLock<FixedBase<Secp>> = OnceLock::new();
    T.get_or_init(|| FixedBase::new(&hv()))
}
pub fn mul_h_u64(v: u64) -> P1 { hv_table().mul_limbs(&[v, 0, 0, 0]) }
pub fn commit(v: u64, x: &Sc) -> P1 { mul_g(x).add(&mul_h_u64(v)) }

pub fn point_from_bytes(b: &[u8]) -> Option<P1> { P1::from_bytes(b) }
pub fn scalar_from_bytes(b: &[u8]) -> Option<Sc> { Sc::from_be_bytes(b) }

/// Hp(P): base da imagem de chave (memorizada).
pub fn hash_point_for_key_image(p: &P1) -> P1 {
    static CACHE: OnceLock<Mutex<HashMap<[u8; 33], P1>>> = OnceLock::new();
    let key = p.to_bytes();
    let m = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(r) = m.lock().unwrap().get(&key) { return *r; }
    let r = hash_to_point_secp(H::new("clsag/keyimage").b(&key)).normalize();
    let mut g = m.lock().unwrap();
    if g.len() > 50_000 { g.clear(); }
    g.insert(key, r);
    r
}

// ------------------------------------------------------------------ Schnorr
pub fn schnorr_verify(p: &P1, msg: &[u8], sig: &[u8], domain: &str) -> bool {
    if sig.len() != 64 || p.is_inf() { return false; }
    let (Some(e), Some(s)) = (Sc::from_be_bytes(&sig[..32]), Sc::from_be_bytes(&sig[32..])) else { return false };
    if e.is_zero() { return false; }
    let r = mul_g(&s).add(&p.mul(&-e));
    if r.is_inf() { return false; }
    let dom = format!("schnorr/{domain}");
    hash_to_scalar(H::new(&dom).b(&r.to_bytes()).b(&p.to_bytes()).b(msg)) == e
}

// ------------------------------------------------------------------ CLSAG
pub struct RingMember { pub p: P1, pub c: P1 }

pub fn clsag_verify(msg: &[u8], ring: &[RingMember], pseudo: &P1, sig: &[u8], ki: &P1) -> bool {
    let n = ring.len();
    if n < 1 || sig.len() != 32 + 32 * n + 33 || ki.is_inf() { return false; }
    let Some(c0) = Sc::from_be_bytes(&sig[..32]) else { return false };
    let mut s = Vec::with_capacity(n);
    for i in 0..n {
        let Some(v) = Sc::from_be_bytes(&sig[32 + 32 * i..64 + 32 * i]) else { return false };
        s.push(v);
    }
    let Some(d) = P1::from_bytes(&sig[32 + 32 * n..]) else { return false };
    let ring_p: Vec<u8> = ring.iter().flat_map(|m| m.p.to_bytes()).collect();
    let ring_c: Vec<u8> = ring.iter().flat_map(|m| m.c.to_bytes()).collect();
    let (kib, db, pb) = (ki.to_bytes(), d.to_bytes(), pseudo.to_bytes());
    let mu_p = hash_to_scalar(H::new("clsag/agg0").b(&ring_p).b(&ring_c).b(&kib).b(&db).b(&pb));
    let mu_c = hash_to_scalar(H::new("clsag/agg1").b(&ring_p).b(&ring_c).b(&kib).b(&db).b(&pb));
    let prefix = H::new("clsag/prefix").b(&ring_p).b(&ring_c).b(&pb).d32();
    let w = ki.mul(&mu_p).add(&d.mul(&mu_c));
    let mut c = c0;
    for i in 0..n {
        let l = mul_g(&s[i]).add(&ring[i].p.mul(&(c * mu_p))).add(&ring[i].c.sub(pseudo).mul(&(c * mu_c)));
        let r = hash_point_for_key_image(&ring[i].p).mul(&s[i]).add(&w.mul(&c));
        c = hash_to_scalar(H::new("clsag/round").b(&prefix).b(msg).b(&l.to_bytes()).b(&r.to_bytes()));
    }
    c == c0
}

// ------------------------------------------------------------------ Bulletproofs (intervalo)
pub const BP_BITS: usize = 64;
pub const BP_MAX_AGG: usize = 16;

struct BpGens { gi: Vec<P1>, hi: Vec<P1>, u: P1 }
fn bp_gens() -> &'static Mutex<BpGens> {
    static G: OnceLock<Mutex<BpGens>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(BpGens { gi: vec![], hi: vec![], u: hash_to_point_secp(H::new("bp/U").s("produto interno")).normalize() }))
}
pub(crate) fn bp_ensure(n: usize) -> (Vec<P1>, Vec<P1>, P1) {
    let mut g = bp_gens().lock().unwrap();
    while g.gi.len() < n {
        let i = g.gi.len() as u32;
        let a = hash_to_point_secp(H::new("bp/G").b(&i.to_le_bytes())).normalize();
        let b = hash_to_point_secp(H::new("bp/H").b(&i.to_le_bytes())).normalize();
        g.gi.push(a);
        g.hi.push(b);
    }
    (g.gi[..n].to_vec(), g.hi[..n].to_vec(), g.u)
}

/// Transcrição de src/crypto/bulletproofs.js.
pub(crate) struct BpTr([u8; 32]);
pub(crate) enum TrX<'a> { P(&'a P1), S(&'a Sc), N(u64) }
impl BpTr {
    pub(crate) fn new(label: &str) -> Self { BpTr(H::new("bp/transcript").s(label).d32()) }
    pub(crate) fn add(&mut self, label: &str, x: TrX) {
        let h = H::new("bp/transcript").b(&self.0).s(label);
        self.0 = match x {
            TrX::P(p) => h.b(&p.to_bytes()),
            TrX::S(s) => h.b(&s.to_be_bytes()),
            TrX::N(n) => h.n(n),
        }.d32();
    }
    pub(crate) fn ch(&mut self, label: &str) -> Option<Sc> {
        let c = hash_to_scalar(H::new("bp/challenge").b(&self.0).s(label));
        if c.is_zero() { return None; }
        self.add("ch", TrX::S(&c));
        Some(c)
    }
}

pub fn range_proof_size(m0: usize) -> usize {
    let rounds = (BP_BITS * m0.next_power_of_two()).trailing_zeros() as usize;
    4 * 33 + 3 * 32 + rounds * 66 + 64
}

/// Verifica a prova agregada contra os compromissos V.
pub fn verify_range(v: &[P1], proof: &[u8]) -> bool {
    (|| -> Option<bool> {
        let m0 = v.len();
        if m0 < 1 || m0 > BP_MAX_AGG || proof.len() != range_proof_size(m0) { return Some(false); }
        let m = m0.next_power_of_two();
        let nn = BP_BITS * m;
        let rounds = nn.trailing_zeros() as usize;
        let mut o = 0usize;
        let mut pt = || { let p = P1::from_bytes(&proof[o..o + 33]); o += 33; p };
        let (a, s, t1, t2) = (pt()?, pt()?, pt()?, pt()?);
        let sc = |o: &mut usize| { let x = Sc::from_be_bytes(&proof[*o..*o + 32]); *o += 32; x };
        let taux = sc(&mut o)?;
        let mu = sc(&mut o)?;
        let that = sc(&mut o)?;
        let mut ls = vec![];
        let mut rs = vec![];
        for _ in 0..rounds {
            ls.push(P1::from_bytes(&proof[o..o + 33])?); o += 33;
            rs.push(P1::from_bytes(&proof[o..o + 33])?); o += 33;
        }
        let pa = sc(&mut o)?;
        let pb = sc(&mut o)?;
        let (gi, hi, ub) = bp_ensure(nn);

        let mut tr = BpTr::new("rangeproof");
        tr.add("bits", TrX::N(BP_BITS as u64));
        tr.add("m", TrX::N(m0 as u64));
        for x in v { tr.add("V", TrX::P(x)); }
        tr.add("A", TrX::P(&a)); tr.add("S", TrX::P(&s));
        let y = tr.ch("y")?; let z = tr.ch("z")?;
        tr.add("T1", TrX::P(&t1)); tr.add("T2", TrX::P(&t2));
        let x = tr.ch("x")?;
        tr.add("taux", TrX::S(&taux)); tr.add("mu", TrX::S(&mu)); tr.add("that", TrX::S(&that));
        let w = tr.ch("w")?;
        let mut u = vec![];
        for k in 0..rounds { tr.add("L", TrX::P(&ls[k])); tr.add("R", TrX::P(&rs[k])); u.push(tr.ch("u")?); }

        let uinv: Vec<Sc> = u.iter().map(|x| x.invert()).collect();
        let u2: Vec<Sc> = u.iter().map(|x| x.square()).collect();
        let uinv2: Vec<Sc> = uinv.iter().map(|x| x.square()).collect();
        let mut svec = vec![Sc::ONE; nn];
        svec[0] = uinv.iter().fold(Sc::ONE, |a, b| a * *b);
        for i in 1..nn {
            let j = 63 - (i as u64).leading_zeros() as usize;
            let k = rounds - 1 - j;
            svec[i] = svec[i - (1 << j)] * u2[k];
        }
        let yinv = y.invert();
        let mut yp = vec![Sc::ONE; nn];
        let mut ypinv = vec![Sc::ONE; nn];
        for i in 1..nn { yp[i] = yp[i - 1] * y; ypinv[i] = ypinv[i - 1] * yinv; }
        let mut zp = vec![Sc::ONE; m + 3];
        for i in 1..m + 3 { zp[i] = zp[i - 1] * z; }
        let mut two = vec![Sc::ONE; BP_BITS];
        for i in 1..BP_BITS { two[i] = two[i - 1].double(); }
        let sum_y = yp.iter().fold(Sc::ZERO, |a, b| a + *b);
        let mut delta = (z - z * z) * sum_y;
        let ones64 = Sc::from_limbs([u64::MAX, 0, 0, 0]);
        for j in 0..m { delta = delta - zp[3 + j] * ones64; }

        let c = Sc::random();
        let mut ks = vec![];
        let mut ps = vec![];
        let mut push = |k: Sc, p: P1| { ks.push(k); ps.push(p); };
        push(Sc::ONE, a);
        push(x, s);
        push(-mu + c * taux, g());
        push(w * (that - pa * pb), ub);
        push(c * (that - delta), hv());
        for j in 0..m0 { push(-(c * zp[2 + j]), v[j]); }
        push(-(c * x), t1);
        push(-(c * x * x), t2);
        for k in 0..rounds { push(u2[k], ls[k]); push(uinv2[k], rs[k]); }
        for i in 0..nn {
            let j = i / BP_BITS;
            push(-z - pa * svec[i], gi[i]);
            let sinv = svec[nn - 1 - i];
            push(z + ypinv[i] * (zp[2 + j] * two[i % BP_BITS] - pb * sinv), hi[i]);
        }
        Some(msm(&ks, &ps).is_inf())
    })().unwrap_or(false)
}

// ------------------------------------------------------------------ MuHash3072
fn muhash_prime() -> &'static BigUint {
    static MP: OnceLock<BigUint> = OnceLock::new();
    MP.get_or_init(|| (BigUint::from(1u32) << 3072usize) - BigUint::from(1103717u32))
}

#[derive(Clone, Debug)]
pub struct MuHash { num: BigUint, den: BigUint }

impl Default for MuHash { fn default() -> Self { Self::new() } }

impl MuHash {
    pub fn new() -> Self { MuHash { num: BigUint::from(1u32), den: BigUint::from(1u32) } }
    fn element(data: &[u8]) -> BigUint {
        let mut inp = b"KRV/muhash".to_vec();
        inp.extend_from_slice(data);
        let v = BigUint::from_bytes_le(&shake256(&inp, 384)) % muhash_prime();
        if v == BigUint::from(0u32) { BigUint::from(1u32) } else { v }
    }
    pub fn add(&mut self, data: &[u8]) { self.num = (&self.num * Self::element(data)) % muhash_prime(); }
    pub fn remove(&mut self, data: &[u8]) { self.den = (&self.den * Self::element(data)) % muhash_prime(); }
    pub fn normalize(&mut self) {
        if self.den != BigUint::from(1u32) {
            let mp = muhash_prime();
            let inv = self.den.modpow(&(mp - BigUint::from(2u32)), mp);
            self.num = (&self.num * inv) % mp;
            self.den = BigUint::from(1u32);
        }
    }
    pub fn digest(&mut self) -> [u8; 32] {
        self.normalize();
        let mut le = self.num.to_bytes_le();
        le.resize(384, 0);
        H::new("muhash/final").b(&le).d32()
    }
}

// ------------------------------------------------------------------ saída furtiva (coinbase)
pub struct ShieldedOut { pub r: P1, pub p: P1, pub c: P1, pub enc_amount: [u8; 8], pub view_tag: u8 }

/// makeShieldedOutput(…, coinbase = true): cegamento zero, C = v·H.
pub fn make_coinbase_shielded_output(a: &P1, b: &P1, r: &Sc, j: u64, v: u64) -> ShieldedOut {
    let rr = b.mul(r);
    let ss = a.mul(r).to_bytes();
    let k = hash_to_scalar(H::new("stealth/key").b(&ss).n(j));
    let p = mul_g(&k).add(b);
    let c = mul_h_u64(v);
    let mask = H::new("stealth/amount").b(&ss).n(j).d32();
    let mut enc = v.to_le_bytes();
    for i in 0..8 { enc[i] ^= mask[i]; }
    let tag = H::new("stealth/tag").b(&ss).n(j).d32()[0];
    ShieldedOut { r: rr, p, c, enc_amount: enc, view_tag: tag }
}

// ------------------------------------------------------------------ ML-DSA-44
pub const MLDSA_PUB_SIZE: usize = 1312;
pub const MLDSA_SIG_SIZE: usize = 2420;

pub fn mldsa_verify(pubk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};
    if pubk.len() != MLDSA_PUB_SIZE || sig.len() != MLDSA_SIG_SIZE { return false; }
    let Ok(ek) = EncodedVerifyingKey::<MlDsa44>::try_from(pubk) else { return false };
    let vk = VerifyingKey::<MlDsa44>::decode(&ek);
    let Ok(es) = EncodedSignature::<MlDsa44>::try_from(sig) else { return false };
    let Some(s) = Signature::<MlDsa44>::decode(&es) else { return false };
    vk.verify_with_context(msg, &[], &s)
}
