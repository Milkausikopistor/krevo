//! Wallet secret vault.
//!
//! The 32-byte seed enters here ONCE; from it come the spend key b, the view key a and
//! all derived keys (transparent, quantum-safe, multisig, swap, one-time keys of the
//! private outputs) — but none of them leaves. JavaScript gets a "handle" (a number) and asks for
//! operations: public key, signature, key image, CLSAG, FCMP ownership proof, the proof of
//! reserves DLEQ, ECDSA for Bitcoin. Exporting the view key is an explicit operation
//! (the user asks for it).
//!
//! Derivations identical to those of src/wallet/keys.js and src/crypto/stealth.js (checked in the tests):
//!   b = Hs("wallet/spend", s)   a = Hs("wallet/view", s)   x_t(i) = Hs("wallet/t", s, i)
//!   x_q(i) = Hs("wallet/q", s, i)   ML-DSA(i) = H("wallet/mldsa", s, i)   x_ms = Hs("wallet/multisig", s)
//!   swap: Hs("wallet/swap/krv"|"wallet/swap/btc", s, i), secret H("wallet/swap/secret", s, i)
//!   output: p = k + b + m_sub, m_0 = 0, m_i = Hs("stealth/subaddr", a, i); k comes from scanning
//!
//! Binary call format: handle (u32 LE) ‖ operation data. Key descriptor:
//!   [1|2|3|4|5|7] ‖ index u32 LE   (t, q, multisig, swap-krv, swap-btc, spend)
//!   [6] ‖ sub u32 LE ‖ k (32)        (one-time key of a private output)

use crate::crypto::*;
use crate::ct::ct_mul;
use crate::curve::P1;
use crate::fcmp::gsp_prove;
use crate::hash::H;
use crate::wallet_ops::*;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

pub struct Vault { seed: [u8; 32], b: Sc, a: Sc, bpub: P1 }

impl Drop for Vault {
    fn drop(&mut self) {
        for x in self.seed.iter_mut() { unsafe { std::ptr::write_volatile(x, 0) } }
        unsafe { std::ptr::write_volatile(&mut self.b, Sc::ZERO); std::ptr::write_volatile(&mut self.a, Sc::ZERO); }
    }
}

#[derive(Clone, Copy)]
enum Desc { T(u32), Q(u32), Ms, SwapKrv(u32), SwapBtc(u32), Spend, Out { k: Sc, sub: u32 } }

fn u32le(b: &[u8]) -> Result<u32, String> { Ok(u32::from_le_bytes(b.get(..4).ok_or("short input")?.try_into().unwrap())) }
fn sc(b: &[u8]) -> Result<Sc, String> { Sc::from_be_bytes(b.get(..32).ok_or("short input")?).ok_or_else(|| "scalar out of range".into()) }
fn pt(b: &[u8]) -> Result<P1, String> { P1::from_bytes(b.get(..33).ok_or("short input")?).ok_or_else(|| "invalid point".into()) }

/// Reads a descriptor; returns (descriptor, bytes consumed).
fn desc(b: &[u8]) -> Result<(Desc, usize), String> {
    let kind = *b.first().ok_or("missing descriptor")?;
    let i = u32le(&b[1..])?;
    Ok(match kind {
        1 => (Desc::T(i), 5), 2 => (Desc::Q(i), 5), 3 => (Desc::Ms, 5), 4 => (Desc::SwapKrv(i), 5), 5 => (Desc::SwapBtc(i), 5), 7 => (Desc::Spend, 5),
        6 => (Desc::Out { k: sc(b.get(5..).ok_or("short input")?)?, sub: i }, 37),
        _ => return Err("unknown key descriptor".into()),
    })
}

impl Vault {
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        let seed: [u8; 32] = seed.get(..32).ok_or("the seed must have 32 bytes")?.try_into().unwrap();
        let b = hash_to_scalar(H::new("wallet/spend").b(&seed));
        let a = hash_to_scalar(H::new("wallet/view").b(&seed));
        Ok(Vault { seed, b, a, bpub: mul_g_ct(&b) })
    }
    fn hs(&self, domain: &str, i: Option<u32>) -> Sc {
        let h = H::new(domain).b(&self.seed);
        hash_to_scalar(match i { Some(i) => h.n(i as u64), None => h })
    }
    fn sub_scalar(&self, i: u32) -> Sc {
        if i == 0 { Sc::ZERO } else { hash_to_scalar(H::new("stealth/subaddr").b(&self.a.to_be_bytes()).n(i as u64)) }
    }
    fn secret(&self, d: &Desc) -> Result<Sc, String> {
        let x = match *d {
            Desc::T(i) => self.hs("wallet/t", Some(i)),
            Desc::Q(i) => self.hs("wallet/q", Some(i)),
            Desc::Ms => self.hs("wallet/multisig", None),
            Desc::SwapKrv(i) => self.hs("wallet/swap/krv", Some(i)),
            Desc::SwapBtc(i) => self.hs("wallet/swap/btc", Some(i)),
            Desc::Spend => self.b,
            Desc::Out { k, sub } => k + self.b + self.sub_scalar(sub),
        };
        if x.is_zero() { return Err("zero key".into()); }
        Ok(x)
    }
    fn mldsa_seed(&self, i: u32) -> [u8; 32] { H::new("wallet/mldsa").b(&self.seed).n(i as u64).d32() }
    /// One-time key of an output, checked against the published P.
    fn out_key(&self, d: &Desc, p: &P1) -> Result<Sc, String> {
        if !matches!(d, Desc::Out { .. }) { return Err("operation only for private output keys".into()); }
        let x = self.secret(d)?;
        if !mul_g_ct(&x).eq(p) { return Err("the key does not match the output".into()); }
        Ok(x)
    }

    pub fn call(&self, op: u32, i: &[u8]) -> Result<Vec<u8>, String> {
        match op {
            // public key of a descriptor
            22 => { let (d, _) = desc(i)?; Ok(mul_g_ct(&self.secret(&d)?).to_bytes().to_vec()) }
            // subaddress i: D ‖ C
            23 => {
                let n = u32le(i)?;
                let m = self.sub_scalar(n);
                let d = if n == 0 { self.bpub } else { self.bpub.add(&mul_g_ct(&m)) };
                let c = ct_mul(&d, &self.a);
                Ok([d.to_bytes(), c.to_bytes()].concat())
            }
            // export the view key (explicit user request): a ‖ B
            24 => Ok([self.a.to_be_bytes().to_vec(), self.bpub.to_bytes().to_vec()].concat()),
            // shared secrets a·R of several outputs (scanning)
            25 => {
                if i.len() % 33 != 0 { return Err("invalid input".into()); }
                let mut out = Vec::with_capacity(i.len());
                for c in i.chunks(33) { out.extend_from_slice(&ct_mul(&pt(c)?, &self.a).to_bytes()); }
                Ok(out)
            }
            // Schnorr: descriptor ‖ len ‖ domain ‖ message
            26 => {
                let (d, o) = desc(i)?;
                if !matches!(d, Desc::T(_) | Desc::Q(_) | Desc::Ms | Desc::SwapKrv(_)) { return Err("this key does not sign Schnorr".into()); }
                let dl = *i.get(o).ok_or("short input")? as usize;
                let dom = std::str::from_utf8(i.get(o + 1..o + 1 + dl).ok_or("short input")?).map_err(|_| "invalid domain")?;
                Ok(schnorr_sign(&self.secret(&d)?, &i[o + 1 + dl..], dom)?.to_vec())
            }
            // ML-DSA-44: public key / signature of index i
            27 => Ok(mldsa_key(&self.mldsa_seed(u32le(i)?)).0),
            28 => { let n = u32le(i)?; mldsa_sign(&self.mldsa_seed(n), &i[4..]) }
            // key image: descriptor(output) ‖ P
            29 => { let (d, o) = desc(i)?; let p = pt(&i[o..])?; Ok(key_image(&self.out_key(&d, &p)?, &p).to_bytes().to_vec()) }
            // CLSAG: descriptor ‖ pi u32 ‖ z ‖ pseudo ‖ n u32 ‖ n × (P ‖ C) ‖ message
            30 => {
                let (d, mut o) = desc(i)?;
                let pi = u32le(&i[o..])? as usize; o += 4;
                let z = sc(&i[o..])?; o += 32;
                let pseudo = pt(&i[o..])?; o += 33;
                let n = u32le(&i[o..])? as usize; o += 4;
                if n == 0 || n > 1024 || pi >= n { return Err("invalid ring".into()); }
                let mut ring = Vec::with_capacity(n);
                for _ in 0..n { ring.push(RingMember { p: pt(&i[o..])?, c: pt(&i[o + 33..])? }); o += 66; }
                let p = self.out_key(&d, &ring[pi].p)?;
                clsag_sign(&i[o..], &ring, &pseudo, pi, &p, &z)
            }
            // FCMP ownership proof: descriptor ‖ ctx ‖ P̂ ‖ Î ‖ D ‖ P ‖ r1 ‖ (x − mask)
            31 => {
                let (d, mut o) = desc(i)?;
                let ctx: [u8; 32] = i.get(o..o + 32).ok_or("short input")?.try_into().unwrap(); o += 32;
                let (phat, ihat, dd, p) = (pt(&i[o..])?, pt(&i[o + 33..])?, pt(&i[o + 66..])?, pt(&i[o + 99..])?); o += 132;
                let (r1, aw) = (sc(&i[o..])?, sc(&i[o + 32..])?);
                let x = self.out_key(&d, &p)?;
                gsp_prove(&ctx, &phat, &ihat, &dd, [x, r1, x * x, x * r1, aw, r1])
            }
            // proof of reserves DLEQ: descriptor ‖ P ‖ I ‖ ctx → c ‖ s
            32 => {
                let (d, o) = desc(i)?;
                let (p, ki) = (pt(&i[o..])?, pt(&i[o + 33..])?);
                let ctx = i.get(o + 66..o + 98).ok_or("short input")?;
                dleq_prove(&self.out_key(&d, &p)?, &p, &ki, ctx)
            }
            // ECDSA (RFC 6979, low S) for Bitcoin: descriptor(swap-btc) ‖ hash → r ‖ s
            33 => {
                let (d, o) = desc(i)?;
                if !matches!(d, Desc::SwapBtc(_)) { return Err("this key does not sign ECDSA".into()); }
                let h: [u8; 32] = i.get(o..o + 32).ok_or("short input")?.try_into().unwrap();
                ecdsa_sign(&self.secret(&d)?, &h)
            }
            // derived values that MAY leave (closed list): 1 = name salt, 2 = swap secret
            34 => match i.first() {
                Some(1) => {
                    let n = u64::from_le_bytes(i.get(1..9).ok_or("short input")?.try_into().unwrap());
                    let name = std::str::from_utf8(&i[9..]).map_err(|_| "invalid name")?;
                    Ok(H::new("wallet/name/salt").b(&self.seed).s(name).n(n).d32().to_vec())
                }
                Some(2) => Ok(H::new("wallet/swap/secret").b(&self.seed).n(u32le(&i[1..])? as u64).d32().to_vec()),
                _ => Err("derivation not allowed".into()),
            },
            // encrypts/decrypts wallet data at rest (key derived from the seed)
            35 | 36 => {
                use aes_gcm::aead::{Aead, KeyInit};
                use aes_gcm::{Aes256Gcm, Nonce};
                let key = H::new("wallet/store").b(&self.seed).d32();
                let c = Aes256Gcm::new_from_slice(&key).map_err(|_| "key")?;
                if op == 35 {
                    let mut iv = [0u8; 12];
                    getrandom::fill(&mut iv).map_err(|_| "randomness unavailable")?;
                    let mut out = iv.to_vec();
                    out.extend(c.encrypt(Nonce::from_slice(&iv), i).map_err(|_| "encryption failed")?);
                    Ok(out)
                } else {
                    if i.len() < 28 { return Err("encrypted data too short".into()); }
                    c.decrypt(Nonce::from_slice(&i[..12]), &i[12..]).map_err(|_| "wallet data corrupted or from another seed".into())
                }
            }
            _ => Err(format!("unknown vault operation: {op}")),
        }
    }
}

// ------------------------------------------------------------------ signatures that use the vault
/// CLSAG (mirrors clsagSign from src/crypto/clsag.js): hedged nonce, checked before returning.
/// Output: c0 ‖ s_0 … s_{n−1} ‖ I ‖ D.
pub fn clsag_sign(msg: &[u8], ring: &[RingMember], pseudo: &P1, pi: usize, p: &Sc, z: &Sc) -> Result<Vec<u8>, String> {
    let n = ring.len();
    let hp_pi = hash_point_for_key_image(&ring[pi].p);
    if !mul_g_ct(z).eq(&ring[pi].c.sub(pseudo)) { return Err("clsag: commitment does not match".into()); }
    let ki = ct_mul(&hp_pi, p);
    let dd = ct_mul(&hp_pi, z);
    let ring_p: Vec<u8> = ring.iter().flat_map(|m| m.p.to_bytes()).collect();
    let ring_c: Vec<u8> = ring.iter().flat_map(|m| m.c.to_bytes()).collect();
    let (kib, db, pb) = (ki.to_bytes(), dd.to_bytes(), pseudo.to_bytes());
    let mu_p = hash_to_scalar(H::new("clsag/agg0").b(&ring_p).b(&ring_c).b(&kib).b(&db).b(&pb));
    let mu_c = hash_to_scalar(H::new("clsag/agg1").b(&ring_p).b(&ring_c).b(&kib).b(&db).b(&pb));
    let prefix = H::new("clsag/prefix").b(&ring_p).b(&ring_c).b(&pb).d32();
    let wt = ki.mul(&mu_p).add(&dd.mul(&mu_c));
    let w = mu_p * *p + mu_c * *z;
    let round = |l: &P1, r: &P1| hash_to_scalar(H::new("clsag/round").b(&prefix).b(msg).b(&l.to_bytes()).b(&r.to_bytes()));
    let alpha = hedged("clsag/alpha", &[&p.to_be_bytes(), &z.to_be_bytes()], &[msg, &kib, &pb].concat());
    let mut c = vec![Sc::ZERO; n];
    let mut s = vec![Sc::ZERO; n];
    c[(pi + 1) % n] = round(&mul_g_ct(&alpha), &ct_mul(&hp_pi, &alpha));
    for k in 1..n {
        let i = (pi + k) % n;
        s[i] = Sc::random(); // fake responses of the other members: public
        let l = mul_g(&s[i]).add(&ring[i].p.mul(&(c[i] * mu_p))).add(&ring[i].c.sub(pseudo).mul(&(c[i] * mu_c)));
        let r = hash_point_for_key_image(&ring[i].p).mul(&s[i]).add(&wt.mul(&c[i]));
        c[(i + 1) % n] = round(&l, &r);
    }
    s[pi] = alpha - c[pi] * w;
    let mut sig = c[0].to_be_bytes().to_vec();
    for x in &s { sig.extend_from_slice(&x.to_be_bytes()); }
    sig.extend_from_slice(&db);
    if !clsag_verify(msg, ring, pseudo, &sig, &ki) { return Err("clsag: signing failed (verification)".into()); }
    let mut out = sig[..32 + 32 * n].to_vec();
    out.extend_from_slice(&kib);
    out.extend_from_slice(&db);
    Ok(out)
}

/// Proof of reserves DLEQ (mirrors src/wallet/reserves.js): log_G(P) = log_Hp(P)(I). Output c ‖ s.
pub fn dleq_prove(p: &Sc, pk: &P1, ki: &P1, ctx: &[u8]) -> Result<Vec<u8>, String> {
    let hp = hash_point_for_key_image(pk);
    let k = hedged("reserves/nonce", &[&p.to_be_bytes()], &[ctx, &pk.to_bytes(), &ki.to_bytes()].concat());
    let (a, b) = (mul_g_ct(&k), ct_mul(&hp, &k));
    let chal = |a: &P1, b: &P1| hash_to_scalar(H::new("reserves/dleq").b(ctx).b(&pk.to_bytes()).b(&ki.to_bytes()).b(&a.to_bytes()).b(&b.to_bytes()));
    let c = chal(&a, &b);
    let s = k - c * *p;
    // checks: s·G + c·P = A and s·Hp + c·I = B
    if chal(&mul_g(&s).add(&pk.mul(&c)), &hp.mul(&s).add(&ki.mul(&c))) != c { return Err("proof of reserves failed (verification)".into()); }
    Ok([c.to_be_bytes(), s.to_be_bytes()].concat())
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut k = [0u8; 64];
    if key.len() > 64 { k[..32].copy_from_slice(&Sha256::digest(key)); } else { k[..key.len()].copy_from_slice(key); }
    let mut inner = Sha256::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    for p in parts { inner.update(p); }
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(ih);
    outer.finalize().into()
}

/// ECDSA with an RFC 6979 nonce and low S — the SAME bytes as src/btc/ecdsa.js. Output r ‖ s.
pub fn ecdsa_sign(x: &Sc, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let xb = x.to_be_bytes();
    let z = Sc::from_be_bytes_reduce(hash);
    let hb = z.to_be_bytes();
    let (mut v, mut k) = ([1u8; 32], [0u8; 32]);
    k = hmac_sha256(&k, &[&v, &[0], &xb, &hb]); v = hmac_sha256(&k, &[&v]);
    k = hmac_sha256(&k, &[&v, &[1], &xb, &hb]); v = hmac_sha256(&k, &[&v]);
    let nonce = loop {
        v = hmac_sha256(&k, &[&v]);
        if let Some(n) = Sc::from_be_bytes(&v) { if !n.is_zero() { break n; } }
        k = hmac_sha256(&k, &[&v, &[0]]); v = hmac_sha256(&k, &[&v]);
    };
    let rp = mul_g_ct(&nonce);
    let (rx, _) = rp.affine().ok_or("point at infinity")?;
    let r = Sc::from_be_bytes_reduce(&rx.to_be_bytes());
    let mut s = nonce.invert() * (z + r * *x);
    if r.is_zero() || s.is_zero() { return Err("degenerate signature".into()); }
    let neg = -s;
    // low S: picks the smaller of s and n − s (comparing values already public in the signature)
    if !crate::field::lt4(&be_limbs(&s.to_be_bytes()), &be_limbs(&neg.to_be_bytes())) { s = neg; }
    // checks: R' = z/s·G + r/s·P, r == R'.x mod n
    let si = s.invert();
    let rr = mul_g(&(z * si)).add(&mul_g_ct(x).mul(&(r * si))); // x only in constant time
    match rr.affine() {
        Some((xx, _)) if Sc::from_be_bytes_reduce(&xx.to_be_bytes()) == r => {}
        _ => return Err("ECDSA signing failed (verification)".into()),
    }
    Ok([r.to_be_bytes(), s.to_be_bytes()].concat())
}
fn be_limbs(b: &[u8; 32]) -> [u64; 4] { crate::field::be_to_limbs(b) }

// ------------------------------------------------------------------ handles
fn table() -> MutexGuard<'static, (u32, BTreeMap<u32, Vault>)> {
    static T: Mutex<(u32, BTreeMap<u32, Vault>)> = Mutex::new((0, BTreeMap::new()));
    T.lock().unwrap_or_else(|e| e.into_inner())
}

/// Operations 20–36 (see the header). 20 opens (seed → handle), 21 closes (wipes).
pub fn vault_call(op: u32, i: &[u8]) -> Result<Vec<u8>, String> {
    let mut t = table();
    match op {
        20 => {
            let v = Vault::new(i)?;
            t.0 = t.0.wrapping_add(1).max(1);
            let h = t.0;
            t.1.insert(h, v);
            Ok(h.to_le_bytes().to_vec())
        }
        21 => { t.1.remove(&u32le(i)?); Ok(vec![]) }
        _ => {
            let h = u32le(i)?;
            let v = t.1.get(&h).ok_or("vault closed or nonexistent")?;
            v.call(op, &i[4..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(seed: &[u8; 32]) -> Vec<u8> { vault_call(20, seed).unwrap() }

    #[test]
    fn derivations_and_signatures() {
        let h = open(&[7u8; 32]);
        let call = |op: u32, data: &[u8]| { let mut v = h.clone(); v.extend_from_slice(data); vault_call(op, &v) };
        // transparent key 0: signs and verifies
        let p = P1::from_bytes(&call(22, &[1, 0, 0, 0, 0]).unwrap()).unwrap();
        let mut req = vec![1, 0, 0, 0, 0, 3];
        req.extend_from_slice(b"sigmessage");
        let sig = call(26, &req).unwrap();
        assert!(schnorr_verify(&p, b"message", &sig, "sig"));
        // output keys do not sign Schnorr; a derivation outside the closed list is refused
        assert!(call(26, &[7, 0, 0, 0, 0, 3, b's', b'i', b'g']).is_err());
        assert!(call(34, &[9]).is_err());
        // private output: P = (k + b + m)·G; key image and DLEQ
        let k = Sc::random();
        let sub = u32::to_le_bytes(3);
        let dc = call(23, &sub).unwrap();
        let d = P1::from_bytes(&dc[..33]).unwrap();
        let out_p = mul_g(&k).add(&d);
        let mut dsc = vec![6];
        dsc.extend_from_slice(&sub);
        dsc.extend_from_slice(&k.to_be_bytes());
        let ki = P1::from_bytes(&call(29, &[dsc.clone(), out_p.to_bytes().to_vec()].concat()).unwrap()).unwrap();
        let ctx = [5u8; 32];
        assert!(call(32, &[dsc.clone(), out_p.to_bytes().to_vec(), ki.to_bytes().to_vec(), ctx.to_vec()].concat()).is_ok());
        // wrong P: refused
        assert!(call(29, &[dsc, mul_g(&k).to_bytes().to_vec()].concat()).is_err());
        // swap ECDSA: valid signature
        let mut e = vec![5, 2, 0, 0, 0];
        e.extend_from_slice(&[9u8; 32]);
        assert_eq!(call(33, &e).unwrap().len(), 64);
        // encryption at rest
        let blob = call(35, b"private data").unwrap();
        assert_eq!(call(36, &blob).unwrap(), b"private data");
        // closed: nothing works anymore
        vault_call(21, &h).unwrap();
        assert!(call(22, &[1, 0, 0, 0, 0]).is_err());
    }
}
