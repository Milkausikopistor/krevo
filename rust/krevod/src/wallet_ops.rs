//! Wallet operations with SECRETS, in constant time (shared by the node and by the
//! wallets' WebAssembly module):
//!   • Schnorr with a "hedged" nonce (deterministic + random) and verification after signing;
//!   • commitments and multiplications by secret scalars (spend key, view
//!     key, masks) in constant time;
//!   • range proof (Bulletproofs) and full FCMP proof, self-checked before returning.
//! A hardware or memory fault during signing could leak the key; verifying the
//! result before returning it prevents a faulty signature from leaving the device.

use crate::crypto::*;
use crate::ct::{ct_mul, CtFixed, PP};
use crate::curve::*;
use crate::fcmp::*;
use crate::hash::H;
use std::sync::OnceLock;

fn g_ct() -> &'static CtFixed<Secp> { static T: OnceLock<CtFixed<Secp>> = OnceLock::new(); T.get_or_init(|| CtFixed::new(&g())) }
fn h_ct() -> &'static CtFixed<Secp> { static T: OnceLock<CtFixed<Secp>> = OnceLock::new(); T.get_or_init(|| CtFixed::new(&hv())) }

/// k·G in constant time.
pub fn mul_g_ct(k: &Sc) -> P1 { g_ct().mul(k) }
/// k·H (value generator) in constant time.
pub fn mul_h_ct(k: &Sc) -> P1 { h_ct().mul(k) }
/// C = x·G + v·H in constant time.
pub fn commit_ct(v: &Sc, x: &Sc) -> P1 { mul_g_ct(x).add(&mul_h_ct(v)) }
/// k·P in constant time (public P).
pub fn mul_ct(p: &P1, k: &Sc) -> P1 { ct_mul(p, k) }
/// Key image p·Hp(P).
pub fn key_image(p: &Sc, pk: &P1) -> P1 { ct_mul(&hash_point_for_key_image(pk), p) }

fn rand32() -> [u8; 32] { let mut b = [0u8; 32]; getrandom::fill(&mut b).expect("system randomness"); b }

/// "Hedged" nonce: safe even with a faulty random generator (it becomes deterministic) and even with
/// a determinism fault (the randomness protects against fault attacks).
pub fn hedged(domain: &str, secret: &[&[u8]], msg: &[u8]) -> Sc {
    for ctr in 0u64.. {
        let mut h = H::new(domain);
        for s in secret { h = h.b(s); }
        let k = hash_to_scalar(h.b(msg).b(&rand32()).n(ctr));
        if !k.is_zero() { return k; }
    }
    unreachable!()
}

/// Schnorr signature (e, s) — same format as src/crypto/schnorr.js.
pub fn schnorr_sign(x: &Sc, msg: &[u8], domain: &str) -> Result<[u8; 64], String> {
    if x.is_zero() { return Err("zero secret key".into()); }
    let p = mul_g_ct(x);
    let pb = p.to_bytes();
    let dom = format!("schnorr/{domain}");
    for _ in 0..16 {
        let k = hedged("schnorr/nonce", &[&x.to_be_bytes(), &pb], msg);
        let r = mul_g_ct(&k);
        let e = hash_to_scalar(H::new(&dom).b(&r.to_bytes()).b(&pb).b(msg));
        if e.is_zero() { continue; }
        let s = k + e * *x;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&e.to_be_bytes());
        sig[32..].copy_from_slice(&s.to_be_bytes());
        if !schnorr_verify(&p, msg, &sig, domain) { return Err("signing failed (verification of the signature itself)".into()); }
        return Ok(sig);
    }
    Err("could not sign".into())
}

// ------------------------------------------------------------------ range proof
fn inner(a: &[Sc], b: &[Sc]) -> Sc { a.iter().zip(b).fold(Sc::ZERO, |s, (x, y)| s + *x * *y) }

/// Aggregated proof that each v ∈ [0, 2⁶⁴) (mirrors proveRange from src/crypto/bulletproofs.js).
/// Returns (commitments V, proof). Self-checked.
pub fn range_prove(values: &[u64], gammas: &[Sc]) -> Result<(Vec<P1>, Vec<u8>), String> {
    let m0 = values.len();
    if m0 < 1 || m0 > BP_MAX_AGG || gammas.len() != m0 { return Err("bp: invalid number of values".into()); }
    let m = m0.next_power_of_two();
    let nn = BP_BITS * m;
    let (gi, hi, ub) = bp_ensure(nn);
    let mut v = values.to_vec();
    v.resize(m, 0);
    let mut gamma = gammas.to_vec();
    gamma.resize(m, Sc::ZERO);
    let vs: Vec<P1> = (0..m0).map(|j| commit_ct(&Sc::from_u64(v[j]), &gamma[j])).collect();
    let one = Sc::ONE;
    let mut al = vec![Sc::ZERO; nn];
    let mut ar = vec![Sc::ZERO; nn];
    let mut bits = vec![0u64; nn];
    for j in 0..m { for i in 0..BP_BITS { let b = (v[j] >> i) & 1; bits[j * BP_BITS + i] = b; al[j * BP_BITS + i] = Sc::from_u64(b); ar[j * BP_BITS + i] = Sc::from_u64(b) - one; } }
    // Nonces from a "hedged" seed (masks + values + commitments + randomness): even with a
    // broken random generator, nothing repeats across different proofs, and values do not leak.
    let secret: Vec<u8> = gamma.iter().flat_map(|g| g.to_be_bytes()).chain(v.iter().flat_map(|x| x.to_le_bytes())).collect();
    let publics: Vec<u8> = vs.iter().flat_map(|p| p.to_bytes()).collect();
    let seed = hedged("bp/seed", &[&secret], &publics).to_be_bytes();
    let nonce = |tag: &str, i: usize| -> Sc { hash_to_scalar(H::new("bp/nonce").b(&seed).b(tag.as_bytes()).n(i as u64)) };
    let (alpha, rho) = (nonce("alpha", 0), nonce("rho", 0));
    let sl: Vec<Sc> = (0..nn).map(|i| nonce("sL", i)).collect();
    let sr: Vec<Sc> = (0..nn).map(|i| nonce("sR", i)).collect();
    // A = α·G + Σ bit·G_i − Σ (1 − bit)·H_i — complete additions chosen by mask (secret bits)
    let mut acc = PP::from_pt(&mul_g_ct(&alpha));
    for i in 0..nn {
        let mask = crate::field::ct_mask(bits[i]);
        acc = acc.add(&PP::select(&PP::identity(), &PP::from_pt(&gi[i]), mask));
        acc = acc.add(&PP::select(&PP::from_pt(&hi[i]).neg(), &PP::identity(), mask));
    }
    let a = acc.to_pt();
    let mut ks = vec![rho];
    ks.extend(&sl);
    ks.extend(&sr);
    let mut ps = vec![g()];
    ps.extend(&gi);
    ps.extend(&hi);
    let s = msm(&ks, &ps); // random vectors: variable timing does not reveal the witness

    let mut tr = BpTr::new("rangeproof");
    tr.add("bits", TrX::N(BP_BITS as u64));
    tr.add("m", TrX::N(m0 as u64));
    for x in &vs { tr.add("V", TrX::P(x)); }
    tr.add("A", TrX::P(&a));
    tr.add("S", TrX::P(&s));
    let y = tr.ch("y").ok_or("zero challenge")?;
    let z = tr.ch("z").ok_or("zero challenge")?;
    let mut yp = vec![Sc::ONE; nn];
    for i in 1..nn { yp[i] = yp[i - 1] * y; }
    let mut zp = vec![Sc::ONE; m + 3];
    for i in 1..m + 3 { zp[i] = zp[i - 1] * z; }
    let mut two = vec![Sc::ONE; BP_BITS];
    for i in 1..BP_BITS { two[i] = two[i - 1].double(); }
    let mut l0 = vec![Sc::ZERO; nn];
    let mut r0 = vec![Sc::ZERO; nn];
    let mut r1 = vec![Sc::ZERO; nn];
    for i in 0..nn {
        let j = i / BP_BITS;
        l0[i] = al[i] - z;
        r0[i] = yp[i] * (ar[i] + z) + zp[2 + j] * two[i % BP_BITS];
        r1[i] = yp[i] * sr[i];
    }
    let t1 = inner(&l0, &r1) + inner(&sl, &r0);
    let t2 = inner(&sl, &r1);
    let (tau1, tau2) = (nonce("tau1", 0), nonce("tau2", 0));
    let tp1 = commit_ct(&t1, &tau1);
    let tp2 = commit_ct(&t2, &tau2);
    tr.add("T1", TrX::P(&tp1));
    tr.add("T2", TrX::P(&tp2));
    let x = tr.ch("x").ok_or("zero challenge")?;
    let mut taux = tau2 * x * x + tau1 * x;
    for j in 0..m { taux = taux + zp[2 + j] * gamma[j]; }
    let mu = alpha + rho * x;
    let l: Vec<Sc> = (0..nn).map(|i| l0[i] + sl[i] * x).collect();
    let r: Vec<Sc> = (0..nn).map(|i| r0[i] + r1[i] * x).collect();
    let that = inner(&l, &r);
    tr.add("taux", TrX::S(&taux));
    tr.add("mu", TrX::S(&mu));
    tr.add("that", TrX::S(&that));
    let w = tr.ch("w").ok_or("zero challenge")?;
    let q = ub.mul(&w);
    let yinv = y.invert();
    let mut ypinv = vec![Sc::ONE; nn];
    for i in 1..nn { ypinv[i] = ypinv[i - 1] * yinv; }
    let mut gv = gi.clone();
    let mut hvv: Vec<P1> = hi.iter().zip(&ypinv).map(|(h, k)| h.mul(k)).collect();
    let (mut av, mut bv) = (l, r);
    let (mut ls, mut rs) = (vec![], vec![]);
    while av.len() > 1 {
        let h2 = av.len() / 2;
        let cl = inner(&av[..h2], &bv[h2..]);
        let cr = inner(&av[h2..], &bv[..h2]);
        let mut k1: Vec<Sc> = av[..h2].to_vec(); k1.extend(&bv[h2..]); k1.push(cl);
        let mut p1: Vec<P1> = gv[h2..].to_vec(); p1.extend(&hvv[..h2]); p1.push(q);
        let lk = msm(&k1, &p1);
        let mut k2: Vec<Sc> = av[h2..].to_vec(); k2.extend(&bv[..h2]); k2.push(cr);
        let mut p2: Vec<P1> = gv[..h2].to_vec(); p2.extend(&hvv[h2..]); p2.push(q);
        let rk = msm(&k2, &p2);
        tr.add("L", TrX::P(&lk));
        tr.add("R", TrX::P(&rk));
        ls.push(lk);
        rs.push(rk);
        let u = tr.ch("u").ok_or("zero challenge")?;
        let ui = u.invert();
        gv = (0..h2).map(|i| gv[i].mul(&ui).add(&gv[h2 + i].mul(&u)).normalize()).collect();
        hvv = (0..h2).map(|i| hvv[i].mul(&u).add(&hvv[h2 + i].mul(&ui)).normalize()).collect();
        av = (0..h2).map(|i| av[i] * u + av[h2 + i] * ui).collect();
        bv = (0..h2).map(|i| bv[i] * ui + bv[h2 + i] * u).collect();
    }
    let mut proof = vec![];
    for p in [&a, &s, &tp1, &tp2] { proof.extend_from_slice(&p.to_bytes()); }
    for k in [&taux, &mu, &that] { proof.extend_from_slice(&k.to_be_bytes()); }
    for k in 0..ls.len() { proof.extend_from_slice(&ls[k].to_bytes()); proof.extend_from_slice(&rs[k].to_bytes()); }
    proof.extend_from_slice(&av[0].to_be_bytes());
    proof.extend_from_slice(&bv[0].to_be_bytes());
    if !verify_range(&vs, &proof) { return Err("range proof failed (self-check)".into()); }
    Ok((vs, proof))
}

// ------------------------------------------------------------------ full FCMP proof
/// Full proof of an input (the two halves + the ownership proof), self-checked.
/// p: one-time key; x, v: blinding and amount of the commitment; pseudo_mask; msg = sighash.
/// Returns (proof, key image, pseudo-commitment).
pub fn fcmp_prove_full(job: &ProveJob, p: &Sc, x: &Sc, v: u64, pseudo_mask: &Sc, msg: &[u8]) -> Result<(Vec<u8>, [u8; 33], [u8; 33]), String> {
    let (head, phat, ihat, chat, root) = prover_statement(job)?;
    let e1 = prove_half(job, Half::E1)?;
    let e2 = prove_half(job, Half::E2)?;
    let mut bps = e1;
    bps.extend(e2);
    let pk = P1::from_bytes(&job.p).ok_or("invalid output")?;
    let ki = key_image(p, &pk);
    let pseudo = commit_ct(&Sc::from_u64(v), pseudo_mask);
    let d = chat.sub(&pseudo);
    let ctx = H::new("fcmp/ctx").b(msg).b(&head).b(&bps).b(&pseudo.to_bytes()).b(&ki.to_bytes()).d32();
    let r1 = job.r1;
    let gsp = gsp_prove(&ctx, &phat, &ihat, &d, [*p, r1, *p * *p, *p * r1, *x - *pseudo_mask, r1])?;
    let mut proof = head;
    proof.extend(bps);
    proof.extend(gsp);
    let mut batch = FcmpBatch::new();
    fcmp_verify_into(&mut batch, job.branch, job.n, &root, &proof, &ki, &pseudo, msg)?;
    if !batch.check() { return Err("membership proof failed (self-check)".into()); }
    Ok((proof, ki.to_bytes(), pseudo.to_bytes()))
}

// ------------------------------------------------------------------ ML-DSA-44 (FIPS 204)
/// Key from the seed ξ (ML-DSA.KeyGen_internal) — the same as OpenSSL's with a "seed only" PKCS#8.
pub fn mldsa_key(seed: &[u8]) -> (Vec<u8>, ml_dsa::SigningKey<ml_dsa::MlDsa44>) {
    use ml_dsa::{Keypair, MlDsa44, Seed, SigningKey};
    let xi: Seed = Seed::try_from(seed).expect("32 bytes");
    let sk = SigningKey::<MlDsa44>::from_seed(&xi);
    (sk.verifying_key().encode().to_vec(), sk)
}
/// "Hedged" ML-DSA signature (FIPS 204, algorithm 2, empty context), checked before returning.
pub fn mldsa_sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let (pk, sk) = mldsa_key(seed);
    let mut rnd = [0u8; 32];
    getrandom::fill(&mut rnd).map_err(|_| "randomness unavailable")?;
    let rnd = ml_dsa::B32::try_from(&rnd[..]).expect("32 bytes");
    // M' = 0 ‖ |ctx| ‖ ctx ‖ M, with an empty ctx ("pure" signature, like OpenSSL)
    let sig = sk.expanded_key().sign_internal(&[&[0u8, 0u8], msg], &rnd).encode().to_vec();
    if !crate::crypto::mldsa_verify(&pk, msg, &sig) { return Err("signing failed (ML-DSA)".into()); }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fe;

    #[test]
    fn schnorr_and_range_proofs() {
        let x = Sc::random();
        let sig = schnorr_sign(&x, b"message", "sig").unwrap();
        assert!(schnorr_verify(&mul_g(&x), b"message", &sig, "sig"));
        assert!(!schnorr_verify(&mul_g(&x), b"other", &sig, "sig"));
        let (vs, proof) = range_prove(&[5000, 7, u64::MAX], &[Sc::random(), Sc::random(), Sc::random()]).unwrap();
        assert!(verify_range(&vs, &proof));
        assert!(mul_ct(&g(), &x).eq(&mul_g(&x)) && mul_h_ct(&x).eq(&hv().mul(&x)));
    }

    #[test]
    fn full_fcmp_proof() {
        let branch = 4;
        let outs: Vec<(Sc, Sc, u64)> = (0..21u64).map(|i| (Sc::random(), Sc::random(), 1000 + i)).collect();
        let bytes: Vec<([u8; 33], [u8; 33])> = outs.iter().map(|(p, x, v)| (mul_g(p).to_bytes(), commit(*v, x).to_bytes())).collect();
        let leaf = |i: u64| -> ([u8; 32], [u8; 33], [u8; 33]) { let mut k = [0u8; 32]; k[..8].copy_from_slice(&i.to_le_bytes()); (k, bytes[i as usize].0, bytes[i as usize].1) };
        let mut tree = CurveTree::new(branch);
        let (n, i) = (21u64, 6usize);
        let path = tree.path_for_chunk(&leaf, n, (i / branch) as u64).unwrap();
        let job = ProveJob { branch, n, path, leaf_pos: i % branch, p: bytes[i].0, c: bytes[i].1, r1: Fe::random(), r2: Fe::random() };
        let (p, x, v) = outs[i];
        let pm = Sc::random();
        let (proof, ki, pseudo) = fcmp_prove_full(&job, &p, &x, v, &pm, b"sighash").unwrap();
        assert_eq!(proof.len(), fcmp_proof_size(n, branch));
        assert_eq!(ki, key_image(&p, &mul_g(&p)).to_bytes());
        let root = tree.root(&leaf, n);
        let mut b = FcmpBatch::new();
        fcmp_verify_into(&mut b, branch, n, &root, &proof, &P1::from_bytes(&ki).unwrap(), &P1::from_bytes(&pseudo).unwrap(), b"sighash").unwrap();
        assert!(b.check());
    }
}
