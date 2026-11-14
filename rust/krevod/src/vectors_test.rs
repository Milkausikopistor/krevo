//! Conferência contra vetores gerados pelo nó de referência em JavaScript
//! (vectors/gen.mjs → vectors/vectors.json).

use crate::bytes::{from_hex, to_hex};
use crate::crypto::*;
use crate::curve::P1;
use crate::field::*;
use crate::hash::H;
use serde_json::Value;

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("rode: node vectors/gen.mjs")).unwrap()
}
fn hx(v: &Value) -> Vec<u8> { from_hex(v.as_str().unwrap()).unwrap() }
fn pt(v: &Value) -> P1 { P1::from_bytes(&hx(v)).unwrap() }
fn sc_hex(s: &str) -> Sc { let mut b = [0u8; 32]; let v = from_hex(&format!("{:0>64}", s)).unwrap(); b.copy_from_slice(&v); Sc::from_be_bytes_reduce(&b) }

#[test]
fn primitives_match_javascript() {
    let v = vectors();
    let h64 = H::new("teste").s("abc").b(&[1, 2, 3]).n(42).d64();
    assert_eq!(to_hex(&h64), v["hash"]["h64"].as_str().unwrap());
    assert_eq!(to_hex(&H::new("vazio").d32()), v["hash"]["h"].as_str().unwrap());
    assert_eq!(to_hex(&hv().to_bytes()), v["pedersen"]["hv"].as_str().unwrap());
    assert_eq!(to_hex(&commit(123456789, &Sc::from_u64(987654321)).to_bytes()), v["pedersen"]["commit"].as_str().unwrap());
    assert_eq!(to_hex(&mul_g(&sc_hex(v["mulG"]["k"].as_str().unwrap())).to_bytes()), v["mulG"]["p"].as_str().unwrap());
}

#[test]
fn signatures_match_javascript() {
    let v = vectors();
    let s = &v["schnorr"];
    let (p, msg) = (pt(&s["p"]), hx(&s["msg"]));
    assert!(schnorr_verify(&p, &msg, &hx(&s["sig"]), "sig"));
    assert!(schnorr_verify(&p, &msg, &hx(&s["binding"]), "binding"));
    assert!(!schnorr_verify(&p, &msg, &hx(&s["binding"]), "sig"));
    assert!(!schnorr_verify(&p, b"outra", &hx(&s["sig"]), "sig"));

    let c = &v["clsag"];
    let ring: Vec<RingMember> = c["ring"].as_array().unwrap().iter().map(|m| RingMember { p: pt(&m["P"]), c: pt(&m["C"]) }).collect();
    assert_eq!(to_hex(&hash_point_for_key_image(&ring[0].p).to_bytes()), c["hp"].as_str().unwrap());
    let ki = pt(&c["ki"]);
    assert!(clsag_verify(&hx(&c["msg"]), &ring, &pt(&c["pseudo"]), &hx(&c["sig"]), &ki));
    assert!(!clsag_verify(b"outra", &ring, &pt(&c["pseudo"]), &hx(&c["sig"]), &ki));

    let m = &v["mldsa"];
    assert!(mldsa_verify(&hx(&m["pub"]), &hx(&m["msg"]), &hx(&m["sig"])), "ML-DSA-44 do OpenSSL verifica em Rust");
    assert!(!mldsa_verify(&hx(&m["pub"]), b"outra", &hx(&m["sig"])));
}

#[test]
fn range_muhash_stealth_match_javascript() {
    let v = vectors();
    let r = &v["range"];
    let vs: Vec<P1> = r["V"].as_array().unwrap().iter().map(pt).collect();
    let proof = hx(&r["proof"]);
    assert!(verify_range(&vs, &proof));
    let mut bad = proof.clone();
    bad[150] ^= 1;
    assert!(!verify_range(&vs, &bad));
    assert!(!verify_range(&[vs[1], vs[0]], &proof));

    let mut mh = MuHash::new();
    mh.add(b"a"); mh.add(b"b"); mh.remove(b"a");
    assert_eq!(to_hex(&mh.digest()), v["muhash"].as_str().unwrap());

    let s = &v["stealth"];
    let o = make_coinbase_shielded_output(&pt(&s["A"]), &pt(&s["B"]), &sc_hex(s["r"].as_str().unwrap()), 1, 5_000_000_000);
    assert_eq!(to_hex(&o.r.to_bytes()), s["R"].as_str().unwrap());
    assert_eq!(to_hex(&o.p.to_bytes()), s["P"].as_str().unwrap());
    assert_eq!(to_hex(&o.c.to_bytes()), s["C"].as_str().unwrap());
    assert_eq!(to_hex(&o.enc_amount), s["enc"].as_str().unwrap());
    assert_eq!(o.view_tag as u64, s["tag"].as_u64().unwrap());
    let _ = FeP::ONE;
}

#[test]
fn pow_emission_targets_match_javascript() {
    use crate::pow::*;
    use crate::rules::*;
    let v = vectors();
    let p = &v["pow"];
    let pre: [u8; 32] = hx(&p["prepow"]).try_into().unwrap();
    let st = PowState::new(pre);
    assert_eq!(to_hex(&st.hash(p["ts"].as_u64().unwrap(), p["nonce"].as_str().unwrap().parse().unwrap())), p["hash"].as_str().unwrap());
    let dp = crate::params::get_params("devnet").unwrap();
    for e in v["emission"].as_array().unwrap() {
        let m: u64 = e["month"].as_str().unwrap().parse().unwrap();
        assert_eq!(subsidy_for_month(m, &dp).to_string(), e["subsidy"].as_str().unwrap(), "mês {m}");
    }
    assert_eq!(capped_subsidy(0, crate::params::MAX_SUPPLY - 5, &dp).to_string(), v["capped"].as_str().unwrap());
    for t in v["targets"].as_array().unwrap() {
        let bits = t["bits"].as_u64().unwrap() as u32;
        let tg = compact_to_target(bits).unwrap();
        assert_eq!(tg.to_str_radix(16), t["target"].as_str().unwrap());
        assert_eq!(target_to_compact(&tg) as u64, t["back"].as_u64().unwrap());
        assert_eq!(calc_work(bits).to_string(), t["work"].as_str().unwrap());
    }
}

#[test]
fn fcmp_matches_javascript() {
    use crate::fcmp::*;
    let v = vectors();
    let f = &v["fcmp"];
    let branch = f["branch"].as_u64().unwrap() as usize;
    let outs: Vec<([u8; 33], [u8; 33])> = f["outputs"].as_array().unwrap().iter()
        .map(|o| (hx(&o["P"]).try_into().unwrap(), hx(&o["C"]).try_into().unwrap())).collect();
    let leaf = |i: u64| -> ([u8; 32], [u8; 33], [u8; 33]) {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&i.to_le_bytes());
        (k, outs[i as usize].0, outs[i as usize].1)
    };
    let mut tree = CurveTree::new(branch);
    for c in f["cases"].as_array().unwrap() {
        let n = c["N"].as_u64().unwrap();
        let root = tree.root(&leaf, n);
        let rb = match &root.point { NodePt::E1(p) => to_hex(&p.to_bytes()), NodePt::E2(p) => to_hex(&p.to_bytes()) };
        assert_eq!(rb, c["root"].as_str().unwrap(), "raiz N={n}");
        assert_eq!(root.count as u64, c["count"].as_u64().unwrap());
        let proof = hx(&c["proof"]);
        let (ki, pseudo, msg) = (pt(&c["ki"]), pt(&c["pseudo"]), hx(&c["msg"]));
        let t = std::time::Instant::now();
        let mut b = FcmpBatch::new();
        fcmp_verify_into(&mut b, branch, n, &root, &proof, &ki, &pseudo, &msg).expect("prova estruturalmente válida");
        assert!(b.check(), "prova FCMP do JavaScript aceita em Rust (N={n})");
        eprintln!("FCMP N={n}: verificada em {:?}", t.elapsed());
        // adulterações
        let mut b = FcmpBatch::new();
        let ok = fcmp_verify_into(&mut b, branch, n, &root, &proof, &ki, &pseudo, b"outra").is_ok() && b.check();
        assert!(!ok, "mensagem errada");
        let mut bad = proof.clone();
        bad[400] ^= 1;
        let mut b = FcmpBatch::new();
        let ok = fcmp_verify_into(&mut b, branch, n, &root, &bad, &ki, &pseudo, &msg).is_ok() && b.check();
        assert!(!ok, "prova adulterada");
        // caminho (entradas dos nós) igual ao do JavaScript
        let path = tree.path_for_chunk(&leaf, n, c["path"][0]["idx"].as_u64().unwrap()).unwrap();
        for (lv, js) in path.iter().zip(c["path"].as_array().unwrap()) {
            let ours: Vec<String> = lv.2.iter().map(|e| num_bigint::BigUint::from_bytes_be(&crate::field::limbs_to_be(e)).to_str_radix(16)).collect();
            let theirs: Vec<String> = js["entries"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
            assert_eq!(ours, theirs);
        }
    }
}

#[test]
fn rust_prover_halves_verify() {
    use crate::fcmp::*;
    let v = vectors();
    let f = &v["fcmp"];
    let branch = f["branch"].as_u64().unwrap() as usize;
    let outs: Vec<([u8; 33], [u8; 33])> = f["outputs"].as_array().unwrap().iter()
        .map(|o| (hx(&o["P"]).try_into().unwrap(), hx(&o["C"]).try_into().unwrap())).collect();
    let leaf = |i: u64| -> ([u8; 32], [u8; 33], [u8; 33]) { let mut k = [0u8; 32]; k[..8].copy_from_slice(&i.to_le_bytes()); (k, outs[i as usize].0, outs[i as usize].1) };
    let mut tree = CurveTree::new(branch);
    for (n, i) in [(3u64, 1usize), (16, 13), (21, 6)] {
        let path = tree.path_for_chunk(&leaf, n, (i / branch) as u64).unwrap();
        let job = ProveJob { branch, n, path, leaf_pos: i % branch, p: outs[i].0, c: outs[i].1, r1: crate::field::Fe::random(), r2: crate::field::Fe::random() };
        let t = std::time::Instant::now();
        let e1 = prove_half(&job, Half::E1).unwrap();
        let e2 = prove_half(&job, Half::E2).unwrap();
        eprintln!("provador Rust N={n}: duas metades em {:?}", t.elapsed());
        assert!(verify_halves(&job, &e1, &e2).unwrap(), "metades do provador Rust verificam (N={n})");
        let mut bad = e1.clone();
        bad[40] ^= 1;
        assert!(!verify_halves(&job, &bad, &e2).unwrap_or(false));
    }
}
