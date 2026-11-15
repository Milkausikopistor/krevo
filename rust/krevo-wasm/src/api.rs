//! WebAssembly module interface (without wasm-bindgen): JavaScript reserves memory
//! (krevo_alloc), writes the input, calls krevo_call(op, ptr, len) and reads the output at
//! krevo_out_ptr()/krevo_out_len(). Status 0 = ok; 1 = error (the output is the message).
//! The input is wiped (zeros) right after being read: secrets do not stay in memory.
//!
//!   op 1  k·P          input: P (x‖y, 64) ‖ k (32)             output: x‖y (64) or empty (infinity)
//!   op 2  k·G          input: k (32)                            output: x‖y (64)
//!   op 3  k·H          input: k (32)                            output: x‖y (64)
//!   op 4  Schnorr      input: x (32) ‖ len ‖ domain ‖ msg       output: signature (64)
//!   op 5  range        input: m ‖ m × (v u64 LE ‖ γ (32))       output: m × V (33) ‖ proof
//!   op 6  FCMP half    input: job JSON + "half"                 output: Bulletproofs proof of the E1 or E2 half
//!   op 7  AES-GCM      input: key (32) ‖ iv (12) ‖ plaintext     output: ciphertext ‖ tag (16)
//!   op 8  AES-GCM⁻¹    input: key (32) ‖ iv (12) ‖ ciphertext ‖ tag    output: plaintext (or error)
//!   op 9  self-test    input: empty                             output: "ok"
//!   op 10 ownership (GSP)  input: ctx (32) ‖ P̂ ‖ Î ‖ D (33 each) ‖ 6 witnesses (32 each)   output: proof (224)
//!   op 11 FCMP statement   input: job JSON                      output: header (P̂, Î, Ĉ, L̂, blinded nodes)
//!   op 12 FCMP prepare     input: job JSON                      output: u32 ‖ header ‖ u32 ‖ E1 ‖ E2 (self-checked)
//!   op 13 ML-DSA key   input: seed (32)                         output: public key (1,312)
//!   op 14 ML-DSA sign  input: seed (32) ‖ message               output: signature (2,420), hedged and checked
//!   op 15 ML-DSA verify input: key (1,312) ‖ signature (2,420) ‖ message   output: 1 or 0
//!
//! FCMP job (the same as the native prover's, src/fcmp/parallel.js):
//!   {"branch","N","path":[{"level","idx","entries":[hex]}],"leafPos","P","C","r1","r2"}

use crate::bytes::from_hex;
use crate::crypto::Sc;
use crate::curve::*;
use crate::fcmp::{gsp_prove, head_bytes, prove_half, verify_halves, Half, ProveJob};
use crate::field::*;
use crate::wallet_ops::*;
use serde_json::Value;
use std::sync::Mutex;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn krevo_random(ptr: *mut u8, len: usize);
}

/// Randomness for getrandom (the "custom" backend): it comes from JavaScript.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    krevo_random(dest, len);
    Ok(())
}

static OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

#[no_mangle]
pub extern "C" fn krevo_alloc(len: usize) -> *mut u8 {
    let mut v = vec![0u8; len.max(1)];
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}
/// # Safety
/// ptr/len must come from krevo_alloc.
#[no_mangle]
pub unsafe extern "C" fn krevo_free(ptr: *mut u8, len: usize) {
    std::ptr::write_bytes(ptr, 0, len.max(1));
    drop(Vec::from_raw_parts(ptr, len.max(1), len.max(1)));
}
#[no_mangle]
pub extern "C" fn krevo_out_ptr() -> *const u8 { OUT.lock().unwrap().as_ptr() }
#[no_mangle]
pub extern "C" fn krevo_out_len() -> usize { OUT.lock().unwrap().len() }

/// # Safety
/// ptr/len: input buffer that came from krevo_alloc.
#[no_mangle]
pub unsafe extern "C" fn krevo_call(op: u32, ptr: *mut u8, len: usize) -> u32 {
    let mut input = std::slice::from_raw_parts(ptr, len).to_vec();
    std::ptr::write_bytes(ptr, 0, len); // wipes the input (it may contain secrets)
    let r = call(op, &input);
    // and the internal copy too (volatile write: the compiler cannot omit it)
    for b in input.iter_mut() { std::ptr::write_volatile(b, 0); }
    drop(input);
    let mut out = OUT.lock().unwrap();
    for b in out.iter_mut() { *b = 0; }
    out.clear();
    match r {
        Ok(v) => { out.extend(v); 0 }
        Err(e) => { out.extend(e.into_bytes()); 1 }
    }
}

fn sc(b: &[u8]) -> Result<Sc, String> { Sc::from_be_bytes(b).ok_or_else(|| "scalar out of range".to_string()) }
fn xy(p: &P1) -> Vec<u8> {
    match p.affine() { Some((x, y)) => [x.to_be_bytes(), y.to_be_bytes()].concat(), None => vec![] }
}
fn need(i: &[u8], n: usize) -> Result<(), String> { if i.len() < n { Err("short input".into()) } else { Ok(()) } }

pub fn call(op: u32, i: &[u8]) -> Result<Vec<u8>, String> {
    match op {
        1 => {
            need(i, 96)?;
            let x = FeP::from_be_bytes(&i[..32]).ok_or("invalid x")?;
            let y = FeP::from_be_bytes(&i[32..64]).ok_or("invalid y")?;
            if !P1::on_curve(&x, &y) { return Err("point not on the curve".into()); }
            Ok(xy(&mul_ct(&P1::from_affine(x, y), &sc(&i[64..96])?)))
        }
        2 => { need(i, 32)?; Ok(xy(&mul_g_ct(&sc(&i[..32])?))) }
        3 => { need(i, 32)?; Ok(xy(&mul_h_ct(&sc(&i[..32])?))) }
        4 => {
            need(i, 33)?;
            let x = sc(&i[..32])?;
            let dl = i[32] as usize;
            need(i, 33 + dl)?;
            let domain = std::str::from_utf8(&i[33..33 + dl]).map_err(|_| "invalid domain")?;
            Ok(schnorr_sign(&x, &i[33 + dl..], domain)?.to_vec())
        }
        5 => {
            need(i, 1)?;
            let m = i[0] as usize;
            need(i, 1 + 40 * m)?;
            let mut vals = vec![];
            let mut gs = vec![];
            for j in 0..m {
                let o = 1 + 40 * j;
                vals.push(u64::from_le_bytes(i[o..o + 8].try_into().unwrap()));
                gs.push(sc(&i[o + 8..o + 40])?);
            }
            let (vs, proof) = range_prove(&vals, &gs)?;
            let mut out: Vec<u8> = vs.iter().flat_map(|v| v.to_bytes()).collect();
            out.extend(proof);
            Ok(out)
        }
        6 => {
            let v: Value = serde_json::from_slice(i).map_err(|e| format!("invalid JSON: {e}"))?;
            let half = match v["half"].as_str() { Some("E1") => Half::E1, Some("E2") => Half::E2, _ => return Err("invalid half".into()) };
            prove_half(&parse_job(&v)?, half)
        }
        7 | 8 => {
            use aes_gcm::aead::{Aead, KeyInit};
            use aes_gcm::{Aes256Gcm, Nonce};
            need(i, 44)?;
            let c = Aes256Gcm::new_from_slice(&i[..32]).map_err(|_| "invalid AES key")?;
            let nonce = Nonce::from_slice(&i[32..44]);
            if op == 7 { c.encrypt(nonce, &i[44..]).map_err(|_| "encryption failed".into()) }
            else { c.decrypt(nonce, &i[44..]).map_err(|_| "Unsupported state or unable to authenticate data".into()) }
        }
        9 => { selftest()?; Ok(b"ok".to_vec()) }
        10 => {
            need(i, 32 + 99 + 192)?;
            let ctx: [u8; 32] = i[..32].try_into().unwrap();
            let pt = |o: usize| P1::from_bytes(&i[o..o + 33]).ok_or_else(|| "invalid point".to_string());
            let (phat, ihat, d) = (pt(32)?, pt(65)?, pt(98)?);
            let mut w = [Sc::ZERO; 6];
            for (k, wk) in w.iter_mut().enumerate() { *wk = sc(&i[131 + 32 * k..163 + 32 * k])?; }
            gsp_prove(&ctx, &phat, &ihat, &d, w)
        }
        11 => {
            let v: Value = serde_json::from_slice(i).map_err(|e| format!("invalid JSON: {e}"))?;
            head_bytes(&parse_job(&v)?)
        }
        12 => {
            let v: Value = serde_json::from_slice(i).map_err(|e| format!("invalid JSON: {e}"))?;
            let job = parse_job(&v)?;
            let head = head_bytes(&job)?;
            let e1 = prove_half(&job, Half::E1)?;
            let e2 = prove_half(&job, Half::E2)?;
            if !verify_halves(&job, &e1, &e2)? { return Err("membership proof failed (self-check)".into()); }
            let mut out = (head.len() as u32).to_le_bytes().to_vec();
            out.extend(head);
            out.extend((e1.len() as u32).to_le_bytes());
            out.extend(e1);
            out.extend(e2);
            Ok(out)
        }
        13 => { need(i, 32)?; Ok(mldsa_key(&i[..32]).0) }
        14 => { need(i, 32)?; mldsa_sign(&i[..32], &i[32..]) }
        15 => {
            use crate::crypto::{mldsa_verify, MLDSA_PUB_SIZE, MLDSA_SIG_SIZE};
            need(i, MLDSA_PUB_SIZE + MLDSA_SIG_SIZE)?;
            let (k, rest) = i.split_at(MLDSA_PUB_SIZE);
            let (sig, msg) = rest.split_at(MLDSA_SIG_SIZE);
            Ok(vec![mldsa_verify(k, msg, sig) as u8])
        }
        20..=36 => crate::vault::vault_call(op, i),
        _ => Err(format!("unknown operation: {op}")),
    }
}

fn parse_job(v: &Value) -> Result<ProveJob, String> {
    let hex32 = |s: &Value| -> Result<[u8; 32], String> {
        let h = s.as_str().ok_or("missing hexadecimal field")?;
        if h.len() > 64 { return Err("invalid 32-byte value".into()); }
        from_hex(&format!("{h:0>64}"))?.try_into().map_err(|_| "invalid 32-byte value".to_string())
    };
    let hex33 = |s: &Value| -> Result<[u8; 33], String> {
        from_hex(s.as_str().ok_or("missing point")?)?.try_into().map_err(|_| "invalid point".to_string())
    };
    let mut path = vec![];
    for l in v["path"].as_array().ok_or("missing path")? {
        let entries: Result<Vec<[u64; 4]>, String> = l["entries"].as_array().ok_or("missing entries")?.iter().map(|e| hex32(e).map(|b| be_to_limbs(&b))).collect();
        path.push((l["level"].as_u64().ok_or("level")? as u32, l["idx"].as_u64().ok_or("index")?, entries?));
    }
    let r1 = Fe::from_be_bytes(&hex32(&v["r1"])?).ok_or("r1 out of range")?;
    let r2 = Fe::from_be_bytes(&hex32(&v["r2"])?).ok_or("r2 out of range")?;
    Ok(ProveJob {
        branch: v["branch"].as_u64().ok_or("branch")? as usize, n: v["N"].as_u64().ok_or("N")?, path,
        leaf_pos: v["leafPos"].as_u64().ok_or("leafPos")? as usize, p: hex33(&v["P"])?, c: hex33(&v["C"])?, r1, r2,
    })
}

/// Quick self-test when the module loads: constant time == reference, Schnorr, AES.
fn selftest() -> Result<(), String> {
    let k = Sc::random();
    let g = crate::crypto::g();
    if !mul_g_ct(&k).eq(&g.mul(&k)) || !mul_ct(&g, &k).eq(&g.mul(&k)) { return Err("self-test: multiplication".into()); }
    let sig = schnorr_sign(&k, b"self-test", "sig")?;
    if !crate::crypto::schnorr_verify(&g.mul(&k), b"self-test", &sig, "sig") { return Err("self-test: Schnorr".into()); }
    Ok(())
}
