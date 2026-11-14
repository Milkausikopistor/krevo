//! Interface do módulo WebAssembly (sem wasm-bindgen): o JavaScript reserva memória
//! (krevo_alloc), escreve a entrada, chama krevo_call(op, ptr, len) e lê a saída em
//! krevo_out_ptr()/krevo_out_len(). Status 0 = ok; 1 = erro (a saída é a mensagem).
//! A entrada é apagada (zeros) logo depois de lida: segredos não ficam na memória.
//!
//!   op 1  k·P          entrada: P (x‖y, 64) ‖ k (32)          saída: x‖y (64) ou vazio (infinito)
//!   op 2  k·G          entrada: k (32)                          saída: x‖y (64)
//!   op 3  k·H          entrada: k (32)                          saída: x‖y (64)
//!   op 4  Schnorr      entrada: x (32) ‖ len ‖ domínio ‖ msg    saída: assinatura (64)
//!   op 5  intervalo    entrada: m ‖ m × (v u64 LE ‖ γ (32))     saída: m × V (33) ‖ prova
//!   op 6  FCMP metade  entrada: JSON da tarefa + "half"         saída: prova Bulletproofs da metade E1 ou E2
//!   op 7  AES-GCM      entrada: chave (32) ‖ iv (12) ‖ texto     saída: cifrado ‖ etiqueta (16)
//!   op 8  AES-GCM⁻¹    entrada: chave (32) ‖ iv (12) ‖ cifrado ‖ etiqueta    saída: texto (ou erro)
//!   op 9  autoteste    entrada: vazia                           saída: "ok"
//!   op 10 posse (GSP)  entrada: ctx (32) ‖ P̂ ‖ Î ‖ D (33 cada) ‖ 6 testemunhas (32 cada)   saída: prova (224)
//!   op 11 FCMP enunc.  entrada: JSON da tarefa                  saída: cabeçalho (P̂, Î, Ĉ, L̂, nós cegados)
//!   op 12 FCMP prep.   entrada: JSON da tarefa                  saída: u32 ‖ cabeçalho ‖ u32 ‖ E1 ‖ E2 (autoverificado)
//!   op 13 ML-DSA chave entrada: semente (32)                    saída: chave pública (1.312)
//!   op 14 ML-DSA ass.  entrada: semente (32) ‖ mensagem         saída: assinatura (2.420), hedged e conferida
//!   op 15 ML-DSA conf. entrada: chave (1.312) ‖ assinatura (2.420) ‖ mensagem   saída: 1 ou 0
//!
//! Tarefa FCMP (a mesma do provador nativo, src/fcmp/parallel.js):
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

/// Aleatoriedade para o getrandom (backend "custom"): vem do JavaScript.
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
/// ptr/len precisam vir de krevo_alloc.
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
/// ptr/len: buffer de entrada vindo de krevo_alloc.
#[no_mangle]
pub unsafe extern "C" fn krevo_call(op: u32, ptr: *mut u8, len: usize) -> u32 {
    let mut input = std::slice::from_raw_parts(ptr, len).to_vec();
    std::ptr::write_bytes(ptr, 0, len); // apaga a entrada (pode conter segredos)
    let r = call(op, &input);
    // e a cópia interna também (escrita volátil: o compilador não pode omitir)
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

fn sc(b: &[u8]) -> Result<Sc, String> { Sc::from_be_bytes(b).ok_or_else(|| "escalar fora do intervalo".to_string()) }
fn xy(p: &P1) -> Vec<u8> {
    match p.affine() { Some((x, y)) => [x.to_be_bytes(), y.to_be_bytes()].concat(), None => vec![] }
}
fn need(i: &[u8], n: usize) -> Result<(), String> { if i.len() < n { Err("entrada curta".into()) } else { Ok(()) } }

pub fn call(op: u32, i: &[u8]) -> Result<Vec<u8>, String> {
    match op {
        1 => {
            need(i, 96)?;
            let x = FeP::from_be_bytes(&i[..32]).ok_or("x inválido")?;
            let y = FeP::from_be_bytes(&i[32..64]).ok_or("y inválido")?;
            if !P1::on_curve(&x, &y) { return Err("ponto fora da curva".into()); }
            Ok(xy(&mul_ct(&P1::from_affine(x, y), &sc(&i[64..96])?)))
        }
        2 => { need(i, 32)?; Ok(xy(&mul_g_ct(&sc(&i[..32])?))) }
        3 => { need(i, 32)?; Ok(xy(&mul_h_ct(&sc(&i[..32])?))) }
        4 => {
            need(i, 33)?;
            let x = sc(&i[..32])?;
            let dl = i[32] as usize;
            need(i, 33 + dl)?;
            let domain = std::str::from_utf8(&i[33..33 + dl]).map_err(|_| "domínio inválido")?;
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
            let v: Value = serde_json::from_slice(i).map_err(|e| format!("JSON inválido: {e}"))?;
            let half = match v["half"].as_str() { Some("E1") => Half::E1, Some("E2") => Half::E2, _ => return Err("metade inválida".into()) };
            prove_half(&parse_job(&v)?, half)
        }
        7 | 8 => {
            use aes_gcm::aead::{Aead, KeyInit};
            use aes_gcm::{Aes256Gcm, Nonce};
            need(i, 44)?;
            let c = Aes256Gcm::new_from_slice(&i[..32]).map_err(|_| "chave AES inválida")?;
            let nonce = Nonce::from_slice(&i[32..44]);
            if op == 7 { c.encrypt(nonce, &i[44..]).map_err(|_| "falha ao cifrar".into()) }
            else { c.decrypt(nonce, &i[44..]).map_err(|_| "Unsupported state or unable to authenticate data".into()) }
        }
        9 => { selftest()?; Ok(b"ok".to_vec()) }
        10 => {
            need(i, 32 + 99 + 192)?;
            let ctx: [u8; 32] = i[..32].try_into().unwrap();
            let pt = |o: usize| P1::from_bytes(&i[o..o + 33]).ok_or_else(|| "ponto inválido".to_string());
            let (phat, ihat, d) = (pt(32)?, pt(65)?, pt(98)?);
            let mut w = [Sc::ZERO; 6];
            for (k, wk) in w.iter_mut().enumerate() { *wk = sc(&i[131 + 32 * k..163 + 32 * k])?; }
            gsp_prove(&ctx, &phat, &ihat, &d, w)
        }
        11 => {
            let v: Value = serde_json::from_slice(i).map_err(|e| format!("JSON inválido: {e}"))?;
            head_bytes(&parse_job(&v)?)
        }
        12 => {
            let v: Value = serde_json::from_slice(i).map_err(|e| format!("JSON inválido: {e}"))?;
            let job = parse_job(&v)?;
            let head = head_bytes(&job)?;
            let e1 = prove_half(&job, Half::E1)?;
            let e2 = prove_half(&job, Half::E2)?;
            if !verify_halves(&job, &e1, &e2)? { return Err("falha na prova de pertencimento (autoverificação)".into()); }
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
        _ => Err(format!("operação desconhecida: {op}")),
    }
}

fn parse_job(v: &Value) -> Result<ProveJob, String> {
    let hex32 = |s: &Value| -> Result<[u8; 32], String> {
        let h = s.as_str().ok_or("campo hexadecimal ausente")?;
        if h.len() > 64 { return Err("valor de 32 bytes inválido".into()); }
        from_hex(&format!("{h:0>64}"))?.try_into().map_err(|_| "valor de 32 bytes inválido".to_string())
    };
    let hex33 = |s: &Value| -> Result<[u8; 33], String> {
        from_hex(s.as_str().ok_or("ponto ausente")?)?.try_into().map_err(|_| "ponto inválido".to_string())
    };
    let mut path = vec![];
    for l in v["path"].as_array().ok_or("caminho ausente")? {
        let entries: Result<Vec<[u64; 4]>, String> = l["entries"].as_array().ok_or("entradas ausentes")?.iter().map(|e| hex32(e).map(|b| be_to_limbs(&b))).collect();
        path.push((l["level"].as_u64().ok_or("nível")? as u32, l["idx"].as_u64().ok_or("índice")?, entries?));
    }
    let r1 = Fe::from_be_bytes(&hex32(&v["r1"])?).ok_or("r1 fora do intervalo")?;
    let r2 = Fe::from_be_bytes(&hex32(&v["r2"])?).ok_or("r2 fora do intervalo")?;
    Ok(ProveJob {
        branch: v["branch"].as_u64().ok_or("branch")? as usize, n: v["N"].as_u64().ok_or("N")?, path,
        leaf_pos: v["leafPos"].as_u64().ok_or("leafPos")? as usize, p: hex33(&v["P"])?, c: hex33(&v["C"])?, r1, r2,
    })
}

/// Autoteste rápido na carga do módulo: tempo constante == referência, Schnorr, AES.
fn selftest() -> Result<(), String> {
    let k = Sc::random();
    let g = crate::crypto::g();
    if !mul_g_ct(&k).eq(&g.mul(&k)) || !mul_ct(&g, &k).eq(&g.mul(&k)) { return Err("autoteste: multiplicação".into()); }
    let sig = schnorr_sign(&k, b"autoteste", "sig")?;
    if !crate::crypto::schnorr_verify(&g.mul(&k), b"autoteste", &sig, "sig") { return Err("autoteste: Schnorr".into()); }
    Ok(())
}
