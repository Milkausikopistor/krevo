//! `krevod provar` — provador nativo das provas de pertencimento à cadeia inteira (FCMP).
//!
//! A carteira JavaScript escolhe os cegamentos (r1, r2), monta o enunciado e a prova de Schnorr
//! final; a parte cara — as duas provas Bulletproofs de circuito de cada entrada — vem para cá.
//! Entrada (stdin):  {"jobs":[{"branch","N","path":[{"level","idx","entries":[hex]}],"leafPos","P","C","r1","r2"}]}
//! Saída (stdout):   {"proofs":[{"head":hex,"E1":hex,"E2":hex}],"ms":n}  ou  {"error":"…"}
//! (head = P̂, Î, Ĉ, L̂ e os nós cegados: a carteira não precisa recalcular o enunciado)
//! Cada metade de cada entrada roda numa thread. Nenhuma chave de gasto passa por aqui.

use crate::bytes::{from_hex, to_hex};
use crate::fcmp::{head_bytes, prove_half, verify_halves, Half, ProveJob};
use crate::field::{be_to_limbs, Fe};
use serde_json::{json, Value};
use std::io::Read;

fn parse_job(v: &Value) -> Result<ProveJob, String> {
    let hex32 = |s: &Value| -> Result<[u8; 32], String> {
        let h = s.as_str().ok_or("campo hexadecimal ausente")?;
        let b = from_hex(&format!("{h:0>64}"))?;
        b.try_into().map_err(|_| "valor de 32 bytes inválido".to_string())
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

pub fn run(self_check: bool) -> Value {
    let t = std::time::Instant::now();
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) { return json!({ "error": e.to_string() }); }
    let req: Value = match serde_json::from_str(&input) { Ok(v) => v, Err(e) => return json!({ "error": format!("JSON inválido: {e}") }) };
    let jobs: Result<Vec<ProveJob>, String> = req["jobs"].as_array().map(|a| a.iter().map(parse_job).collect()).unwrap_or(Err("jobs ausente".into()));
    let jobs = match jobs { Ok(j) => j, Err(e) => return json!({ "error": e }) };
    let results: Vec<(Result<Vec<u8>, String>, Result<Vec<u8>, String>)> = std::thread::scope(|s| {
        let hs: Vec<_> = jobs.iter().map(|j| (s.spawn(move || prove_half(j, Half::E1)), s.spawn(move || prove_half(j, Half::E2)))).collect();
        hs.into_iter().map(|(a, b)| (a.join().unwrap_or(Err("thread falhou".into())), b.join().unwrap_or(Err("thread falhou".into())))).collect()
    });
    let mut proofs = vec![];
    for (i, (e1, e2)) in results.into_iter().enumerate() {
        let (e1, e2) = match (e1, e2) { (Ok(a), Ok(b)) => (a, b), (Err(e), _) | (_, Err(e)) => return json!({ "error": e }) };
        if self_check && !verify_halves(&jobs[i], &e1, &e2).unwrap_or(false) { return json!({ "error": "autoverificação falhou" }); }
        let head = match head_bytes(&jobs[i]) { Ok(h) => h, Err(e) => return json!({ "error": e }) };
        proofs.push(json!({ "head": to_hex(&head), "E1": to_hex(&e1), "E2": to_hex(&e2) }));
    }
    json!({ "proofs": proofs, "ms": t.elapsed().as_millis() as u64 })
}
