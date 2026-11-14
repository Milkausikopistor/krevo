//! `krevod replay`: reprocessa um arquivo de blocos (de um nó JavaScript ou Rust) e imprime um
//! resumo do estado final — o mesmo que vectors/replay.mjs imprime com o nó de referência.

use crate::bytes::to_hex;
use crate::consensus::{AddResult, Consensus, Status};
use crate::hash::H;
use crate::params::Params;
use crate::storage::BlockFile;
use serde_json::json;

pub fn summary(c: &mut Consensus) -> serde_json::Value {
    c.ensure_virtual_base();
    let v = c.virt();
    let view = c.virtual_view();
    let mut statuses: Vec<(String, &str)> = c.status.iter().map(|(h, s)| (to_hex(h), if *s == Status::Chain { "chain" } else { "disq" })).collect();
    statuses.sort();
    let mut sh = H::new("replay/status");
    for (h, s) in &statuses { sh = sh.s(h).s(s); }
    let t_count = c.utxo.t.len() + view.diff.add_t.len() - view.diff.rem_t.len();
    let mut mh = v.acceptance.muhash.clone();
    json!({
        "blocks": c.store.gd.len(),
        "chain": statuses.iter().filter(|x| x.1 == "chain").count(),
        "disq": statuses.iter().filter(|x| x.1 == "disq").count(),
        "statusDigest": to_hex(&sh.d32()),
        "virtual": {
            "blueScore": v.gd.blue_score, "daaScore": v.gd.daa_score,
            "selectedParent": to_hex(&v.gd.selected_parent.unwrap()), "parents": v.parents.len(), "bits": v.bits,
        },
        "utxoCommitment": to_hex(&mh.digest()),
        "acceptedRoot": to_hex(&v.acceptance.accepted_root),
        "minted": v.acceptance.minted.to_string(),
        "feePool": v.acceptance.pool.to_string(),
        "shielded": v.acceptance.shielded.to_string(),
        "sCount": view.s_count(),
        "tCount": t_count,
        "kiCount": c.utxo.ki.len() + view.diff.add_ki.len(),
        "names": view.all_names().len(),
    })
}

pub fn run(params: Params, file: &std::path::Path) -> serde_json::Value {
    let bf = BlockFile { file: file.to_path_buf() };
    let blocks = bf.read_all();
    let mut c = Consensus::new(params);
    let t = std::time::Instant::now();
    let (mut ok, mut other) = (0, 0);
    for b in blocks {
        match c.add_block(b, 0, true) {
            AddResult::Accepted { .. } => ok += 1,
            AddResult::Invalid { hash, reason } => { eprintln!("inválido {}: {reason}", to_hex(&hash)); other += 1 }
            _ => other += 1,
        }
    }
    let mut s = summary(&mut c);
    eprintln!("{ok} blocos aceitos, {other} outros, em {:.2} s", t.elapsed().as_secs_f64());
    for (h, r) in &c.disqualified { eprintln!("desqualificado {}: {r}", to_hex(h)); }
    s["replayMs"] = json!(t.elapsed().as_millis() as u64);
    s
}
