//! Regras de validade das transações (espelha src/consensus/txvalidation.js).
//!   stateless  — estrutura, limites, provas de intervalo
//!   in_context — contra uma visão UTXO: existência, maturidade, gasto duplo, assinaturas,
//!                anéis, provas de pertencimento à cadeia inteira, nomes e balanço.

use crate::crypto::*;
use crate::curve::P1;
use crate::fcmp::{fcmp_proof_size, fcmp_verify_into, FcmpBatch};
use crate::params::{Params, MAX_SUPPLY};
use crate::rules::*;
use crate::tx::Transaction;
use crate::utxo::{TEntry, UtxoView};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

pub type TxRes<T> = Result<T, String>;

fn cache(which: usize) -> &'static Mutex<HashSet<[u8; 32]>> {
    static C: OnceLock<[Mutex<HashSet<[u8; 32]>>; 2]> = OnceLock::new();
    &C.get_or_init(|| [Mutex::new(HashSet::new()), Mutex::new(HashSet::new())])[which]
}
fn remembered(which: usize, k: &[u8; 32]) -> bool { cache(which).lock().unwrap().contains(k) }
fn remember(which: usize, k: [u8; 32]) {
    let mut c = cache(which).lock().unwrap();
    if c.len() > 100_000 { c.clear(); }
    c.insert(k);
}

pub fn validate_tx_stateless(tx: &Transaction, p: &Params) -> TxRes<()> {
    if tx.version != 1 { return Err("versão de transação desconhecida".into()); }
    if tx.is_coinbase() { return Err("transação sem entradas".into()); }
    if tx.t_out.len() + tx.s_out.len() == 0 { return Err("transação sem saídas".into()); }
    if tx.payload.len() > p.max_tx_payload { return Err("payload grande demais".into()); }
    if tx.fee > MAX_SUPPLY { return Err("taxa inválida".into()); }
    let mut seen = HashSet::new();
    for i in &tx.t_in { if !seen.insert((i.txid, i.index)) { return Err("entrada duplicada".into()); } }
    let mut kis = HashSet::new();
    for si in &tx.s_in {
        if si.ring.is_empty() {
            if si.anchor < 1 || si.anchor > (1u64 << 53) { return Err("âncora de entrada privada inválida".into()); }
            if si.fcmp.len() != fcmp_proof_size(si.anchor, p.fcmp_branch) { return Err("prova de pertencimento com tamanho inválido".into()); }
        } else {
            if !p.ring_inputs { return Err("assinaturas em anel não são aceitas nesta rede: a entrada privada precisa provar pertencer à árvore de TODAS as saídas (FCMP)".into()); }
            if si.ring.len() != p.ring_size { return Err(format!("anel deve ter {} membros", p.ring_size)); }
            let members: HashSet<_> = si.ring.iter().collect();
            if members.len() != si.ring.len() { return Err("membro de anel repetido".into()); }
            if si.clsag.len() != 32 + 32 * si.ring.len() + 33 { return Err("assinatura em anel com tamanho inválido".into()); }
        }
        if !kis.insert(si.key_image) { return Err("imagem de chave repetida na transação".into()); }
        if P1::from_bytes(&si.pseudo).is_none() || P1::from_bytes(&si.key_image).is_none() { return Err("ponto inválido em entrada privada".into()); }
    }
    let mut out_sum: u128 = 0;
    let mut name_outs = 0;
    for o in &tx.t_out {
        if o.amount < 1 || o.amount > MAX_SUPPLY { return Err("valor de saída inválido".into()); }
        out_sum += o.amount as u128;
        let a = parse_address_data(&o.lock).ok_or("trava de saída inválida")?;
        match &a {
            Addr::S { .. } => return Err("trava de saída inválida".into()),
            Addr::N { record, .. } => {
                name_outs += 1;
                let owner = parse_address_data(&record.owner);
                let target = parse_address_data(&record.target);
                let (Some(owner), Some(target)) = (owner, target) else { return Err("registro de nome com dono ou destino inválido".into()) };
                if !matches!(owner.kind(), 't' | 'm' | 'q') { return Err("o dono de um nome precisa ser um endereço krv, krq ou de multiassinatura".into()); }
                if !matches!(target.kind(), 't' | 's' | 'm' | 'q') { return Err("destino de nome inválido".into()); }
            }
            _ => {}
        }
    }
    if name_outs > 1 { return Err("no máximo um registro de nome por transação".into()); }
    if out_sum + tx.fee as u128 > MAX_SUPPLY as u128 { return Err("soma de saídas acima da oferta máxima".into()); }
    let has_shielded = !tx.s_in.is_empty() || !tx.s_out.is_empty();
    if !tx.s_out.is_empty() {
        if tx.s_out.len() > BP_MAX_AGG { return Err("saídas privadas demais".into()); }
        if tx.range_proof.len() != range_proof_size(tx.s_out.len()) { return Err("prova de intervalo com tamanho inválido".into()); }
        let mut cs = vec![];
        for o in &tx.s_out {
            if P1::from_bytes(&o.r).is_none() || P1::from_bytes(&o.p).is_none() { return Err("ponto inválido em saída privada".into()); }
            cs.push(P1::from_bytes(&o.c).ok_or("ponto inválido em saída privada")?);
        }
        let key = tx.hash();
        if !remembered(0, &key) {
            if !verify_range(&cs, &tx.range_proof) { return Err("prova de intervalo inválida".into()); }
            remember(0, key);
        }
    } else if !tx.range_proof.is_empty() { return Err("prova de intervalo sem saídas privadas".into()); }
    if has_shielded != tx.binding_sig.is_some() { return Err("assinatura de balanço ausente ou indevida".into()); }
    let cm = compute_mass(tx, p);
    if tx.mass < cm { return Err(format!("massa declarada ({}) menor que a de computação ({})", tx.mass, cm)); }
    if tx.mass > p.max_tx_mass { return Err("transação pesada demais".into()); }
    Ok(())
}

/// Testemunha "de dentro" (registro de nome e compromisso são gastos pelo DONO).
struct Inner { lock: Vec<u8>, witness: Vec<u8>, commit: Option<CommitWitness> }
fn unwrap_spend(lock: &[u8], witness: &[u8]) -> Option<Inner> {
    if lock.first() == Some(&LOCK_NAME) {
        return parse_name_record(lock).map(|r| Inner { lock: r.owner, witness: witness.to_vec(), commit: None });
    }
    if lock.first() == Some(&LOCK_NAME_COMMIT) {
        let c = parse_commit_witness(witness)?;
        if name_commit_hash(&c.name, &c.salt, &c.owner) != lock[1..] { return None; }
        return Some(Inner { lock: c.owner.clone(), witness: c.inner.clone(), commit: Some(c) });
    }
    Some(Inner { lock: lock.to_vec(), witness: witness.to_vec(), commit: None })
}

fn check_name_rules(tx: &Transaction, view: &UtxoView, pov: u64, p: &Params, inners: &[Inner], entries: &[&TEntry]) -> TxRes<u64> {
    let Some(out) = tx.t_out.iter().find(|o| o.lock.first() == Some(&LOCK_NAME)) else { return Ok(0) };
    let rec = parse_name_record(&out.lock).ok_or("registro de nome inválido")?;
    let fee = name_fee(p, &rec.name);
    if out.amount < p.name_min_deposit { return Err(format!("o registro de um nome precisa guardar ao menos {} grãos de depósito", p.name_min_deposit)); }
    if rec.expiry <= pov { return Err("vencimento do nome no passado (renove pagando a taxa)".into()); }
    let spent: HashSet<_> = tx.t_in.iter().map(|i| (i.txid, i.index)).collect();
    let mut prev: Option<NameRecord> = None;
    for (key, e) in view.name_entries(&rec.name) {
        let Some(r) = parse_name_record(&e.lock) else { continue };
        if pov > r.expiry + p.name_grace { continue; }
        if !spent.contains(&key) { return Err(format!("@{} já tem dono", rec.name)); }
        prev = Some(r);
    }
    if let Some(prev) = prev {
        if rec.expiry <= prev.expiry { return Ok(0); }
        if tx.fee < fee { return Err(format!("renovar @{} custa {} grãos", rec.name, fee)); }
        if rec.expiry > prev.expiry.max(pov) + p.name_period { return Err("renovação além de um período".into()); }
        return Ok(fee);
    }
    if tx.fee < fee { return Err(format!("registrar @{} custa {} grãos", rec.name, fee)); }
    if rec.expiry > pov + p.name_period { return Err("registro além de um período".into()); }
    let ok = inners.iter().enumerate().any(|(n, u)| match &u.commit {
        Some(c) => c.name == rec.name && c.owner == rec.owner && pov - entries[n].daa >= p.name_commit_min && pov - entries[n].daa <= p.name_commit_max,
        None => false,
    });
    if !ok { return Err(format!("registrar @{} exige revelar um compromisso feito entre {} e {} blocos atrás", rec.name, p.name_commit_min, p.name_commit_max)); }
    Ok(fee)
}

pub struct CtxResult { pub fee: u64, pub t_in: u64, pub name_fee: u64 }

pub fn validate_tx_in_context(tx: &Transaction, view: &UtxoView, pov: u64, p: &Params) -> TxRes<CtxResult> {
    let mut t_in_amounts = vec![];
    let mut inners = vec![];
    let mut entries: Vec<&TEntry> = vec![];
    for i in &tx.t_in {
        let e = view.get_t(&(i.txid, i.index)).ok_or("entrada inexistente ou já gasta")?;
        if e.coinbase && pov.saturating_sub(e.daa) < p.coinbase_maturity { return Err("coinbase imatura".into()); }
        let u = unwrap_spend(&e.lock, &i.sig).ok_or("testemunha não confere com a saída (compromisso de nome errado?)")?;
        if u.lock.first() == Some(&LOCK_MULTISIG) {
            let delay = witness_delay(&u.witness).ok_or("testemunha de multiassinatura malformada")?;
            let age = pov.saturating_sub(e.daa);
            if age < delay { return Err(format!("bloqueado por tempo: faltam {} blocos", delay - age)); }
        }
        t_in_amounts.push(e.amount);
        inners.push(u);
        entries.push(e);
    }
    let mut rings: Vec<Option<Vec<RingMember>>> = vec![];
    for si in &tx.s_in {
        if view.has_ki(&si.key_image) { return Err("gasto duplo (imagem de chave já usada)".into()); }
        if si.ring.is_empty() {
            let base = view.base;
            if si.anchor > base.s_list.len() as u64 { return Err("âncora além das saídas privadas conhecidas".into()); }
            let last = &base.s[&base.s_list[si.anchor as usize - 1]];
            if pov.saturating_sub(last.daa) < p.fcmp_maturity || pov < last.daa { return Err(format!("âncora recente demais: use uma árvore com ao menos {} blocos", p.fcmp_maturity)); }
            rings.push(None);
            continue;
        }
        let mut ring = vec![];
        for (txid, idx) in &si.ring {
            let e = view.get_s(&(*txid, *idx)).ok_or("membro de anel inexistente")?;
            let need = if e.coinbase { p.ring_maturity.max(p.coinbase_maturity) } else { p.ring_maturity };
            if pov.saturating_sub(e.daa) < need || pov < e.daa { return Err("membro de anel imaturo".into()); }
            ring.push(RingMember { p: P1::from_bytes(&e.p).unwrap(), c: P1::from_bytes(&e.c).unwrap() });
        }
        rings.push(Some(ring));
    }
    if storage_mass(tx, &t_in_amounts, p) > tx.mass { return Err("massa de armazenamento acima da declarada".into()); }
    let name_fee_paid = check_name_rules(tx, view, pov, p, &inners, &entries)?;

    let t_in: u64 = t_in_amounts.iter().sum();
    let t_out: u64 = tx.t_out.iter().map(|o| o.amount).sum();
    let has_shielded = !tx.s_in.is_empty() || !tx.s_out.is_empty();
    if !has_shielded && t_in as u128 != t_out as u128 + tx.fee as u128 { return Err("entradas ≠ saídas + taxa".into()); }

    let key = tx.hash();
    if !remembered(1, &key) {
        let msg = tx.sighash();
        for (n, i) in tx.t_in.iter().enumerate() {
            let u = &inners[n];
            let _ = i;
            match parse_address_data(&u.lock) {
                Some(Addr::M { data }) => if !verify_multisig_witness(&data, &u.witness, &msg) { return Err("multiassinatura inválida (faltam assinaturas ou alguma não confere)".into()); },
                Some(Addr::Q { data }) => if !verify_pq_witness(&data, &u.witness, &msg) { return Err("assinatura híbrida quântica inválida (Schnorr e ML-DSA precisam conferir)".into()); },
                Some(Addr::T { pubkey, .. }) => if u.witness.len() != 64 || !schnorr_verify(&pubkey, &msg, &u.witness, "sig") { return Err("assinatura inválida".into()); },
                Some(_) => return Err("esta saída não pode ser gasta".into()),
                None => return Err("trava não gastável".into()),
            }
        }
        let mut pseudos = vec![];
        let mut batch = FcmpBatch::new();
        let mut fcmps = 0;
        for (n, si) in tx.s_in.iter().enumerate() {
            let pseudo = P1::from_bytes(&si.pseudo).unwrap();
            pseudos.push(pseudo);
            let ki = P1::from_bytes(&si.key_image).unwrap();
            match &rings[n] {
                None => {
                    let root = view.base.tree_root(si.anchor);
                    fcmp_verify_into(&mut batch, p.fcmp_branch, si.anchor, &root, &si.fcmp, &ki, &pseudo, &msg)
                        .map_err(|e| format!("prova de pertencimento inválida ({e})"))?;
                    fcmps += 1;
                }
                Some(ring) => if !clsag_verify(&msg, ring, &pseudo, &si.clsag, &ki) { return Err("assinatura em anel inválida".into()); },
            }
        }
        if fcmps > 0 && !batch.check() { return Err("prova de pertencimento inválida".into()); }
        if has_shielded {
            let mut e = P1::inf();
            for ps in &pseudos { e = e.add(ps); }
            e = e.add(&mul_h_u64(t_in));
            for o in &tx.s_out { e = e.sub(&P1::from_bytes(&o.c).unwrap()); }
            e = e.sub(&mul_h_u64(t_out + tx.fee));
            let ok = match &tx.binding_sig { Some(sig) => !e.is_inf() && schnorr_verify(&e, &msg, sig, "binding"), None => false };
            if !ok { return Err("balanço inválido".into()); }
        }
        remember(1, key);
    }
    Ok(CtxResult { fee: tx.fee, t_in, name_fee: name_fee_paid })
}

/// Variação do pool privado (catraca): entradas transparentes − saídas transparentes − taxa.
pub fn shielded_delta(tx: &Transaction, t_in_sum: u64) -> i128 {
    if tx.s_in.is_empty() && tx.s_out.is_empty() { return 0; }
    t_in_sum as i128 - tx.t_out.iter().map(|o| o.amount as i128).sum::<i128>() - tx.fee as i128
}
