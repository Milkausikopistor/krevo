//! Mempool (espelha src/node/mempool.js): transações válidas contra o estado do virtual.
//! Seleção para blocos por amostragem aleatória ponderada pela taxa (Efraimidis–Spirakis),
//! para que mineradores paralelos escolham conjuntos diferentes.

use crate::consensus::Consensus;
use crate::tx::Transaction;
use crate::txvalidation::*;
use crate::utxo::Op;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Entry { pub tx: Arc<Transaction>, pub fee_rate: f64, pub added: u64 }

pub struct Mempool {
    pub txs: HashMap<[u8; 32], Entry>,
    pub order: Vec<[u8; 32]>,
    pub spent: HashMap<Op, [u8; 32]>,
    pub kis: HashMap<[u8; 33], [u8; 32]>,
    pub max_size: usize,
    pub version: u64,
    rng: u64,
}

pub fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }

impl Mempool {
    pub fn new() -> Self {
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        Mempool { txs: HashMap::new(), order: vec![], spent: HashMap::new(), kis: HashMap::new(), max_size: 20_000, version: 0, rng: u64::from_le_bytes(seed) | 1 }
    }
    fn rand(&mut self) -> f64 {
        self.rng ^= self.rng << 13; self.rng ^= self.rng >> 7; self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Valida sem inserir (também usado na fase "haste" do Dandelion++).
    pub fn check(&self, c: &mut Consensus, tx: &Transaction) -> Result<(), String> {
        let id = tx.id();
        if c.tx_status(&id)["status"] == "accepted" { return Err("transação já confirmada".into()); }
        validate_tx_stateless(tx, &c.params)?;
        for i in &tx.t_in { if self.spent.contains_key(&(i.txid, i.index)) { return Err("conflito com transação no mempool".into()); } }
        for si in &tx.s_in { if self.kis.contains_key(&si.key_image) { return Err("imagem de chave já usada no mempool".into()); } }
        c.ensure_virtual_base();
        let v = c.virt();
        let r = validate_tx_in_context(tx, &c.virtual_view(), v.gd.daa_score, &c.params)?;
        if v.acceptance.shielded + shielded_delta(tx, r.t_in) < 0 { return Err("catraca: retiraria do pool privado mais KRV do que existe nele".into()); }
        if (tx.fee as u128) < tx.mass as u128 * c.params.min_relay_fee_rate as u128 { return Err("taxa abaixo do mínimo de retransmissão".into()); }
        Ok(())
    }

    /// Insere; devolve (ok, duplicada, motivo).
    pub fn add(&mut self, c: &mut Consensus, tx: Arc<Transaction>) -> (bool, bool, String) {
        let id = tx.id();
        if self.txs.contains_key(&id) { return (true, true, String::new()); }
        if self.txs.len() >= self.max_size { return (false, false, "mempool cheio".into()); }
        if let Err(e) = self.check(c, &tx) { return (false, false, e); }
        for i in &tx.t_in { self.spent.insert((i.txid, i.index), id); }
        for si in &tx.s_in { self.kis.insert(si.key_image, id); }
        let fee_rate = tx.fee as f64 / (tx.mass.max(1)) as f64;
        self.txs.insert(id, Entry { tx, fee_rate, added: now_ms() });
        self.order.push(id);
        self.version += 1;
        (true, false, String::new())
    }

    pub fn remove(&mut self, id: &[u8; 32]) {
        let Some(e) = self.txs.remove(id) else { return };
        for i in &e.tx.t_in { self.spent.remove(&(i.txid, i.index)); }
        for si in &e.tx.s_in { self.kis.remove(&si.key_image); }
        self.order.retain(|x| x != id);
        self.version += 1;
    }

    /// Depois que o virtual muda: tira o que foi confirmado ou ficou inválido.
    pub fn revalidate(&mut self, c: &mut Consensus) {
        c.ensure_virtual_base();
        let ids: Vec<[u8; 32]> = self.order.clone();
        for id in ids {
            let v = c.virt();
            let gone = v.acceptance.accepted_set.contains(&id) || c.tx_index.contains_key(&id) || {
                let tx = self.txs[&id].tx.clone();
                validate_tx_in_context(&tx, &c.virtual_view(), v.gd.daa_score, &c.params).is_err()
            };
            if gone { self.remove(&id); }
        }
    }

    pub fn select(&mut self, max_mass: u64) -> Vec<Transaction> {
        let mut items: Vec<(f64, [u8; 32])> = vec![];
        let ids: Vec<([u8; 32], f64)> = self.order.iter().map(|id| (*id, self.txs[id].fee_rate)).collect();
        for (id, fr) in ids { let r = self.rand(); items.push((r.powf(1.0 / fr.max(1e-9)), id)); }
        items.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut out = vec![];
        let mut mass = 0u64;
        for (_, id) in items {
            let tx = &self.txs[&id].tx;
            if mass + tx.mass > max_mass { continue; }
            mass += tx.mass;
            out.push((**tx).clone());
        }
        out
    }
}
