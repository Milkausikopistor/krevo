//! JSON-RPC over HTTP (mirrors src/node/rpc.js): the same methods and the same responses —
//! a JavaScript BigInt becomes text, a Buffer becomes hexadecimal — so that the project's wallets, light server,
//! explorer and miners work with the Rust node unchanged.

use crate::block::{merkle_proof, Block};
use crate::bytes::{from_hex, from_hex32, to_hex};
use crate::consensus::Status;
use crate::dag::Hash;
use crate::mempool::now_ms;
use crate::node::{guarded, lock_node, Node, Shared};
use crate::pow::{calc_work, compact_to_target};
use crate::rules::*;
use crate::tx::Transaction;
use num_traits::ToPrimitive;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub fn start(shared: Shared, host: &str, port: u16) -> std::io::Result<()> {
    let l = TcpListener::bind((host, port))?;
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let sh = shared.clone();
            std::thread::spawn(move || serve(sh, s));
        }
    });
    Ok(())
}

fn serve(shared: Shared, s: TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5))); // like Node.js keep-alive
    let mut w = match s.try_clone() { Ok(x) => x, Err(_) => return };
    let mut r = BufReader::new(s);
    loop {
        // limited lines and headers: a hostile client cannot make the node store endless data
        let mut line = String::new();
        if (&mut r).take(8192).read_line(&mut line).unwrap_or(0) == 0 || !line.ends_with('\n') { return; }
        let method = line.split_whitespace().next().unwrap_or("").to_string();
        let mut len = 0usize;
        let mut close = false;
        let mut headers = 0;
        loop {
            headers += 1;
            if headers > 100 { return; }
            let mut h = String::new();
            if (&mut r).take(8192).read_line(&mut h).unwrap_or(0) == 0 || !h.ends_with('\n') { return; }
            let h = h.trim_end();
            if h.is_empty() { break; }
            if let Some((k, v)) = h.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                if k == "content-length" { len = v.trim().parse().unwrap_or(0); }
                if k == "connection" && v.trim().eq_ignore_ascii_case("close") { close = true; }
            }
        }
        if len > 10_000_000 { return; }
        let mut body = vec![0u8; len];
        if r.read_exact(&mut body).is_err() { return; }
        let (status, out) = if method != "POST" { ("405 Method Not Allowed", String::new()) } else { ("200 OK", handle(&shared, &body)) };
        let resp = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: {}\r\n\r\n{out}", out.len(), if close { "close" } else { "keep-alive" });
        if w.write_all(resp.as_bytes()).is_err() || close { return; }
    }
}

fn handle(shared: &Shared, body: &[u8]) -> String {
    let msg: Value = match serde_json::from_slice(body) { Ok(v) => v, Err(e) => return json!({ "id": null, "error": format!("invalid JSON: {e}") }).to_string() };
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg["method"].as_str().unwrap_or("").to_string();
    let params = msg.get("params").cloned().filter(|p| p.is_object()).unwrap_or(json!({}));
    let (lock, cv) = &**shared;
    // getblocktemplate with long polling: waits (without holding the node) until the template changes, at most 1 s
    if method == "getblocktemplate" {
        if let Some(lp) = params["longpollid"].as_str() {
            let g = lock_node(lock);
            if lp == template_id(&g) { let _ = cv.wait_timeout(g, Duration::from_secs(1)); }
        }
    }
    let mut n = lock_node(lock);
    let v0 = n.c.virtual_version;
    let r = guarded(|| dispatch(&mut n, &method, &params));
    let changed = n.c.virtual_version != v0 || method == "sendrawtransaction";
    let pending = std::mem::take(&mut n.to_connect);
    drop(n);
    if changed { cv.notify_all(); }
    for a in pending { crate::node::connect(shared, a); }
    match r {
        Ok(result) => json!({ "id": id, "result": result }).to_string(),
        Err(e) => json!({ "id": id, "error": e }).to_string(),
    }
}

fn template_id(n: &Node) -> String { format!("{}-{}", n.c.virtual_version, n.mempool.version) }
fn s(v: u64) -> Value { Value::String(v.to_string()) }
fn hx(b: &[u8]) -> Value { Value::String(to_hex(b)) }
fn p_u64(p: &Value, k: &str, d: u64) -> u64 { p.get(k).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))).unwrap_or(d) }
fn p_str<'a>(p: &'a Value, k: &str) -> Result<&'a str, String> { p.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing parameter: {k}")) }
fn h32(sv: &str) -> Result<Hash, String> { from_hex32(sv) }

fn shielded_entry(n: &Node, index: usize) -> Value {
    let v = n.c.virtual_view();
    let Some(key) = v.s_at(index) else { return Value::Null };
    let e = v.get_s(&key).unwrap();
    let mut o = json!({
        "index": index, "outpoint": format!("{}:{}", to_hex(&key.0), key.1), "P": hx(&e.p), "C": hx(&e.c), "encAmount": hx(&e.enc_amount),
        "viewTag": e.view_tag, "R": hx(&e.r), "j": e.j, "daa": e.daa, "coinbase": e.coinbase,
    });
    if !e.coinbase {
        if let Some(tx) = n.c.find_tx(&key.0) { if !tx.payload.is_empty() { o["memo"] = hx(&tx.payload); } }
    }
    o
}

fn check_name(raw: &str) -> Result<String, String> {
    let mut nm = raw.trim().to_lowercase();
    if let Some(x) = nm.strip_prefix('@') { nm = x.to_string(); }
    if !is_valid_name(nm.as_bytes()) {
        return Err(format!("invalid name \"{raw}\": use 3 to 32 characters among a-z, 0-9 and hyphen (no accents, not starting or ending with a hyphen and no \"--\")"));
    }
    Ok(nm)
}

fn name_info(n: &Node, raw: &str) -> Result<Value, String> {
    let p = &n.params;
    let v = n.c.virt();
    let daa = v.gd.daa_score;
    let name = check_name(raw)?;
    let fee = name_fee(p, &name);
    let view = n.c.virtual_view();
    let live = view.name_entries(&name).into_iter()
        .filter_map(|(k, e)| parse_name_record(&e.lock).map(|r| (k, e.clone(), r)))
        .find(|(_, _, r)| daa <= r.expiry + p.name_grace);
    let Some((key, e, r)) = live else { return Ok(json!({ "name": name, "status": "free", "fee": s(fee), "daaScore": daa })) };
    let bps = p.bps as f64;
    Ok(json!({
        "name": name, "status": if daa <= r.expiry { "active" } else { "grace" }, "fee": s(fee), "daaScore": daa,
        "target": encode_address(p, &r.target), "targetType": parse_address_data(&r.target).map(|a| a.kind().to_string()),
        "targetData": hx(&r.target), "owner": encode_address(p, &r.owner), "ownerLock": hx(&r.owner),
        "expiry": r.expiry, "expiresIn": (r.expiry as f64 - daa as f64) / bps, "graceEndsIn": ((r.expiry + p.name_grace) as f64 - daa as f64) / bps,
        "outpoint": format!("{}:{}", to_hex(&key.0), key.1), "txid": to_hex(&key.0), "deposit": s(e.amount), "since": e.daa,
    }))
}

fn colors(n: &Node) -> (HashSet<Hash>, HashSet<Hash>) {
    let chain: HashSet<Hash> = n.c.selected_chain(600).into_iter().collect();
    let mut reds: HashSet<Hash> = n.c.virt().gd.mergeset_reds.iter().copied().collect();
    for h in &chain { for r in &n.c.store.gd[h].mergeset_reds { reds.insert(*r); } }
    (chain, reds)
}

fn block_summary(n: &Node, h: &Hash, col: &(HashSet<Hash>, HashSet<Hash>)) -> Value {
    let b = n.c.blocks.get(h); // (a pruned node may no longer keep the body)
    let gd = &n.c.store.gd[h];
    let miner = encode_address(&n.params, &n.c.miner_data[h]).filter(|_| !n.c.miner_data[h].is_empty());
    let txids: Vec<String> = b.map(|b| b.txs[1..].iter().map(|t| t.id_hex()).collect()).unwrap_or_default();
    json!({
        "hash": to_hex(h), "parents": n.c.store.parents[h].iter().map(|h| to_hex(h)).collect::<Vec<_>>(), "blueScore": gd.blue_score,
        "daaScore": gd.daa_score, "timestamp": n.c.headers[h].timestamp, "txs": txids.len(),
        "txids": txids, "chain": col.0.contains(h),
        "color": if col.1.contains(h) { "red" } else { "blue" }, "tip": n.c.tips.contains(h), "miner": miner,
    })
}

pub fn dispatch(n: &mut Node, method: &str, p: &Value) -> Result<Value, String> {
    n.c.ensure_virtual_base();
    match method {
        "getcompactoutputs" => {
            let v = n.c.virtual_view();
            let start = p_u64(p, "start", 0) as usize;
            let count = p_u64(p, "count", 5000).min(20_000) as usize;
            let end = v.s_count().min(start.saturating_add(count));
            let mut data = vec![];
            for i in start..end { let e = v.get_s(&v.s_at(i).unwrap()).unwrap(); data.extend_from_slice(&e.r); data.push(e.j as u8); data.push(e.view_tag); }
            Ok(json!({ "total": v.s_count(), "daaScore": n.c.virt().gd.daa_score, "start": start, "count": end.saturating_sub(start), "data": hx(&data) }))
        }
        "getkeyimagebucket" => {
            let prefix = p_str(p, "prefix")?.to_string();
            if prefix.len() != 2 || !prefix.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) { return Err("invalid key image prefix (use 1 byte, e.g. \"a7\")".into()); }
            let v = n.c.virtual_view();
            let mut spent: Vec<String> = v.base.ki.iter().map(|k| to_hex(k)).filter(|k| k.starts_with(&prefix)).collect();
            spent.extend(v.diff.add_ki.iter().map(|k| to_hex(k)).filter(|k| k.starts_with(&prefix)));
            let (_, skis) = n.stem_spends();
            let mut mempool: Vec<String> = n.mempool.kis.keys().map(|k| to_hex(k)).filter(|k| k.starts_with(&prefix)).collect();
            mempool.extend(skis.iter().map(|k| to_hex(k)).filter(|k| k.starts_with(&prefix)));
            Ok(json!({ "prefix": prefix, "spent": spent, "mempool": mempool }))
        }
        "getheader" => {
            let hs = p_str(p, "hash")?;
            let h = n.c.headers.get(&h32(hs)?).ok_or("unknown block")?;
            Ok(json!({ "hash": hs, "header": hx(&h.serialize(false)) }))
        }
        "gettxproof" => {
            let txid = h32(p_str(p, "txid")?)?;
            let depth = p_u64(p, "depth", 100).clamp(1, 5000) as usize;
            let Some(h) = n.c.tx_index.get(&txid).copied() else {
                return Err(if n.c.tx_status(&txid)["status"] == "accepted" { "accepted just now: the proof will be ready at the next block".into() } else { "transaction not accepted".into() });
            };
            let accepted = &n.c.acc.get(&h).ok_or("this pruned node no longer keeps that block")?.accepted;
            let idx = accepted.iter().position(|x| *x == txid).ok_or("transaction not accepted")?;
            let merkle = merkle_proof(accepted, idx);
            let hscore = n.c.store.gd[&h].blue_score;
            let mut after: std::collections::VecDeque<Hash> = Default::default();
            let mut x = n.c.virt().gd.selected_parent;
            while let Some(b) = x {
                if b == h { break; }
                let g = &n.c.store.gd[&b];
                if g.blue_score <= hscore { return Err("the accepting block left the selected chain (reorganization): try again".into()); }
                after.push_back(b);
                if after.len() > depth { after.pop_front(); }
                x = g.selected_parent;
            }
            if x.is_none() { return Err("accepting block outside the chain".into()); }
            let chain: Vec<Value> = after.iter().rev().map(|b| hx(&n.c.headers[b].serialize(false))).collect();
            Ok(json!({ "txid": to_hex(&txid), "block": to_hex(&h), "header": hx(&n.c.headers[&h].serialize(false)), "merkle": merkle, "chain": chain, "available": after.len() }))
        }
        "resolvename" => name_info(n, p_str(p, "name")?),
        "listnames" => {
            let owners: Option<HashSet<String>> = p.get("owners").and_then(|o| o.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
            let limit = p_u64(p, "limit", 1000).min(5000) as usize;
            let mut names: Vec<String> = n.c.virtual_view().all_names().into_iter().collect();
            names.sort();
            let mut out = vec![];
            for nm in names {
                let Ok(info) = name_info(n, &nm) else { continue };
                if info["status"] == "free" { continue; }
                if let Some(w) = &owners { if !w.contains(info["ownerLock"].as_str().unwrap_or("")) { continue; } }
                out.push(info);
                if out.len() >= limit { break; }
            }
            Ok(Value::Array(out))
        }
        "getinfo" => {
            let v = n.c.virt();
            let target = compact_to_target(v.bits).unwrap_or_default();
            let elapsed = ((now_ms() - n.started_at) as f64 / 1000.0).clamp(1.0, 60.0);
            let bps = n.block_times.len() as f64 / elapsed;
            let work = calc_work(v.bits).to_f64().unwrap_or(0.0);
            let view = n.c.virtual_view();
            Ok(json!({
                "network": n.params.name, "genesis": to_hex(&n.c.genesis_hash), "blocks": n.c.blocks_count + 1, "tips": n.c.tips.len(),
                "pruned": n.c.pruning_point.is_some(), "pruningPoint": n.c.pruning_point.map(|h| to_hex(&h)),
                "virtual": { "blueScore": v.gd.blue_score, "daaScore": v.gd.daa_score, "selectedParent": v.gd.selected_parent.map(|h| to_hex(&h)), "parents": v.parents.len() },
                "difficulty": work, "target": target.to_str_radix(16), "blocksPerSecond": (bps * 100.0).round() / 100.0,
                "hashrate": (work * bps).round(), "mempool": n.mempool.txs.len(), "peers": n.peers.values().filter(|x| x.ready).count(),
                "minted": s(v.acceptance.minted), "feePool": s(v.acceptance.pool), "shieldedSupply": v.acceptance.shielded.to_string(),
                "shieldedOutputs": view.s_count(), "redBlocks": n.c.reds_count, "names": view.all_names().len(), "implementation": "krevod (Rust)",
            }))
        }
        "getblocktemplate" => {
            let addr = decode_address(&n.params, p_str(p, "address")?)?;
            let id = template_id(n);
            let key = format!("{id}{}", to_hex(addr.data()));
            if let Some(t) = n.template_cache.get(&key) { return Ok(t.clone()); }
            let max = n.params.max_block_mass - 20_000;
            let txs = n.mempool.select(max);
            let count = txs.len();
            let block = n.c.build_template(addr.data(), txs, b"krevod", now_ms()).ok_or("could not build the template")?;
            let t = json!({ "block": hx(&block.serialize()), "prePowHash": hx(&block.header.pre_pow_hash()), "bits": block.header.bits, "longpollid": id, "txs": count });
            if n.template_cache.len() > 64 { n.template_cache.clear(); }
            n.template_cache.insert(key, t.clone());
            Ok(t)
        }
        "submitblock" => {
            let b = Block::deserialize(&from_hex(p_str(p, "block")?)?)?;
            let (status, hash, reason) = n.receive_block(b, None);
            let mut r = json!({ "status": status, "hash": to_hex(&hash) });
            if let Some(x) = reason { r["reason"] = json!(x); }
            Ok(r)
        }
        "sendrawtransaction" => {
            let tx = Transaction::deserialize(&from_hex(p_str(p, "tx")?)?)?;
            let r = n.receive_tx(Arc::new(tx), None, true);
            if r["ok"] != true { return Err(r["reason"].as_str().unwrap_or("transaction rejected").to_string()); }
            Ok(json!({ "txid": r["txid"], "phase": r["phase"] }))
        }
        "gettransaction" => {
            let txid = h32(p_str(p, "txid")?)?;
            let m = n.mempool.txs.get(&txid).map(|e| e.tx.clone()).or_else(|| n.stem.get(&txid).map(|e| e.0.clone()));
            let raw = match &m { Some(t) => t.serialize(), None => n.c.find_tx(&txid).ok_or("unknown transaction")?.serialize() };
            let st = n.c.tx_status(&txid);
            let status = if st["status"] == "unknown" && m.is_some() { json!("mempool") } else { st["status"].clone() };
            Ok(json!({
                "txid": to_hex(&txid), "tx": hx(&raw), "status": status, "confirmations": st.get("confirmations").cloned().unwrap_or(json!(0)),
                "includedIn": n.c.tx_block.get(&txid).map(|h| to_hex(h)), "acceptingBlock": st.get("acceptingBlock").cloned().unwrap_or(Value::Null),
            }))
        }
        "gettransactionstatus" => {
            let txid = h32(p_str(p, "txid")?)?;
            let st = n.c.tx_status(&txid);
            if st["status"] == "unknown" && (n.mempool.txs.contains_key(&txid) || n.stem.contains_key(&txid)) { return Ok(json!({ "status": "mempool" })); }
            Ok(st)
        }
        "getutxos" => {
            let daa = n.c.virt().gd.daa_score;
            let (souts, _) = n.stem_spends();
            let mut out = vec![];
            for l in p["locks"].as_array().cloned().unwrap_or_default() {
                let Some(lock) = l.as_str().and_then(|x| from_hex(x).ok()) else { continue };
                for (k, e) in n.c.utxos_by_lock(&lock) {
                    out.push(json!({
                        "outpoint": format!("{}:{}", to_hex(&k.0), k.1), "amount": s(e.amount), "lock": hx(&e.lock), "daa": e.daa, "coinbase": e.coinbase,
                        "mature": !e.coinbase || daa.saturating_sub(e.daa) >= n.params.coinbase_maturity,
                        "inMempool": n.mempool.spent.contains_key(&k) || souts.contains(&k),
                    }));
                }
            }
            Ok(json!({ "daaScore": daa, "utxos": out }))
        }
        "getshieldedoutputs" => {
            let total = n.c.virtual_view().s_count();
            let start = p_u64(p, "start", 0) as usize;
            let count = p_u64(p, "count", 1000).min(5000) as usize;
            let outs: Vec<Value> = (start..total.min(start.saturating_add(count))).map(|i| shielded_entry(n, i)).collect();
            Ok(json!({ "total": total, "daaScore": n.c.virt().gd.daa_score, "outputs": outs }))
        }
        "getshieldedbyindex" => {
            let total = n.c.virtual_view().s_count();
            let idx: Vec<usize> = p["indices"].as_array().cloned().unwrap_or_default().iter().take(500).filter_map(|x| x.as_u64()).map(|x| x as usize).collect();
            let outs: Vec<Value> = idx.into_iter().map(|i| shielded_entry(n, i)).filter(|v| !v.is_null()).collect();
            Ok(json!({ "total": total, "daaScore": n.c.virt().gd.daa_score, "outputs": outs }))
        }
        "getkeyimages" => {
            let (_, skis) = n.stem_spends();
            let v = n.c.virtual_view();
            let out: Vec<Value> = p["keyImages"].as_array().cloned().unwrap_or_default().iter().map(|k| {
                let ks = k.as_str().unwrap_or("");
                let kb: Option<[u8; 33]> = from_hex(ks).ok().and_then(|b| b.try_into().ok());
                let (spent, mp) = match kb { Some(b) => (v.has_ki(&b), n.mempool.kis.contains_key(&b) || skis.contains(&b)), None => (false, false) };
                json!({ "keyImage": ks, "spent": spent, "inMempool": mp })
            }).collect();
            Ok(Value::Array(out))
        }
        "getfcmpanchor" => {
            let daa = n.c.virt().gd.daa_score;
            let limit = daa as i128 - n.params.fcmp_maturity as i128 - 1;
            let base = &n.c.utxo;
            let (mut lo, mut hi) = (0usize, base.s_list.len());
            while lo < hi {
                let mid = (lo + hi).div_ceil(2);
                if (base.s[&base.s_list[mid - 1]].daa as i128) <= limit { lo = mid; } else { hi = mid - 1; }
            }
            Ok(json!({ "anchor": lo, "branch": n.params.fcmp_branch, "total": base.s_list.len(), "daaScore": daa }))
        }
        "getfcmppath" => {
            let anchor = p["anchor"].as_u64().ok_or("invalid anchor")?;
            let b = n.params.fcmp_branch as u64;
            let base = &n.c.utxo;
            if anchor < 1 || anchor > base.s_list.len() as u64 { return Err("invalid anchor".into()); }
            let last = anchor.div_ceil(b) - 1;
            let mut paths = vec![];
            for k in p["chunks"].as_array().cloned().unwrap_or_default().iter().take(32).filter_map(|x| x.as_u64()) {
                if k > last { continue; }
                let Some(levels) = base.tree_path(anchor, k) else { continue };
                let lv: Vec<Value> = levels.into_iter().map(|(l, idx, entries)| json!({
                    "level": l, "idx": idx, "entries": entries.iter().map(|e| to_hex(&crate::field::limbs_to_be(e))).collect::<Vec<_>>(),
                })).collect();
                paths.push(json!({ "chunk": k, "levels": lv }));
            }
            Ok(json!({ "anchor": anchor, "branch": b, "paths": paths }))
        }
        "getblock" => {
            let h = h32(p_str(p, "hash")?)?;
            let b = n.c.blocks.get(&h).cloned().ok_or(if n.c.headers.contains_key(&h) { "this pruned node no longer keeps that block's body" } else { "unknown block" })?;
            let col = colors(n);
            let mut r = block_summary(n, &h, &col);
            let gd = &n.c.store.gd[&h];
            let cb = &b.txs[0];
            let o = r.as_object_mut().unwrap();
            let extra: Map<String, Value> = serde_json::from_value(json!({
                "bits": b.header.bits, "nonce": s(b.header.nonce), "blueWork": b.header.blue_work.to_string(),
                "selectedParent": gd.selected_parent.map(|x| to_hex(&x)), "blues": gd.mergeset_blues.iter().map(|h| to_hex(h)).collect::<Vec<_>>(),
                "reds": gd.mergeset_reds.iter().map(|h| to_hex(h)).collect::<Vec<_>>(),
                "status": match n.c.status.get(&h) { Some(Status::Chain) => json!("chain"), Some(Status::Disq) => json!("disq"), None => Value::Null },
                "children": n.c.store.children.get(&h).map(|c| c.iter().map(|h| to_hex(h)).collect::<Vec<_>>()).unwrap_or_default(),
                "size": b.serialize().len(), "mass": b.txs.iter().map(|t| t.mass).sum::<u64>(), "utxoCommitment": hx(&b.header.utxo_commitment),
                "txs": b.txs.iter().map(|t| t.id_hex()).collect::<Vec<_>>(),
                "coinbase": {
                    "txid": cb.id_hex(),
                    "transparent": cb.t_out.iter().map(|o| json!({ "address": describe_lock(&n.params, &o.lock), "amount": s(o.amount) })).collect::<Vec<_>>(),
                    "shielded": cb.s_out.len(),
                },
                "accepted": n.c.acc.get(&h).map(|a| a.accepted.len()).unwrap_or(0),
            })).unwrap();
            for (k, v) in extra { o.insert(k, v); }
            Ok(r)
        }
        "getdag" => {
            let limit = p_u64(p, "limit", 80).clamp(1, 500) as usize;
            let col = colors(n);
            let from = n.c.order.len().saturating_sub(limit);
            let blocks: Vec<Value> = n.c.order[from..].iter().map(|h| block_summary(n, h, &col)).collect();
            Ok(json!({ "virtualBlueScore": n.c.virt().gd.blue_score, "blocks": blocks }))
        }
        "getaddresshistory" => {
            let a = decode_address(&n.params, p_str(p, "address")?)?;
            if a.kind() == 's' { return Err("private address: the balance and history are invisible by design".into()); }
            let daa = n.c.virt().gd.daa_score;
            let utxos: Vec<Value> = n.c.utxos_by_lock(a.data()).into_iter().map(|(k, e)| json!({
                "outpoint": format!("{}:{}", to_hex(&k.0), k.1), "amount": s(e.amount), "daa": e.daa, "coinbase": e.coinbase,
                "mature": !e.coinbase || daa.saturating_sub(e.daa) >= n.params.coinbase_maturity,
            })).collect();
            let limit = p_u64(p, "limit", 50).clamp(1, 500) as usize;
            let all = n.c.lock_txs.get(a.data()).cloned().unwrap_or_default();
            let txids: Vec<String> = all[all.len().saturating_sub(limit)..].iter().rev().map(|t| to_hex(t)).collect();
            Ok(json!({ "type": a.kind().to_string(), "utxos": utxos, "txids": txids, "daaScore": daa }))
        }
        "getblockreward" => {
            let h = h32(p_str(p, "hash")?)?;
            if !n.c.has(&h) { return Ok(json!({ "status": "unknown" })); }
            let Some(r) = n.c.reward_index.get(&h).copied() else { return Ok(json!({ "status": "pending" })) };
            if r.red { return Ok(json!({ "status": "red", "paidBy": to_hex(&r.paid_by) })); }
            let age = n.c.virt().gd.daa_score - n.c.store.gd[&r.paid_by].daa_score;
            Ok(json!({ "status": "paid", "amount": s(r.amount), "paidBy": to_hex(&r.paid_by), "age": age, "mature": age > n.params.coinbase_maturity + 2 }))
        }
        "getmempool" => {
            let limit = p_u64(p, "limit", 50).clamp(1, 500) as usize;
            let mut es: Vec<&crate::mempool::Entry> = n.mempool.txs.values().collect();
            es.sort_by(|a, b| b.added.cmp(&a.added));
            Ok(Value::Array(es.into_iter().take(limit).map(|e| json!({ "txid": e.tx.id_hex(), "fee": s(e.tx.fee), "mass": e.tx.mass, "size": e.tx.size(), "added": e.added })).collect()))
        }
        "getpeers" => Ok(Value::Array(n.peers.values().map(|p| json!({ "addr": p.listen.clone().unwrap_or(p.addr.clone()), "outbound": p.outbound, "ready": p.ready })).collect())),
        "addpeer" => { let a = p_str(p, "addr")?.to_string(); if !n.known.contains(&a) { n.known.push(a.clone()); } n.to_connect.push(a); Ok(json!(true)) }
        "estimatefee" => Ok(json!({ "feeRate": s(n.params.min_relay_fee_rate) })),
        _ => Err(format!("unknown method: {method}")),
    }
}
