//! Hostile inputs: nothing that arrives from the network (blocks, transactions, P2P messages, RPC calls)
//! may bring the node down. Tens of thousands of mutations of valid data and of random garbage
//! go through the decoders, the handling of peer messages and the RPC — any
//! panic makes the test fail.

use crate::block::{Block, Header};
use crate::bytes::{from_hex, to_hex};
use crate::node::Node;
use crate::params::get_params;
use crate::rpc::dispatch;
use crate::tx::Transaction;
use serde_json::{json, Value};

struct Rng(u64);
/// Fixed seed (reproducible); KREVO_FUZZ_SEED=n changes the seed to explore more cases.
fn seed(d: u64) -> u64 { std::env::var("KREVO_FUZZ_SEED").ok().and_then(|s| s.parse::<u64>().ok()).map(|x| (x.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ d) | 1).unwrap_or(d) }
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: usize) -> usize { (self.next() % n.max(1) as u64) as usize }
    fn bytes(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.next() as u8).collect() }
}

/// Mutation of a valid piece of data: flips bits, truncates, inserts, duplicates stretches and plants
/// huge "varints" (0xfd/0xfe/0xff followed by giant values).
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        if v.is_empty() { let k = 1 + rng.below(64); v = rng.bytes(k); }
        let at = rng.below(v.len());
        match rng.below(7) {
            0 => { let bit = rng.below(8); v[at] ^= 1 << bit; }
            1 => v.truncate(at),
            2 => { let k = 1 + rng.below(40); let ins = rng.bytes(k); v.splice(at..at, ins); }
            3 => { let big = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]; let k = 1 + rng.below(big.len()); v.splice(at..at, big[..k].iter().copied()); v.insert(at, [0xfd, 0xfe, 0xff][rng.below(3)]); }
            4 => { let end = (at + 1 + rng.below(64)).min(v.len()); let dup = v[at..end].to_vec(); v.splice(at..at, dup); }
            5 => { let r = rng.next() as u8; v[at] = r; }
            _ => { let end = (at + 1 + rng.below(32)).min(v.len()); for b in &mut v[at..end] { *b = 0; } }
        }
    }
    v
}

fn genesis_bytes() -> Vec<Vec<u8>> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).expect("vectors.json")).unwrap();
    ["mainnet", "testnet", "devnet", "simnet"].iter().map(|n| from_hex(v["genesis"][n]["block"].as_str().unwrap()).unwrap()).collect()
}

#[test]
fn decoders_never_panic_on_hostile_bytes() {
    let mut rng = Rng(seed(0x9e37_79b9_7f4a_7c15));
    let blocks = genesis_bytes();
    let mut bases: Vec<Vec<u8>> = blocks.clone();
    for b in &blocks {
        let blk = Block::deserialize(b).expect("valid genesis");
        assert_eq!(&blk.serialize(), b, "round trip");
        for t in &blk.txs { bases.push(t.serialize()); }
        bases.push(blk.header.serialize(false));
    }
    let mut accepted = 0;
    for i in 0..40_000 {
        let data = if i % 5 == 0 { let n = rng.below(400); rng.bytes(n) } else { let k = rng.below(bases.len()); mutate(&mut rng, &bases[k]) };
        if let Ok(b) = Block::deserialize(&data) { accepted += 1; let _ = b.hash(); let _ = b.serialize(); }
        if let Ok(t) = Transaction::deserialize(&data) { accepted += 1; let _ = t.id(); let _ = t.serialize(); }
        let _ = Header::deserialize(&data);
    }
    // some mutations (e.g. just one bit of a free field) stay decodable — and that is fine
    assert!(accepted < 40_000);
}

/// Hostile P2P messages (wrong types, invalid hex, mutated blocks and transactions, giant
/// lists) delivered to the node's handler: no panic.
#[test]
fn hostile_peer_messages_never_panic() {
    let params = get_params("simnet").unwrap();
    let mut n = Node::new(params, None, 0, "127.0.0.1".into(), 0);
    let mut rng = Rng(seed(0x2545_f491_4f6c_dd1d));
    let gb = n.c.blocks.get(&n.c.genesis_hash).expect("genesis").serialize();
    let gtx = Block::deserialize(&gb).unwrap().txs[0].serialize();
    let h32 = to_hex(&[0xab; 32]);
    let mut msgs: Vec<Value> = vec![
        json!(null), json!([]), json!("text"), json!(7), json!({}), json!({ "t": null }), json!({ "t": 5 }), json!({ "t": "unknown" }),
        json!({ "t": "hello", "network": 5, "genesis": [], "listen": "x", "nonce": {} }),
        json!({ "t": "hello", "network": "simnet", "genesis": "zz", "listen": u64::MAX }),
        json!({ "t": "getdag", "from": -1 }), json!({ "t": "getdag", "from": "x" }), json!({ "t": "getdag", "from": u64::MAX }),
        json!({ "t": "inv", "blocks": [1, null, "zz", h32, {}], "txs": [h32, "00", 5] }),
        json!({ "t": "inv", "blocks": "not a list", "txs": {} }),
        json!({ "t": "getblocks", "hashes": "x" }), json!({ "t": "getblocks", "hashes": vec![h32.clone(); 5000] }),
        json!({ "t": "gettxs", "txids": [null, 1, "zz", h32] }),
        json!({ "t": "block" }), json!({ "t": "block", "data": 5 }), json!({ "t": "block", "data": "zz" }), json!({ "t": "block", "data": "0" }),
        json!({ "t": "tx" }), json!({ "t": "tx", "data": [] }), json!({ "t": "tx", "data": "abc", "stem": "sim" }),
        json!({ "t": "addr", "addrs": [":", "a:b", "x".repeat(10_000), 5, "1.2.3.4:99999", "[::1]:1"] }),
        json!({ "t": "addr", "addrs": vec!["9.9.9.9:1"; 5000] }),
        json!({ "t": "block", "data": to_hex(&gb) }), // repeated: already known
        json!({ "t": "tx", "data": to_hex(&gtx), "stem": true }), // a loose coinbase: invalid
    ];
    for _ in 0..3000 {
        msgs.push(json!({ "t": "block", "data": to_hex(&mutate(&mut rng, &gb)) }));
        msgs.push(json!({ "t": "tx", "data": to_hex(&mutate(&mut rng, &gtx)), "stem": rng.below(2) == 0 }));
    }
    for m in &msgs {
        let p = n.test_peer();
        let _ = n.handle(p, m);
    }
    assert!(n.c.store.gd.len() == 1, "no hostile block may get in");
    assert!(n.mempool.txs.is_empty(), "no hostile transaction may get in");
}

/// Every RPC method with hostile parameters: no panic, only errors.
#[test]
fn hostile_rpc_params_never_panic() {
    let params = get_params("simnet").unwrap();
    let mut n = Node::new(params, None, 0, "127.0.0.1".into(), 0);
    let mut rng = Rng(seed(0x1234_5678_9abc_def1));
    let gb = n.c.blocks.get(&n.c.genesis_hash).expect("genesis").serialize();
    let methods = [
        "getcompactoutputs", "getkeyimagebucket", "getheader", "gettxproof", "resolvename", "listnames", "getinfo", "getblocktemplate",
        "submitblock", "sendrawtransaction", "gettransaction", "gettransactionstatus", "getutxos", "getshieldedoutputs", "getshieldedbyindex",
        "getkeyimages", "getfcmpanchor", "getfcmppath", "getblock", "getdag", "getaddresshistory", "getblockreward", "getmempool", "getpeers",
        "estimatefee", "nao_existe",
    ];
    let keys = ["addr", "address", "anchor", "block", "chunks", "count", "depth", "hash", "indices", "keyImages", "limit", "locks", "name", "owners", "prefix", "start", "tx", "txid"];
    let hostile = |rng: &mut Rng| -> Value {
        match rng.below(12) {
            0 => json!(null), 1 => json!(-1), 2 => json!(u64::MAX), 3 => json!("zz"), 4 => json!(to_hex(&[0xab; 32])),
            5 => json!([1, "x", null]), 6 => json!({ "a": 1 }), 7 => json!("x".repeat(5000)), 8 => json!(vec![u64::MAX; 300]),
            9 => json!(to_hex(&mutate(rng, &gb))), 10 => json!(1.5e300), _ => json!(vec![to_hex(&[0; 32]); 300]),
        }
    };
    for _ in 0..60 {
        for m in methods {
            let mut p = serde_json::Map::new();
            for k in keys { if rng.below(2) == 0 { p.insert(k.into(), hostile(&mut rng)); } }
            let _ = dispatch(&mut n, m, &Value::Object(p));
        }
    }
    assert!(n.c.store.gd.len() == 1);
}
