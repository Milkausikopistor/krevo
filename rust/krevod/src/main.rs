//! krevod — Krevo full node in Rust.
//!
//! An independent reimplementation of the JavaScript reference node (src/): the same consensus
//! rules, bit for bit, the same P2P protocol and the same RPC — the project's wallets, miners,
//! light server and explorer work with it unchanged.
//!
//!   krevod node    --network devnet [--datadir DIR] [--port N] [--rpcport N] [--peer host:port]… [--no-seeds]
//!   krevod replay  --network devnet --file DIR/devnet/blocks.dat
//!   krevod prove   [--check]   (native FCMP prover for the wallets: JSON in and out)
//!
//! The original Portuguese command and option names (no, provar, --rede, --dados…) are still accepted.

pub mod block;
pub mod bytes;
pub mod consensus;
pub mod crypto;
pub mod ct;
pub mod curve;
pub mod dag;
pub mod fcmp;
pub mod field;
pub mod hash;
pub mod mempool;
pub mod node;
pub mod params;
pub mod pow;
pub mod provecmd;
pub mod replay;
pub mod rpc;
pub mod rules;
pub mod storage;
pub mod tx;
pub mod txvalidation;
pub mod utxo;
pub mod vault;
pub mod wallet_ops;
#[cfg(test)]
mod ct_timing_test;
#[cfg(test)]
mod hostile_test;
#[cfg(test)]
mod vectors_test;

use std::collections::HashMap;

/// Arguments in the style of the JavaScript CLI (English, with the original Portuguese names as aliases).
pub struct Args { pub cmd: String, pub opts: HashMap<String, Vec<String>> }

impl Args {
    pub fn parse() -> Self {
        let alias = |k: &str| -> String {
            match k {
                "rede" => "network", "dados" => "datadir", "porta" => "port", "rpcporta" => "rpcport",
                "par" => "peer", "arquivo" => "file", "sem-sementes" => "no-seeds", "conferir" => "check", other => other,
            }.to_string()
        };
        let raw: Vec<String> = std::env::args().skip(1).collect();
        let mut cmd = String::new();
        let mut opts: HashMap<String, Vec<String>> = HashMap::new();
        let mut i = 0;
        while i < raw.len() {
            if let Some(k) = raw[i].strip_prefix("--") {
                let v = if i + 1 < raw.len() && !raw[i + 1].starts_with("--") { i += 1; raw[i].clone() } else { "true".into() };
                opts.entry(alias(k)).or_default().push(v);
            } else if cmd.is_empty() { cmd = raw[i].clone(); }
            i += 1;
        }
        let cmd = match cmd.as_str() { "no" => "node".into(), "provar" => "prove".into(), other => other.to_string() };
        Args { cmd, opts }
    }
    pub fn get(&self, k: &str) -> Option<&str> { self.opts.get(k).and_then(|v| v.last()).map(|s| s.as_str()) }
    pub fn all(&self, k: &str) -> Vec<String> { self.opts.get(k).cloned().unwrap_or_default() }
}

fn main() {
    let args = Args::parse();
    let net = args.get("network").unwrap_or("devnet").to_string();
    let Some(params) = params::get_params(&net) else { eprintln!("unknown network: {net}"); std::process::exit(1) };
    match args.cmd.as_str() {
        "prove" => {
            let out = provecmd::run(args.get("check").is_some());
            println!("{out}");
            if out.get("error").is_some() { std::process::exit(1); }
        }
        "replay" => {
            let Some(f) = args.get("file") else { eprintln!("usage: krevod replay --network NETWORK --file blocks.dat"); std::process::exit(1) };
            let s = replay::run(params, std::path::Path::new(f));
            println!("{}", serde_json::to_string_pretty(&s).unwrap());
        }
        "node" => {
            // default data folder: ./data (one created by an older version, ./dados, is still used)
            let base = args.get("datadir").map(String::from).unwrap_or_else(|| {
                if !std::path::Path::new("./data").exists() && std::path::Path::new("./dados").exists() { "./dados".into() } else { "./data".into() }
            });
            let datadir = std::path::PathBuf::from(base).join(params.name);
            let storage = match storage::BlockFile::new(&datadir) { Ok(s) => s, Err(e) => { eprintln!("could not open {}: {e}", datadir.display()); std::process::exit(1) } };
            let port = args.get("port").and_then(|x| x.parse().ok()).unwrap_or(params.default_p2p_port);
            let rpc_port = args.get("rpcport").and_then(|x| x.parse().ok()).unwrap_or(params.default_rpc_port);
            let rpc_host = args.get("rpchost").unwrap_or("127.0.0.1").to_string();
            // given peers + the network's seed nodes (seeds/<network>.txt), unless --no-seeds
            let mut peers: Vec<String> = args.all("peer").into_iter().filter(|x| x != "true").collect();
            if args.get("no-seeds").is_none() {
                for s in params::seeds(params.name) { if !peers.contains(&s) { peers.push(s); } }
            }
            let n = node::Node::new(params, Some(storage), port, rpc_host, rpc_port);
            let shared: node::Shared = std::sync::Arc::new((std::sync::Mutex::new(n), std::sync::Condvar::new()));
            let sh = shared.clone();
            std::thread::spawn(move || {
                let mut last_bs = 0;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    let n = node::lock_node(&sh.0);
                    let bs = n.c.virt().gd.blue_score;
                    if bs != last_bs {
                        last_bs = bs;
                        node::log(&format!("blue score {bs} | blocks {} | tips {} | mempool {} | peers {}", n.c.store.gd.len(), n.c.tips.len(), n.mempool.txs.len(), n.peers.len()));
                    }
                }
            });
            if let Err(e) = node::run(shared, peers) { eprintln!("error: {e}"); std::process::exit(1); }
        }
        _ => {
            eprintln!("krevod — Krevo node in Rust\n  krevod node --network devnet [--datadir DIR] [--port N] [--rpcport N] [--peer host:port] [--no-seeds]\n  krevod replay --network devnet --file blocks.dat\n  krevod prove [--check]");
        }
    }
}
