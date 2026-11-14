//! krevod — nó completo do Krevo em Rust.
//!
//! Reimplementação independente do nó de referência em JavaScript (src/): mesmas regras
//! de consenso, bit a bit, mesmo protocolo P2P e o mesmo RPC — carteiras, mineradores,
//! servidor leve e explorador do projeto funcionam com ele sem mudanças.
//!
//!   krevod no      --rede devnet [--dados DIR] [--porta N] [--rpcporta N] [--par host:porta]… [--sem-sementes]
//!   krevod replay  --rede devnet --arquivo DIR/devnet/blocos.dat
//!   krevod provar  [--conferir]   (provador FCMP nativo para as carteiras: JSON na entrada e na saída)

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

/// Argumentos no estilo da CLI JavaScript (português, com apelidos em inglês).
pub struct Args { pub cmd: String, pub opts: HashMap<String, Vec<String>> }

impl Args {
    pub fn parse() -> Self {
        let alias = |k: &str| -> String {
            match k {
                "network" => "rede", "datadir" => "dados", "port" => "porta", "rpcport" => "rpcporta",
                "peer" => "par", "file" => "arquivo", other => other,
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
        let cmd = match cmd.as_str() { "node" => "no".into(), other => other.to_string() };
        Args { cmd, opts }
    }
    pub fn get(&self, k: &str) -> Option<&str> { self.opts.get(k).and_then(|v| v.last()).map(|s| s.as_str()) }
    pub fn all(&self, k: &str) -> Vec<String> { self.opts.get(k).cloned().unwrap_or_default() }
}

fn main() {
    let args = Args::parse();
    let net = args.get("rede").unwrap_or("devnet").to_string();
    let Some(params) = params::get_params(&net) else { eprintln!("rede desconhecida: {net}"); std::process::exit(1) };
    match args.cmd.as_str() {
        "provar" | "prove" => {
            let out = provecmd::run(args.get("conferir").is_some() || args.get("check").is_some());
            println!("{out}");
            if out.get("error").is_some() { std::process::exit(1); }
        }
        "replay" => {
            let Some(f) = args.get("arquivo") else { eprintln!("use: krevod replay --rede REDE --arquivo blocos.dat"); std::process::exit(1) };
            let s = replay::run(params, std::path::Path::new(f));
            println!("{}", serde_json::to_string_pretty(&s).unwrap());
        }
        "no" => {
            let datadir = std::path::PathBuf::from(args.get("dados").unwrap_or("./dados")).join(params.name);
            let storage = match storage::BlockFile::new(&datadir) { Ok(s) => s, Err(e) => { eprintln!("não consegui abrir {}: {e}", datadir.display()); std::process::exit(1) } };
            let port = args.get("porta").and_then(|x| x.parse().ok()).unwrap_or(params.default_p2p_port);
            let rpc_port = args.get("rpcporta").and_then(|x| x.parse().ok()).unwrap_or(params.default_rpc_port);
            let rpc_host = args.get("rpchost").unwrap_or("127.0.0.1").to_string();
            // pares indicados + nós-semente da rede (seeds/<rede>.txt), salvo com --sem-sementes
            let mut peers: Vec<String> = args.all("par").into_iter().filter(|x| x != "true").collect();
            if args.get("sem-sementes").is_none() && args.get("no-seeds").is_none() {
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
                        node::log(&format!("blue score {bs} | blocos {} | pontas {} | mempool {} | pares {}", n.c.store.gd.len(), n.c.tips.len(), n.mempool.txs.len(), n.peers.len()));
                    }
                }
            });
            if let Err(e) = node::run(shared, peers) { eprintln!("erro: {e}"); std::process::exit(1); }
        }
        _ => {
            eprintln!("krevod — nó do Krevo em Rust\n  krevod no --rede devnet [--dados DIR] [--porta N] [--rpcporta N] [--par host:porta]\n  krevod replay --rede devnet --arquivo blocos.dat");
        }
    }
}
