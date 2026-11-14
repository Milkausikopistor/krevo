//! Núcleo criptográfico das carteiras do Krevo, em Rust, compilado para WebAssembly.
//!
//! Reaproveita os MESMOS arquivos do nó em Rust (rust/krevod/src): corpo finito, curvas,
//! hash, Bulletproofs, FCMP e as operações de tempo constante — uma só implementação,
//! conferida contra o nó de referência em JavaScript.
//! As carteiras JavaScript (CLI no Node e app no navegador) carregam o .wasm e usam estas
//! funções para tudo o que envolve SEGREDOS: multiplicações por chaves e máscaras, assinaturas,
//! provas de intervalo, provas de pertencimento à cadeia inteira e AES-GCM.

#[path = "../../krevod/src/bytes.rs"]
pub mod bytes;
#[path = "../../krevod/src/crypto.rs"]
pub mod crypto;
#[path = "../../krevod/src/ct.rs"]
pub mod ct;
#[path = "../../krevod/src/curve.rs"]
pub mod curve;
#[path = "../../krevod/src/fcmp.rs"]
pub mod fcmp;
#[path = "../../krevod/src/field.rs"]
pub mod field;
#[path = "../../krevod/src/hash.rs"]
pub mod hash;
#[path = "../../krevod/src/vault.rs"]
pub mod vault;
#[path = "../../krevod/src/wallet_ops.rs"]
pub mod wallet_ops;

pub mod api;
