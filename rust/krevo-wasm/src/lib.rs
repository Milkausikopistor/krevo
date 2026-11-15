//! Krevo wallets' cryptographic core, in Rust, compiled to WebAssembly.
//!
//! Reuses the SAME files as the Rust node (rust/krevod/src): finite field, curves,
//! hash, Bulletproofs, FCMP and the constant-time operations — a single implementation,
//! checked against the JavaScript reference node.
//! The JavaScript wallets (CLI on Node and the browser app) load the .wasm and use these
//! functions for everything involving SECRETS: multiplications by keys and masks, signatures,
//! range proofs, full-chain membership proofs and AES-GCM.

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
