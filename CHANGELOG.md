# Changelog

## [0.1.0] — 2026-11-15
First public release: a complete reference implementation, ready to download and run on a local
devnet or the (volunteer-run) public testnet. **Not audited — do not use it with real money.**

**Downloads in this release**
- `krevo-v0.1.0.zip` / `.tar.gz` — the whole project. Unpack it and run it with **Node.js 24.7+**;
  there is nothing to install (zero npm dependencies). Start with `node scripts/web-demo.js` (a local
  network + the web wallet at http://127.0.0.1:8091) or `node src/cli.js --help`.
- `krevod-v0.1.0-<platform>` — the Rust full node for Linux (x86_64, arm64), macOS (Apple silicon,
  Intel) and Windows (x86_64). `krevod node --network testnet` joins the testnet;
  `krevod prove` is also the wallets' native prover (point `KREVO_PROVER` at it).
- Docker: `ghcr.io/milkausikopistor/krevo:v0.1.0` — every tool plus `krevod` (see `docker-compose.yml`).
- `SHA256SUMS.txt` — checksums of every file above.

**What is inside**
- Proof-of-work BlockDAG (GHOSTDAG, 10 blocks/s), smooth emission with a hard cap of 1 billion KRV,
  zero premine.
- Optional privacy per transaction: every private spend hides among *all* private outputs ever
  created (full-chain membership proofs on a curve tree), confidential amounts (Bulletproofs),
  encrypted memos, subaddresses, view keys and payment proofs.
- Quantum-safe addresses (Schnorr + ML-DSA-44 hybrid signatures), multisig, inheritance plans,
  escrow, proof of reserves, human-readable `@names`, atomic swaps with Bitcoin.
- Two compatible full nodes (JavaScript reference + Rust), a light-wallet server (one or two
  servers, proofs checked by the wallet), an installable web/phone wallet, a block explorer, a mining
  pool and a testnet faucet.
- A constant-time Rust core (compiled to WebAssembly) that keeps every wallet secret.

**Since the project was first published**
- Everything — code, comments, messages, the web wallet and the docs — is now in English. The original
  Portuguese command and option names still work as aliases, and wallets, data folders and saved
  files from earlier versions are still found and opened.
- The web wallet got a new purple design.
- The placeholder mainnet genesis message changed (the mainnet has not been launched; testnet and
  devnet are unchanged).
