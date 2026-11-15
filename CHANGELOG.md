# Changelog

## [Unreleased]
**Rust node (krevod)** (#2)
- State snapshots: the node writes `state.snap` (every 6,000 new blocks, or a quarter of what it
  keeps if more) and restarts from it, validating only the newer blocks — 0.11 s instead of 1.9 s for
  3,000 blocks. The snapshot is checksummed and its UTXO set must re-commit to the chain's MuHash;
  an unusable one is ignored (full re-validation, as before). `blocks.dat` keeps its format.
- Optional pruning: `krevod node --prune [--prune-depth N]` keeps only the recent history (default
  ~3 hours of blocks) and compacts `blocks.dat`, so disk and memory stay bounded. A pruned node
  cannot serve old blocks and refuses chains that fork off below its pruning point; its folder is not
  readable by the JavaScript node. It does not offer peers blocks whose bodies it has dropped.
- Tests: a pruned engine validates every block exactly like an archival one (parallel blocks,
  reorganizations, red blocks, shielded coinbases, repeated snapshot reloads); restart from disk,
  crash between the snapshot and the compaction, damaged and tampered snapshots, local finality.

**Web wallet**
- Translations: every screen goes through a small dictionary (`src/web/i18n.js`), with Portuguese as
  the first translation. The language follows the browser and can be changed in Settings; amounts
  and dates use the language's format, and ambiguous amounts ("1,000" / "1.000") are refused. (#7)
- Quantum-safe addresses (krq): receive on your krq address, see how much is protected, and move
  your classic transparent coins to krq with one tap; spends from krq are signed in the browser with
  Schnorr + ML-DSA (WebAssembly core). (#4)

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
