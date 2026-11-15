# Krevo (KRV)

[![tests](https://github.com/Milkausikopistor/krevo/actions/workflows/ci.yml/badge.svg)](https://github.com/Milkausikopistor/krevo/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/Milkausikopistor/krevo?include_prereleases&label=release)](https://github.com/Milkausikopistor/krevo/releases)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![help wanted](https://img.shields.io/github/issues/Milkausikopistor/krevo/help%20wanted?label=help%20wanted&color=7c3aed)](https://github.com/Milkausikopistor/krevo/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

A **proof-of-work** cryptocurrency on a **BlockDAG (GHOSTDAG, Kaspa's technology)**, with
**per-transaction optional privacy** in which every private spend hides among **all private outputs
the network has ever created** (full-chain membership proofs on a curve tree), **10 blocks per second**, sub-second confirmation, fees of a
fraction of a cent, a **hard cap of 1 billion coins**, **zero premine**, **quantum-safe addresses**
(Schnorr + ML-DSA hybrid signatures, NIST FIPS 204), **trustless atomic swaps with Bitcoin** and
**human-readable names** (pay `@bakery`) — with a full node in JavaScript and a second, compatible one in
**Rust** — whose constant-time code also handles every secret inside the wallets (WebAssembly).

📄 Full details, measured numbers and limitations: [docs/WHITEPAPER.md](docs/WHITEPAPER.md)

> ⚠️ **Reference implementation, not audited.** It is meant for testing, studying and evolving the
> protocol on a test network. **Do not use it with real money.** See section 8 of the whitepaper.

## Download
Ready-to-run packages are on the **[Releases page](https://github.com/Milkausikopistor/krevo/releases)**:

| File | What it is |
|---|---|
| `krevo-<version>.zip` / `.tar.gz` | The whole project: JavaScript node, wallet CLI, web/phone wallet, block explorer, mining pool, faucet. Unpack it and run it with **Node.js 24.7+** — nothing to install (zero npm dependencies). |
| `krevod-<version>-<platform>` | The Rust full node for Linux (x86_64, arm64), macOS (Apple silicon, Intel) and Windows. Also the wallets' fast native prover. |
| `ghcr.io/milkausikopistor/krevo` | Docker image with every tool plus `krevod` (see [docker-compose.yml](docker-compose.yml)). |

```bash
# after unpacking krevo-<version>.zip:
cd krevo-<version>
node scripts/web-demo.js            # a local network + the web wallet → http://127.0.0.1:8091
node src/cli.js --help              # every command
```

## Project status and how to help
Krevo is published **as-is**: there is no company, no foundation, no funded team and no
infrastructure behind it. The code, the tests and the documentation are complete enough for others
to take it from here — the next steps need volunteers:

- **Run the public testnet.** It is already defined in the code (`--network testnet`); it starts
  when someone runs a node. Docker, a step-by-step guide and a faucet are ready:
  **[docs/TESTNET.md](docs/TESTNET.md)**.
- **Build what a long-running network needs** — above all, storage with state snapshots and pruning
  in the Rust node (today a restart re-validates the whole chain).
- **Review and audit** the cryptography and consensus: **[docs/SECURITY.md](docs/SECURITY.md)**.
- **Wallets and apps** — mobile packaging, hardware wallets, quantum-safe addresses in the web app.

How to contribute: **[CONTRIBUTING.md](CONTRIBUTING.md)**. License: MIT.

## Requirements
Just a recent **Node.js (24.7 or newer, tested on 26)** — it ships OpenSSL 3.5, which provides the
ML-DSA post-quantum signatures. Zero external dependencies (no npm packages) — all other cryptography,
consensus and networking code lives in this repository. Optional: a stable **Rust** toolchain (tested
with 1.100) to build the second node, `krevod` (`cd rust/krevod && cargo test && cargo build --release`),
and to rebuild the WebAssembly crypto core (`rustup target add wasm32-unknown-unknown`, then
`node rust/krevo-wasm/build.mjs`) — the compiled core already ships with the repository.

## Try it in one minute
```bash
node --test "test/*.test.js"   # (or: npm test) 85 tests (one needs the Rust prover built): cryptography, full-chain membership proofs, GHOSTDAG, consensus, reorgs, wallet, BIP-39, memos, proofs, QR, subaddresses, multisig, inheritance, explorer, pool, quantum, Bitcoin, atomic swaps, names, light wallet (1 and 2 servers), browser crypto, the WebAssembly core, escrow, proof of reserves
node scripts/web-demo.js     # the web/phone wallet with a local devnet, light server and faucet → http://127.0.0.1:8091
node scripts/devnet.js       # starts 3 nodes + 2 miners and runs every transaction type (incl. quantum-safe)
node scripts/swap-demo.js    # a full KRV ⇄ BTC atomic swap between two wallets, using only the CLI (simulated Bitcoin)
BITCOIND=/path/to/bitcoind node --test test/bitcoin-core.test.js   # optional: validate swaps against real Bitcoin Core (regtest)
node scripts/simulate.js     # simulates 40 nodes on 6 continents and measures confirmation time
node src/cli.js emission --network mainnet   # emission table
```

## Running it by hand (devnet)
In separate terminals:
```bash
# 1. create a wallet: prints a 24-word recovery phrase (write it down on paper!),
#    a transparent krvdev1… address and a private krsdev1… address
node src/cli.js wallet create --password mySecret   # later commands ask for it (hidden) or read KREVO_PASSWORD

# 2. start a node
node src/cli.js node --network devnet --datadir ./data

# 3. mine (to get paid privately, use the krsdev1… address)
node src/cli.js mine --address krvdev1... --threads 2

# 4. check balances and send
node src/cli.js wallet balance --password mySecret
node src/cli.js wallet send --to krsdev1... --amount 2.5 --password mySecret
node src/cli.js wallet send --to krvdev1... --amount 1 --from private --password mySecret
node src/cli.js wallet viewkey --password mySecret   # audit access without spending power
node src/cli.js info

# 5. open the block explorer at http://127.0.0.1:8080
node src/cli.js explorer --port 8080
```
To connect several nodes, use `--port`, `--rpcport` and `--peer host:port` (repeatable).

## Rust node (`krevod`)
A second, independent implementation of the full node, in Rust (`rust/krevod/`, ~6,400 lines). It
follows the same consensus rules bit for bit, speaks the same P2P protocol and serves the same JSON-RPC,
so Rust and JavaScript nodes form **one network**, and the project's wallets, miners, light server and
block explorer work with it unchanged. The JavaScript node stays as the reference — the executable
specification the Rust node is checked against.

```bash
cd rust/krevod && cargo build --release
./target/release/krevod node --network devnet --datadir ./data-rust --port 16320 --rpcport 16321 --peer 127.0.0.1:16310
# everything else talks to it through RPC, as with the JavaScript node:
node src/cli.js mine --address krvdev1… --rpc http://127.0.0.1:16321
node src/cli.js wallet send --to krsdev1… --amount 2 --from private --rpc http://127.0.0.1:16321
node src/cli.js light-server --rpc http://127.0.0.1:16321      # and the explorer: explorer --rpc …
./target/release/krevod replay --network devnet --file ./data/devnet/blocks.dat   # re-validate a block file
```
* **What is inside:** its own Montgomery arithmetic for both curves of the secp256k1/secq256k1 cycle,
  GHOSTDAG and the difficulty adjustment, KrevoHash, emission, mass, the UTXO state with MuHash
  commitments and reorganizations, every transaction rule (Schnorr, multisig/inheritance/hash-locked
  policies, quantum-safe witnesses, @names, CLSAG rings on the test network, range proofs, the balance
  signature, the private-pool turnstile) and **full-chain membership proof verification** (curve tree +
  circuit Bulletproofs + the Schnorr-style proof), mempool, P2P with Dandelion++, JSON-RPC and the same
  block file format. Dependencies: BLAKE2b, SHA-2/SHAKE, big integers, JSON and ML-DSA (RustCrypto).
* **How it was checked against the JavaScript node:**
  * test vectors generated by the JavaScript code (`rust/krevod/vectors/gen.mjs`, `cargo test`): hashes,
    generators, Schnorr, CLSAG, **ML-DSA-44 signatures made by OpenSSL**, range proofs, MuHash, private
    coinbase outputs, KrevoHash, emission, targets, curve-tree roots and paths, and full-chain proofs at
    depths 1, 2 and 3 (accepted; tampered ones rejected);
  * **29 complete chains re-validated by both nodes with identical final state** — UTXO commitment,
    accepted-transactions root, coin supply, Security Fund, private pool, every block's status: a
    1,051-block devnet chain from `scripts/devnet.js` (two miners, private payments with full-chain
    proofs, quantum-safe spends, @names) and the 28 chains the JavaScript test suite builds
    (reorganizations, a disqualified block, multisig, inheritance, atomic swaps, rings, light wallets…),
    recorded with `rust/krevod/vectors/record.mjs` and compared with `vectors/compare.mjs`;
  * a **mixed network with real processes** (`vectors/mixed.mjs`): a JavaScript and a Rust node, a
    JavaScript miner on each (the Rust node's templates, including private coinbases, were accepted by
    the JavaScript node), CLI wallets sending transparent, shielding and full-chain private payments
    through the Rust node's RPC, a light wallet through a light server on top of it — and both nodes
    ending with exactly the same state (760 blocks, nothing rejected);
  * restart from its own block file, the JavaScript node re-validating a file written by the Rust node,
    and the block explorer running on top of it (`vectors/restart.mjs`).
* **Speed** (same machine): re-validating the 1,051-block devnet chain takes 1.8 s (JavaScript: 11 s);
  the 28 test chains 4.0 s (21.6 s); verifying one full-chain membership proof ~0.13–0.19 s (~1 s).
* **Native prover for wallets:** `krevod prove` computes the two circuit Bulletproofs of each
  private input — the expensive part of a full-chain proof — one thread per half. The JavaScript
  wallets use it automatically when the binary exists (`rust/krevod/target/release` or `…/debug`, or
  `KREVO_PROVER=/path/to/krevod`); otherwise they use the same Rust code compiled to WebAssembly (next
  section). The wallet still picks the blinding factors and makes the final Schnorr-style proof in its
  own process: the spending key never goes to the prover. Measured with real CLI processes on the devnet: a
  private payment proved in **1.7 s** (9.2 s in JavaScript), a light-wallet payment with two inputs in
  **2.0 s** (11.7 s). The JavaScript verifier accepts the native proofs (a test checks depths 1–3).
* **Limits:** it is a node and a prover — wallets, miners, the light server and the
  explorer remain JavaScript programs that use it; storage is the same simple append-only file with full
  re-validation at start-up; verification of public data uses fast variable-time arithmetic (the node
  holds no secret keys — wallet operations use the constant-time code below); equivalence was checked on
  every chain above, not proven; hostile inputs are fuzz-tested (next section); not audited.

## Hardened cryptography (a Rust core inside the wallets)
Everything a wallet does with a **secret** runs in Rust: the same code as the Rust node, compiled to
WebAssembly (`rust/krevo-wasm` → `src/crypto/krevo_core.wasm`, 1.2 MB) and loaded by both the
command-line wallet (Node.js) and the browser app (`src/crypto/wasm.js`). Nothing to build: the compiled
module ships with the repository (`node rust/krevo-wasm/build.mjs` rebuilds it, after
`rustup target add wasm32-unknown-unknown`).
* **Constant time:** multiplications by spending keys, view keys, blinding factors and nonces (k·P, k·G,
  k·H, commitments, key images), Schnorr signatures, range proofs (the bits of each amount select points
  through masks, not branches), the blinding of full-chain proofs and their Schnorr-style proof, ML-DSA-44
  signatures and AES-256-GCM (bitsliced AES — the JavaScript AES uses lookup tables, which leak through the
  cache). The field arithmetic is branchless (Montgomery form, masked selects, constant-time square roots),
  the point formulas are complete (Renes–Costello–Batina: no special case to branch on), and table lookups
  read every entry.
* **Measured, not just argued** (method of *dudect*: a fixed secret against fresh random ones, interleaved
  at random, Welch's t-test with percentile crops; |t| > 4.5 means a leak). The first run **found a real
  leak**: the optimizer had turned the masked table lookup back into a conditional branch, so a repeated
  key ran ~1.5% faster (|t| up to 48). Every mask now goes through an optimization barrier
  (`ct_mask`), and the measurements came back clean — natively: k·G, k·P, k·H, Schnorr, range proofs
  |t| ≤ 2.3; in the WebAssembly core the wallets run (V8): the same plus AES-GCM |t| ≤ 2.0 — while a
  control (the variable-time verification multiplication) shows |t| ≈ 2,800 natively and ≈ 270 in
  JavaScript BigInt, proof that the test sees leaks when they exist. Reproduce:
  `cargo test ct_timing -- --ignored --nocapture` (in `rust/krevod`) and `node rust/krevo-wasm/ct-timing.mjs`.
  The circuit prover also stopped skipping zero entries of its witness vectors (that made its running time
  depend on the bits of the blinding factors, i.e. on which coin is being spent).
* **A key vault:** the wallet's seed enters the core once (`src/crypto/vault.js`, `rust/krevod/src/vault.rs`)
  and the JavaScript copy is wiped. The spend key, view key and every derived key (transparent,
  quantum-safe, multisig, swap, and each private output's one-time key) live only there; the wallet gets
  *signers* — objects that sign, compute key images, CLSAG rings, the full-chain proof's Schnorr-style
  part, reserve proofs and Bitcoin ECDSA — never the keys. Same keys and addresses as before (tested
  derivation by derivation; the ECDSA is byte-identical to the JavaScript RFC 6979). `wallet.close()`
  zeroes it. What still passes through JavaScript is view-level data (shared secrets, amounts, masks,
  per-transaction randomness): enough to see, never to spend.
* **The wallet file:** the internal review found that the command-line wallet stored each private
  output's **one-time spend key in plain text**, even with a password — whoever read the file could spend
  the private coins without it. Fixed: only a view-level scalar is kept, the spend key is derived in the
  vault when spending, old files are cleaned and rescanned automatically. With a password, everything
  except the encrypted seed and phrase (outputs, history, transaction secrets, swaps, labels) is now
  sealed with AES-256-GCM under a key derived from the seed inside the vault; files are written
  atomically with owner-only permissions (0600); the phrase is decrypted only when asked for
  (`wallet phrase`). `--password` is no longer needed on the command line (shell history, process
  list): the CLI asks for it without echo, or reads `KREVO_PASSWORD`.
* **The browser wallet:** the password now yields two keys — one opens the secret block (seed + phrase)
  only at unlock and is wiped; the other seals the rest at each save and cannot open the secret block.
  Old browser wallets migrate on the next unlock.
* **Hedged nonces everywhere:** each nonce hashes the secret, the message **and** fresh randomness. A broken
  random generator can no longer leak a key (nonces never repeat across different messages), and the
  randomness still protects against fault attacks on purely deterministic nonces. Covers Schnorr, CLSAG,
  the full-chain proof's Schnorr-style part, range-proof blinding, the circuit proofs' blinding (seeded
  by the witness), payment proofs and proofs of reserves; batch-verification weights mix randomness with
  a hash of the proof.
* **Sign, then verify:** every signature and proof is checked before it leaves the core, so a computation
  fault (hardware, memory) that could reveal the key is caught instead of broadcast.
* **Hygiene:** inputs are wiped from WebAssembly memory as soon as they are read (and the core's own copy
  after use), the output buffer before every call; a trap rebuilds the instance; a self-test runs at
  load. **Threat model, honestly:** WebAssembly memory is readable by any JavaScript running in the same
  page or process — the vault prevents leaks through timing, carelessness and persistence (a key cannot
  end up in a file, a log or a JSON dump), not attacks by malicious code already running inside the wallet.
* **Checked** (`test/wasm.test.js`, `test/vault.test.js`): same points as the JavaScript code, proofs accepted by the JavaScript
  verifier, AES-GCM byte-identical to OpenSSL, ML-DSA keys identical to OpenSSL's from the same seed and
  signatures accepted both ways; hostile inputs (off-curve points, non-canonical scalars, malformed jobs,
  random bytes) become errors and the module keeps working.
* **Faster, too:** a full-chain proof without the native binary takes ~10 s in WebAssembly instead of
  ~18 s in pure JavaScript (one input, sequential, as in browsers); in Node.js the two halves run in
  WebAssembly threads. Prover order: native `krevod prove` → WebAssembly → JavaScript.
* **ML-DSA in the browser:** quantum-safe signatures used to need OpenSSL; the core brings them to the
  browser (the app's screens don't offer `krq` addresses yet).
* **Fallback:** if WebAssembly is unavailable (or `KREVO_NO_WASM=1`), the JavaScript code takes over —
  also with hedged nonces and sign-then-verify, but without the constant-time guarantee. The whole test
  suite passes both ways.
* **The Rust node under hostile input:** `krevod` catches panics per peer message and per RPC call (the
  peer is disconnected, the node keeps running), its state lock survives a panicking thread, and RPC
  request lines and headers are bounded. Fuzz tests push ~50,000 mutated blocks, transactions, P2P
  messages and RPC calls through it per run (`cargo test hostile`; `KREVO_FUZZ_SEED=n` explores other
  cases — 25 seeds clean); they found an integer overflow in two RPC methods, now fixed. A live node also
  took 46 hostile connections (wrong magic, a 2 GB length, broken JSON, garbage blocks and transactions,
  endless HTTP lines, absurd parameters) without a single panic.
* **Not done:** an **independent** audit — it has to come from outside the project; the internal review
  above and `docs/SECURITY.md` (threat model, scope, how to reproduce every check) are its starting point.
  Timing measurements are statistical evidence on this machine and engine, not a proof; wallets created
  **without** a password keep their seed in plain text by choice.

## Full-network anonymity (no more rings)
A private input no longer hides among 16 decoys: it proves that the coin it spends is **one of all the
private outputs that ever existed** — the anonymity set is the whole network, and there is no decoy
selection left for statistics to attack.

* Every private output is a leaf of a **curve tree** (Curve Trees, USENIX 2023): nodes alternate
  between secp256k1 and its twin curve secq256k1, whose field is secp256k1's group order and vice
  versa, so a zero-knowledge proof on one curve can do elliptic-curve math on the other.
* The spender re-randomizes the coin and its path to the root and publishes two **Bulletproofs for
  arithmetic circuits** (no trusted setup, ~3 KB per input) plus a small Schnorr-style proof that
  ties in the spending key, the amount and the **same key image as before** — so double spends are
  caught exactly as with rings, and wallets, light wallets and proofs of reserves are unchanged.
* The transaction names its **anchor** (the tree of the first N outputs, at least 100 s old so every
  coin in it is mature). Wallets download their part of the tree mixed with 7 decoy parts, from a node
  or a light server.
* Cost: proving takes ~2 s per transaction with the native Rust prover (`krevod prove`, used
  automatically when built), ~7–10 s with the Rust core in WebAssembly (the default otherwise, browsers
  included) and ~11–18 s in pure JavaScript; verifying takes ~1 s per input in JavaScript
  and ~0.15 s in the Rust node; fee ~0.0003 KRV per input. Because every node verifies before relaying, a private payment
  takes **seconds** to reach distant nodes in this JavaScript implementation (10.5 s two hops away
  for 4 inputs in `scripts/devnet.js`); transparent payments stay sub-second. Native code would be
  ~50–100× faster.
```bash
node src/cli.js wallet send --to krsdev1… --amount 2 --from private
# Entrada(s) privada(s): 1, cada uma escondida entre TODAS as 47 saídas privadas da rede (provas em 9.2 s)
```
Rings remain valid only on the automated-test network (simnet), to keep the rest of the test suite
fast. The construction is new and **unaudited** — see section 4.17 of the whitepaper.

## Block explorer
A web explorer served by `node src/cli.js explorer` (it reads any node through its RPC):

* **Live dashboard:** blocks per second, hashrate, coins issued vs. the cap, Security Fund, mempool,
  anonymity set size — and a **live drawing of the DAG**: parallel blocks side by side, edges to every
  parent, the selected chain highlighted, red blocks in red. It refreshes every second.
* **Block pages:** parents, children, blue/red mergeset, rewards paid by the coinbase, UTXO commitment.
* **Transaction pages:** transparent amounts and addresses are shown; private parts are shown as
  hidden ("one of the N private outputs that ever existed", one-time keys, encrypted memo) — the
  explorer can't see them either.
* **Address pages:** balance and history for transparent and multisig/inheritance addresses. Looking
  up a private address shows nothing, by design.
* **Search** by block hash, txid or address, and a **JSON API** under `/api/` (`info`, `dag`,
  `block/<hash>`, `tx/<txid>`, `address/<address>`, `name/<name>`, `panel`).

Static snapshots from a demo run are in [docs/explorer-example/](docs/explorer-example/)
(regenerate them with `node scripts/examples.js`).

## Mining pool
Small miners can combine their hashing power and get paid steadily instead of waiting for luck.
```bash
# pool operator: a wallet that receives the block rewards, then the pool itself
node src/cli.js wallet create --file pool-wallet.json
node src/cli.js pool --file pool-wallet.json --port 5555 --web-port 8081 --fee 1 --min-payout 1 --interval 60s

# each miner (pays out to a transparent krv… or a PRIVATE krs… address)
node src/cli.js mine --pool POOL_HOST:5555 --address krs1… --threads 4 --worker my-pc
```
* **Share protocol** (JSON lines over TCP, Stratum-style): login with a payout address, receive jobs,
  submit shares. Shares are proofs of work with an easier target that measure each miner's effort;
  difficulty is tuned per miner (vardiff, ~1 share every 2 s). Duplicate, stale and too-easy shares
  are rejected; a share that also meets the block target becomes a pool block.
* **PPLNT payout method:** the **actual** reward of each pool block (read from the node, including fees
  and the Security Fund release) is split, once it matures, among the shares of the 60 s before the
  block was found, weighted by difficulty. Red blocks pay nothing, as on the network itself.
* **Automatic batched payouts** to transparent or private addresses. At 10 blocks/s a pool receives
  many small rewards, so each round uses several transactions (≤ ~140 inputs each, partial payments
  when needed) and consolidates small coins when they pile up.
* **Stats page** at the web port (pool power, miners, blocks, balances, payments) plus a JSON API
  (`/api/stats`, `/api/miner/<address>`). State survives restarts.

In a local test with real CPU mining, a miner with 2 threads and another with 1 were paid at a
1.98 : 1 ratio (≈ their 2 : 1 power), the private-address miner received privately, and the amounts
in both wallets matched the pool's records to the last grain. Example page:
[docs/pool-example.html](docs/pool-example.html).

## Recovery phrase
Every new wallet gets a standard **BIP-39** recovery phrase of 24 words (the same standard used by
Bitcoin, Ledger and Trezor). If you lose the wallet file, the phrase alone rebuilds it on any
computer — including private funds, which are found again by rescanning the network.
```bash
node src/cli.js wallet phrase --password mySecret            # show the stored phrase again
node src/cli.js wallet restore --file restored.json          # asks for the phrase in the terminal
node src/cli.js wallet restore --phrase "word1 word2 …" --file restored.json
```
* Typing only the **first 4 letters** of each word is enough (e.g. `aban` = `abandon`).
* A mistyped or swapped word is detected by the phrase's built-in checksum.
* Optional **passphrase** (`--passphrase`, the BIP-39 "25th word"): the same 24 words plus a
  different passphrase open a completely different wallet. If you use one, you need both to restore.
* Use `--words 12` for a shorter phrase (128 bits instead of 256).

Anyone who has the phrase controls the funds: never type it into websites or send it by message or photo.

## Encrypted memos and payment proofs
Private payments can carry a short **encrypted memo** (up to 127 bytes, e.g. an order number) that
only the recipient can read. Every private transaction carries a fixed-size memo block — empty when
you write nothing — so outside observers can't even tell whether a message exists.
```bash
node src/cli.js wallet send --to krsdev1... --amount 2.5 --memo "Order #123" --password mySecret
node src/cli.js wallet history --password mySecret      # sent payments and received memos
```
A **payment proof** lets you show a third party (a shop, an accountant, a court) that a specific
transaction paid a specific private address — revealing that payment's amount and memo, and nothing
else about your wallet. Anyone with access to a node can check it, no wallet needed:
```bash
node src/cli.js wallet prove --txid <txid> --message "invoice 123" --password mySecret   # prints krpdev1…
node src/cli.js wallet check-proof --proof krpdev1... --address krsdev1... --message "invoice 123"
```
Memos to transparent addresses are refused, because they would be public. Payment proofs need the
wallet file that sent the payment (the per-transaction secret is stored there); a wallet restored from
its recovery phrase can't prove payments made before the restore.
The project started in Portuguese: the original command and option names (`no`, `minerar`,
`carteira enviar --para --valor`, …) are still accepted as aliases, so older scripts keep working.

## Layout
```
src/crypto/      secp256k1, Schnorr, Pedersen, stealth addresses, CLSAG, Bulletproofs, MuHash, ML-DSA (post-quantum),
                 wasm.js + krevo_core.wasm (the constant-time Rust core the wallets use for every secret)
src/fcmp/        full-chain membership proofs: secp256k1/secq256k1 cycle, curve tree, circuit Bulletproofs, proving threads
src/consensus/   GHOSTDAG, PoW (KrevoHash), difficulty, emission, mass, transactions, UTXO state, consensus engine
src/node/        full node: mempool, P2P (with Dandelion++), JSON-RPC, multi-threaded miner
src/wallet/      keys, BIP-39 recovery phrase, transaction building, memos, payment proofs, payment requests, wallet
src/util/        binary encoding, Bech32m addresses, QR code generator
src/explorer/    web block explorer (live DAG, blocks, transactions, addresses, JSON API)
rust/krevod/     the full node reimplemented in Rust (krevod) + cross-check scripts against the JavaScript node
seeds/           seed nodes of each network (testnet volunteers add theirs by pull request)
src/faucet/      faucet of test coins for testnet operators (krevo faucet)
rust/krevo-wasm/ the wallet crypto core: krevod's code compiled to WebAssembly (build.mjs → src/crypto/krevo_core.wasm)
src/pool/        mining pool (share protocol, vardiff, PPLNT accounting, batched payouts, stats page)
src/light/       light wallet: public light server, client with compact scanning and acceptance proofs
src/web/         web/phone wallet (PWA): app, encrypted browser storage, Buffer/crypto for the browser
src/btc/         Bitcoin side of atomic swaps: addresses, transactions, BIP-143, ECDSA, HTLC, Bitcoin Core + Esplora clients, simulator
src/params.js    ALL consensus parameters (name, prefixes, supply, timings…)
test/            automated tests
scripts/         devnet.js (real local network), simulate.js (simulated global network)
docs/            whitepaper
```

## Subaddresses
One wallet can create any number of private addresses — one per customer, per invoice, per website.
Nobody can tell that they belong to the same wallet (they look exactly like a main address), and all
funds arrive in the same balance. Checking for payments costs the same with 1 or 100,000 subaddresses.
```bash
node src/cli.js wallet subaddress --label "Customer A" --password mySecret   # prints a new krs… address
node src/cli.js wallet subaddresses --password mySecret                      # list + amount received by each
```
Labels stay in your wallet file only. The recovery phrase also restores subaddresses (the wallet looks
50 addresses ahead while scanning). Each private QR invoice uses a fresh subaddress automatically
(`--main-address` to opt out). Known limitation, shared with Monero: the "Janus" linking attack — see
section 4.8 of the whitepaper.

## Multisignature (M-of-N)
A group address that only spends when M of N people sign — partners in a company, a family vault, or
custody with a backup key. Each person signs whenever they can; nobody needs to be online at the same time.
```bash
# 1. each participant shares their multisig key (krk1…)
node src/cli.js wallet multisig key
# 2. anyone creates the group (same keys + same M = same address for everybody)
node src/cli.js wallet multisig create --name Company --min 2 --keys krk1…,krk1…,krk1…
#    the others import it with the printed descriptor (krm1…)
node src/cli.js wallet multisig import --name Company --descriptor krm1…
# 3. pay from the group: propose → each signer checks and signs the file → send
node src/cli.js wallet multisig propose --name Company --to krs1… --amount 4 --memo "Invoice 881" --out proposal.json
node src/cli.js wallet multisig sign --proposal proposal.json        # shows exactly what you authorize
node src/cli.js wallet multisig send --proposal proposal.json
```
Before signing, the wallet recomputes destination, amount, change and fee from the transaction itself
(and checks the inputs on the network), so a tampered proposal is caught. Back up the group descriptor
together with your recovery phrase. Group funds are transparent; private multisig is on the roadmap.

## Inheritance (time-locked recovery)
A "dead man's switch" enforced by the network: the owner spends normally; if the funds sit **unmoved**
for a chosen period (e.g. 1 year), the heirs can claim them. Every movement — or the `renew` command —
restarts the countdown. No lawyer or company holds the keys.
```bash
# owner: heirs share their keys with "wallet multisig key"; then
node src/cli.js wallet inheritance create --name Grandma --heirs krk1…,krk1… --after 365d
node src/cli.js wallet inheritance renew --name Grandma        # proof of life: restarts the countdown
node src/cli.js wallet inheritance send --name Grandma --to … --amount …   # owner spends, no wait
# heir: import the plan, follow the countdown, claim once it expires
node src/cli.js wallet inheritance import --name Grandma --descriptor krm1…
node src/cli.js wallet inheritance status --name Grandma
node src/cli.js wallet inheritance claim --name Grandma
```
Time units: `d` days, `m` months, `a`/`y` years, `h` hours, `min`, `s`. With several heirs you can
require more than one (`--min 2`); then the claim uses the multisig proposal flow with `--path 1`.
Under the hood these are consensus-level spending policies with up to 4 alternative paths, each with
its own keys and relative time lock (whitepaper section 4.10).

## Quantum protection
A large enough quantum computer could derive an elliptic-curve private key from its public key — a
long-term threat to Bitcoin, Kaspa, Monero and every other secp256k1 coin. Krevo already has two
defenses in consensus:

* **Quantum-safe addresses (`krq1…`).** Spending requires **two** signatures at once: Schnorr
  (secp256k1) **and ML-DSA-44** (NIST FIPS 204, lattice-based). Breaking the curve is not enough, and
  neither is a hypothetical flaw in the newer lattice math. Both keys come from your 24-word phrase and
  stay hidden behind a hash until the first spend. Cost: ~3.8 KB per input, fee ≈ 0.00006 KRV;
  confirmed in ~370 ms on the local devnet.
* **Shielded-pool turnstile.** The network publicly tracks how many KRV are inside the private pool
  (rewards and transparent value going in, minus value coming out). No transaction may take out more
  than went in — so even if someone forged coins inside the pool (a quantum computer or a bug), the
  counterfeit could never leave it, and the 1-billion cap stays auditable. Shown as `shieldedSupply`
  in `getinfo` and in the explorer.

```bash
node src/cli.js wallet quantum status     # how much is classic (krv), quantum-safe (krq) and private (krs)
node src/cli.js wallet quantum address    # your krq1… address (you can also mine straight to it)
node src/cli.js wallet quantum migrate    # move krv → krq and turn on quantum mode (change goes to krq)
node src/cli.js wallet quantum migrate --include-private --yes   # also pull private funds out to krq (amounts become public)
```
Not covered yet (whitepaper section 4.11): `krv1…` addresses, multisig/inheritance policies and the
private pool still rely on elliptic curves; the roadmap has hybrid policies and a post-quantum private
pool. Proof of work is not at risk (Grover's algorithm only gives a square-root speedup).

## Atomic swaps with Bitcoin
Trade KRV for BTC (or BTC for KRV) directly with another person — **no exchange, no custodian, no
trust**. Either both sides get paid, or both get their money back.

How it works (hash time-locked contracts, the same technique used for BTC⇄LTC swaps since 2017):
1. The **initiator** creates an offer: a `krx1…` code containing the price and `H = SHA-256(secret)`.
   Only the initiator's wallet knows the secret.
2. The **participant** accepts and sends back a `krx1…` acceptance code. No money has moved yet.
3. The initiator locks what they sell in a contract that pays the participant **only with the secret**,
   or refunds the initiator after a long deadline (48 h by default).
4. The participant's wallet checks that lock on chain and locks the other coin in a contract with the
   **same H** and a shorter deadline (24 h).
5. The initiator claims the participant's coins — which **publishes the secret** on that chain.
6. The participant's wallet reads the secret and claims the initiator's coins.

On Krevo the contract is a consensus-level spending policy with a SHA-256 hash lock (whitepaper 4.12);
on Bitcoin it is a standard P2WSH script with `OP_SHA256` + `OP_CHECKLOCKTIMEVERIFY`. Keys and secrets
for every swap are derived from your 24-word phrase.

```bash
# Alice sells 5 KRV for 0.002 BTC
node src/cli.js swap create --sell krv --krv 5 --btc 0.002 --btc-address <Alice's BTC address>
#   → prints an offer code krx1…; she sends it to Bob (it is not secret)
# Bob accepts with his own Bitcoin address and sends back the acceptance code
node src/cli.js swap accept --code krx1… --btc-address <Bob's BTC address>
node src/cli.js swap confirm --code krx1…          # Alice registers the acceptance
# both run this and the wallets do the rest: lock, verify, claim — or refund if the other side vanishes
node src/cli.js swap watch
```
* When the wallet must lock **bitcoin**, it shows the contract address, the exact amount and a QR code
  (`bitcoin:` URI): you pay it from any Bitcoin wallet (Electrum, Sparrow, a phone wallet…). Krevo
  locks, claims and all Bitcoin claims/refunds are signed and broadcast automatically.
* Safety checks built in: the participant refuses to lock if the initiator's deadline is too close;
  the initiator refuses to reveal the secret if the participant's deadline is too close; secrets must
  be exactly 32 bytes on both chains; test networks of Krevo only swap with **test** bitcoins.
* Bitcoin is followed either through **your own Bitcoin Core node** (`--btc-rpc http://user:pass@127.0.0.1:8332`
  — best for privacy; the wallet creates a watch-only `krevo-swaps` wallet in the node, with no private
  keys) or through an Esplora API (mempool.space by default, or `--btc-api` for your own instance).
  For local testing, `node src/cli.js btc-sim` runs a simulated Bitcoin (regtest-style) with the same
  API that really validates scripts, signatures and time locks.
* In the demo (`scripts/swap-demo.js`) the whole swap completed about 4 seconds after Bob paid.

**Validated against real Bitcoin Core.** Besides matching the official BIP-143/BIP-350 test vectors byte
for byte (including Bitcoin Core's own signatures), the Bitcoin side was checked against **Bitcoin Core
32.1** in regtest (binary verified by SHA-256, 8 maintainer GPG signatures and its code-signing
certificate). Core decodes our HTLC to the same P2WSH address, computes the same txid/weight/vsize,
accepts and mines our claim and refund transactions, and rejects a wrong secret, a wrong key, a 31-byte
secret, an early refund and a lowered `nLockTime`. Two complete swaps (selling KRV and selling BTC)
ran end to end with the wallet following Bitcoin through the node. To repeat it:
```bash
BITCOIND=/path/to/bitcoind node --test test/bitcoin-core.test.js
```
> ⚠️ Still not exercised on testnet4/signet or mainnet, and still an unaudited reference
> implementation: do not risk real bitcoins.

## Light wallet (no node needed)
Use Krevo from a laptop or a weak device without running a node: the wallet talks to a public
**light server** that anyone can run next to a full node — and **does not trust it**.
```bash
# server operator (next to a node; --publico listens on all interfaces — put HTTPS in front)
node src/cli.js light-server --port 8090 --publico
# user: any wallet command + --light SERVER_URL
node src/cli.js wallet create --light https://light.example.com
node src/cli.js wallet balance --light https://light.example.com
node src/cli.js wallet send --to @bakery --amount 2 --light https://light.example.com
```
* **Keys never leave the device** — neither the spending key nor the view key.
* **Private, compact scanning.** The wallet downloads only 35 bytes per private output (R, index and a
  1-byte *view tag*) and tests them locally; just ~1 in 256 needs to be fetched in full, and each one is
  requested together with 15 random decoys, so the server can't tell which outputs are yours. Spent
  checks ask for whole *buckets* of key images (1/256 of all), never for yours. In the tests this
  scan used **11× less bandwidth** than a full-node wallet.
* **Nothing counts until it's proven.** A coin reported by the server only enters the balance (and can
  only be spent) after a proof the wallet checks itself: the txid matches the transaction content, the
  output is in it, a Merkle path links it to the accepting block, and N following headers (100 on
  mainnet ≈ 10 s of network work) carry valid proof of work. A test server that invented a
  1,000 KRV payment was caught: the money never entered the balance and the fraud was reported.
* **Optional delegated scanning** for weak devices: `wallet scanning delegada --light URL` sends the
  *view* key so the server finds your payments (it then sees what you receive, but still can't spend
  or see what you spend). The default is `local`.
* Everything else works the same: private and transparent sends (the tree path for a private spend
  comes from the server, mixed with 7 decoy parts), memos, subaddresses, names, quantum addresses.
* **Two servers are better than one.** A server can't invent money (proofs), but it could *hide* a
  payment or show a coin that was already spent. Give two servers run by different people —
  `--light https://a.example,https://b.example` (or the second field in the app's settings) — and the
  wallet compares them: private-output data batch by batch (if they differ, it scans both, so what one
  hides the other shows), transparent coins (a coin shown by only one server counts unless someone
  *proves* it was spent with the spending transaction + acceptance proof), spends of private coins
  (one server knowing is enough) and broadcasts to both. Every disagreement is reported. In the tests,
  a server that hid a private payment, hid a transparent coin and resurrected a spent one fooled a
  single-server wallet — and with an honest second server the balance came out exact, with all four
  tricks reported (including the exact position where the data started to differ).

## Escrow contract (buyer, seller, arbiter)
Buy from a stranger without trusting them — or a company in the middle. The buyer's money sits in a
contract address that consensus already understands:
* **2 of 3** (buyer, seller, arbiter) can move it at any time: buyer + seller release to the seller when
  everything is fine; if the buyer vanishes, seller + arbiter release; in a dispute the arbiter decides
  together with one party (release or refund);
* **after a deadline the buyer alone** takes it back — the money is never stuck;
* the arbiter alone, or the seller alone, gets nothing.
```bash
# each party shares its key:            node src/cli.js wallet multisig key
node src/cli.js escrow create --name Order42 --buyer krk1… --seller krk1… --arbiter krk1… --amount 50 --deadline 30d
node src/cli.js escrow import --name Order42 --code krm1…          # the other parties
node src/cli.js escrow fund --name Order42                         # buyer
node src/cli.js escrow release --name Order42 --to <seller address> # makes a proposal signed by you (a file)
node src/cli.js escrow sign --proposal escrow-Order42-liberar.json --yes   # the other party: checks, signs, sends
node src/cli.js escrow reclaim --name Order42                      # buyer, after the deadline, alone
```
The proposal file shows each signer exactly where the money goes (read from the transaction itself,
not from whoever proposed it).

## Proof of reserves (for exchanges)
An exchange can prove it holds its customers' money — **without revealing who the customers are**.
* **Assets:** `reserves prove --message "Exchange X — 2026-11-13"` signs every transparent coin with its
  key and, for every private coin, reveals the amount (opening its commitment) plus a key image with a
  DLEQ proof of ownership. Anyone with a node runs `reserves verify --proof reserves.json` and gets the
  total that really checks out: the coins exist, are unspent (the key images were never used — which
  also stops two exchanges from counting the same coin) and the proof is bound to that day's message.
* **Liabilities:** `reserves liabilities --customers customers.csv` builds a Merkle *sum* tree: the
  public root carries the total owed; each customer gets (privately) a proof with a salt, and checks
  their own account with `reserves check --proof mine.json --root root.json` — without learning anyone
  else's balance or name.
* `reserves verify --proof reserves.json --liabilities root.json` prints **solvent** when reserves ≥
  total owed. Faked amounts, coins of other people, spent coins and proofs reused with another date
  are all rejected in the tests. The exchange's own private outputs become identifiable (the
  customers' do not).

## Web and phone wallet (installable app)
The same light wallet also runs **in the browser** — on a computer or a phone, where it can be
installed as an app (PWA). Try the whole thing locally:
```bash
node scripts/web-demo.js
# app:      http://127.0.0.1:8091        (devnet node, miners and a light server start too)
# test KRV: http://127.0.0.1:8092/?to=YOUR_ADDRESS   (a faucet that sends 10 KRV)
```
Or serve just the app (`node src/cli.js web-wallet --port 8091`) and point it to any light server.
* **Create or restore** with the 24-word phrase (the app makes you confirm three words), choose a
  password, and the wallet is stored **encrypted on the device** (AES-256-GCM, key from PBKDF2-SHA256
  with 600,000 iterations). Nothing — phrase, keys, view key — is ever sent to the server.
* Home with balance (private / transparent / *awaiting proof*), activity with memos and change,
  **receive** with QR codes and payment links, **send** to addresses, `krevo:` links or `@names` (with
  camera QR scanning on phones that support it), encrypted memos, and settings (server, local or
  delegated scanning, reveal phrase — password required —, view key, remove from device).
* **No dependencies, no build step.** The browser cannot use Node's crypto, so BLAKE2b, SHA-256/512,
  HMAC, PBKDF2 and AES-256-GCM were written in plain JavaScript (`src/util/purecrypto.js`) — SHA-2
  constants are *computed* from prime roots and the AES S-box from GF(2⁸) inverses, not typed in — and
  checked **byte for byte against OpenSSL** on thousands of random inputs. A test also runs the whole
  wallet with only these browser pieces against a real node: same address from the phrase, proofs
  with proof of work, memo decryption, and a private payment that the network accepted. On networks
  without rings the app proves private spends against the whole tree in the browser too (Rust core in
  WebAssembly, no threads: 9.3 s on a desktop in the test, 14.3 s before in pure JavaScript; slower on
  phones). Everything that touches secrets — the AES-GCM of the stored wallet included — runs in that
  constant-time core; the JavaScript versions above stay as the fallback.
* Tested in a real browser at phone size: created a wallet, received a private payment (proven before
  counting), sent 2.5 KRV with an encrypted memo — **confirmed by the network in 1.1 s** — and the
  recipient's node wallet read the memo.
* **Security note:** in any web wallet, whoever serves the *code* could steal keys. That's why the app
  is **not** served by the light server (which is untrusted): run it yourself or host it somewhere you
  trust, then point it to any light server. A strict Content-Security-Policy allows only code from the
  app's own origin (plus `'wasm-unsafe-eval'`, which lets the page compile its own WebAssembly core —
  JavaScript `eval` stays blocked). On phones, install it from an **HTTPS** origin (browsers only allow installing and
  WebCrypto there; over plain HTTP on a local network it still works, with a slower key derivation).
* ML-DSA now runs in the browser (through the Rust core), but the app's screens don't offer
  quantum-safe (`krq`) addresses or multisig yet — use the command-line wallet for those.

## Human-readable names (@name)
Pay `@bakery` instead of `krs1qyp3h27…`. Names live **on the Krevo network itself**: there is no
company, registrar or authority that can take them away.
```bash
node src/cli.js name register @bakery            # points to your private address by default (--to transparent | ADDRESS)
node src/cli.js wallet send --to @bakery --amount 2
node src/cli.js name show @bakery                # anyone can look up where a name points, its owner and expiry
node src/cli.js name update @bakery --to <address>     # change where it points (no fee)
node src/cli.js name transfer @bakery --to <new owner> # sell or give it away (krv, krq or multisig owner)
node src/cli.js name renew @bakery               # one more year
node src/cli.js name release @bakery             # give it up; the 0.01 KRV deposit comes back
```
* **Private payments to a public name.** A name can point to a private `krs` address: everyone sees
  that `@bakery` exists, but each payment still goes to a fresh one-time address with a hidden amount.
* **No front-running.** Registering takes two transactions: a *commitment* that only publishes a hash
  (nobody can tell which name you want), then, after a short wait (30 s on mainnet), the *reveal*.
  Someone who sees the reveal and tries to copy the name is too late: their own commitment would be too
  recent. The wallet does both steps for you.
* **Fair pricing against squatting.** Yearly fee by length — 3 characters 100 KRV, 4 → 20 KRV,
  5 → 5 KRV, 6 or more → 1 KRV. The fee goes **entirely to the Security Fund** (future miners): it is not
  burned and no organization receives it. Names expire after 1 year; there are 30 days of grace in which
  only the owner can renew; after that the name is free again.
* Names are `a-z`, `0-9` and hyphens, 3–32 characters, ASCII only (no look-alike Unicode letters).
  Payment links work with names too: `krevo:@bakery?amount=2.5`.
* Owners can be a normal, quantum-safe (`krq`) or multisig address; a name is just a special coin in the
  UTXO set, so reorganizations and the UTXO commitment handle it like any other coin.

## QR code payment requests
A shop (or anyone) can charge with a QR code. The request is a `krevo:` link in the style of
Bitcoin's BIP-21:
```
krevo:krs1…?amount=3.75&memo=KRV-0TBWFR&label=Padaria%20Sol&exp=1794504543
```
```bash
# shop: show a QR in the terminal, save a printable SVG and wait until it's paid
node src/cli.js wallet request --amount 3.75 --label "Padaria Sol" --expires 15 --svg qr.svg --wait

# customer: pay the link (asks for confirmation; --yes skips it)
node src/cli.js wallet pay --uri "krevo:krs1…?amount=3.75&memo=KRV-0TBWFR&label=Padaria%20Sol"
```
* Requests go to a **fresh private subaddress** by default, with a unique order code (`KRV-XXXXXX`) sent as
  the encrypted memo. `--wait` matches the incoming payment by that code, so the shop knows exactly
  which order was paid; in a local test the "✅ PAID!" appeared about 2 s after the customer ran `pay`.
* `--transparent` charges to the transparent address instead (no memo; amounts are public).
* The link carries the network in the address prefix, so a devnet QR can't be paid on mainnet by
  mistake. Expired requests (`--expires`, in minutes) are refused by the payer's wallet.
* The QR generator is built in (no dependencies), supports all 40 versions and 4 error-correction
  levels, and was checked against an independent decoder (jsQR). An example is in
  [docs/payment-request-example.svg](docs/payment-request-example.svg).

## Addresses
| Prefix | Type |
|---|---|
| `krv1…` | transparent — public amounts |
| `krs1…` | private — amount and recipient hidden |
| `krq1…` | quantum-safe transparent — needs Schnorr **and** ML-DSA signatures |
| `krw1…` | view key — shows incoming private payments, cannot spend |
| `krp1…` | payment proof — proves one specific payment to a private address |
| `krk1…` / `krm1…` | multisig participant key / multisig group descriptor |
| `krx1…` | atomic swap offer or acceptance code |
| `@name` | a human-readable name registered on the network (resolves to any of the above) |

On devnet/testnet the prefixes get a suffix (`krvdev1…`, `krstest1…`), so coins can't be sent to the
wrong network by mistake.

## Changing the name or parameters
Name, address prefixes, ports, supply and emission all live in [src/params.js](src/params.js). Any
change there creates a new, incompatible network — do it before launch.

## License
MIT.
