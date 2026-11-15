# Contributing to Krevo

Krevo is offered as-is: no company, no foundation, no funded team, no infrastructure. It moves
forward only if people pick it up. Thank you for being one of them.

## Where help is needed most

1. **Run the public testnet** — a node, a miner, a light server, an explorer, a faucet:
   [docs/TESTNET.md](docs/TESTNET.md). Even one always-on node matters.
2. **Storage for long-running networks (Rust)** — state snapshots, pruning and snapshot sync, so a
   node does not re-validate the whole chain at every restart ([docs/TESTNET.md §6](docs/TESTNET.md)).
3. **Review and audit** — the cryptography (full-chain membership proofs, the constant-time core)
   and consensus: [docs/SECURITY.md](docs/SECURITY.md) lists the threat model, scope and how to
   reproduce every check.
4. **Wallets** — `krq` addresses in the web app, native mobile packaging, hardware-wallet support.
5. **Performance** — Web Workers for proving in the browser, elliptic-curve divisors to shrink circuits.

The roadmap is in [docs/WHITEPAPER.md §9](docs/WHITEPAPER.md).

## Ground rules

- **The JavaScript node is the executable specification.** Any consensus change goes into
  `src/consensus/` *and* `rust/krevod/src/` in the same pull request; regenerate the vectors
  (`node rust/krevod/vectors/gen.mjs`) and check that both nodes agree (`cargo test`, and the chain
  comparison scripts in `rust/krevod/vectors/`).
- **Zero runtime dependencies in JavaScript.** No npm packages; the Rust crates stay few and
  well-known (RustCrypto, serde_json, num-bigint).
- **Cryptography that touches secrets lives in Rust** (`wallet_ops.rs`, `vault.rs`, `ct.rs`): no
  branches or memory accesses that depend on a secret, masks through `ct_mask`, hedged nonces,
  verify before returning. Re-run the timing test after touching it:
  `cargo test ct_timing -- --ignored --nocapture` and `node rust/krevo-wasm/ct-timing.mjs`.
  Rebuild the WebAssembly core with `node rust/krevo-wasm/build.mjs` and commit
  `src/crypto/krevo_core.wasm`.
- **Never log, persist or return secret keys.** The wallet holds signers, not keys.
- **Tests for everything.** `node --test "test/*.test.js"` (also with `KREVO_NO_WASM=1`) and `cargo test` must
  pass; continuous integration runs them on every pull request.
- Code, comments, messages and documentation are in English (the original Portuguese command and
  option names still work as aliases). Pull requests and issues are welcome in any language.

## Getting started

```bash
node --test "test/*.test.js"           # Node.js 24.7+ (or: npm test)
cd rust/krevod && cargo test            # stable Rust
node scripts/devnet.js                  # a real local network (3 nodes, miners, wallets)
node scripts/web-demo.js                # the web wallet against a local devnet + faucet
```

## Reporting vulnerabilities

Please report security problems privately first (see [docs/SECURITY.md](docs/SECURITY.md)), and
give maintainers time to fix them before publishing.
