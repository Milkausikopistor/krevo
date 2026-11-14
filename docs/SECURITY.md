# Krevo — security notes for reviewers and auditors

> **Status: not independently audited.** This is a reference implementation for test networks. Do not
> use it with real money. This document is the starting point for an external audit: what is
> protected, against whom, where the code is, and how to reproduce every check.

## 1. Threat model

| Adversary | In scope | Defence |
|---|---|---|
| Network peer sending hostile blocks, transactions, P2P frames | yes | strict decoders, full validation, per-message panic guard in `krevod`, fuzz tests |
| RPC / light-server client sending hostile requests | yes | bounded HTTP lines/headers, saturating arithmetic, panic guard per call |
| Untrusted light server (lies, hides data) | yes | Merkle + PoW proofs, two-server cross-check (whitepaper §4.14) |
| Observer measuring the wallet's **timing** (local or remote) | yes | constant-time Rust core, measured (§3) |
| Faulty hardware / broken random generator during signing | yes | hedged nonces, verify-before-release |
| Someone who **reads the wallet file** without the password | yes | seed and phrase encrypted (scrypt + AES-GCM), everything else sealed by the vault |
| Careless leaks (logs, JSON dumps, crash reports, files) | yes | keys live only in the vault; JavaScript holds signers, not keys |
| **Malicious code running inside the wallet's process/page** | **no** | WebAssembly memory is readable by same-realm JavaScript; use a hardware wallet for that threat |
| Someone with the unlocked machine | no | out of scope (as for any hot wallet) |
| Quantum computer | partly | `krq` hybrid addresses and the private-pool turnstile (whitepaper §4.11) |

## 2. Where the security-critical code is

| Area | Files |
|---|---|
| Constant-time field/curve arithmetic | `rust/krevod/src/field.rs` (`ct_mask`, `sel4`, `sqrt_ct`), `rust/krevod/src/ct.rs` |
| Wallet operations with secrets | `rust/krevod/src/wallet_ops.rs`, `rust/krevod/src/vault.rs` |
| Full-chain proof prover / verifier | `rust/krevod/src/fcmp.rs`, `src/fcmp/*.js` |
| WebAssembly interface and loader | `rust/krevo-wasm/src/api.rs`, `src/crypto/wasm.js`, `src/crypto/vault.js` |
| Wallet storage | `src/wallet/wallet.js` (`fileData`, constructor), `src/web/browser-wallet.js` |
| Consensus validation | `src/consensus/*.js` (reference), `rust/krevod/src/{txvalidation,consensus,utxo,rules}.rs` |
| Node robustness | `rust/krevod/src/node.rs` (`guarded`, `lock_node`), `rust/krevod/src/rpc.rs` |

## 3. Reproducing the checks

```bash
node --test "test/*.test.js"                       # 85 tests (with the WebAssembly core)
KREVO_NO_WASM=1 node --test "test/*.test.js"       # the same, JavaScript fallback
cd rust/krevod && cargo test                        # vectors vs. JavaScript, fuzzing, vault, CT unit tests
cargo test ct_timing -- --ignored --nocapture       # dudect-style timing test, native (~1 min)
KREVO_FUZZ_SEED=7 cargo test hostile                # fuzzing with another seed
node rust/krevo-wasm/ct-timing.mjs                  # dudect-style timing test of the WebAssembly core (~2 min)
node rust/krevod/vectors/compare.mjs …              # chain equivalence JS ↔ Rust (see the README)
```

Last results on the development machine (Windows 11, x86-64, Node 26 / V8):

| Operation | native \|t\| | WebAssembly \|t\| |
|---|---|---|
| k·G, k = 1 vs. random | 0.95 | 1.24 |
| k·G, fixed random k vs. random | 1.07 | 1.20 |
| k·P | 2.18 | 1.21 |
| k·H | 2.24 | 1.96 |
| Schnorr signature | 1.45 | 1.15 |
| Range proof (value 0 vs. random) | 0.89 | 0.35 |
| AES-256-GCM (fixed vs. random key) | — | 1.57 |
| **Control**: variable-time multiplication | **2,770** | **269** (JS BigInt) |

|t| > 4.5 indicates a timing difference between the classes. These are statistical results for one CPU
and one engine; repeat them on the target hardware.

## 4. Internal review — findings fixed

1. **One-time spend keys in plain text in the CLI wallet file** (critical): each private output's key
   `p` was saved unencrypted even in password-protected wallets. Now only a view-level scalar is stored,
   `p` is derived inside the vault, the file is sealed, and old files are migrated (keys erased, rescan).
2. **Compiler-introduced branch in constant-time code** (high): LLVM turned masked selects into a
   conditional branch; a repeated key ran ~1.5% faster (|t| ≈ 48). Fixed with optimization barriers.
3. **Witness-dependent branches in the circuit prover** (medium, privacy): zero entries were skipped,
   making proving time depend on the blinding bits. Fixed.
4. **Non-hedged nonces** in CLSAG, range proofs, payment/reserve proofs and circuit-proof blinding
   (medium): now hedged everywhere; batch-verification weights mix randomness with the proof's hash.
5. **Integer overflow on hostile RPC parameters** in `krevod` (low): found by fuzzing, saturating now.
6. **Panics on hostile input could take the Rust node down** (medium): per-message/per-call guards and a
   poison-tolerant state lock.
7. **Secrets as JavaScript strings/BigInts** (medium): seed, phrase and keys no longer live in JavaScript
   objects; the phrase is decrypted only on request; the browser wallet's data key cannot open the seed.
8. **Wallet file written in place with default permissions** (low): atomic write, mode 0600.
9. **Password on the command line** (low): hidden prompt or `KREVO_SENHA` instead of `--password`.
10. **Table-based AES in the browser** (medium): replaced by the bitsliced constant-time AES of the core.

## 5. Known limitations (not fixed)

- No independent audit; the full-chain membership proof construction is new.
- The vault does not isolate keys from malicious code in the same process (see the threat model).
- View-level secrets (shared secrets, amounts, masks, per-transaction randomness) pass through JavaScript.
- Wallets created without a password store the seed in plain text.
- Timing guarantees depend on the CPU and the WebAssembly engine; only one combination was measured.
- The JavaScript fallback (no WebAssembly) is not constant-time.

## 6. Reporting

This is a test-network project; please report issues privately to the maintainers before publishing.
