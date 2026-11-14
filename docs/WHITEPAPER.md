# Krevo (KRV)
### Fast, cheap digital cash with optional privacy — on a proof-of-work BlockDAG

*Technical whitepaper — version 0.1 (reference implementation + local testnet)*

---

## Abstract

Krevo is a proof-of-work (PoW) cryptocurrency built on a **BlockDAG ordered by the GHOSTDAG
protocol** — the same consensus family as Kaspa — producing **10 blocks per second** without
discarding parallel blocks. On top of that consensus, Krevo adds a **single transaction format** in
which every input and every output can be either **transparent** (public amounts, as in Bitcoin) or
**private** (sender hidden among **every private output the network has ever created** by a full-chain
membership proof on a curve tree, recipient hidden by a stealth address, amount hidden by a Pedersen
commitment + Bulletproofs). Users choose, per transaction, whether they want privacy.

The economics are fixed and authority-free: a **hard cap of 1,000,000,000 KRV**, a smooth emission
that drops a little every month and halves every 4 years, **zero premine**, rewards only for those who
mine, and a **Security Fund** that smooths miner income using half of all fees.

Against future quantum computers, Krevo offers **quantum-safe addresses** that require both a Schnorr
and an **ML-DSA-44 (NIST FIPS 204)** signature, and a public **turnstile** on the private pool that keeps
any counterfeit value created inside it from ever leaving. And Krevo trades with Bitcoin directly:
consensus-level **hash-locked contracts** make trustless **atomic swaps KRV ⇄ BTC** possible from the
wallet, with no exchange in the middle. Finally, **human-readable names** (`@bakery`) are registered in
consensus, with commit–reveal against front-running and yearly fees that fund miners.

Measurements on the reference implementation: transparent transactions accepted by the DAG in
**~200–300 ms** on a local 3-node network, and in **421 ms (median) / 796 ms (p99)** in a global
simulation of 40 nodes across 6 continents, with **fees on the order of 0.00001–0.001 KRV**.

---

## 1. Design goals

| Requirement | How Krevo meets it |
|---|---|
| Kaspa's BlockDAG technology | GHOSTDAG (k derived from network assumptions), selected chain, mergeset, "virtual" block |
| Proof of work | KrevoHash (BLAKE2b + 64×64 matrix multiplication), difficulty adjusted every block |
| Optional privacy | Private inputs/outputs (full-chain membership proofs + Bulletproofs + stealth addresses) in the same format as transparent ones; the anonymity set is the whole network |
| Confirmation < 1 s | 10 blocks/s; a transaction enters the "virtual" state as soon as a block includes it |
| Negligible fees | Fee = mass × 1 grain/gram → ~0.00001 KRV (transparent), ~0.001 KRV (private) |
| Scale without absurd hardware | Storage mass (KIP-9), UTXO commitment (MuHash), path to pruning and higher block rates |
| Global, 24/7 operation | Peer-to-peer network with no central servers; no checkpoints or admin keys |
| Supply cap | 1 billion KRV, enforced by a consensus counter — not just by the formula |
| Predictable emission | Exact integer table; 50% in 4 years, 75% in 8, 99.6% in 32 |
| No issuing authority | No special keys; the coinbase must match the rule exactly |
| Miner rewards | Subsidy + fees + Security Fund release, per block |
| No premine | The genesis block has no outputs and receives no reward; launch with proof of date |

---

## 2. Consensus: BlockDAG + GHOSTDAG

### 2.1 Why a DAG
In a blockchain (Bitcoin), two blocks found at the same time compete and one becomes an orphan: its
work is wasted and, to keep that rare, blocks must be slow (10 min). In a BlockDAG, **each block points
to every tip the miner knows about** (up to 16 parents). Parallel blocks do not compete — they all
enter the graph. This allows very frequent blocks without losing security.

### 2.2 GHOSTDAG
The protocol colors blocks **blue** (the largest "well-connected" subset: each blue block has at most
*k* blue blocks outside its past and future) or **red** (the rest — typically blocks withheld by an
attacker). From this:

* a block's **selected parent** = the parent with the most accumulated blue work;
* the **selected chain** = following selected parents down from the top;
* a block's **mergeset** = blocks in its past that are not in its selected parent's past;
* **total order**: the selected parent first, then the mergeset in ascending blue-work order.

This total order defines the order of transactions. If two parallel blocks contain conflicting
transactions (a double spend), **the first one in the order wins and the other is simply ignored** —
no block is invalidated because of it.

**Choosing k.** k is the smallest integer such that P[Poisson(2·D·λ) > k] < δ, with λ = 10 blocks/s,
D = 5 s (assumed maximum network delay) and δ = 1%. Result: **k = 124** (the same value Kaspa uses at
10 blocks/s; at 1 block/s the formula gives k = 18, also identical). The code computes k from the
parameters (`computeGhostdagK`), so changing the block rate adjusts k automatically.

### 2.3 The "virtual" block and state
The *virtual* is a hypothetical block whose parents are all current tips. The virtual's UTXO state
is the network's state, and the mempool validates transactions against it. Each chain block "accepts"
the transactions of its mergeset on top of its selected parent's state; the header commits to:

* `utxoCommitment` — **MuHash3072** of the full UTXO set (transparent + private + key images);
* `acceptedIdMerkleRoot` — the root of the accepted transactions;
* `blueScore`, `blueWork`, `daaScore` — GHOSTDAG data, verified by everyone.

A block whose state does not match (wrong coinbase, wrong commitment) stays in the DAG — its work
counts — but becomes **disqualified from the chain**: nobody builds state on top of it.

### 2.4 Protection rules
* **Mergeset limit**: at most 512 blocks merged per block.
* **Merge depth bound**: a block cannot merge blocks whose blue score is more than 3,600 below its
  own (6 min). An attacker cannot mine in secret for long and then "glue" the branch onto the DAG.
* **Parents form an antichain**: no parent may be an ancestor of another.
* **Past median time**: the timestamp must be ≥ the median of the 263 most recent blocks.

---

## 3. Proof of work and difficulty

### 3.1 KrevoHash
Inspired by kHeavyHash. For each block template, a 64×64 matrix of 4-bit values is generated from
the pre-PoW hash (which excludes timestamp and nonce), and must have full rank. Each attempt:

```
h1 = BLAKE2b("KrevoHash/1" ‖ prePow ‖ timestamp ‖ nonce)
v  = 64 nibbles of h1;   p_i = (Σ_j M[i][j]·v_j) >> 10
h2 = BLAKE2b("KrevoHash/2" ‖ (h1 XOR p))
valid if h2 (little-endian) ≤ target
```

Verification costs microseconds, which is essential at 10 blocks/s: even a modest computer can
validate the whole network.

### 3.2 Per-block difficulty adjustment
The window is the 2,640 most recent blocks in the block's past (blue **and** red — all of them
represent hashrate). New target = average target × actual time ÷ expected time, with change capped at
4×. **Novelty:** the actual time is measured between the 5th and 95th percentiles of the window's
timestamps, so a miner with less than 5% of the blocks cannot skew difficulty with fake timestamps — a
real problem on fast-block networks.

---

## 4. Transactions: one format, two worlds

### 4.1 Structure
```
Transaction
 ├─ transparent inputs:  (txid, index) + Schnorr signature, or policy + M signatures (multisig)
 ├─ private inputs:      anchor N + pseudo-commitment C' + key image I + full-chain membership proof
 ├─ transparent outputs: public amount + public key
 ├─ private outputs:     ephemeral key R, one-time key P, commitment C, encrypted amount, view tag
 ├─ explicit fee, declared mass, payload (encrypted memo)
 └─ witness: signatures, aggregated range proof (Bulletproofs), balance signature
```
The `txid` is the hash of the body **without** signatures and proofs, so signatures do not change the
id (no malleability).

### 4.2 The four combinations
| From → To | Typical use | Size (approx.) | Measured fee |
|---|---|---|---|
| transparent → transparent | everyday payments, commerce | ~0.2–1 KB | ~0.00001–0.0001 KRV |
| transparent → private ("shield") | entering privacy | ~1.5 KB | ~0.0001 KRV |
| private → private | confidential payment | ~4–7 KB (~3 KB per input) | ~0.0003 KRV per input |
| private → transparent ("unshield") | moving to an exchange | ~4 KB | ~0.0003 KRV |

### 4.3 How privacy works
* **Hidden recipient — stealth addresses.** A private address is a pair (C, D) with C = a·D, where a
  is the wallet's view key (section 4.8). For each private output j the sender picks a fresh r_j,
  publishes R_j = r_j·D in that output and creates P = Hs(r_j·C, j)·G + D. Only the holder of *a*
  recognizes the output (a·R_j = r_j·C), and every payment uses a different key — nobody can link two
  payments to the same address. A 1-byte **view tag** makes scanning ~256× faster.
* **Hidden amount — Pedersen commitments.** C = x·G + v·H. Since nobody knows log_G(H), C reveals
  nothing about v and cannot be opened to a different value.
* **No hidden inflation — Bulletproofs.** Each private output proves v ∈ [0, 2⁶⁴) without revealing v
  (~690 bytes for 1 output, ~755 for 2, no trusted setup).
* **Hidden sender — full-chain membership proof.** The spender proves that the coin is *one of all the
  private outputs that ever existed* (up to a recent anchor), that they own it and that C' carries the
  same amount — without saying which one (section 4.17). The **key image** I = p·Hp(P) is
  deterministic: spending the same output twice repeats I, and the network rejects it. (Earlier versions
  used CLSAG rings of 16; rings remain valid only on the automated-test network.)
* **Universal balance rule.** For any mix of inputs and outputs:
  `E = ΣC' + (Σtransparent_inputs)·H − ΣC_out − (Σtransparent_outputs + fee)·H`.
  With no private parts, E = 0 is required. With private parts, the sender signs with E's key (the
  "balance signature"), which is only possible if the amounts cancel out exactly.
* **Network layer — Dandelion++.** New transactions first travel along a "stem" of nodes (one at a
  time) and only then are announced to everyone; an observer cannot tell which IP sent them.
* **Optional auditing — view key.** `krw1…` = (a, B): it reveals what a private address has received
  but **cannot spend**. Useful for accounting, audits, or proving income, while keeping privacy as the
  default.

### 4.4 Private coinbase (novelty)
Miners can be paid directly to a private address. Because everyone must validate the coinbase, the
coinbase secret r_j of each output is derived publicly from the block's parents and the output index; the amount and recipient are already
public in any coinbase, but the output goes to a one-time key and **later blends into the anonymity
set**. Result: the set of private outputs grows from day one (up to 10 outputs/s), solving the
"empty anonymity set" problem of new privacy coins.

### 4.5 Wallet recovery (BIP-39)
Every wallet is backed by a standard **BIP-39 recovery phrase**: 24 words from the official
2048-word English list (256 bits of entropy + an 8-bit checksum; 12 words / 128 bits optional).
Keys are derived deterministically from it:

```
bip39_seed  = PBKDF2-HMAC-SHA512(phrase, "mnemonic" ‖ passphrase, 2048 iterations, 64 bytes)
wallet_seed = H("wallet/bip39", bip39_seed)                     — 32 bytes
spend key b = Hs("wallet/spend", wallet_seed)    view key a = Hs("wallet/view", wallet_seed)
transparent key i = Hs("wallet/t", wallet_seed, i)
```

Because every private output can be re-found with the view key, restoring from the phrase recovers
**both transparent and private funds** by rescanning the network — no other backup is needed. The
optional BIP-39 passphrase turns the same words into a different wallet, protecting against a stolen
phrase. The checksum catches mistyped or swapped words, and the first four letters of each word are
enough to identify it. The implementation reproduces the official BIP-39 test vectors exactly.

### 4.6 Encrypted memos and payment proofs
**Memos.** A transaction's `payload` field (already covered by the txid and every signature) carries
an encrypted memo addressed to the first private output:

```
key = H("memo/key", ss, 0)        ss = r_0·C = a·R_0  (the stealth shared secret of output 0)
memo block = 0x01 ‖ AES-256-GCM(key, [len ‖ text ‖ zero padding to 128 bytes]) ‖ tag   — 145 bytes
```

The wallet attaches a memo block to **every** transaction that has a private output, encrypting an
empty text when the user writes nothing. Since all blocks have the same size and look random, an
observer cannot tell which payments carry a message, nor how long it is. The recipient (or anyone
holding their view key) finds the memo while scanning; it costs ~145 grams of mass (≈0.0000015 KRV).
This is a wallet convention, not a consensus rule — no change to block validity was needed.

**Payment proofs.** The sender knows the secret r of the paid output (R = r·D is published in it).
Instead of revealing r, a proof reveals only S = r·C — the shared secret of *that* output with
*that* recipient address (C, D) — together with a Chaum–Pedersen (DLEQ) proof that
log_D(R) = log_C(S), bound to the txid, the output index j and an optional message:

```
T1 = k·D, T2 = k·C, c = Hs(txid, j, R, D, C, S, T1, T2, message), s = k − c·r
verify: c == Hs(txid, j, R, D, C, S, s·D + c·R, s·C + c·S, message)
```

With S, a verifier recomputes the recipient's one-time key, decrypts the amount, checks it against
the Pedersen commitment, and reads the memo. Nothing else leaks: the change output stays hidden (it
has its own ephemeral key and secret), and no wallet key of either party is revealed. Proofs
(`krp1…`) cannot be re-targeted to another address or message without knowing r. Optional privacy
with selective disclosure — private by default, provable when needed — is what makes the private
mode usable for commerce, accounting and compliance.

### 4.7 Payment requests (QR codes)
Merchants request payment with a `krevo:` URI modeled on Bitcoin's BIP-21, rendered as a QR code:

```
krevo:<address>?amount=<KRV, decimal point>&memo=<order code>&label=<merchant name>&exp=<unix time>
```

* **Private by default.** Requests point to the merchant's private address and carry a unique order
  code that the payer's wallet sends as the encrypted memo (section 4.6). The merchant's wallet
  matches the incoming payment by that code, so it knows which order was paid while outsiders see
  neither the amount nor the recipient. Transparent requests are possible but carry no memo.
* **Safety.** The address prefix fixes the network; expired requests are refused; unknown parameters
  are ignored except `req-*` ones, which the wallet must understand or reject (as in BIP-21).
* **Speed at the counter.** In a local test, the merchant's wallet showed the payment as received
  about 2 seconds after the customer started paying, with the transaction itself accepted in 0.87 s.

The reference implementation includes a dependency-free QR encoder (ISO/IEC 18004: byte mode,
versions 1–40, levels L/M/Q/H, penalty-based mask selection) that prints the code in the terminal
and exports a printable SVG. Its output was verified with an independent decoder.

### 4.8 Subaddresses
One wallet can hand out any number of private addresses — one per customer, per invoice, per
website — that **nobody can link to each other or to the main address**, while all funds land in the
same balance. The scheme follows Monero's subaddresses, made uniform:

```
m_i = 0 for i = 0 (main address), otherwise Hs("subaddr", a, i)
D_i = B + m_i·G        C_i = a·D_i        address_i = (C_i, D_i)
one-time spend key of an output received at i:  p = Hs(ss, j) + b + m_i
```

* **Every address has the same shape.** The main address is simply subaddress 0, so an observer
  cannot tell a main address from a subaddress, nor whether two addresses share a wallet.
* **Ephemeral key in every private output** (R_j = r_j·D_i), not only when a subaddress is paid. This
  is what lets a payment to a subaddress and the sender's change live in the same transaction, and
  because *every* transaction does it, payments to subaddresses are indistinguishable from the rest.
  It costs 33 bytes per private output (the old per-transaction key was removed).
* **Scanning cost does not grow with the number of subaddresses.** For each output the wallet computes
  ss = a·R_j once, derives D' = P − Hs(ss, j)·G and looks D' up in a table of its subaddresses — one
  scalar multiplication per output whether the wallet has 1 or 100,000 subaddresses. View keys
  (a, B) see incoming payments to all subaddresses.
* **Recovery.** A wallet restored from its phrase scans with 50 subaddresses of look-ahead and extends
  the table whenever it finds one in use, so subaddresses created on another device are found again.
* **Invoices.** Each private QR invoice (section 4.7) gets a fresh subaddress by default, so customers
  cannot link the shop's invoices to each other.

*Known limitation (shared with Monero today):* the "Janus" attack. Someone who suspects two
subaddresses belong to the same wallet can craft an output mixing parts of both; if the recipient
then behaves as if it was received (e.g. ships goods), the link is confirmed. It reveals a link, never
funds. Wallets should only treat a payment as matching an invoice when it arrives at that invoice's
own subaddress (which this wallet does); a cryptographic fix in the style of Monero's upcoming
"Carrot" address scheme is on the roadmap.

### 4.9 Multisignature (M-of-N)
Transparent funds can be locked to a group — for example 2 of 3 partners, or a family vault where any
2 of 3 devices must agree. The design follows Bitcoin's pay-to-witness-script-hash pattern:

```
policy  = [0x01][M][N][N public keys, sorted]          (canonical: same keys + same M = same address)
lock    = [0x03][H("lock/multisig", policy)]           — 33 bytes; address krv1…, like any transparent one
witness = policy ‖ [M] ‖ M × ([key index][Schnorr signature])   — indices strictly increasing
```

* **The keys stay hidden until spending.** The address commits only to the hash of the policy.
* **Distinct signers.** Strictly increasing indices guarantee that M *different* keys signed; the policy
  hash binds the address to that exact M and key set, so a weaker policy (e.g. 1-of-3 with the same
  keys) can never unlock it.
* **Asynchronous signing.** All signatures cover the same message (the txid excludes witnesses), so
  each participant signs whenever they can, offline, in any order — no interactive rounds.
* **Proposals that signers can verify.** The wallet coordinates through a proposal file (similar to
  Bitcoin's PSBT) carrying the unsigned transaction. Before signing, each participant's wallet re-derives
  what the transaction does from the transaction itself — destination, amount, change, fee — and checks
  on the network that the inputs belong to the group; for private destinations the proposal includes
  the output secret so the amount and recipient can be verified (as in a payment proof). Copies signed
  separately are merged at the end.
* **Cost.** Each signature adds 1,000 grams of mass; a 2-of-3 payment costs about 0.00007 KRV.

Multisig groups can pay private addresses (with memos), but their own funds are transparent: private
(RingCT) multisig is much harder — Monero needed years to get it right — and is on the roadmap, as is
"invisible" threshold multisig with FROST (Schnorr threshold signatures whose result looks like a normal
single-key signature, at the cost of interactive signing rounds).

### 4.10 Inheritance and time-locked recovery
Policies (section 4.9) can also hold several **alternative spending paths**, each with its own keys and
a minimum waiting time. The wait is **relative**: it counts blocks since the output was created, like
Bitcoin's `OP_CHECKSEQUENCEVERIFY`.

```
policy v2 = [0x02][C] ‖ C × ([M][N][delay u64, in blocks][N public keys, sorted])
witness   = policy ‖ [path index] ‖ [M] ‖ M × ([key index][Schnorr signature])
rule      = the M signatures are valid for that path AND  age(output) ≥ delay(path)
```

The inheritance plan in the wallet is a two-path policy — a "dead man's switch":

* **Path 0 — owner:** 1-of-1, no wait. The owner spends normally, at any time.
* **Path 1 — heirs:** M-of-N heir keys, after the output has been **unmoved** for the chosen period
  (e.g. 1 year). Any owner movement creates fresh outputs, so the countdown restarts; the wallet's
  `renew` command does exactly that ("proof of life") by moving the whole balance back to the plan.

Properties:

* **Enforced by consensus, not by trust.** No lawyer, company or custodian holds the keys; heirs get
  nothing early, and the owner keeps full control while active.
* **Private until used.** Only the policy hash is on chain; heirs' keys and the delay appear only if a
  path is used.
* **The delay is part of the commitment.** A forged policy with a shorter wait has a different hash
  and cannot unlock the address. The time check runs on every validation (it depends on the moment,
  not only on the transaction), while signature checks stay cached.
* **Flexible.** Up to 4 paths per policy and up to 15 keys per path: e.g. "owner alone; or 2 of 3
  children after 1 year; or a lawyer plus 1 child after 2 years".
* **Cost.** Moving an inheritance plan costs about 0.00002 KRV; in a devnet test a heir claimed the
  balance seconds after a 25-second test delay expired, and an earlier attempt was refused.

Limitations: plans hold transparent funds; if the owner forgets to renew, heirs can claim — the delay
should be chosen with margin (the wallet's `status` shows how much time remains).

### 4.11 Quantum protection
**Threat.** A cryptographically relevant quantum computer (CRQC) running Shor's algorithm would recover
any secp256k1 private key from its public key. For a coin like Krevo that means: (a) funds sitting at
addresses whose public key is known could be stolen; (b) a spend in flight reveals its key, and a fast
enough attacker could race it with a competing spend; (c) inside the private pool, an attacker could
spend other people's outputs, break the *binding* of Pedersen commitments (creating value from
nothing) and retroactively link private spends to the outputs they spent. Proof of work and hashes are not seriously affected:
Grover's algorithm gives at most a square-root speedup against KrevoHash and BLAKE2b.

Nobody knows when (or whether) a CRQC will exist, but coins in cold storage live for decades, so Krevo
ships two defenses in consensus from the start.

**1. Hybrid quantum-safe addresses (`krq1…`, lock type 0x04).**
```
lock    = [0x04] ‖ H("lock/pq", schnorrPub (33) ‖ mldsaPub (1,312))                      — 33 bytes
witness = [0xF1] ‖ schnorrPub ‖ mldsaPub ‖ schnorrSig (64) ‖ mldsaSig (2,420)            — 3,830 bytes
rule    = the hash matches  AND  the Schnorr signature is valid  AND  the ML-DSA signature is valid
```
* **ML-DSA-44** is the lattice-based signature standardized by NIST as FIPS 204 (2024), security
  category 2. Krevo does not implement it: it uses OpenSSL 3.5's implementation shipped with Node.js.
* **Hybrid by design (AND, not OR).** If secp256k1 falls to a quantum computer, ML-DSA still protects
  the coins; if a classical flaw is found in the much younger lattice cryptography, Schnorr still
  protects them. This is the transition approach recommended by several national security agencies.
* **Keys hidden until first use.** Only a hash is on chain while the money rests. ML-DSA is a
  many-time signature (unlike hash-based one-time schemes), so reusing a `krq` address for change is
  safe even after its keys are revealed.
* **Same recovery phrase.** `x = Hs("wallet/q", seed, i)` for Schnorr, and the ML-DSA key is generated
  deterministically from the 32-byte seed `H("wallet/mldsa", seed, i)` (FIPS 204 key generation from ξ).
  Restoring a wallet from its 24 words restores the quantum-safe address and its balance.
* **Works everywhere a transparent address does:** payments, change, pool payouts and mining rewards
  (the coinbase can pay a `krq` address directly).
* **Cost.** A quantum-safe input costs ~5,900 g of mass (bytes + two signature checks) instead of ~1,100;
  a 1-input payment paid a fee of about 0.00006 KRV and was confirmed in 368 ms on the 3-node devnet. A
  block fits ~80 such payments (~800/s), about 5× fewer than plain Schnorr ones — the price of 2.4 KB
  signatures. ML-DSA verification takes ~0.1 ms, close to Schnorr.

**2. Shielded-pool turnstile** (the idea of Zcash's ZIP-209). Every node keeps a public counter `Z` of
the KRV inside the private pool, computed only from public values:
```
Z += Σ private coinbase rewards
Z += (transparent inputs − transparent outputs − fee)    for every transaction with private parts
rule: a transaction that would make Z negative is not accepted (consensus; the mempool refuses it too)
```
Value conservation inside the pool is guaranteed by cryptography (Pedersen + Bulletproofs + balance
signature); the turnstile adds a second, independent guarantee that does not depend on that
cryptography: whatever happens inside the pool — a quantum break of commitment binding, or a
counterfeiting bug like the one fixed in Zcash in 2019 — **counterfeit coins can never leave it** beyond
what really went in. The transparent supply and the 1-billion cap stay auditable by anyone, and a drain
of `Z` would be publicly visible. `Z` is exposed as `shieldedSupply` in `getinfo` and on the explorer.

**Wallet migration.** `wallet quantum status` shows how much is classic (`krv`), quantum-safe (`krq`)
and private (`krs`); `wallet quantum migrate` sweeps classic coins to `krq` in batches and turns on
*quantum mode* (change and consolidations go to `krq` from then on); `--include-private` also moves
private funds out to `krq`, making those amounts public in exchange for quantum-safe custody. The
wallet weighs quantum inputs ~6× when selecting coins, so transactions stay under the mass limit.

**Not yet covered (honest list).**
* `krv1…` single-key addresses embed the public key, so they are exposed; multisig and inheritance
  policies reveal their keys on first spend. Planned: hybrid keys inside policies (a future policy
  version).
* The private pool still relies on elliptic curves: a CRQC could steal private outputs, decrypt amounts
  and memos sent to a *known* `krs` address, and retroactively trace private spends. Amount commitments
  themselves are perfectly hiding. The turnstile limits the damage to the pool; protecting privacy
  itself needs a post-quantum private-pool protocol (research).
* **Emergency plan** (roadmap): if a CRQC becomes plausible, a pre-announced soft fork would stop
  Schnorr-only spends from `krv` (allowing rescue with a hash-based proof of knowledge of the
  recovery seed) and freeze or migrate the private pool — the turnstile guarantees such a migration
  cannot extract forged value.

### 4.12 Atomic swaps with Bitcoin
Two people can exchange KRV and BTC **without an exchange and without trusting each other**: either
both payments happen or neither does. Krevo uses hash time-locked contracts (HTLCs), the technique
behind cross-chain atomic swaps since 2017 (BIP-199 on the Bitcoin side).

**Consensus support: hash-locked spending paths (policy v3).** Spending policies (sections 4.9–4.10)
gain an optional hash lock per path:
```
policy v3 = [0x03][C] ‖ C × ([M][N][delay u64][has hash: 0|1][SHA-256 (32), if any][N keys])
witness   = policy ‖ [path] ‖ [32-byte secret, if the path has a hash] ‖ [M] ‖ M × ([key index][sig])
rule      = M valid signatures  AND  age(output) ≥ delay  AND  (no hash OR SHA-256(secret) = hash)
```
The secret must be exactly 32 bytes and the hash is plain SHA-256 — the same as Bitcoin's `OP_SHA256`,
so one secret unlocks both chains. Versions 1 and 2 are unchanged (existing multisig and inheritance
addresses keep their meaning). A Krevo HTLC is a two-path v3 policy:
*path 0* = recipient's key + secret, no wait; *path 1* = sender's key after N blocks.

**The Bitcoin contract** is a standard P2WSH script:
```
OP_IF    OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <recipient key>
OP_ELSE  <deadline> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender key>
OP_ENDIF OP_CHECKSIG
```
`OP_SIZE 32` mirrors Krevo's 32-byte rule: without it, a secret of a different length could be valid
on one chain and invalid on the other, trapping one party. The deadline is a Unix time compared with
Bitcoin's median-time-past (BIP-113).

**Protocol.** The *initiator* creates the secret and an offer (`krx1…` code: direction, amounts, H,
public keys, deadlines); the *participant* answers with an acceptance code (public keys). Then:

| Step | Who | What |
|---|---|---|
| 1 | initiator | locks what they sell; refund after the **long** deadline (default 48 h) |
| 2 | participant | verifies that lock on chain, then locks the other coin with the same H; refund after the **short** deadline (default 24 h) |
| 3 | initiator | claims the participant's coins — the claim **publishes the secret** |
| 4 | participant | reads the secret from that chain and claims the initiator's coins |

Because the participant's deadline is shorter, the participant always has time to use the secret
before the initiator could take their own coins back. The wallet enforces it:
* the participant does not lock unless the initiator's lock has at least *(participant's own window +
  25 %)* left — otherwise it reports "too late" and the swap ends with no loss;
* the initiator does not reveal the secret if the participant's deadline is less than 1/8 of the
  participant window away (the participant might not have time to claim);
* deadlines on Krevo are counted in blocks (10/s), on Bitcoin in median time; Krevo test networks only
  accept Bitcoin test networks, and Krevo mainnet only Bitcoin mainnet.

All keys (one Krevo key and one Bitcoin key per swap) and the secret are derived from the 24-word phrase.
Krevo-side locks, claims and refunds, and Bitcoin-side claims and refunds, are signed and broadcast by
the wallet; locking bitcoin is done from the user's usual Bitcoin wallet (address, amount and a
`bitcoin:` QR code are shown). The wallet follows Bitcoin either through the user's own Bitcoin Core
node (a watch-only, key-less wallet inside the node; nothing leaks to third parties) or through an
Esplora API (mempool.space or a self-hosted instance), so running a Bitcoin node is optional.

**Bitcoin implementation.** Addresses (Bech32/Bech32m/Base58Check), transaction serialization (BIP-144),
segwit signature hashing (BIP-143) and ECDSA with RFC 6979 nonces, low-S and strict DER. They reproduce
the official BIP-143 and BIP-350 test vectors byte for byte — including the exact signatures produced by
Bitcoin Core. A built-in Bitcoin simulator (same REST API as mempool.space) validates scripts,
signatures, time locks and double spends, and is used by the tests and by `scripts/swap-demo.js`, where a
swap between two CLI wallets completed about 4 seconds after the BTC payment.

**Validation against Bitcoin Core.** An optional test suite (`BITCOIND=… node --test
test/bitcoin-core.test.js`) runs a real, isolated Bitcoin Core in regtest. Against Bitcoin Core 32.1 it
confirmed that Core derives the same P2WSH address from our script and the same txid, weight and vsize
from our transactions; accepts and mines the claim (with the secret visible in the confirmed witness)
and the refund after median time passes the deadline; and rejects — under its own consensus and policy
rules — a wrong secret, a wrong key, a 31-byte secret, a refund before the deadline and a refund whose
`nLockTime` is lower than the contract's. Two full swaps, in both directions, completed with the wallet
following Bitcoin through the node.

**Limitations.** (1) Validated on regtest, not yet on testnet4/signet or mainnet. (2) The *free option*
problem of every HTLC swap: the initiator may wait, within the deadline, to see if the price moves
before claiming; short deadlines limit it. (3) The two legs are linkable on chain (same H on both
sides); adaptor signatures ("scriptless scripts") would hide this. (4) Krevo-side HTLC funds are
transparent. (5) Bitcoin claims are not fee-bumped automatically yet; in a fee spike the participant
should watch the deadline. (6) The chosen Esplora server learns which contract addresses you watch.

### 4.13 Human-readable names (@name)
Long addresses are the main usability barrier of cryptocurrencies. Krevo lets anyone register a name —
`@bakery` — that resolves to an address, **in consensus**, with no registrar or authority.

**Names are coins.** Following Namecoin's design, a name is a special output in the UTXO set:
```
name record     lock = [0x05][len][name][expiry u64][len][owner lock][target address data]
                value = deposit (≥ 0.01 KRV; returned when the name is released)
commitment      lock = [0x06][H("name/commit", name, salt, owner lock)]
```
Only the owner (a `krv`, `krq` or multisig lock) can spend the record; spending it and creating a new
record changes the target or the owner; spending it without a new record releases the name. Because
names are UTXOs, reorganizations, the MuHash UTXO commitment and ownership need no new machinery. A
name index (name → records) is maintained in the UTXO set and in every pending diff, so consensus can
check uniqueness in O(1).

**Rules** (checked for every transaction that creates a record, at its accepting block):
* at most one record per transaction; names are 3–32 characters of `a-z`, `0-9` and `-` (no leading,
  trailing or double hyphen) — ASCII only, which rules out look-alike Unicode names;
* a name has at most one *live* record. A record is live until `expiry + grace` (30 days);
* **registration** (no live record): the transaction must spend a *commitment* to the same name and
  owner made between 300 blocks (30 s) and 1 day earlier, pay the yearly fee, and set
  `expiry ≤ now + 1 year`;
* **update / transfer** (spends the live record, signed by its owner): free while the expiry does not
  increase;
* **renewal** (increases the expiry): pays the yearly fee, `expiry ≤ max(old expiry, now) + 1 year`;
  during the grace period only this is allowed;
* miners cannot create records through the coinbase.

**Front-running.** The commitment hides the name (salted hash), so nobody can race a registration they
cannot see. Once the reveal is broadcast the name is public — but a copycat would need a commitment at
least 30 s old, and the reveal is accepted in about a second. The salt is derived from the recovery
phrase, so a registration can be completed from another copy of the wallet.

**Economics.** The yearly fee depends on length — 100 KRV (3 characters), 20 (4), 5 (5), 1 (6 or more) —
because short names are scarce. The fee is not burned and goes to no organization: the acceptance rule
moves it **entirely into the Security Fund** (section 7.3), which releases it to miners over time. A
miner including its own registration therefore does not get its fee back. Expiry plus grace returns
abandoned names to the pool instead of locking them forever.

**Privacy.** A name and its target are public, by design. When the target is a private `krs` address,
payments to the name stay private: each one goes to a fresh one-time key with a hidden amount, so
publishing `@bakery` does not reveal who paid or how much.

**Measured.** On the 3-node devnet (owner with a quantum-safe address) a registration took about 6 s
including the 5 s devnet commitment wait, a payment to the name was confirmed in ~0.4 s, and the three
nodes resolved the name identically.

**Limitations.** Names can still be phished with similar spellings (`@bakery` vs `@bakeri`); wallets
show the resolved address and owner. The fee schedule is a parameter guess and should be revisited
before launch. Names are not yet recoverable automatically after restoring a wallet *during* a pending
commitment (the reveal needs the local commitment record).

### 4.14 Light wallets
Most people will not run a node. Krevo's light wallet talks to a public **light server** (a small
process anyone can run next to a full node, exposing only read-only queries and transaction
broadcast) and is designed so that the server is **not trusted** with keys, privacy or balances.

**Keys.** Spending and view keys stay on the device. Transactions are built and proved locally, exactly
as in the full wallet; for a private spend the wallet downloads its part of the curve tree mixed with 7
decoy parts, so the server does not learn which coin is spent.

**Private scanning with view tags.** Every private output already carries a 1-byte view tag
(section 4.3). The server streams outputs in a compact binary form — `R (33) ‖ j (1) ‖ tag (1)`, 35 bytes
— and the wallet computes `a·R` and the tag locally. Only matches (~1/256 false positives plus real
payments) are fetched in full, each request padded with 15 random other indices. Spent status is asked
per *bucket* — all key images sharing the first byte (≈1/256 of the set) — so the server never learns
which key image is yours. In the test network the compact scan used 1,455 bytes for 41 outputs versus
16,218 bytes for the full-node wallet's download (≈11×; 35 vs ~396 bytes per output, the gap being the
encrypted amount, commitments, keys and the 145-byte memo).

**Acceptance proofs (SPV for a DAG).** The server could invent payments: anyone can create an output to
a public address. So a coin counts in the balance — and can be spent — only after the wallet verifies:
1. the transaction content hashes to its txid and contains the reported output;
2. a Merkle path from the txid to the `acceptedIdMerkleRoot` of the chain block that accepted it
   (new RPC `gettxproof`; the tree avoids Bitcoin's CVE-2012-2459 duplication);
3. that header and the next N selected-chain headers have valid KrevoHash proof of work, each listing
   the previous as a parent, with strictly increasing blue score and blue work;
4. no header has less than ¼ of the highest difficulty the wallet has seen (the tip header returned by
   the server is PoW-checked on every sync), so a server cannot mine a cheap fake chain.

N defaults to 100 blocks on mainnet (≈10 s of the whole network's work); faking one payment means
mining that much work at real difficulty. In the tests a server that injected a valid-looking
1,000 KRV output (with a fabricated transaction and a proof borrowed from another transaction) was
caught: the amount stayed out of the balance, could not be spent, and the wallet recorded the fraud.

**Delegated scanning (optional).** For very weak devices the wallet can send its *view* key to the
server, which scans and returns matching indices. The server then learns incoming payments and
amounts, but still cannot spend nor see spends (key images need the spend key). Default: local.

**Two servers.** Proofs stop a server from inventing money, but not from *omitting* a payment or
presenting an already-spent coin as available. With two servers run by different parties the wallet
compares them: compact private-output batches are compared byte for byte, and on any difference both
are scanned (what one hides, the other shows), with the exact first differing position reported; a
server showing fewer outputs at the same chain point is reported; a transparent coin shown by only one
server counts unless a spend is *proven* (the spending transaction from the address history plus its
acceptance proof), so neither hiding nor resurrecting coins works; a private coin is treated as spent
if either server knows its key image; transactions are broadcast to both. Lag is told apart from lies by
comparing each server's tip with the block that created the coin. In the tests, a server that hid a
private payment (shifting all later indices), hid a transparent coin and resurrected a spent one fooled a
single-server wallet completely, while the two-server wallet got the exact balance and reported all four.

**Limitations.** A single server can still *omit* transactions (a light client cannot prove absence) —
the two-server mode above is the mitigation, assuming at least one server is honest; transparent addresses are revealed to the server (they
are public anyway, but this links the wallet's `krv` and `krq`); the ranges you sync reveal when you
were offline; local scanning costs one elliptic-curve multiplication per private output, like the full
wallet; newly received coins become spendable only after N blocks; the difficulty floor is learned
on first use.

**In the browser and on phones.** The same light client runs as an installable web app (PWA). Browsers
lack Node.js's crypto module, so the few primitives the wallet needs — BLAKE2b, SHA-256, SHA-512, HMAC,
PBKDF2 and AES-256-GCM — were reimplemented in plain JavaScript with no dependencies; SHA-2 constants
are computed from prime roots and the AES S-box from GF(2⁸) inverses rather than typed in, and every
primitive is checked byte for byte against OpenSSL on thousands of random inputs. An import map swaps
them in, so the wallet code is literally the same as on the command line. The wallet is stored on the
device encrypted with AES-256-GCM under a PBKDF2-SHA256 key (600,000 iterations). Because whoever
serves a web wallet's code could steal keys, the app is not served by the (untrusted) light server: it
is run locally or hosted on a trusted origin, under a strict Content-Security-Policy. In a real
browser at phone size, a wallet received a private payment (counted only after its proof), sent one
with an encrypted memo — confirmed in 1.1 s — and the recipient decrypted the memo with the node wallet.
Quantum-safe addresses are not available in the browser yet (no ML-DSA there).

### 4.15 Escrow contracts
A sale between strangers needs neither trust nor a company holding the money. The buyer pays into a
spending policy (section 4.10, no consensus change) with two paths:
```
path 0: 2 of 3 {buyer, seller, arbiter}, no wait      path 1: buyer alone, after the deadline
```
Buyer + seller release to the seller; seller + arbiter release if the buyer vanishes; in a dispute the
arbiter decides with one of the parties; if nobody acts, the buyer takes the money back after the
deadline. Neither the arbiter nor the seller can move the money alone, and it can never be stuck. The
contract code (`krm1…`) carries the policy plus the roles, amount and label, and is checked against the
policy hash, so every party derives the same address and sees its own role. Payments use the
multisig proposal files: each signer checks the destination by reading the transaction itself.
Tested on a node: release by buyer + seller, refund decided by the arbiter, buyer reclaim refused before
the deadline and accepted after it, outsiders and single parties refused.

### 4.16 Proof of reserves
Custodians (exchanges) can prove solvency without exposing customers:
* **Assets.** Bound to a statement of the moment (e.g. "Exchange X — 2026-11-13"): each transparent coin
  is signed with its address key; each private coin is opened (amount and blinding factor of
  `C = x·G + v·H`) and accompanied by its key image `I` and a Chaum–Pedersen DLEQ proof that
  `log_G(P) = log_{Hp(P)}(I)`. The verifier, with any node, checks that every coin exists, the amounts
  open the commitments, ownership is proven and no key image has been used — so the coins are unspent
  *and* two custodians cannot count the same coin (a coin has exactly one key image). Revealing the
  custodian's own outputs is the price; customers' outputs are untouched. Privacy-preserving reserve
  proofs over the whole anonymity set (MProve-style) are future work.
* **Liabilities.** A Merkle *sum* tree (Maxwell): leaves are `H(account, salt, balance)`, nodes commit to
  their children's hashes and sums, the published root carries the total owed. Each customer receives
  their salt and path privately and verifies their own balance is included; leaves reveal neither
  names nor balances. Solvency is `reserves ≥ root total`.
* Tested on a node: honest proofs verify with the exact wallet balance; inflated amounts, coins owned by
  others, coins spent after the proof and proofs reused with another statement are rejected.

### 4.17 Full-chain membership proofs: the whole network is the anonymity set
A ring hides a spend among 16 outputs, and statistics (decoy-selection heuristics, chain reactions,
timing) erode even that. Krevo replaces rings with a **full-chain membership proof (FCMP)**: every
private input proves that the coin it spends is *one of all N private outputs that have ever existed*
(up to a recent anchor), without revealing which. There is no decoy selection left to get wrong.

**The curve cycle.** secp256k1 (E1: y² = x³ + 7 over F_p, with n points) has a twin, secq256k1
(E2: the same equation over F_n, with exactly p points). The x-coordinate of an E1 point is an E2
scalar and vice versa, so a zero-knowledge proof over one curve can do elliptic-curve arithmetic on
points of the other. The tests check the cycle (p·G = O on E2).

**The curve tree** (Campanelli, Hall-Andersen, Kamp — *Curve Trees*, USENIX Security 2023). Each private
output becomes a leaf on E2:
```
L = P.x·G0 + P.y·G1 + I.x·G2 + I.y·G3 + C.x·G4 + C.y·G5      I = Hp(P) (key-image base), C = commitment
```
Up to 256 leaves form a node on E1 (a Pedersen hash of their x-coordinates), up to 256 of those a node
on E2, and so on, alternating curves: depth 3 covers 16.7 million outputs, depth 4 covers 4.3 billion.
Every child is first shifted by k·H (smallest k ≥ 0) to a *permissible* point — y + 1 a square and
1 − y not — so its x-coordinate identifies it uniquely. The leaves follow the global order of private
outputs, so nothing new is stored on chain: every node derives the same tree, and the root of any
prefix, from its UTXO state. Nodes are computed lazily and cached; a reorganization truncates them.

**The proof.** The spender re-randomizes the coin and its path:
```
P̂ = P + r1·T    Î = I + r1·T_I    Ĉ = C + r1·T_C    L̂ = L + r2·G6    N̂_l = N_l + r·G_blind(l)
```
and publishes two **Bulletproofs for arithmetic circuits** (no trusted setup), one over each curve:
* over E2: "un-blinding" P̂, Î, Ĉ with the bits of r1 gives exactly the coordinates committed in L̂,
  and every E1 node of the path, un-blinded, is a child of the node above;
* over E1: the leaf and every E2 node of the path, un-blinded with r2, are children of the node above —
  up to the public root.

The blinded nodes enter the proofs as **vector commitments**, each at its own power of the challenge
(as in Generalized Bulletproofs), so the circuit opens them without revealing them:
```
l(X) = (aL + y⁻ⁿ∘wR)·X + aO·X² + sL·X³ + Σ_k c_k·X^(4+k)
r(X) = (wO − yⁿ) + (yⁿ∘aR + wL)·X + yⁿ∘sR·X³ + Σ_k wC_k·X^(−2−k)
```
The X² coefficient of ⟨l, r⟩ equals the constraints' public value exactly when every constraint
holds. Un-blinding is a fixed-base scalar multiplication in 3-bit windows (86 windows; table offsets
2^j·Ω rule out exceptional additions, and the last addition checks x ≠ x with an inverse): 259 gates per
point plus 602 for the scalar's bits. "Is a child" is Π(e_j − x) = 0 over the node's entries. At depth 3
the circuits have 1,894 gates over E2 and 1,632 over E1 (n = 2,048 each). The inner-product argument
folds generators as G' = G_lo + u·G_hi with 128-bit challenges.

A **generalized Schnorr proof** ties everything to the transaction and the spender, revealing nothing:
```
P̂ = p·G + t·T             (the spender knows the key)
p·P̂ = q·G + y·T           (with the line above, forces q = p², y = p·t)
KI = p·Î − y·T_I          (hence KI = p·Hp(P): the SAME key image as ring spends)
Ĉ − C' = a·G + b·T_C      (the pseudo-commitment C' carries the same amount)
```
Because the key image is unchanged, double spends are caught exactly as before, wallets, light-wallet
buckets and proofs of reserves keep working, and an output can never be spent twice through different
proof types.

**Anchors.** A private input names its anchor N (the tree of the first N private outputs). Validators
require N to be within the state of their selected parent (the global order is the selected chain's)
and the N-th output to be at least `fcmpMaturity` = 1,000 blocks old (100 s) — so every coin in the
tree is mature (this also covers coinbase maturity) and the root is stable under any realistic
reorganization. Wallets take the newest mature anchor and download their part of the tree — the
entries of each node from their level-1 chunk up to the root — **mixed with 7 decoy chunks**, from a
full node (`getfcmpanchor`, `getfcmppath`) or a light server (`/v1/fcmp/anchor`, `/v1/fcmp/path`).

**Cost and measurements.** ~2.9–3.1 KB per input (a CLSAG ring of 16 was ~0.6 KB); 20,000 g of mass per
input (~0.0002 KRV). All proofs of a transaction are verified with one multi-exponentiation per curve.
In pure JavaScript, proving takes ~9–12 s per transaction on a desktop — the two curves' proofs, and
the inputs, run in parallel threads — and verifying ~1 s per input; native code should be ~50–100×
faster. Measured on the devnet with real processes: a private payment with one input, 4,131 bytes,
fee 0.0003 KRV, proved in 9.2 s and accepted 106 ms after submission; a light-wallet payment with two
inputs, 7,056 bytes, proved in 11.7 s and accepted 45 ms after submission. With the native prover of
the Rust node (`krevod provar`, which the wallets use automatically when it is built) the same two
payments were proved in 1.7 s and 2.0 s, and the Rust node verifies a proof in ~0.15 s. Without the
binary, the same Rust code compiled to WebAssembly proves instead (section 4.18): one input at depth 4
in ~10 s sequentially, as in browsers (pure JavaScript: ~18 s); in the browser test environment the
proof took 9.3 s (14.3 s before, in pure JavaScript) and the network accepted it.

**Tests.** Valid proofs at depths 1, 2 and 3; rejected: tampered proofs, another transaction's message,
an invented key image, a different amount, another root, an output that is not in the tree, a double
spend, an immature anchor, and ring inputs on networks that no longer accept them. A dishonest prover
that skips its own checks (claiming 3·5 = 16, or opening a commitment to other values) does not
convince the verifier.

**Limitations.** This is new, **unaudited** cryptography assembled for this project: the ideas follow
published work (Curve Trees, Generalized Bulletproofs, Monero's FCMP++), but this composition and code
have not been reviewed by third parties. Soundness relies on discrete logarithms being hard on both
curves, privacy on DDH. Proving time in JavaScript is the main usability cost, especially on phones
(browsers prove sequentially here, in WebAssembly). Each node verifies a private input in ~1 s before relaying it, so in
this JavaScript implementation a private payment reaches distant nodes in seconds, not under one
second (section 5.2). After start-up, the first validation computes the whole tree (~2 ms per output). Rings remain valid only on the automated-test network (simnet), to keep the other tests fast.

### 4.18 Hardened wallet cryptography

The secrets of a wallet — spending and view keys, blinding factors, amounts, nonces, the wallet file
key — are handled by a **constant-time Rust core**: the code of the Rust node (`rust/krevod/src`:
fields, curves, `ct.rs`, `wallet_ops.rs`, the FCMP prover), compiled to WebAssembly
(`rust/krevo-wasm`) and loaded by the command-line wallet in Node.js and by the browser app alike.

* **Constant-time by construction.** Montgomery field arithmetic with masked selects and a
  constant-time Tonelli–Shanks square root (no branch or memory access depends on a secret); complete
  projective addition formulas for a = 0 curves (Renes–Costello–Batina, b₃ = 21), so the same
  operations run whether points are equal, opposite or the identity; fixed-window scalar multiplication
  whose table lookups read every entry; fixed-base tables for G and H; a constant-time Straus
  multi-exponentiation for the secret parts of the circuit proofs. In range proofs, each bit of an
  amount selects G_i or −H_i through masks. AES-256-GCM is the bitsliced RustCrypto implementation
  (the pure-JavaScript AES of the browser uses lookup tables and stays only as a fallback); ML-DSA-44
  is RustCrypto's `ml-dsa`, which derives the same key as OpenSSL from the same seed.
* **Hedged nonces.** Every nonce is H(domain ‖ secret ‖ message ‖ 32 random bytes): with a failing
  random generator it degrades to a deterministic nonce (never repeated across messages, so the key
  cannot be solved from two signatures), and with a good one the randomness defeats fault attacks
  against deterministic nonces. Applied to Schnorr signatures, CLSAG, the full-chain Schnorr-style
  proof, payment proofs, proof-of-reserves DLEQ and the blinding of range proofs (derived from a hedged
  seed) — in the Rust core and in the JavaScript fallback alike.
* **Verify before release.** Schnorr, CLSAG, range proofs, the full-chain proof (both circuit halves
  plus the Schnorr-style part) and ML-DSA signatures are verified before they are returned; a fault
  during signing produces an error instead of a signature that could expose the key.
* **Memory hygiene and robustness.** Inputs are zeroed in WebAssembly memory right after being read
  (the core's internal copy with volatile writes after use), the output buffer before every call; a
  WebAssembly trap discards the instance; a self-test runs at load. Hostile inputs (off-curve points,
  non-canonical scalars, malformed proving jobs) are rejected with errors.
* **The node.** `krevod` holds no secrets but faces hostile peers: panics while handling a peer message
  or an RPC call are caught (the peer is disconnected and the node continues — as the JavaScript node
  does with exceptions), the state lock tolerates a panicked thread, HTTP request lines and headers are
  bounded, and arithmetic on request parameters saturates. Fuzz tests feed it ~50,000 mutated blocks,
  transactions, P2P messages and RPC calls per run (they found and fixed an overflow in two RPC
  methods); a live node survived 46 hostile connections without a panic.

* **Measured constant time.** dudect-style tests (fixed vs. random secrets, Welch's t-test with
  percentile crops) run natively (`cargo test ct_timing -- --ignored`) and on the WebAssembly core under
  V8 (`rust/krevo-wasm/ct-timing.mjs`). The first run detected a leak (|t| ≈ 48): LLVM had compiled the
  masked table lookup into a conditional branch, which the branch predictor learns for a repeated key.
  All masks now pass through an optimization barrier; afterwards every operation measured |t| ≤ 2.3
  (k·G, k·P, k·H, Schnorr, range proofs, AES-GCM), against |t| ≈ 2,800 (native) and ≈ 270 (JavaScript
  BigInt) for variable-time controls. The circuit prover no longer skips zero witness entries.
* **Key vault.** The seed enters the core once; spend, view and all derived keys (transparent,
  quantum-safe, multisig, swap, one-time output keys p = k + b + m) stay there. The JavaScript wallet holds
  signers and spenders — handles that sign, compute key images, CLSAG, the FCMP Schnorr-style proof,
  reserve DLEQs and RFC 6979 ECDSA (byte-identical to the JavaScript implementation) — and only
  view-level data. Wallet files with a password seal everything but the encrypted seed and phrase
  (AES-256-GCM, key H("wallet/store", seed) inside the vault). An internal review found that earlier
  files stored each private output's one-time key in plain text, making coins spendable without the
  password; files are now migrated automatically (keys erased, outputs rescanned).

**Measured.** k·P in the core ~0.5 ms (variable-time JavaScript ~1 ms); a two-output range proof
~0.4 s; ML-DSA-44 signing ~2 ms; the browser app loads the 1.2 MB module under its Content Security
Policy (`'wasm-unsafe-eval'` allows WebAssembly compilation only, not JavaScript `eval`). The test
suite passes with the core and without it (`KREVO_NO_WASM=1`, the JavaScript fallback).

**Limitations.** Timing tests are statistical evidence on one machine and engine, not a proof, and other
engines/CPUs may differ; WebAssembly memory is readable by JavaScript in the same page or process, so
the vault protects against timing, careless leaks and persistence, not against malicious code already
running in the wallet; view-level secrets (shared secrets, amounts, masks) still pass through
JavaScript; wallets without a password keep the seed in plain text.

---

## 5. Speed

### 5.1 Confirmation levels
| Level | What it means | Typical time |
|---|---|---|
| **Accepted** | a block included the tx and the recipient's node sees it in the virtual state | 0.2–0.8 s |
| **Safe for everyday amounts** | dozens of blue blocks on top | ~2–5 s |
| **Safe for large amounts** | hundreds of blue blocks on top | ~10–30 s |

An important and honest point: in any PoW system, security against double spends is
**probabilistic** and grows over time. "Under one second" refers to acceptance, which is what matters
for everyday commerce (like a contactless card payment). For large amounts, wait a few seconds —
still hundreds of times faster than Bitcoin's 6 confirmations (~60 min).

### 5.2 Measurements
**Real local network** (3 nodes in a line, 2 miners, `scripts/devnet.js`): time from sending until the
transaction shows as accepted **on the recipient's node** (2 network hops):

| Transaction | Time to acceptance (range over 6 runs) | Fee |
|---|---|---|
| transparent → transparent (8 sends per run) | median 133–291 ms (min 75, max 443) | 0.00011 KRV |
| transparent → private | 326–606 ms | 0.00011 KRV |
| private → private | 0.8–1.8 s ¹ | 0.00108 KRV |
| private → transparent | 335–848 ms | 0.00055 KRV |

¹ measured with ring signatures, before full-chain proofs; dominated by verification in pure JavaScript
at every hop. With full-chain proofs (section 4.17), the same 3-node run measured: private → private
with 4 inputs (12.9 KB) built in 23.8 s and accepted by the recipient's node, two hops away, 10.5 s
after submission; private → transparent with 2 inputs built in 16.8 s, accepted after 5.5 s. Every
node verifies before relaying (~1 s per input in JavaScript), and each node's first full-chain
verification also builds the generators and the tree. With a single node, acceptance after submission
was 45–106 ms. In native code (Rust) proving and verification are expected to be ~50–100× faster —
which is what sub-second private payments need.

**Global simulation** (`scripts/simulate.js`, using the project's real GHOSTDAG): 40 nodes on 6
continents, typical backbone latencies, 8 peers per node, 300 simulated seconds:

| Block rate | Red blocks | Propagation (90% of nodes) | Acceptance: median / p90 / p99 | < 1 s |
|---|---|---|---|---|
| 10 blocks/s | 0.00% | 286 ms | 421 / 602 / 796 ms | 100% |
| 32 blocks/s | 0.00% | 287 ms | 326 / 437 / 534 ms | 100% |

The second row shows the design's headroom: raising the block rate *reduces* latency without
producing red blocks — the natural path for growth.

---

## 6. Fees, mass and scalability

### 6.1 Mass
`mass = max(compute mass, storage mass)`, declared inside the transaction itself.

* **Compute:** 1 g/byte + 1,000 g per signature + 20,000 g per private input (full-chain proof; 1,500 g per
  ring member on the test network) + 3,000 g per private output.
* **Storage (Kaspa's KIP-9):** C·(Σ 1/output − |I|²/Σ input), C = 10⁹. Creating lots of tiny outputs
  ("dust") is expensive; normal payments and consolidations are practically free. This is the
  mechanism that keeps the UTXO set — and therefore nodes' RAM and disk — under control **without
  requiring high fees**.
* Limits: 250,000 g per transaction, 500,000 g per block (5,000,000 g/s of capacity).
* Minimum relay fee: **1 grain per gram** (1 KRV = 100,000,000 grains).

### 6.2 Scaling without absurd hardware
* **Cheap validation:** PoW costs microseconds to verify; GHOSTDAG and difficulty adjustment cost a
  few milliseconds per block even in the JavaScript implementation (~6.5 ms per full block, measured).
* **Bounded state:** storage mass makes growing the UTXO set expensive.
* **State commitment (MuHash3072):** each header commits to the full state. This lets a new node
  download a *snapshot* of the state and verify it against the headers — without downloading the
  history (pruned sync, not yet implemented; see roadmap).
* **More blocks per second:** the DAG scales by increasing the block rate (the 32 blocks/s simulation
  produced no red blocks), and k adjusts automatically.
* **The cost of privacy:** private outputs can never be removed from the set (nobody knows which were
  spent). That is why they pay a fixed storage mass (2,000 g). It is the same trade-off Monero makes.

---

## 7. Economics

### 7.1 Supply
* **Hard cap:** 1,000,000,000 KRV (10¹⁷ grains). Consensus tracks the total minted at every chain
  block and **cuts** any reward that would exceed the cap — the guarantee does not rely on the formula
  alone.
* **Reward:** 5.45 KRV/s in the first month (0.545 KRV per block at 10 blocks/s), multiplied by
  2^(−m/48) in month *m*: it drops ~1.43% per month and halves every 48 months. No halving "shocks".
* **Exact arithmetic:** the 48 factors 2^(−j/48) are exact integer roots computed in the code; any
  implementation reaches the same bit-for-bit result.

| Year | Reward per block | Cumulative emission | % of total |
|---|---|---|---|
| 1 | 0.465 KRV | 159.1 million | 15.9% |
| 2 | 0.391 KRV | 292.8 million | 29.3% |
| 4 | 0.276 KRV | 499.8 million | 50.0% |
| 8 | 0.138 KRV | 749.8 million | 75.0% |
| 16 | 0.035 KRV | 937.2 million | 93.7% |
| 32 | 0.002 KRV | 995.8 million | 99.6% |
| ~103 | emission ends | 999.69 million | 99.97% |

(`node src/cli.js emission --network mainnet` prints the full table.)

### 7.2 Who gets paid
Each chain block pays, in its coinbase, every block in its mergeset:
* a **blue** block → subsidy + ½ of the fees it included + the fund release, to **its own miner**;
* a **red** block → the same amount goes to the miner of the block that merged it (an attacker who
  withheld a block gains nothing from it).

Honest parallel blocks are blue and all of them get paid — **there are no orphan blocks** losing their
reward, which reduces the advantage of large pools and the pressure toward centralization.

### 7.3 Security Fund (novelty)
Negligible fees plus a capped supply raise a real question: who pays for security once emission ends?
Krevo answers it in consensus:
* **½ of every fee** goes into a fund held by the protocol (nobody controls it);
* each merged block receives **1/864,000 of the fund** (half-life of ~16 h at 10 blocks/s).

Effects: miner income becomes smooth (fee spikes are spread over hours), the incentive to "steal fees"
by reorganizing blocks drops, and security comes to depend on **total transaction volume** (many tiny
fees) rather than on high individual fees. No coins are created: the fund only redistributes fees
over time.

### 7.5 Mining pools
At 10 blocks per second a single CPU or small GPU still finds blocks regularly, but income is noisy;
pools smooth it. The reference implementation ships a complete pool:

* **Share protocol** (JSON lines over TCP, Stratum-style) with per-miner difficulty (vardiff) and
  rejection of duplicate, stale or too-easy shares. Shares that meet the block target are submitted
  as blocks; in a DAG even a block built on a slightly old template is merged rather than orphaned.
* **Exact accounting.** Nodes keep a local index of the reward actually paid to each block (subsidy,
  half of its fees and the Security Fund release, or nothing if it was red). The pool credits a block
  only after that reward matures and splits it among the shares of the preceding 60 seconds (PPLNT),
  weighted by difficulty.
* **Payouts** are batched and can go to private addresses, so miners need not reveal their earnings.
  Because every merged block pays its own coinbase output, a busy pool accumulates thousands of small
  outputs; payouts therefore use several transactions per round and consolidate small coins — the
  storage-mass rule makes consolidation cheap.

Measured in a local test with real CPU mining: payouts matched each miner's share of hashing power
within 1% (1.98 : 1 for a 2 : 1 split), and wallet balances matched the pool's books exactly.

### 7.6 Fair launch, no premine
* The genesis block has no outputs and **receives no reward** (an explicit consensus rule).
* There is no admin key, no signed checkpoint and no coins reserved for the creators.
* **Launch procedure:** the mainnet genesis message must contain the hash of a Bitcoin block mined
  minutes before the announcement, proving nobody could have mined beforehand. The code, binaries and
  genesis hash are published together, and mining starts for everyone at the same time.

---

## 8. Security and limitations (read before using)

This is a **reference implementation**. It shows the design works, but it **must not hold real
money** until the items below are resolved:

1. **Not audited.** New cryptography needs an independent external audit before any launch.
2. **Wallet secrets: constant time measured, isolation limited.** Wallet operations on secrets run in a
   constant-time Rust core with the keys kept in a vault (section 4.18); timing was measured with
   dudect-style tests (one leak found and fixed). Not audited independently; the JavaScript fallback
   (only without WebAssembly) is not constant-time; the vault does not isolate keys from malicious code
   running in the same process. See `docs/SECURITY.md`.
3. **Full-chain membership proofs are new and slow in JavaScript.** Private spends hide among every
   private output (section 4.17), but the construction is unaudited. Proving takes ~2 s with the native
   Rust prover, ~7–10 s with the Rust core in WebAssembly (the option in browsers, slower on phones) and
   ~11–18 s in pure JavaScript.
4. **PoW security is probabilistic.** Whoever controls more than 50% of the hashrate can reorganize
   recent history, as in any PoW system.
5. **Finality and pruning are not implemented.** The current node keeps every block and revalidates
   everything on restart. Still missing: body pruning, pruning proofs and snapshot sync.
6. **The Security Fund has a known weak spot:** a miner can arrange fees "off-chain" with users to
   avoid the half that goes to the fund. With tiny fees the incentive is small, but it exists.
7. **Quantum computing** threatens secp256k1 in the long term (as it does Bitcoin, Kaspa and Monero).
   Krevo's quantum-safe `krq` addresses and the private-pool turnstile (section 4.11) cover transparent
   funds and the supply; `krv` addresses, multisig policies and the privacy of the private pool are
   still elliptic-curve based.
8. **Regulation.** Privacy coins face restrictions in some jurisdictions (for example, the European
   Union's anti-money-laundering rules foresee restrictions on anonymity-enhancing assets at exchanges
   from 2027). The optional model with view keys helps, but consult a lawyer before launching.

### What is inherited and what is new
* **Inherited (and therefore trustworthy):** GHOSTDAG and storage mass (Kaspa); RingCT/CLSAG, stealth
  addresses and view tags (Monero); Bulletproofs; Curve Trees on a 2-cycle of curves (Campanelli,
  Hall-Andersen, Kamp) and vector commitments in arithmetic-circuit Bulletproofs (Generalized Bulletproofs,
  as used by Monero's FCMP++); the balance signature (Zcash Sapling/Mimblewimble);
  MuHash (Bitcoin/Kaspa); Dandelion++; ML-DSA (NIST FIPS 204, via OpenSSL and RustCrypto); complete addition
  formulas (Renes–Costello–Batina) and hedged nonces (deterministic + random, as BIP-340's auxiliary randomness); the shielded-pool
  turnstile idea (Zcash ZIP-209); HTLC atomic swaps (Tier Nolan's protocol, BIP-199); names as UTXOs (Namecoin); SPV-style proofs and view-tag scanning for light clients (Bitcoin, Monero); Merkle sum trees for liabilities (Maxwell) and key-image reserve proofs (Monero).
* **New in Krevo:** combining a 10 blocks/s BlockDAG with privacy whose anonymity set is **every
  private output ever created** (full-chain membership proofs on the secp256k1/secq256k1 cycle, with the
  same key images as rings), **optional in the same transaction format**; a deterministic private coinbase that feeds the anonymity set from
  day 1; uniform subaddresses with an ephemeral key in every private output; fixed-size encrypted memos
  on every private transaction plus DLEQ payment proofs (selective disclosure without exposing keys);
  hash-committed spending policies with alternative paths and relative time locks, used for multisig
  and for consensus-enforced inheritance ("proof of life" renewals); hybrid Schnorr + ML-DSA
  quantum-safe addresses derived from the same recovery phrase, available from launch, plus a turnstile
  that confines any counterfeit to the private pool; hash-locked policy paths compatible with Bitcoin's
  `OP_SHA256`, giving wallet-driven atomic swaps with automatic safety checks; human-readable names with
  commit–reveal, length-based yearly fees routed to the Security Fund, and private payments to public names;
  light wallets that scan privately with view tags, accept nothing without a Merkle + proof-of-work proof
  over the BlockDAG selected chain and cross-examine two servers (spends must be proven);
  escrow contracts with a deadline refund on consensus-level policies; proof of reserves covering private
  coins (DLEQ + key images) and liabilities (Merkle sum tree);
  a consensus-level Security Fund;
  percentile-based difficulty adjustment; smooth emission in exact integer arithmetic with the cap
  enforced by a counter.

---

## 9. Roadmap to mainnet

1. **Reimplement the node in Rust** — started: `rust/krevod` is a second, independent full node that
   validates every rule (including full-chain membership proofs), speaks the same P2P protocol and RPC,
   and was checked against the JavaScript node on test vectors, 29 complete chains re-validated with
   identical state, and a mixed JavaScript/Rust network with miners and wallets. Its constant-time wallet
   code, compiled to WebAssembly, already handles every secret of the JavaScript wallets (section 4.18),
   and its native full-chain prover (`krevod provar`) serves the desktop wallets. Still to do: measuring
   constant time on more CPUs and engines, a key-value database with pruning, parallel validation in the
   rusty-kaspa style. The JavaScript version remains the executable specification and the source of
   test vectors.
2. **Independent audits** of the cryptography and consensus.
3. **Pruning + pruning proofs + snapshot sync** (nodes with constant disk usage).
4. **Wallet ecosystem:** BIP-39 recovery phrases (section 4.5) and trustless light wallets (section 4.14)
   are done, and the light wallet runs in browsers and on phones as an installable app; next come native
   mobile packaging, hardware wallet apps (Ledger/Trezor)
   implementing the derivation above.
5. A **public testnet** for at least 6 months, with a bug bounty program. The reference block
   explorer (live DAG view, blocks, transactions, transparent addresses, JSON API) already exists and
   shows private parts only as hidden; a public deployment needs pruning-aware indexes and rate limits.
6. Evaluate **DAGKNIGHT** (GHOSTDAG's successor without a fixed k) and higher block rates.
7. **Faster full-chain proofs:** the native prover (`krevod provar`) and the WebAssembly build for
   browsers and phones exist; next, the two halves in parallel Web Workers, and elliptic-curve divisors to shrink the circuits
   (as in FCMP++); and **Janus-resistant subaddresses** (Carrot-style).
8. **Private multisig** and **FROST threshold signatures** (multisig indistinguishable from single-key).
9. **Post-quantum, phase 2:** hybrid keys inside multisig/inheritance policies, a post-quantum
   private pool, and a pre-announced emergency soft fork with seed-based rescue for `krv` coins
   (section 4.11).
10. **Atomic swaps, phase 2:** public-testnet runs (testnet4/signet; regtest against Bitcoin Core is done), fee bumping (RBF/CPFP)
    for Bitcoin claims, private swaps with adaptor signatures, and an order book for finding a
    counterparty (section 4.12).
11. **Fair launch** as described in section 7.6.

---

## 10. Consensus parameters (mainnet)

| Parameter | Value |
|---|---|
| Blocks per second | 10 (100 ms target) |
| GHOSTDAG k | 124 |
| Maximum parents | 16 |
| Mergeset limit | 512 |
| Maximum merge depth | 3,600 blue score (~6 min) |
| Difficulty window | 2,640 blocks, 5th–95th percentiles |
| Median time window | 263 blocks |
| Coinbase maturity | 1,000 blocks (~100 s) |
| Private inputs | full-chain membership proof: anchor N, ~2.9–3.1 KB, 20,000 g of mass |
| Curve tree | leaves on secq256k1, 256 children per node, alternating curves; depth 3 = 16.7 M outputs |
| Anchor maturity | 1,000 blocks (~100 s; covers coinbase maturity) |
| Ring size (test network only) | 16 |
| Maximum mass: transaction / block | 250,000 / 500,000 g |
| Maximum supply | 1,000,000,000 KRV |
| Smallest unit | 1 grain = 0.00000001 KRV |
| Initial reward | 5.45 KRV/s, halving every 4 years (monthly reduction) |
| Security Fund | ½ of fees; releases 1/864,000 per block |
| Addresses | `krv1…` transparent (single key or M-of-N multisig), `krs1…` private (main or subaddress — identical form), `krq1…` quantum-safe transparent, `krw1…` view key, `krp1…` payment proof, `krk1…` multisig participant key, `krm1…` multisig descriptor, `krx1…` atomic swap offer/acceptance |
| Quantum-safe spend | Schnorr (64 B) **and** ML-DSA-44 (2,420 B) signatures; witness 3,830 B; counts as 2 signature checks |
| Private-pool turnstile | public counter of KRV in the pool; transactions that would make it negative are not accepted |
| Multisig | up to 15 keys; witness = policy + M Schnorr signatures |
| Spending paths | up to 4 per policy, each with a relative time lock (in blocks) and, in policy v3, an optional SHA-256 hash lock (32-byte secret) |
| Escrow | policy: 2-of-3 {buyer, seller, arbiter} or buyer alone after the deadline; code `krm1…` with roles |
| Proof of reserves | assets: Schnorr per transparent coin; private coins opened + key image + DLEQ; liabilities: Merkle sum tree with salted leaves |
| Light wallets | compact scan 35 B/output; candidates fetched with 15 decoys; tree paths with 7 decoy chunks; key-image buckets of 1/256; acceptance proof = Merkle path + 100 chain headers with PoW (policy, not consensus) |
| Names (@name) | 3–32 chars `a-z0-9-`; yearly fee 100 / 20 / 5 / 1 KRV (3 / 4 / 5 / 6+ chars) to the Security Fund; expiry 1 year + 30 days grace; commitment age 300 blocks – 1 day; deposit ≥ 0.01 KRV |
| Atomic swaps | `krx1…` offer/acceptance codes; default deadlines 48 h (initiator) / 24 h (participant); Bitcoin side P2WSH + CLTV |
| Memo block | 145 bytes, present in every transaction with a private output |
| Private output | R (33) + P (33) + C (33) + encrypted amount (8) + view tag (1) = 108 bytes |
| Payment request URI | `krevo:<address>?amount=…&memo=…&label=…&exp=…` |
