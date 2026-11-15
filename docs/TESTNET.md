# Running the Krevo public testnet

There is no company, foundation or server behind Krevo. The **testnet is already defined in the
code** — genesis block, ports, address prefixes — so it exists as soon as someone runs a node, and it
grows as other volunteers join. This guide is for those volunteers.

> Testnet coins have **no value** and the network may be reset. Never use real money.

## 1. What the testnet is

| | |
|---|---|
| Network name | `testnet` (`--network testnet`) |
| Genesis | fixed in `src/params.js` / `rust/krevod/src/params.rs` (message `Krevo testnet`) |
| Ports | P2P **16210** (open to the Internet), RPC 16211 (keep private) |
| Addresses | `krvtest1…` transparent, `krstest1…` private, `krqtest1…` quantum-safe |
| Seed nodes | `seeds/testnet.txt` (empty until the first volunteer adds one) |
| Block rate | 10 blocks per second, same rules as the planned mainnet |

The first node to start mines on top of the genesis; everyone else connects to it (directly with
`--par host:16210`, or through the seed list) and syncs.

## 2. Roles you can take

| Role | What it gives the network | Typical machine |
|---|---|---|
| **Seed / full node** | others can find and sync the network | 2 vCPU, 4 GB RAM, ~10 GB disk per month (see §6) |
| **Miner** | blocks; coins for faucets and testers | any CPU (connects to a node's RPC) |
| **Light server** | lets phone/browser wallets work without a node | next to a node, behind HTTPS |
| **Block explorer** | public view of the DAG, blocks, transactions | next to a node |
| **Web wallet host** | the installable wallet app, served from an origin you control | static-like, behind HTTPS |
| **Faucet** | gives test KRV to newcomers | next to a node, with a funded hot wallet |

You can run one role or all of them.

## 3. Quick start with Docker

```bash
git clone <this repository> krevo && cd krevo
docker compose up -d                       # node (Rust) + light server + explorer + web wallet
docker compose logs -f no                  # watch it sync
```

- Mining: `MINING_ADDRESS=krvtest1… docker compose --profile mine up -d`
  (create that wallet on your own computer — `node src/cli.js wallet create --network testnet` — and
  only give the address to the server; **keep the wallet file and its recovery phrase safe**).
- Faucet: create a wallet with a password inside the `faucet` volume, send it some mined KRV
  (transparent address), then `KREVO_PASSWORD=… docker compose --profile faucet up -d`.
- Put a reverse proxy with HTTPS in front of ports 8080 (explorer), 8090 (light server),
  8091 (web wallet) and 8092 (faucet). Example `Caddyfile`:

```
explorer.example.org { reverse_proxy 127.0.0.1:8080 }
light.example.org    { reverse_proxy 127.0.0.1:8090 }
wallet.example.org   { reverse_proxy 127.0.0.1:8091 }
faucet.example.org   { reverse_proxy 127.0.0.1:8092 }
```

The Docker files are built by the continuous integration on every change; they were not run on the
original development machine (no Docker there). Report problems in an issue.

## 4. Without Docker

Requirements: Node.js **24.7+** (tested on 26); for the Rust node, a stable Rust toolchain.

```bash
# node — JavaScript (reference) or Rust (faster); both speak the same protocol
node src/cli.js node --network testnet --datadir ./data
cd rust/krevod && cargo build --release && ./target/release/krevod node --network testnet --datadir ./data
#   add --prune to keep only the last ~3 hours of history (bounded disk and memory; such a node cannot
#   serve old blocks or headers to new nodes, so the network also needs some archival nodes — the default)
#   add --fast-sync to a NEW node: it validates every header, then starts from a verified recent state
#   instead of re-validating every block (needs at least one archival Rust node among its peers)

# the rest talks to the node's RPC (default http://127.0.0.1:16211)
node src/cli.js wallet create --network testnet                       # asks for nothing; add --password to encrypt
node src/cli.js mine --network testnet --address krvtest1… --threads 2
node src/cli.js light-server --network testnet --public               # public: put HTTPS in front
node src/cli.js explorer --network testnet --public
node src/cli.js web-wallet --public
KREVO_PASSWORD=… node src/cli.js faucet --network testnet --file faucet-wallet-testnet.json --public --trusted-proxy
```

Run them under a service manager (systemd, pm2, Docker) so they restart on failure.

## 5. Joining the seed list

When your node has been reachable and stable for a few days, open a pull request adding one line
to `seeds/testnet.txt` (`host:16210`). Nodes connect to the seeds at start-up and then discover each
other. Please only list nodes you intend to keep online.

## 6. Known limits — help wanted

These are the main obstacles to a **long-running** testnet. They are good projects for contributors
(see `CONTRIBUTING.md`):

1. **Storage and restart time (top priority).** Blocks take ~355 bytes each on disk, i.e. **~300 MB
   per day** at 10 blocks/s. The **Rust node** restarts from a state snapshot (`state.snap`, written
   every 6,000 new blocks or a quarter of what it keeps) and validates only the newer blocks; with
   `--prune` it also keeps disk and memory bounded (see the Rust node section of the README for the
   trade-offs). The **JavaScript node** still keeps every block and re-validates the whole chain at
   start-up (~230 blocks/s, so each day of chain adds about an hour to its restart). A **new** Rust
   node can `--fast-sync`: every header (small) from an archival Rust node, then a verified recent
   state from its peers. Still needed: a logarithmic pruning proof, so that new nodes need no old
   headers and no archival peer at all (whitepaper §9, item 3), and a key-value database (the
   snapshot is rewritten whole, ~1.6 KB per kept block).
2. **Memory.** The block index lives in RAM in both nodes and grows with the chain (a pruned Rust node
   keeps only its recent window).
3. **Peer management.** Discovery is a plain `getaddr/addr` exchange plus the seed list; there is no
   DNS seeding, peer scoring beyond simple misbehaviour bans, or eclipse-attack protection.
4. **Releases.** A version tag makes CI publish `krevod` binaries (Linux, macOS, Windows), the
   project package and a Docker image (`ghcr.io/<owner>/krevo`); the binaries are not code-signed yet.
5. **Mobile.** The web wallet installs as an app (PWA); native packaging (Android/iOS) is not done.
6. **Independent audit** of the cryptography and consensus — see `docs/SECURITY.md`.

## 7. Resets and upgrades

The testnet may need a reset (for example after a consensus change): the new testnet gets a new
genesis message (`Krevo testnet 2`, …) in the code, and operators update and start with an empty
data directory. Announce resets in the repository well in advance.

## 8. Security for operators

- Never expose the node's RPC port (16211) to the Internet; the light server and explorer are the
  public faces.
- The faucet wallet is a hot wallet: keep only what it needs, protect it with a password
  (`KREVO_PASSWORD` in an environment file readable only by the service).
- Keep wallet files and recovery phrases out of the repository and out of Docker images
  (`.gitignore` and `.dockerignore` already exclude wallet files (`wallet-*.json`, `*-wallet-*.json`) and data directories).
- Report vulnerabilities privately (see `docs/SECURITY.md`).
