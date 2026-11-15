# Krevo image: the JavaScript tools (node, miner, light server, explorer, web app,
# faucet) + the Rust node (krevod, also the wallets' native prover).
#
#   docker build -t krevo .
#   docker run --rm krevo emission --network testnet                 # any CLI command
#   docker run -d -v krevo-data:/data -p 16210:16210 krevo            # JavaScript testnet node
#   docker run -d -v krevo-data:/data -p 16210:16210 --entrypoint krevod krevo node --network testnet --datadir /data
#
# For a complete operator stack, see docker-compose.yml and docs/TESTNET.md.

FROM rust:1-slim AS rust
WORKDIR /src
COPY seeds seeds
COPY rust/krevod rust/krevod
RUN cd rust/krevod && cargo build --release --locked

# Node 24.7+ ships OpenSSL 3.5 (ML-DSA signatures for the quantum-safe addresses)
FROM node:24-slim
LABEL org.opencontainers.image.source="https://github.com/Milkausikopistor/krevo" \
      org.opencontainers.image.description="Krevo (KRV): proof-of-work BlockDAG cryptocurrency with optional privacy — reference implementation (testnet only)" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /krevo
COPY package.json LICENSE ./
COPY src src
COPY scripts scripts
COPY seeds seeds
COPY --from=rust /src/rust/krevod/target/release/krevod /usr/local/bin/krevod
# the wallets use the native prover automatically
ENV KREVO_PROVER=/usr/local/bin/krevod
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
# testnet P2P and RPC, explorer, light server, web app, faucet
EXPOSE 16210 16211 8080 8090 8091 8092
ENTRYPOINT ["node", "src/cli.js"]
CMD ["node", "--network", "testnet", "--datadir", "/data"]
