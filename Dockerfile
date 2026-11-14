# Imagem do Krevo: ferramentas em JavaScript (nó, minerador, servidor leve, explorador, app web,
# torneira) + o nó em Rust (krevod, também provador nativo das carteiras).
#
#   docker build -t krevo .
#   docker run --rm krevo emissao --rede testnet                     # qualquer comando da CLI
#   docker run -d -v krevo-dados:/dados -p 16210:16210 krevo         # nó JavaScript da testnet
#   docker run -d -v krevo-dados:/dados -p 16210:16210 --entrypoint krevod krevo no --rede testnet --dados /dados
#
# Para uma pilha completa de operador, veja docker-compose.yml e docs/TESTNET.md.

FROM rust:1-slim AS rust
WORKDIR /src
COPY seeds seeds
COPY rust/krevod rust/krevod
RUN cd rust/krevod && cargo build --release --locked

# Node 24.7+ traz o OpenSSL 3.5 (assinaturas ML-DSA dos endereços quânticos)
FROM node:24-slim
WORKDIR /krevo
COPY package.json LICENSE ./
COPY src src
COPY scripts scripts
COPY seeds seeds
COPY --from=rust /src/rust/krevod/target/release/krevod /usr/local/bin/krevod
# as carteiras usam o provador nativo automaticamente
ENV KREVO_PROVER=/usr/local/bin/krevod
RUN mkdir -p /dados && chown node:node /dados
USER node
VOLUME /dados
# P2P e RPC da testnet, explorador, servidor leve, app web, torneira
EXPOSE 16210 16211 8080 8090 8091 8092
ENTRYPOINT ["node", "src/cli.js"]
CMD ["no", "--rede", "testnet", "--dados", "/dados"]
