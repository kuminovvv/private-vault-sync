FROM rust:1-bookworm AS build
WORKDIR /app
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN groupadd -g 10001 sync && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin sync
COPY --from=build /app/target/release/private-sync /usr/local/bin/private-sync
USER 10001:10001
ENV SYNC_BIND=0.0.0.0:8877 SYNC_DATA=/data
EXPOSE 8877
ENTRYPOINT ["/usr/local/bin/private-sync"]
