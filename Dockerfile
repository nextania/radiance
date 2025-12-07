FROM rust:1.91.1 AS builder
USER 0:0
WORKDIR /usr/app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo install --path . --locked
 
FROM debian:trixie-slim
WORKDIR /usr/app
COPY --from=builder /usr/local/cargo/bin/zenith ./
CMD ["./zenith"]