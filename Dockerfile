# syntax=docker/dockerfile:1.6
# bookworm (Debian 12) builder to match the distroless-debian12 runtime glibc.
FROM rust:1.90-slim-bookworm AS builder
WORKDIR /src

# rustez / rustnetconf are crates.io dependencies now (no sibling checkout),
# so the build context is just the repo root and this Dockerfile is
# self-contained:
#   docker build -t rust-junosmcp:0.7 .
COPY . .
RUN cargo build --release --bin rust-junosmcp

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/RustJunosMCP"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
ENV RUST_LOG=info
USER nonroot
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json"]
