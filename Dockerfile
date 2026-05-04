# syntax=docker/dockerfile:1.6
FROM rust:1.83-slim AS builder
WORKDIR /src

# rustEZ is a workspace path dependency; the build context must contain both
# RustJunosMCP and ../rustEZ. Invoke from the parent dir:
#   docker build -f RustJunosMCP/Dockerfile -t rust-junosmcp:0.1 .
COPY . .

WORKDIR /src/RustJunosMCP
RUN cargo build --release --bin rust-junosmcp

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/RustJunosMCP"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /src/RustJunosMCP/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
ENV RUST_LOG=info
USER nonroot
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json"]
