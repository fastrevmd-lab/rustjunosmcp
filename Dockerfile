# syntax=docker/dockerfile:1.6
# linux/amd64 manifests pinned on 2026-07-10. The published image is currently
# amd64-only; update both digests deliberately when refreshing either base.
FROM rust:1.97-slim-bookworm@sha256:37cb5d16e04dcf484fdf071dfb132ce95d9b449d75ac12df3b7031b6f7023675 AS builder
WORKDIR /src

# rustez / rustnetconf are crates.io dependencies now (no sibling checkout),
# so the build context is just the repo root and this Dockerfile is
# self-contained:
#   docker build -t rust-junosmcp:0.7 .
COPY . .
RUN cargo build --release --bin rust-junosmcp

FROM debian:12-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/RustJunosMCP"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client passwd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 jmcp \
    && useradd --uid 65532 --gid 65532 --home-dir /var/lib/jmcp \
        --no-create-home --shell /usr/sbin/nologin jmcp \
    && install -d -m 0750 -o 65532 -g 65532 \
        /etc/jmcp /etc/jmcp/keys /var/lib/jmcp /var/lib/jmcp/staging \
    && install -d -m 0700 -o 65532 -g 65532 /var/lib/jmcp/device-leases \
    && install -m 0600 -o 65532 -g 65532 /dev/null /var/lib/jmcp/known_hosts

COPY --from=builder --chown=65532:65532 \
    /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
ENV RUST_LOG=info
VOLUME ["/var/lib/jmcp"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json", "--staging-dir", "/var/lib/jmcp/staging", "--known-hosts-file", "/var/lib/jmcp/known_hosts", "--device-lease-dir", "/var/lib/jmcp/device-leases"]
