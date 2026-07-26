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

# Runtime base. NOT distroless — see below.
#
# `docs/PACKAGING.md` §1 sets `gcr.io/distroless/cc-debian13:nonroot` as the
# standard, and rustpanosmcp runs on it. This repo cannot, because distroless
# has no shell and no utilities, and two production paths spawn external
# binaries:
#
#   rust-junosmcp-core/src/tools/transfer_file.rs:1002,1017  `scp`
#     (OpenSshScpRunner — powers transfer_file and fetch_file)
#   rust-junosmcp-srx-core/src/workflows/support_bundle/mod.rs:691  `tar`
#     (powers collect_jtac_support_bundle)
#
# The `openssh-client` install below exists for exactly that. On distroless
# those tools would build and start fine, then fail the first time someone
# used them — the worst place to find out.
#
# So this moves to Debian 13 instead, matching the LXC's distro generation so
# there is one CVE surface to track rather than two. Adopting distroless
# requires removing the spawns first (SFTP over the SSH connection the server
# already holds; a Rust archive crate instead of tar), tracked separately.
#
# glibc rule: builder generation must be <= runtime generation. The builder is
# bookworm (12) and this is trixie (13), so the direction is safe. Moving the
# builder forward would require moving this first.
FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustjunosmcp"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client passwd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 jmcp \
    && useradd --uid 65532 --gid 65532 --home-dir /var/lib/jmcp \
        --no-create-home --shell /usr/sbin/nologin jmcp \
    && install -d -m 0750 -o 65532 -g 65532 \
        /etc/jmcp /etc/jmcp/keys /var/lib/jmcp /var/lib/jmcp/staging \
        /var/lib/jmcp/srx-staging/bundles \
    && install -d -m 0700 -o 65532 -g 65532 /var/lib/jmcp/device-leases \
    && install -m 0600 -o 65532 -g 65532 /dev/null /var/lib/jmcp/known_hosts

COPY --from=builder --chown=65532:65532 \
    /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
ENV RUST_LOG=info \
    JMCP_SUPPORT_BUNDLE_STAGING_DIR=/var/lib/jmcp/srx-staging/bundles \
    JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES=524288000
VOLUME ["/var/lib/jmcp"]
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD kill -0 1
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json", "--staging-dir", "/var/lib/jmcp/staging", "--known-hosts-file", "/var/lib/jmcp/known_hosts", "--device-lease-dir", "/var/lib/jmcp/device-leases"]
