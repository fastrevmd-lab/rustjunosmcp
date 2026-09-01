# syntax=docker/dockerfile:1.6
# linux/amd64 manifests pinned on 2026-08-07. The published image is currently
# amd64-only; update both digests deliberately when refreshing either base.
#
# Builder version is taken from rust-toolchain.toml (currently 1.98.0). The two
# must stay in sync.
FROM rust:1.98-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS builder
WORKDIR /src

# rustez / rustnetconf are crates.io dependencies now (no sibling checkout),
# so the build context is just the repo root and this Dockerfile is
# self-contained:
#   docker build -t rust-junosmcp:0.7 .
COPY . .
RUN cargo build --release --bin rust-junosmcp

# Create the directory tree and known_hosts file in the builder stage with the
# right modes and ownership, since distroless has no shell and cannot run
# groupadd/useradd/install. The distroless :nonroot variant already ships uid
# 65532, so we create the tree with explicit modes and then COPY it.
#
# COPY preserves source modes, so we set them here to match the current Debian
# image's layout: 0750 for most dirs, 0700 for device-leases, 0600 for known_hosts.
RUN install -d -m 0750 -o 65532 -g 65532 \
        /stage-etc/jmcp /stage-etc/jmcp/keys \
    && install -d -m 0750 -o 65532 -g 65532 \
        /stage-var/lib/jmcp /stage-var/lib/jmcp/staging \
        /stage-var/lib/jmcp/srx-staging /stage-var/lib/jmcp/srx-staging/bundles \
    && install -d -m 0700 -o 65532 -g 65532 /stage-var/lib/jmcp/device-leases \
    && install -m 0600 -o 65532 -g 65532 /dev/null /stage-var/lib/jmcp/known_hosts

# Runtime base: distroless. Now possible because #212 removed the last
# Command::new spawn (the scp subprocess). The server no longer shells out, so
# it no longer needs a shell or utilities.
#
# glibc rule: builder generation must be <= runtime generation. The builder is
# bookworm (glibc 2.36) and this is debian13 (glibc 2.41), so the direction is
# safe. Moving the builder forward would require moving this first.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:a77defd6fedbb3392b175ba8ea3d1c22be963c1597c248c3ba987ddd80bfb512
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustjunosmcp"
LABEL org.opencontainers.image.licenses="MIT"

# CA certificates are shipped in gcr.io/distroless/cc-* at /etc/ssl/certs. The
# binary makes outbound TLS calls (HTTPS requests for device APIs), and rustls
# uses the system CA bundle via rustls-native-certs.
COPY --from=builder --chown=65532:65532 \
    /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
COPY --from=builder --chown=65532:65532 /stage-etc/jmcp /etc/jmcp
COPY --from=builder --chown=65532:65532 /stage-var/lib/jmcp /var/lib/jmcp

ENV RUST_LOG=info \
    JMCP_SUPPORT_BUNDLE_STAGING_DIR=/var/lib/jmcp/srx-staging/bundles \
    JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES=524288000
VOLUME ["/var/lib/jmcp"]
USER 65532:65532

# HEALTHCHECK removed: distroless has no shell and no `kill` utility. Container
# orchestrators (Compose healthcheck, Kubernetes liveness probes) supervise the
# process directly via the container runtime rather than shelling out.

ENTRYPOINT ["/usr/local/bin/rust-junosmcp", "-f", "/etc/jmcp/devices.json", "--staging-dir", "/var/lib/jmcp/staging", "--known-hosts-file", "/var/lib/jmcp/known_hosts", "--device-lease-dir", "/var/lib/jmcp/device-leases"]
