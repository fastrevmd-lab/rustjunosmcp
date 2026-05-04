#!/usr/bin/env bash
# Build a release tarball for LXC / Debian deployment.
# Output: dist/rust-junosmcp_<version>_amd64.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(grep -E '^version' Cargo.toml | head -n1 | cut -d'"' -f2 || true)
if [[ -z "${VERSION:-}" ]]; then
    VERSION=$(grep -E '^version' rust-junosmcp/Cargo.toml | head -n1 | cut -d'"' -f2)
fi

echo ">> Building release binary..."
cargo build --release --bin rust-junosmcp

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

PKG="rust-junosmcp_${VERSION}_amd64"
PKGROOT="$STAGING/$PKG"

mkdir -p "$PKGROOT/usr/local/bin"
mkdir -p "$PKGROOT/etc/jmcp"
mkdir -p "$PKGROOT/etc/systemd/system"

cp target/release/rust-junosmcp                    "$PKGROOT/usr/local/bin/rust-junosmcp"
cp devices-template.json                           "$PKGROOT/etc/jmcp/devices.json.example"
cp packaging/systemd/rust-junosmcp.service         "$PKGROOT/etc/systemd/system/"
cp packaging/lxc/install.sh                        "$PKGROOT/install.sh"
chmod +x "$PKGROOT/install.sh"
chmod +x "$PKGROOT/usr/local/bin/rust-junosmcp"

mkdir -p dist
tar -czf "dist/$PKG.tar.gz" -C "$STAGING" "$PKG"
echo ">> Wrote dist/$PKG.tar.gz"
