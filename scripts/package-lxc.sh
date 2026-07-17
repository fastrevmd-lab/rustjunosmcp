#!/usr/bin/env bash
# Build a release tarball for LXC / Debian and Ubuntu deployment.
# Output: dist/rust-junosmcp_<version>_<arch>.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${JMCP_PACKAGE_VERSION:-$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-junosmcp/Cargo.toml)}"
case "$(uname -m)" in
    x86_64) DEFAULT_ARCH=amd64 ;;
    aarch64) DEFAULT_ARCH=arm64 ;;
    *) DEFAULT_ARCH="$(uname -m)" ;;
esac
ARCH="${JMCP_PACKAGE_ARCH:-$DEFAULT_ARCH}"
OUTPUT_DIR="${JMCP_PACKAGE_OUTPUT_DIR:-dist}"

if [[ "${JMCP_PACKAGE_SKIP_BUILD:-0}" != "1" ]]; then
    echo ">> Building release binary..."
    cargo build --release -p rust-junosmcp
fi

if [[ ! -x target/release/rust-junosmcp ]]; then
    echo ">> Missing executable target/release/rust-junosmcp" >&2
    exit 1
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

PKG="rust-junosmcp_${VERSION}_${ARCH}"
PKGROOT="$STAGING/$PKG"

mkdir -p "$PKGROOT/usr/local/bin"
mkdir -p "$PKGROOT/etc/jmcp"
mkdir -p "$PKGROOT/etc/systemd/system"

install -m 0755 target/release/rust-junosmcp "$PKGROOT/usr/local/bin/rust-junosmcp"
install -m 0644 devices-template.json "$PKGROOT/etc/jmcp/devices.json.example"
install -m 0644 packaging/systemd/rust-junosmcp.service "$PKGROOT/etc/systemd/system/rust-junosmcp.service"
install -m 0755 packaging/lxc/install.sh "$PKGROOT/install.sh"

mkdir -p "$OUTPUT_DIR"
tar -czf "$OUTPUT_DIR/$PKG.tar.gz" -C "$STAGING" "$PKG"
echo ">> Wrote $OUTPUT_DIR/$PKG.tar.gz"
