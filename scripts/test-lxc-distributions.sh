#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCHIVE="${1:?usage: test-lxc-distributions.sh <package.tar.gz>}"
ARCHIVE="$(realpath "$ARCHIVE")"
SMOKE_SCRIPT="$ROOT/packaging/tests/distribution-smoke.sh"

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

for image in debian:12-slim ubuntu:24.04; do
    echo ">> Testing $image"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "$ARCHIVE:/tmp/jmcp-package.tar.gz:ro" \
        -v "$SMOKE_SCRIPT:/tmp/distribution-smoke.sh:ro" \
        "$image" \
        bash -c 'apt-get update >/dev/null && apt-get install -y --no-install-recommends passwd systemd >/dev/null && bash /tmp/distribution-smoke.sh'
done
