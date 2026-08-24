#!/usr/bin/env bash
# Packaging test: assert no unnumbered journald drop-ins.
#
# An unnumbered /etc/systemd/journald.conf.d/retention.conf sorts after
# numbered drop-ins like 20-audit-retention.conf and silently overrides them.
# This test asserts that install.sh cleans up any stale unnumbered drop-ins
# and does not create new ones.
set -euo pipefail

WORK="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

ROOTFS="$WORK/rootfs"
mkdir -p "$ROOTFS/etc/systemd/journald.conf.d"

# Simulate stale unnumbered drop-ins from a previous install or manual edit.
printf '%s\n' '[Journal]' >"$ROOTFS/etc/systemd/journald.conf.d/retention.conf"
printf '%s\n' 'MaxRetentionSec=30day' >>"$ROOTFS/etc/systemd/journald.conf.d/retention.conf"

printf '%s\n' '[Journal]' >"$ROOTFS/etc/systemd/journald.conf.d/jmcp.conf"
printf '%s\n' 'SystemMaxUse=128M' >>"$ROOTFS/etc/systemd/journald.conf.d/jmcp.conf"

# Simulate the numbered fleet policy drop-ins that should win.
printf '%s\n' '[Journal]' >"$ROOTFS/etc/systemd/journald.conf.d/10-audit-sealing.conf"
printf '%s\n' 'Storage=persistent' >>"$ROOTFS/etc/systemd/journald.conf.d/10-audit-sealing.conf"
printf '%s\n' 'Seal=yes' >>"$ROOTFS/etc/systemd/journald.conf.d/10-audit-sealing.conf"

printf '%s\n' '[Journal]' >"$ROOTFS/etc/systemd/journald.conf.d/20-audit-retention.conf"
printf '%s\n' 'SystemMaxUse=512M' >>"$ROOTFS/etc/systemd/journald.conf.d/20-audit-retention.conf"
printf '%s\n' 'MaxRetentionSec=90day' >>"$ROOTFS/etc/systemd/journald.conf.d/20-audit-retention.conf"

# Build a minimal package to run install.sh.
ARCHIVE="${1:?usage: journald-dropin-ordering.sh <package.tar.gz>}"
[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }

mkdir -p "$WORK/extract"
tar -xzf "$ARCHIVE" -C "$WORK/extract"
mapfile -t package_roots < <(find "$WORK/extract" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#package_roots[@]}" -eq 1 ]] || { echo "archive must contain one package root" >&2; exit 1; }
PACKAGE_ROOT="${package_roots[0]}"

# Run the installer against the rootfs with stale drop-ins.
JMCP_INSTALL_ROOT="$ROOTFS" \
    JMCP_INSTALL_SKIP_USER=1 \
    JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    "$PACKAGE_ROOT/install.sh" >/dev/null

# Assert that the unnumbered drop-ins are gone.
if [[ -e "$ROOTFS/etc/systemd/journald.conf.d/retention.conf" ]]; then
    echo "FAIL: unnumbered retention.conf still exists after install" >&2
    exit 1
fi

if [[ -e "$ROOTFS/etc/systemd/journald.conf.d/jmcp.conf" ]]; then
    echo "FAIL: unnumbered jmcp.conf still exists after install" >&2
    exit 1
fi

# Assert that the numbered drop-ins are preserved (the installer did not touch them).
[[ -f "$ROOTFS/etc/systemd/journald.conf.d/10-audit-sealing.conf" ]] || {
    echo "FAIL: numbered drop-in 10-audit-sealing.conf was removed" >&2
    exit 1
}

[[ -f "$ROOTFS/etc/systemd/journald.conf.d/20-audit-retention.conf" ]] || {
    echo "FAIL: numbered drop-in 20-audit-retention.conf was removed" >&2
    exit 1
}

# Assert that systemd would parse them in the correct order.
# Numbered drop-ins sort before unnumbered ones, so 10-*.conf and 20-*.conf
# should be the only drop-ins present after install.
# mapfile, not $( ) word-splitting: the packaging job runs shellcheck over
# packaging/tests/*.sh and SC2207 makes it exit 1 before this test ever runs.
mapfile -t dropins < <(find "$ROOTFS/etc/systemd/journald.conf.d" -name '*.conf' -type f -printf '%f\n' | sort)
expected=("10-audit-sealing.conf" "20-audit-retention.conf")

if [[ "${dropins[*]}" != "${expected[*]}" ]]; then
    echo "FAIL: drop-in ordering is wrong" >&2
    echo "Expected: ${expected[*]}" >&2
    echo "Got:      ${dropins[*]}" >&2
    exit 1
fi

echo ">> journald drop-in ordering test passed"
