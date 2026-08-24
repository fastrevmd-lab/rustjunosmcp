#!/usr/bin/env bash
# The installer must never create an empty token store at the new /var/lib path
# while a live one still exists at the legacy /etc path.
#
# The runtime prefers an existing primary, so an empty file there shadows the
# live tokens: the service starts and rejects every existing bearer token. A
# silent auth wipe on upgrade is worse than a refusal to start.
set -euo pipefail

ARCHIVE="${1:?usage: token-migration-guard.sh <package.tar.gz>}"
[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/extract"
tar -xzf "$ARCHIVE" -C "$WORK/extract"
mapfile -t roots < <(find "$WORK/extract" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#roots[@]}" -eq 1 ]] || { echo "archive must contain one package root" >&2; exit 1; }
PACKAGE_ROOT="${roots[0]}"

run_install() {
    JMCP_INSTALL_ROOT="$1" \
        JMCP_INSTALL_SKIP_USER=1 \
        JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
        "$PACKAGE_ROOT/install.sh" >"$2" 2>&1
}

# --- Case 1: upgrade with live tokens still at the legacy /etc path.
UPGRADE="$WORK/upgrade"
mkdir -p "$UPGRADE/etc/jmcp"
printf '%s\n' '{"version":1,"tokens":[{"name":"live-token"}]}' >"$UPGRADE/etc/jmcp/tokens.json"

run_install "$UPGRADE" "$WORK/upgrade.log"

if [[ -e "$UPGRADE/var/lib/jmcp/tokens.json" ]]; then
    echo "FAIL: installer created an empty primary store while a legacy store exists" >&2
    echo "      this shadows the live tokens and rejects every existing client" >&2
    exit 1
fi

if ! grep -q 'Not creating' "$WORK/upgrade.log"; then
    echo "FAIL: installer did not explain why it skipped creating the primary store" >&2
    sed -n '1,20p' "$WORK/upgrade.log" >&2
    exit 1
fi

if ! grep -q 'live-token' "$UPGRADE/etc/jmcp/tokens.json"; then
    echo "FAIL: the legacy token store was modified" >&2
    exit 1
fi

# --- Case 2: fresh install with no legacy store — an empty primary IS correct.
FRESH="$WORK/fresh"
mkdir -p "$FRESH"
run_install "$FRESH" "$WORK/fresh.log"

if [[ ! -e "$FRESH/var/lib/jmcp/tokens.json" ]]; then
    echo "FAIL: fresh install did not create the primary token store" >&2
    exit 1
fi

if ! grep -q '"tokens":\[\]' "$FRESH/var/lib/jmcp/tokens.json"; then
    echo "FAIL: fresh install did not write an empty token store" >&2
    exit 1
fi

echo ">> token migration guard test passed"
