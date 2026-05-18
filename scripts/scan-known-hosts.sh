#!/usr/bin/env bash
# scan-known-hosts.sh — pre-populate the known_hosts file used by rust-junosmcp's
# transfer_file / upgrade_junos tools.
#
# As of v0.5.2, the server defaults to StrictHostKeyChecking=yes (RJMCP-SEC-004).
# That means scp will refuse to push to any device whose host key isn't already
# pinned in `--known-hosts-file` (default `/etc/jmcp/known_hosts`). This script
# enumerates `(ip, port)` pairs from a `devices.json` inventory and runs
# `ssh-keyscan` against each, writing the results atomically so a partial scan
# can't corrupt an existing file.
#
# Usage:
#   scan-known-hosts.sh [--inventory PATH] [--known-hosts PATH] [--append | --replace]
#
# Notes:
#   - Requires `jq` and `ssh-keyscan`.
#   - Refuses to clobber an existing known_hosts unless `--append` or
#     `--replace` is supplied.
#   - Run with the same uid that the server process uses, so the file is
#     readable at runtime.

set -euo pipefail

INVENTORY="/etc/jmcp/devices.json"
KNOWN_HOSTS="/etc/jmcp/known_hosts"
MODE=""

usage() {
  sed -n '2,22p' "$0"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory)    INVENTORY="$2"; shift 2 ;;
    --known-hosts)  KNOWN_HOSTS="$2"; shift 2 ;;
    --append)       MODE="append"; shift ;;
    --replace)      MODE="replace"; shift ;;
    -h|--help)      usage ;;
    *)              echo "unknown arg: $1" >&2; usage ;;
  esac
done

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
command -v ssh-keyscan >/dev/null || { echo "ssh-keyscan is required" >&2; exit 2; }

if [[ ! -r "$INVENTORY" ]]; then
  echo "inventory not readable: $INVENTORY" >&2
  exit 2
fi

if [[ -e "$KNOWN_HOSTS" && -z "$MODE" ]]; then
  echo "known_hosts already exists: $KNOWN_HOSTS" >&2
  echo "pass --append to add to it, or --replace to overwrite it" >&2
  exit 2
fi

TMP="$(mktemp "${KNOWN_HOSTS}.scan.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

# Extract (ip, port) — ignore `_blocklist_defaults` and any non-object entry.
mapfile -t TARGETS < <(jq -r '
  to_entries[]
  | select(.key != "_blocklist_defaults")
  | select(.value | type == "object")
  | "\(.value.ip) \(.value.port // 22)"
' "$INVENTORY")

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  echo "no devices found in $INVENTORY" >&2
  exit 1
fi

added=0
for entry in "${TARGETS[@]}"; do
  read -r host port <<<"$entry"
  echo "scanning $host (port $port)..." >&2
  if ssh-keyscan -T 5 -p "$port" "$host" >>"$TMP" 2>/dev/null; then
    added=$((added + 1))
  else
    echo "  WARNING: ssh-keyscan failed for $host:$port (skipping)" >&2
  fi
done

if [[ $added -eq 0 ]]; then
  echo "no host keys collected; not touching $KNOWN_HOSTS" >&2
  exit 1
fi

case "$MODE" in
  append)
    cat "$TMP" >>"$KNOWN_HOSTS"
    echo "appended $added host key entries to $KNOWN_HOSTS" >&2
    ;;
  replace|"")
    # Empty MODE only reachable when KNOWN_HOSTS didn't exist; in that case
    # we simply atomically install the new file.
    mv "$TMP" "$KNOWN_HOSTS"
    trap - EXIT
    echo "wrote $added host key entries to $KNOWN_HOSTS" >&2
    ;;
esac
