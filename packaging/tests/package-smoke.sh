#!/usr/bin/env bash
set -euo pipefail

ARCHIVE="${1:?usage: package-smoke.sh <package.tar.gz>}"
[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/extract"
tar -xzf "$ARCHIVE" -C "$WORK/extract"
mapfile -t package_roots < <(find "$WORK/extract" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#package_roots[@]}" -eq 1 ]] || { echo "archive must contain one package root" >&2; exit 1; }
PACKAGE_ROOT="${package_roots[0]}"

for relative in \
    install.sh \
    usr/local/bin/rust-junosmcp \
    usr/local/bin/rust-srxmcp \
    etc/jmcp/devices.json.example \
    etc/systemd/system/rust-junosmcp.service \
    etc/systemd/system/rust-srxmcp.service; do
    [[ -s "$PACKAGE_ROOT/$relative" ]] || { echo "missing package file: $relative" >&2; exit 1; }
done

# A corrupt package must fail before creating any target state.
cp -a "$PACKAGE_ROOT" "$WORK/bad-package"
rm "$WORK/bad-package/usr/local/bin/rust-srxmcp"
if JMCP_INSTALL_ROOT="$WORK/bad-root" \
    JMCP_INSTALL_SKIP_USER=1 \
    JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    "$WORK/bad-package/install.sh" >/dev/null 2>&1; then
    echo "installer accepted a package with a missing binary" >&2
    exit 1
fi
[[ ! -e "$WORK/bad-root" ]] || { echo "failed preflight changed target state" >&2; exit 1; }

ROOTFS="$WORK/rootfs"
run_installer() {
    JMCP_INSTALL_ROOT="$ROOTFS" \
        JMCP_INSTALL_SKIP_USER=1 \
        JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
        "$PACKAGE_ROOT/install.sh" >/dev/null
}

run_installer
printf '%s\n' '{"preserved":"devices"}' >"$ROOTFS/etc/jmcp/devices.json"
printf '%s\n' '{ "version": 1, "tokens": [] }' >"$ROOTFS/etc/jmcp/tokens.json"
printf '%s\n' 'preserved-known-host' >"$ROOTFS/etc/jmcp/known_hosts"
devices_before="$(sha256sum "$ROOTFS/etc/jmcp/devices.json")"
tokens_before="$(sha256sum "$ROOTFS/etc/jmcp/tokens.json")"
known_hosts_before="$(sha256sum "$ROOTFS/etc/jmcp/known_hosts")"
run_installer
[[ "$devices_before" == "$(sha256sum "$ROOTFS/etc/jmcp/devices.json")" ]]
[[ "$tokens_before" == "$(sha256sum "$ROOTFS/etc/jmcp/tokens.json")" ]]
[[ "$known_hosts_before" == "$(sha256sum "$ROOTFS/etc/jmcp/known_hosts")" ]]

[[ "$(stat -c '%a' "$ROOTFS/usr/local/bin/rust-junosmcp")" == "755" ]]
[[ "$(stat -c '%a' "$ROOTFS/etc/jmcp/devices.json")" == "600" ]]
[[ "$(stat -c '%a' "$ROOTFS/etc/jmcp/tokens.json")" == "600" ]]
[[ -d "$ROOTFS/var/lib/jmcp/staging" ]]
[[ -d "$ROOTFS/var/lib/jmcp/srx-staging/bundles" ]]

JUNOS_UNIT="$ROOTFS/etc/systemd/system/rust-junosmcp.service"
SRX_UNIT="$ROOTFS/etc/systemd/system/rust-srxmcp.service"
grep -Fq -- '--transport streamable-http' "$JUNOS_UNIT"
grep -Fq -- '--tokens-file /etc/jmcp/tokens.json' "$JUNOS_UNIT"
grep -Fq -- '--host 127.0.0.1' "$JUNOS_UNIT"
grep -Fq 'JMCP_SRX_STAGING_DIR=/var/lib/jmcp/srx-staging/bundles' "$SRX_UNIT"
printf '%s\n' 'jmcp:x:998:998:RustJunosMCP:/var/lib/jmcp:/usr/sbin/nologin' >"$ROOTFS/etc/passwd"
printf '%s\n' 'jmcp:x:998:' >"$ROOTFS/etc/group"
systemd-analyze verify --recursive-errors=no --root="$ROOTFS" \
    rust-junosmcp.service rust-srxmcp.service

# Start the installed binary and perform an authenticated MCP initialize.
cat >"$ROOTFS/etc/jmcp/devices.json" <<'JSON'
{
  "smoke": {
    "ip": "192.0.2.1",
    "username": "smoke",
    "auth": {"type": "password", "password": "unused"}
  }
}
JSON
SECRET="$("$ROOTFS/usr/local/bin/rust-junosmcp" token add \
    --tokens-file "$ROOTFS/etc/jmcp/tokens.json" \
    --name packaging-smoke \
    --routers '*' \
    --tools '*')"
PORT="${JMCP_PACKAGE_SMOKE_PORT:-39030}"
"$ROOTFS/usr/local/bin/rust-junosmcp" \
    --device-mapping "$ROOTFS/etc/jmcp/devices.json" \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port "$PORT" \
    --tokens-file "$ROOTFS/etc/jmcp/tokens.json" \
    --inventory-readonly \
    >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl -sS -o /dev/null "http://127.0.0.1:$PORT/mcp" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ "$ready" != "1" ]]; then
    cat "$WORK/server.log" >&2
    echo "MCP endpoint did not become ready" >&2
    exit 1
fi

HTTP_STATUS="$(curl -sS \
    -D "$WORK/headers" \
    -o "$WORK/body" \
    -w '%{http_code}' \
    -H "Authorization: Bearer $SECRET" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"package-smoke","version":"1"}}}' \
    "http://127.0.0.1:$PORT/mcp")"
if [[ "$HTTP_STATUS" != "200" ]] || ! grep -Fq '"result"' "$WORK/body"; then
    cat "$WORK/server.log" >&2
    cat "$WORK/body" >&2
    echo "MCP initialize failed with HTTP $HTTP_STATUS" >&2
    exit 1
fi

echo ">> Package layout, idempotence, units, and MCP endpoint passed"
