#!/usr/bin/env bash
# Installer for the extracted RustJunosMCP LXC package.
set -euo pipefail

PACKAGE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_ROOT="${JMCP_INSTALL_ROOT:-/}"
SERVICE_USER="${JMCP_SERVICE_USER:-jmcp}"
SERVICE_GROUP="${JMCP_SERVICE_GROUP:-jmcp}"
SKIP_USER_SETUP="${JMCP_INSTALL_SKIP_USER:-0}"
SKIP_SYSTEMD_RELOAD="${JMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}"

fail() {
    echo ">> Installation refused: $*" >&2
    exit 1
}

target_path() {
    local relative="${1#/}"
    if [[ "$INSTALL_ROOT" == "/" ]]; then
        printf '/%s\n' "$relative"
    else
        printf '%s/%s\n' "${INSTALL_ROOT%/}" "$relative"
    fi
}

required_files=(
    usr/local/bin/rust-junosmcp
    etc/jmcp/devices.json.example
    etc/systemd/system/rust-junosmcp.service
)

# Validate the complete payload before creating users, directories, or files.
for relative in "${required_files[@]}"; do
    [[ -s "$PACKAGE_ROOT/$relative" ]] || fail "package payload is missing $relative"
done
[[ -x "$PACKAGE_ROOT/usr/local/bin/rust-junosmcp" ]] \
    || fail "package binary is not executable: usr/local/bin/rust-junosmcp"

[[ "$INSTALL_ROOT" == /* ]] || fail "JMCP_INSTALL_ROOT must be an absolute path"
if [[ "$INSTALL_ROOT" != "/" && "$SKIP_USER_SETUP" != "1" ]]; then
    fail "a staged install requires JMCP_INSTALL_SKIP_USER=1"
fi
if [[ "$SKIP_USER_SETUP" != "1" && "$EUID" -ne 0 ]]; then
    fail "run as root, or use JMCP_INSTALL_SKIP_USER=1 for a staged smoke test"
fi

if [[ "$SKIP_USER_SETUP" != "1" ]] && ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
fi
if [[ "$SKIP_USER_SETUP" != "1" ]] && ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --create-home --home-dir /var/lib/jmcp \
        --shell /usr/sbin/nologin "$SERVICE_USER"
fi

BIN_DIR="$(target_path /usr/local/bin)"
CONFIG_DIR="$(target_path /etc/jmcp)"
UNIT_DIR="$(target_path /etc/systemd/system)"
STATE_DIR="$(target_path /var/lib/jmcp)"
JUNOS_STAGING_DIR="$STATE_DIR/staging"
SRX_STAGING_DIR="$STATE_DIR/srx-staging/bundles"
DEVICE_LEASE_DIR="$STATE_DIR/device-leases"

remove_legacy_runtime() {
    local legacy_binary legacy_unit
    legacy_binary="$(target_path /usr/local/bin/rust-srxmcp)"
    legacy_unit="$(target_path /etc/systemd/system/rust-srxmcp.service)"

    if [[ "$INSTALL_ROOT" == "/" && -e "$legacy_unit" ]]; then
        command -v systemctl >/dev/null 2>&1 \
            || fail "systemctl is required to retire rust-srxmcp.service"
        if systemctl is-active --quiet rust-srxmcp.service; then
            systemctl stop rust-srxmcp.service
        fi
        systemctl disable rust-srxmcp.service >/dev/null
    fi

    rm -f "$legacy_binary" "$legacy_unit"
}

install -d -m 0755 "$BIN_DIR" "$UNIT_DIR"
install -d -m 0750 "$CONFIG_DIR" "$STATE_DIR" "$JUNOS_STAGING_DIR" "$SRX_STAGING_DIR"
install -d -m 0700 "$DEVICE_LEASE_DIR"

remove_legacy_runtime

install -m 0755 "$PACKAGE_ROOT/usr/local/bin/rust-junosmcp" "$BIN_DIR/rust-junosmcp"
install -m 0644 "$PACKAGE_ROOT/etc/jmcp/devices.json.example" "$CONFIG_DIR/devices.json.example"
install -m 0644 "$PACKAGE_ROOT/etc/systemd/system/rust-junosmcp.service" "$UNIT_DIR/rust-junosmcp.service"

if [[ ! -e "$CONFIG_DIR/devices.json" ]]; then
    install -m 0600 "$PACKAGE_ROOT/etc/jmcp/devices.json.example" "$CONFIG_DIR/devices.json"
fi
if [[ ! -e "$CONFIG_DIR/tokens.json" ]]; then
    printf '%s\n' '{"version":1,"tokens":[]}' >"$CONFIG_DIR/tokens.json"
fi
if [[ ! -e "$CONFIG_DIR/known_hosts" ]]; then
    : >"$CONFIG_DIR/known_hosts"
fi
chmod 0600 "$CONFIG_DIR/devices.json" "$CONFIG_DIR/tokens.json"
chmod 0644 "$CONFIG_DIR/known_hosts"

if [[ "$SKIP_USER_SETUP" != "1" ]]; then
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    chown "$SERVICE_USER:$SERVICE_GROUP" \
        "$CONFIG_DIR/devices.json" \
        "$CONFIG_DIR/tokens.json" \
        "$CONFIG_DIR/known_hosts"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"
fi

if [[ "$INSTALL_ROOT" == "/" && "$SKIP_SYSTEMD_RELOAD" != "1" ]]; then
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for a live install"
    systemctl daemon-reload
fi

echo ">> RustJunosMCP package installed."
echo ">> Edit $CONFIG_DIR/devices.json and mint a bearer token before enabling the service."
echo ">> Junos/SRX endpoint: http://127.0.0.1:30030/mcp"
