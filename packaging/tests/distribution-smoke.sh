#!/usr/bin/env bash
set -euo pipefail

ARCHIVE="${1:-/tmp/jmcp-package.tar.gz}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

tar -xzf "$ARCHIVE" -C "$WORK"
mapfile -t package_roots < <(find "$WORK" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#package_roots[@]}" -eq 1 ]]
PACKAGE_ROOT="${package_roots[0]}"

run_installer() {
    JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 "$PACKAGE_ROOT/install.sh" >/dev/null
}

run_installer
printf '%s\n' '{"preserved":"devices"}' >/etc/jmcp/devices.json
printf '%s\n' '{ "version": 1, "tokens": [] }' >/etc/jmcp/tokens.json
printf '%s\n' 'preserved-known-host' >/etc/jmcp/known_hosts
devices_before="$(sha256sum /etc/jmcp/devices.json)"
tokens_before="$(sha256sum /etc/jmcp/tokens.json)"
known_hosts_before="$(sha256sum /etc/jmcp/known_hosts)"
run_installer

[[ "$devices_before" == "$(sha256sum /etc/jmcp/devices.json)" ]]
[[ "$tokens_before" == "$(sha256sum /etc/jmcp/tokens.json)" ]]
[[ "$known_hosts_before" == "$(sha256sum /etc/jmcp/known_hosts)" ]]
[[ "$(stat -c '%U:%G' /etc/jmcp)" == "jmcp:jmcp" ]]
[[ "$(stat -c '%U:%G' /var/lib/jmcp/srx-staging/bundles)" == "jmcp:jmcp" ]]
[[ "$(stat -c '%a' /etc/jmcp/devices.json)" == "600" ]]
[[ "$(stat -c '%a' /etc/jmcp/tokens.json)" == "600" ]]
systemd-analyze verify \
    /etc/systemd/system/rust-junosmcp.service \
    /etc/systemd/system/rust-srxmcp.service

distribution="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
echo ">> Distribution install passed on $distribution"
