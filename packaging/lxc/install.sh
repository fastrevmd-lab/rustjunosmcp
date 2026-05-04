#!/usr/bin/env bash
# Post-extract installer for rust-junosmcp tarball deployment.
# Run inside the target LXC after `tar xzf` extracts files to /.
set -euo pipefail

# Create service user if missing.
if ! id -u jmcp >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/jmcp \
            --shell /usr/sbin/nologin jmcp
fi

mkdir -p /etc/jmcp /var/lib/jmcp
chown -R jmcp:jmcp /var/lib/jmcp
chmod 755 /usr/local/bin/rust-junosmcp

# Only install example if no real devices.json yet.
if [[ ! -f /etc/jmcp/devices.json ]]; then
    cp -n /etc/jmcp/devices.json.example /etc/jmcp/devices.json || true
    chmod 600 /etc/jmcp/devices.json
    chown jmcp:jmcp /etc/jmcp/devices.json
    echo ">> Edit /etc/jmcp/devices.json with your real devices, then:"
    echo ">>   systemctl daemon-reload && systemctl enable --now rust-junosmcp"
fi

systemctl daemon-reload || true
echo ">> rust-junosmcp installed. Service unit: rust-junosmcp.service"
