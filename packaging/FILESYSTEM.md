# Filesystem layout

## Directory naming exception (#335)

Junos is the naming outlier in the mecmcp server fleet. Every other server names
its directories after its binary; junos uses `jmcp`.

| Server | service dir | config dir        | state dir           |
|--------|-------------|-------------------|---------------------|
| junos  | `jmcp`      | `/etc/jmcp`       | `/var/lib/jmcp`     |
| panos  | `rust-panosmcp` | `/etc/rust-panosmcp` | `/var/lib/rust-panosmcp` |
| sdc    | `rustsdcmcp`    | `/etc/rustsdcmcp`    | `/var/lib/rustsdcmcp`    |
| mist   | `rustmistmcp`   | `/etc/rustmistmcp`   | `/var/lib/rustmistmcp`   |

This is a **permanent documented exception** to the fleet's full-binary-name
convention. Renaming would touch the unit, installer, site overrides on live
guests (950/610/611), token and inventory paths, audit paths, documentation, and
the MCP registry, with a live client-lockout failure mode, for a cosmetic gain.
The tax is this documentation; the migration risk lands on production guests
tagged `protected`. Decision: keep `jmcp`. (Issue #335)

The same split runs through everything junos-specific: the service user is
`jmcp`, `StateDirectory=jmcp`, and the env vars are `JMCP_*`.

## File locations

### Configuration (read-only to the service)

- `/etc/jmcp/devices.json` — inventory, hand-edited or managed via `add_device`
  when `--inventory-readonly` is not set
- `/etc/jmcp/known_hosts` — SSH host keys for scp transfers

`ProtectSystem=strict` makes `/etc` read-only to the service process, so runtime
state that the server must write lives in `/var/lib/jmcp` instead.

### Runtime state (writable by the service)

- `/var/lib/jmcp/tokens.json` — bearer tokens (moved from `/etc/jmcp` in v0.22.0, #333)
- `/var/lib/jmcp/audit-hmac.key` — HMAC key for tamper-evident audit log (added v0.22.0, #334)
- `/var/lib/jmcp/changeset-state.json` — two-person approval lifecycle state
- `/var/lib/jmcp/audit.jsonl` — JSON audit log (when configured via site override)
- `/var/lib/jmcp/device-leases/` — cross-process destructive-operation leases
- `/var/lib/jmcp/staging/` — staging directory for scp push (`transfer_file`)
- `/var/lib/jmcp/srx-staging/bundles/` — JTAC support bundle staging

### Migration from legacy token path

Versions prior to v0.22.0 stored `tokens.json` in `/etc/jmcp`. The runtime
prefers `/var/lib/jmcp/tokens.json` and falls back to `/etc/jmcp/tokens.json`
when the new path is absent, logging a migration warning.

The installer creates the new path but **never copies** the old file — a stale
token file left behind in `/etc` is a stale secret on disk. When the warning
appears, the operator must:

1. Verify the new file exists and is owned by the service user: `ls -l /var/lib/jmcp/tokens.json`
2. Mint a token in the new location if needed: `rust-junosmcp token add <name>`
3. Securely delete the stale copy: `shred -u /etc/jmcp/tokens.json`

Do not symlink `/etc/jmcp/tokens.json` to `/var/lib/jmcp/tokens.json` — that
defeats the hardening goal and hands the service write access to `/etc` via the
link target.
