<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-junosmcp</h1>

<p align="center"><strong>MCP server for Juniper Junos devices, in Rust</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This repository is an independent, community-driven project. It is not affiliated with, endorsed by, sponsored by, or supported by Hewlett Packard Enterprise or Juniper Networks. "HPE", "Juniper", "SRX", "JUNOS", "Security Director" and "Juniper Mist" are trademarks of their respective owners and are used here only to describe what this software interoperates with. Please direct support and licensing questions about those products to the respective vendors.

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper Junos
devices, written in Rust. Drop-in compatible with [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
on the inventory format and tool surface, but built on async Rust ([rustEZ](https://github.com/fastrevmd-lab/rustEZ) + [rustnetconf](https://github.com/fastrevmd-lab/rustnetconf))
instead of PyEZ.

## Beyond Juniper/junos-mcp-server

Drop-in on `devices.json` and the core tools — plus a lot the Python/PyEZ server doesn't have:

- **Safer config** — `commit_check_config` (validate, never commit), confirmed commits with auto-rollback, and `discard_candidate` to unstick a dirty candidate.
- **Device lifecycle** — staged `upgrade_junos` (image → install → reboot → verify), SCP `transfer_file`/`fetch_file`, PFE commands.
- **Scale & UX** — parallel session-pooled batch (~1.7× faster), `| last N`/`| count` + `max_lines`/`max_bytes` output caps, `router`/`router_name` aliases, Jinja2 templates.
- **Transport & auth** — streamable-HTTP with per-token router/tool scopes, TLS, and a `Host` allowlist; upstream is stdio-only.
- **SRX tools** (`rust-srxmcp`) — IDP & Application-ID **signature-package updates** (check/download/install/rollback), chassis-cluster health, license & security-services status, JTAC bundle with secret redaction.

## Performance

Benchmarked against [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
(Python/PyEZ) on the same vSRX lab devices, same network path.

| Test | rust-junosmcp (v0.3.0) | junos-mcp (Python) | Speedup |
|------|------------------------|--------------------|---------|
| 5 sequential commands | 30.4s (6.1s/cmd) | 52.2s (10.4s/cmd) | **1.7x** |
| 5 parallel commands | 8.1s (1.6s/cmd) | 11.1s (2.2s/cmd) | **1.4x** |
| 4 routers x 3 commands (batch) | 16.1s (1.3s/cmd) | N/A | Rust-only |

Session pooling (`PooledDevice`) eliminates SSH/NETCONF handshake overhead
on sequential commands to the same router. The batch tool runs routers in
parallel with a configurable concurrency cap.

> ## v0.7.0 released
>
> Two new non-destructive candidate-safety tools and a hardened HTTP
> transport. `commit_check_config` validates a candidate (`commit check`)
> and discards it without ever activating config; `discard_candidate`
> recovers a candidate left dirty via `rollback 0`. `junos_config_diff`
> now returns an actionable hint when the on-box config won't parse for
> the current mode. Security: `rmcp` 0.8.5 → 2.0.0 (closes
> RUSTSEC-2026-0189 DNS-rebinding; adds a `Host` allowlist — off-loopback
> deployments must pass `--allowed-host`) and `quick-xml` 0.36 → 0.41
> (closes RUSTSEC-2026-0194/-0195 DoS). Tool surface 15 → 17.
>
> See the [v0.7.0 release notes](https://github.com/fastrevmd-lab/rustjunosmcp/releases/tag/v0.7.0).

## Feature scope

### v0.1 (released)

- 6 tools: `get_router_list`, `gather_device_facts`, `execute_junos_command`,
  `get_junos_config`, `junos_config_diff`, `load_and_commit_config`.
- stdio transport only.
- `devices.json` drop-in compatible (`auth.type` ∈ {`password`, `ssh_key`}).
- Docker image (distroless) and LXC release tarball with systemd unit.

### v0.2 (released)

- streamable-http transport (with optional rustls TLS).
- bearer-token auth with per-token router/tool scopes.
- SIGHUP hot-reload of the token store.

### v0.2 follow-up: PFE + batch (released)

- `execute_junos_pfe_command` — single PFE-shell call against an explicit FPC target.
- `execute_junos_command_batch` — N routers x M operational CLI commands, parallel across routers, per-command and optional whole-batch timeouts. Pre-flight blocklist + unknown-router checks; continue-on-error after pre-flight.
- New `pfe_commands` rule list under `_blocklist_defaults` and per-device `blocklist`. Independent from `commands`.

### v0.2 follow-up: Templates (released)

- `render_and_apply_j2_template` — render a Jinja2 template (inline `template_content`) with a JSON `vars_content` object. Supports single (`router_name`) or multiple routers (`router_names`), dry-run, and full commit. Reuses the same blocklist + format gating as `load_and_commit_config`.
- Vars must be a top-level JSON object. **YAML is no longer accepted** as of v0.5.2 (RJMCP-SEC-002): the `serde_yml` / `libyml` advisory chain (RUSTSEC-2025-0067/-0068) was reachable from MCP input, so the YAML branch was removed.
- Size caps: `template_content` and `vars_content` are each bounded at 64 KiB.
- Strict-undefined: missing variables fail with the variable name rather than rendering empty.
- Auto-format detection: leading `<` → `xml`, any `set ` / `delete ` line → `set`, otherwise `text`. Override via `config_format`.
- Result shape: one row per router with `rendered_template`, `config_format`, and either `diff` (dry-run), `commit_comment` (apply-mode echo of the supplied comment — rustez does not return a server-issued commit id), or `error`.

### v0.2 follow-up: Inventory mutation (released)

- `add_device` — add a Junos device to the in-memory inventory and persist to `devices.json`. Atomic write (tempfile + rename), preserves `_blocklist_defaults`, per-device `blocklist`, and other top-level fields. SHA-256-based TOCTOU guard rejects calls that race with external edits.
- `reload_devices` — re-read the current `--device-mapping` (no args) or swap to a new inventory file (`file_name`). Reports added / removed / changed device names.
- New CLI flags: `--inventory-readonly` (rejects both tools unconditionally), `--allow-password-auth-add` (permits `auth.type=password` in `add_device`; mutually exclusive with `--inventory-readonly`).
- SIGHUP now also re-reads the inventory in addition to the token store.

**Documented sharp edge:** `add_device` does not modify the token store. If a token has `--routers 'edge-*'` and you `add_device` for `core-3`, the existing token will not see the new router. Mint a new token or rotate scopes after `add_device`.

### v0.3 (released)

- **NETCONF session pooling** — `PooledDevice` RAII guard with per-router single-slot pool (300s idle timeout, 30s SSH keepalive, background reaper). Eliminates SSH handshake overhead on sequential commands.
- **Tool reliability fixes** — XML wrapper stripping for `get_junos_config` and `junos_config_diff`, corrected `show configuration | compare rollback N` command, timeout now covers SSH connect + NETCONF handshake (not just CLI execution).
- **Batch partial results** — `execute_junos_command_batch` returns inline error rows for unknown routers instead of aborting the entire batch. Blocklist violations remain strict.
- **Confirmed commits** — `load_and_commit_config` gains `confirm_timeout_mins` parameter for `commit confirmed N` with auto-rollback safety net.
- **crates.io dependency** — `rustez` switched from path dep to crates.io 0.10.1; CI no longer requires sibling repo checkout.

### v0.4 (released)

- **`transfer_file`** — idempotent SCP push (`scp -O`, since Junos disables OpenSSH SFTP) of a host-staged file to `/var/tmp/<basename>` on a Junos device. Pre-flight free-space check on `/var` (`local_size + 32 MiB` headroom), SHA-256 verify, post-transfer checksum re-validation with delete-on-mismatch. SSH-key auth only — password-auth devices rejected with `[code=unsupported_auth]`.
- **`list_staged_files`** — lists host staging dir always, plus device `/var/tmp/` listing when `router_name` is supplied.
- **Stable error codes** — every transfer failure carries an LLM-readable `[code=...]` Display tag (`bad_source_path`, `insufficient_disk`, `unsupported_auth`, `dest_exists_differs`, `scp_failed`, `connect_timeout`, `verify_mismatch`, `outer_timeout`, `device_probe_failed`).
- **New CLI flags** — `--staging-dir` (default `/var/lib/jmcp/staging`) and `--known-hosts-file` (default `/etc/jmcp/known_hosts`).
- **Packaging** — `install.sh` provisions the new on-disk surface owned by `jmcp:jmcp`. See the File transfers section below for details.
- Tool count: 11 → 13.

### v0.5 (released)

- **`upgrade_junos`** — two-call (stage then confirm) Junos software upgrade. Uploads the package via `transfer_file` semantics, runs `request system software add`, and reboots. Standalone-only; rejected if a session pool entry exists for the target router.
- Tool count: 13 → 14.

### v0.6 (released)

- **`fetch_file`** — downloads a file from `<device>:/var/tmp/<basename>` to the host staging dir. SHA-256-verified, idempotent skip if the local copy already matches, per-router serialization. Mirror of `transfer_file`.
- Tool count: 14 → 15.

### v0.7 (released)

- **`commit_check_config`** — validate a candidate config (`commit check`) without committing — loads, diffs, checks, then discards. Never activates config. Own token scope (least-privilege).
- **`discard_candidate`** — discard uncommitted candidate changes (`rollback 0`) to recover a candidate left dirty ("configuration database modified"). Never changes the running config. Own token scope (least-privilege).
- Tool count: 15 → 17.

## Blocklist guardrails (v0.2)

`devices.json` may carry an optional `_blocklist_defaults` block plus an
optional `blocklist` field on each device entry. Rules use simple globs
(`*`, `?`) and an `action` of `"deny"` or `"allow"`. Most-specific match
wins; per-device rules tiebreak top-level defaults. See
[`devices-template.json`](devices-template.json) for an example, and
[`docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md`](docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md)
for the full design.

The `pfe_commands` rule list is independent: a deny on `commands` does not gate `execute_junos_pfe_command` and vice versa. Use it to restrict PFE inputs (e.g. `set *`) without affecting the operational CLI.

The blocklist applies to `execute_junos_command` and `load_and_commit_config`.
For `load_and_commit_config`, `config_format` must be `set` whenever the
device has any effective config rules; `text` and `xml` payloads are
rejected pre-flight in that case.

> **Compat note:** files using `_blocklist_defaults` or per-device
> `blocklist` are not cross-compatible with Juniper/junos-mcp-server's
> inventory format. Files without these fields remain drop-in compatible.

## Confirmed commits (v0.3)

`load_and_commit_config` supports Junos `commit confirmed` via the
`confirm_timeout_mins` parameter. The router auto-rolls back after N
minutes unless a follow-up commit confirms the change — a critical safety
net for remote config pushes that might break management connectivity.

```json
{
  "router_name": "core-1",
  "config_text": "set interfaces ge-0/0/0 description test",
  "confirm_timeout_mins": 10,
  "commit_comment": "safe change with rollback window"
}
```

Response:
```json
{
  "success": true,
  "diff": "[edit interfaces ge-0/0/0]\n+   description test;",
  "confirmed": true,
  "rollback_in_minutes": 10,
  "message": "Commit confirmed: auto-rollback in 10 minutes unless confirmed. Send another commit to confirm."
}
```

To confirm (prevent rollback), send another `load_and_commit_config` with
the same config (or any valid config) without `confirm_timeout_mins`.

## File transfers (`transfer_file` / `fetch_file` / `list_staged_files`)

`transfer_file` pushes a host-staged file to `/var/tmp/<basename>` on a Junos
device using legacy SCP (`scp -O`, since Junos disables the OpenSSH SFTP
subsystem). It is **idempotent on SHA-256**: if the remote file already exists
with a matching digest the call returns `status: "skipped"`. Pass `force: true`
to overwrite when digests differ.

`fetch_file` is the mirror operation: it downloads `/var/tmp/<basename>` from a
Junos device to the host staging dir using the same legacy SCP path. It is
**idempotent on SHA-256** — if the local file already exists with a matching
digest the call returns `status: "skipped"`. Per-router serialization and
post-transfer SHA-256 re-verification apply identically to `transfer_file`.

**Auth:** SSH key only. Devices with `auth.type = "password"` are rejected with
`[code=unsupported_auth]`. Add an SSH key to the device and reference its path
via `auth.private_key_path` in `devices.json`.

**On-disk surface:**

| Path                          | Purpose                                       | Default mode | Owner       |
| ----------------------------- | --------------------------------------------- | ------------ | ----------- |
| `/var/lib/jmcp/staging/`      | Host-side stage for files awaiting transfer  | `0750`       | `jmcp:jmcp` |
| `/etc/jmcp/known_hosts`       | SSH `known_hosts` consulted for every push    | `0644`       | `jmcp:jmcp` |
| `/var/lib/jmcp/device-leases` | Shared Junos/SRX destructive-operation locks | `0700`       | `jmcp:jmcp` |

Override at startup with `--staging-dir <path>`, `--known-hosts-file <path>`,
and `--device-lease-dir <path>`. Junos and SRX services must use the same
device lease directory.

**Host-key policy (v0.5.2+):** scp runs with `StrictHostKeyChecking=yes` by
default — unknown device host keys are refused. The `known_hosts` file must
exist before the first `transfer_file` / `upgrade_junos` call, otherwise the
tool errors with `[code=known_hosts_missing]`. Pre-populate it with the
bundled helper:

```bash
scripts/scan-known-hosts.sh --inventory /etc/jmcp/devices.json \
                            --known-hosts /etc/jmcp/known_hosts
```

For lab / first-contact use, pass `--ssh-accept-new-host-keys` to fall back
to OpenSSH's `accept-new` (TOFU) mode.

`list_staged_files` returns the contents of the host staging dir. If
`router_name` is supplied it also runs `file list /var/tmp/ detail` on the
device and includes those entries under `device_files`.

**Source path safety:** `source_path` must be a basename only (no `/`, no `\`,
no `..`, no leading dot, ≤ 255 bytes); it is resolved relative to
`--staging-dir` and never escapes it.

**Pre-flight checks:** before scp, `transfer_file` runs
`show system storage no-forwarding` and refuses to push when free space on
`/var` is below `local_size + 32 MiB`.

**Post-verify:** unless `verify: false` is passed, the device-side checksum is
re-computed via `file checksum sha-256 /var/tmp/<basename>` and the file is
deleted on mismatch.

## Long-running operational commands

Each MCP tool exposes a per-call `timeout` parameter (default 360 s). This is
the **sole user-visible bound** on operation duration; the underlying
`rustez::Device` is configured with a 1-hour internal RPC timeout at
connection time, so commands that legitimately take many minutes
(`request system software add`, `request support information`,
`request system snapshot`, etc.) will not be silently truncated.

If you need to run an operation that exceeds 1 hour, split it into
phases or invoke the work fire-and-forget on the device and poll for
completion separately.

**Caveat:** when a long-running RPC is followed by a device reboot, the
NETCONF session will of course die. The session pool reconnects cleanly
on the next call.

## Security warning

This server lets an LLM run commands and push configuration changes against
your Junos devices. Read [Juniper/junos-mcp-server's security notice](https://github.com/Juniper/junos-mcp-server#important-security-notice)
before deploying. The same warnings apply.

- Prefer SSH key authentication over passwords.
- Review configurations before allowing commit tools to run.
- Restrict network access to the MCP server.
- Don't deploy to untrusted networks.
- Set `devices.json` permissions to `0600` — it contains SSH credentials.
- `get_junos_config` returns the full config including `## SECRET-DATA`
  hashed password lines. Restrict this tool's scope to trusted tokens.
- `reload_devices` requires `file_name` to be a *relative* path resolving
  inside the original `--device-mapping` directory (since v0.5.2). Absolute
  paths, `..` traversal, and symlinks pointing outside the inventory
  directory are all rejected.
- Text input fields (`command`, `config_text`, `template_content`,
  `pfe_command`) are capped at 1 MB. Batch lists are capped at 100
  routers and 50 commands.

## Quick start (local)

```bash
git clone https://github.com/fastrevmd-lab/rustjunosmcp.git
cd RustJunosMCP

# Build (rustez pulled from crates.io automatically).
cargo build --release

# Configure devices.
cp devices-template.json devices.json
$EDITOR devices.json   # set ip / username / auth

# Run as MCP stdio server.
./target/release/rust-junosmcp -f devices.json
```

## Claude Desktop config

```json
{
  "mcpServers": {
    "junos": {
      "command": "/path/to/rust-junosmcp",
      "args": ["-f", "/path/to/devices.json"]
    }
  }
}
```

## Docker

Prebuilt images are published to GHCR on every version tag. The package is
public — no `docker login` required. The runtime includes OpenSSH `scp` with
legacy `-O` protocol support and runs as numeric UID/GID `65532:65532`.

Prepare read-only configuration/key mounts and one persistent writable state
directory. Private-key paths in `devices.json` must use their in-container
locations under `/etc/jmcp/keys`.

```bash
# Pull the prebuilt image (tags: latest, 0.7, 0.7.0).
docker pull ghcr.io/fastrevmd-lab/rust-junosmcp:latest

# Prepare host paths. Review scanned host-key fingerprints against a trusted
# source before starting the server in strict mode.
mkdir -p keys jmcp-state/staging jmcp-state/device-leases
touch jmcp-state/known_hosts
./scripts/scan-known-hosts.sh \
  --inventory "$PWD/devices.json" \
  --known-hosts "$PWD/jmcp-state/known_hosts" \
  --replace

# The image's non-root process must own its writable state and be able to read
# the inventory and private keys. Keep all three private from other host users.
sudo chown -R 65532:65532 devices.json keys jmcp-state
sudo chmod 0600 devices.json keys/* jmcp-state/known_hosts
sudo chmod 0700 keys jmcp-state jmcp-state/device-leases
sudo chmod 0750 jmcp-state/staging

# Run with configuration/keys read-only and state persistent + writable.
docker run --rm -i \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/jmcp-state:/var/lib/jmcp" \
  ghcr.io/fastrevmd-lab/rust-junosmcp:latest
```

The state mount holds staged upload/download files, the shared destructive
operation leases, and `known_hosts`. Do not delete its lease files while a
server is running. Strict host-key checking is the default. For an isolated lab
only, append `--ssh-accept-new-host-keys` to the `docker run` command; this lets
`scp` add first-seen keys to the writable state file, but does not authenticate
that first connection out of band.

Startup fails with `[code=scp_dependency_unavailable]` when the runtime cannot
execute an OpenSSH-compatible `scp -O`. That check occurs before the MCP server
accepts requests, so a broken custom image is not advertised as transfer-ready.

> **Apple Silicon (M-series):** images are built for `linux/amd64` only, so
> they run under emulation on Apple Silicon. This works, but if you hit a
> platform-mismatch warning add `--platform linux/amd64` to both the `pull`
> and `run` commands.

Prefer to build locally instead:

```bash
docker build -t rust-junosmcp:0.7 .

docker run --rm -i \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/jmcp-state:/var/lib/jmcp" \
  rust-junosmcp:0.7
```

## LXC (Proxmox)

```bash
# Build the tarball.
./scripts/package-lxc.sh

# Push and install on VM 115 (Debian 12 / Ubuntu 24.04 LXC). The
# installer copies both binaries and units from its extracted package root.
pct push 115 dist/rust-junosmcp_0.7.0_amd64.tar.gz /tmp/jmcp.tar.gz
pct exec 115 -- bash -c "tar xzf /tmp/jmcp.tar.gz -C /tmp && /tmp/rust-junosmcp_0.7.0_amd64/install.sh"

# Edit /etc/jmcp/devices.json, then mint the first bearer token. The command
# prints the one-time secret needed by MCP clients.
pct exec 115 -- runuser -u jmcp -- /usr/local/bin/rust-junosmcp token add \
  --tokens-file /etc/jmcp/tokens.json \
  --name ops \
  --routers '*' \
  --tools '*'

# Start the authenticated loopback HTTP endpoints. Enable either or both.
pct exec 115 -- systemctl enable --now rust-junosmcp rust-srxmcp
```

The installer is idempotent: rerunning it upgrades binaries and units without
overwriting `devices.json`, `tokens.json`, or `known_hosts`. It validates the
complete archive before changing system state. The packaged endpoints listen on
`127.0.0.1:30030/mcp` (Junos) and `127.0.0.1:30032/mcp` (SRX) and require bearer
authentication. Use an SSH tunnel or a TLS reverse proxy for remote clients.

## Remote transport + auth

### Mint a token

```bash
cargo run -- token add \
  --tokens-file tokens.json \
  --name ops \
  --routers '*' \
  --tools execute_junos_command,gather_device_facts
```

`get_router_list` applies the same router scope as device tools. Authenticated
allowlist tokens receive only the current inventory names in their scope;
stale scope entries and excluded routers are omitted without counts or errors.
An empty allowlist or empty intersection returns `[]`. Wildcard tokens, local
stdio, and explicitly unauthenticated loopback mode retain the full inventory.

> **Note:** See [`tokens-template.json`](tokens-template.json) for the file
> shape. Use `token add` rather than editing the file by hand — the hash field
> must be a SHA-256 of the secret, not the plaintext.

> **Run token subcommands as the service user.** When the systemd unit runs
> the server as a dedicated user (e.g. `User=jmcp` in the packaged unit), the
> file `token add`/`revoke`/`rotate` writes inherits the calling user's
> ownership. If you run them as `root`, the resulting `tokens.json` will be
> `root:root 0600` and the service user cannot read it — the server then
> crash-loops on startup with `Permission denied`. Either:
>
> ```bash
> # Preferred: run subcommands as the service user.
> sudo -u jmcp rust-junosmcp token add --tokens-file /etc/jmcp/tokens.json ...
>
> # Or fix ownership after running as root.
> rust-junosmcp token add --tokens-file /etc/jmcp/tokens.json ...
> chown jmcp:jmcp /etc/jmcp/tokens.json
> ```
>
> If the server hits this case on startup, the error message now reports the
> file's uid/mode and the caller's uid so the fix is obvious without trawling
> journald.

### Run with auth (streamable-http)

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 127.0.0.1 \
  -p 8765 \
  --tokens-file tokens.json
```

### Loopback escape hatch (no auth, local only)

```bash
cargo run -- --device-mapping devices.json --transport streamable-http \
  -H 127.0.0.1 -p 8765 --allow-no-auth
```

`--allow-no-auth` is refused if the bind address is not loopback.

### Non-loopback requires TLS

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 0.0.0.0 \
  -p 8765 \
  --tokens-file tokens.json \
  --tls-cert cert.pem \
  --tls-key key.pem
```

To bind off-loopback over plain HTTP (e.g., behind a TLS-terminating proxy on
the same host), add `--allow-insecure-bind`. This flag overrides the TLS
requirement and should be used with care — only when you have an external
guarantee of transport security.

### Host allowlist (DNS-rebinding guard)

The streamable-http transport validates the incoming `Host` header against an
allowlist (default: loopback only — `localhost`, `127.0.0.1`, `::1`). This
closes RUSTSEC-2026-0189 (DNS rebinding). Off-loopback clients must be
allowlisted with `--allowed-host <HOST>` (repeatable) or they are rejected
with HTTP 403, regardless of auth state:

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 0.0.0.0 \
  -p 8765 \
  --tokens-file tokens.json \
  --tls-cert cert.pem \
  --tls-key key.pem \
  --allowed-host jmcp.lab.internal
```

`--disable-host-check` turns the allowlist off entirely (accept any `Host`),
reintroducing the DNS-rebinding exposure; bearer auth still applies. Off by
default — only set this if you understand the tradeoff.

### Hot reload

After revoking or rotating a token, the server reloads the token store without
restarting. Pass `--server-pid <pid>` to any write subcommand and the SIGHUP
is sent automatically after the file is written:

```bash
# Revoke — writes file, then signals the server.
cargo run -- token revoke --tokens-file tokens.json --name ops --server-pid <pid>

# Rotate (mints a new secret, preserves scopes) — same pattern.
cargo run -- token rotate --tokens-file tokens.json --name ops --server-pid <pid>

# Add a new token and signal in one step.
cargo run -- token add \
  --tokens-file tokens.json \
  --name ops2 \
  --routers '*' \
  --tools execute_junos_command,gather_device_facts \
  --server-pid <pid>
```

If you need to trigger a reload without a token change (e.g., after editing the
file by hand), send SIGHUP directly:

```bash
kill -HUP <pid>
```

### Refusal matrix

| Flags | Bind address | Result |
|---|---|---|
| _(none)_ | any | Refused — `--tokens-file` or `--allow-no-auth` required for streamable-http |
| `--allow-no-auth` only | non-loopback | Refused — `--allow-no-auth` is loopback-only |
| `--allow-no-auth` only | loopback | OK — but note: if you also supply `--tls-cert`/`--tls-key`, auth is still disabled; TLS gives confidentiality but any client that can reach the port has full tool access (foot-gun) |
| `--tokens-file` only | non-loopback, no TLS | Refused — add `--tls-cert`/`--tls-key` or `--allow-insecure-bind` |
| `--tokens-file --allow-insecure-bind` | non-loopback, no TLS | OK — tokens are checked; you are asserting external transport security |
| `--tokens-file --tls-cert cert.pem --tls-key key.pem` | any | OK |

## Resource limits (streamable-HTTP)

Both endpoints enforce configurable DoS guardrails, enabled by default with
generous values. Every numeric limit accepts `0` to disable it.

| Flag | Env (junos / srx) | Default | Effect |
|------|-------------------|---------|--------|
| `--max-request-body-bytes` | `JMCP_MAX_REQUEST_BODY_BYTES` / `JMCP_SRX_MAX_REQUEST_BODY_BYTES` | 10 MiB | Reject larger bodies with **413** before buffering |
| `--max-inflight-requests` | `JMCP_MAX_INFLIGHT_REQUESTS` / `JMCP_SRX_MAX_INFLIGHT_REQUESTS` | 64 | Global concurrency cap; over-limit → **503** |
| `--max-inflight-requests-per-token` | `JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN` / `JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN` | 16 | Per-token concurrency cap → **503** |
| `--max-sessions` | `JMCP_MAX_SESSIONS` / `JMCP_SRX_MAX_SESSIONS` | 128 | Session count cap → **503** |
| `--session-idle-timeout-secs` | `JMCP_SESSION_IDLE_TIMEOUT_SECS` / `JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS` | 300 | Idle sessions reaped |
| `--session-max-lifetime-secs` | `JMCP_SESSION_MAX_LIFETIME_SECS` / `JMCP_SRX_SESSION_MAX_LIFETIME_SECS` | 3600 | Old sessions reaped |

Over-limit responses carry `Retry-After: 1`. Concurrency permits are released when
the response stream ends, so slow clients hold at most one slot each.

**Deferred (follow-ups on #131):** per-router limits composing with destructive
leases, per-token session caps, a Prometheus `/metrics` endpoint, and RPS
rate-limiting.

## CLI

```
Junos MCP server (Rust)

Usage: rust-junosmcp [OPTIONS] [COMMAND]

Commands:
  token  Manage the bearer-token store
  help   Print this message or the help of the given subcommand(s)

Options:
  -f, --device-mapping <DEVICE_MAPPING>
          JSON file with device mapping (Juniper junos-mcp-server compatible) [default: devices.json]
  -t, --transport <TRANSPORT>
          Transport [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>
          Bind host (streamable-http only) [default: 127.0.0.1]
  -p, --port <PORT>
          Bind port (streamable-http only) [default: 30030]
      --tokens-file <TOKENS_FILE>
          Bearer-token file. Required for streamable-http unless --allow-no-auth
      --tls-cert <TLS_CERT>
          PEM-encoded TLS cert (streamable-http only). Pair with --tls-key
      --tls-key <TLS_KEY>
          PEM-encoded TLS key (streamable-http only). Pair with --tls-cert
      --allow-no-auth
          Disable bearer-token auth. Refuses to bind off-loopback
      --allow-insecure-bind
          Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured
      --inventory-readonly
          Reject add_device and reload_devices unconditionally
      --allow-password-auth-add
          Permit add_device to accept auth.type=password (mutually exclusive
          with --inventory-readonly)
      --device-lease-dir <DEVICE_LEASE_DIR>
          Shared directory for cross-process destructive-operation leases
          [default: /var/lib/jmcp/device-leases]
      --allowed-host <HOST>
          Additional Host authorities to accept on the streamable-http
          endpoint, beyond the loopback defaults (localhost, 127.0.0.1, ::1).
          Repeatable
      --disable-host-check
          Disable the streamable-http Host allowlist entirely (accept any
          Host). Off by default
  -h, --help
          Print help
  -V, --version
          Print version
```

## Testing against a real device

```bash
JMCP_TEST_HOST=10.0.0.1 \
JMCP_TEST_USER=admin \
JMCP_TEST_PASS=secret \
cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>
