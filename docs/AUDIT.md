# Audit Event Schema

`rust-junosmcp` and `rust-srxmcp` emit structured audit logs for every MCP tool invocation. Each event records the caller, tool, target routers, authorization decision, outcome, and duration. Events are written to stderr (or an optional append-only JSON file) and are machine-parseable for SIEM ingestion.

## Schema

Every audit event has `target="audit"` and the following fields (in order):

| Field | Type | Description |
|-------|------|-------------|
| `correlation_id` | string | Unique request identifier (`req-<nanos>` epoch-based). |
| `caller` | string | Bearer-token name, or `"stdio"` when unauthenticated. |
| `tool` | string | MCP tool name (e.g., `execute_junos_command`, `get_chassis_cluster_status`). |
| `routers` | string | Comma-separated list of target router names (empty for inventory/list tools). |
| `router_count` | u64 | Number of target routers. |
| `action` | string | Stable action category: `read`, `commit`, `add-device`, `upgrade`, `pfe`, `transfer`, `destructive`, etc. |
| `authorization` | enum | Authorization decision: `allowed`, `denied`, or `no_auth` (stdio caller). |
| `result` | enum | Outcome: `ok` (success), `error` (failure), `denied` (authorization rejected), or `unsettled` (client disconnect). |
| `duration_ms` | u64 | Elapsed time from handler entry to drop (milliseconds). |
| `error_kind` | string | Stable error category when `result=error` (e.g., `"timeout"`, `"lease_busy"`, `"transport"`). Empty otherwise. See [Error kinds](#error-kinds) for the full vocabulary. |
| `error` | string | Bounded error message when `result=error` (max 512 chars, truncated with `…`). Empty otherwise. |
| `reason` | string | Denial reason when `result=denied` (see below). Empty otherwise. |
| `metadata` | string | Space-separated `key=value` pairs of allowlisted, non-secret tool-specific fields (e.g., `command_count=5 dry_run=true`). Empty if none. |

### Authorization values

- **`allowed`** — caller has required scopes; work proceeds.
- **`denied`** — caller lacks required scopes or context; work refused before execution.
- **`no_auth`** — stdio transport (no bearer token); treated as allowed.

### Result values

- **`ok`** — handler completed successfully.
- **`error`** — handler returned an error (see `error_kind` and `error`).
- **`denied`** — authorization check rejected the request (see `reason`).
- **`unsettled`** — guard dropped without an outcome (client disconnect or cancel).

### Denial reasons

| Reason | Meaning |
|--------|---------|
| `tool_scope` | Token lacks permission for the requested tool. |
| `router_scope` | Token lacks permission for one or more target routers. |
| `inventory_readonly` | Server started with `--inventory-readonly`; inventory mutations refused. |
| `missing_caller_context` | SRX tool invoked without caller context (stdio or unauthenticated HTTP). |

### Error kinds

When `result=error`, `error_kind` carries a stable category derived from the failing error variant (`JmcpError::audit_kind` / `SrxError::audit_kind`). The strings are a closed vocabulary — the mapping is an exhaustive match, so adding a new error variant forces a deliberate classification at compile time. Use these to alert on error *classes* (e.g. "> 10 `lease_busy` in 5 min") rather than parsing free-text `error`.

Emitted by both servers (SRX inherits every Junos kind via its `Transport` variant):

| Kind | Meaning |
|------|---------|
| `unknown_router` | Target router is not present in the inventory. |
| `invalid_input` | Malformed or invalid arguments, formats, SSH config, or blocklist rules (client error). |
| `parse` | JSON, template, or config parse failure. |
| `not_found` | A required file/resource is missing (key file, `known_hosts`, remote file). |
| `unsupported` | Operation unsupported for this device/config (password auth, chassis cluster, etc.). |
| `conflict` | Destination/device/inventory state conflict (exists-differs, on-disk drift, already-exists). |
| `timeout` | Operation exceeded its time budget (connect, transfer, install, reboot, or outer timeout). |
| `cancelled` | Client cancelled the in-flight operation. |
| `lease_busy` | Device destructive-lease held by another workflow (contention). |
| `lease_error` | Lease acquisition or candidate cleanup failed. |
| `verify_mismatch` | Post-op checksum or version verification mismatch. |
| `host_key_mismatch` | SSH host-key verification rejected the device. |
| `confirmation_required` | Operation needs re-call with `confirm=true`. |
| `commit_confirmed_active` | A pending commit-confirmed rollback window blocks the operation. |
| `insufficient_disk` | Not enough free space on the device. |
| `dependency_unavailable` | A required external tool (e.g. `scp`/openssh) is missing. |
| `scp_failed` | An `scp` transfer returned a non-zero exit. |
| `device_probe_failed` | A pre-flight device probe failed. |
| `blocked` | A blocklist rule denied the command or config. |
| `inventory_readonly` | Inventory mutation refused under `--inventory-readonly` (normally surfaces as a `denied`/`inventory_readonly` reason; see [Denial reasons](#denial-reasons)). |
| `inventory_empty` | Inventory contains no devices. |
| `transport` | NETCONF/SSH transport-layer error. |
| `io` | Filesystem / I/O error (including inventory file read/write). |

SRX-only kinds (`rust-srxmcp`):

| Kind | Meaning |
|------|---------|
| `rpc` | Device returned an RPC error. |
| `confirmation_token` | Confirmation token missing, invalid, drifted, or over capacity. |
| `license_inactive` | Required feature license is not active. |
| `unreachable` | Signature/AppID package server is unreachable. |
| `precondition_failed` | Required precondition missing (no rollback/uninstall target). |
| `cluster_desynced` | Chassis cluster is not synchronized. |
| `download_failed` | Signature/AppID package download failed. |
| `install_failed` | Signature/AppID package install failed. |
| `daemon_not_ready` | `idp-policy` daemon not initialized. |
| `timeout` | Poll or cluster-health-check budget exceeded. |
| `staging_full` | Support-bundle staging dir over cap even after LRU eviction. |
| `staging_evicted` | Requested bundle not present in staging (LRU evicted or never written). |
| `bundle_partial` | A subset of support-bundle RPCs failed. |
| `contention` | Another per-router workflow is already in flight. |
| `capture_failed` | Universal-baseline config-capture RPC failed. |

Server-level (not from an error enum):

| Kind | Meaning |
|------|---------|
| `serialize` | Response serialization failed (internal error). |

## JSON Event Format

When `--audit-format json` is set, events are emitted as line-delimited JSON. The `tracing` crate's JSON formatter nests field data under a `"fields"` object:

```json
{"timestamp":"2026-07-12T18:32:14.091234Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805534091123456","caller":"ci","tool":"execute_junos_command","routers":"vsrx-lab-01","router_count":1,"action":"read","authorization":"allowed","result":"ok","duration_ms":142,"error_kind":"","error":"","reason":"","metadata":"format=text"},"message":"audit"}
```

### Example: Success

```json
{"timestamp":"2026-07-12T18:32:15.001Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805535001000000","caller":"automation","tool":"load_and_commit_config","routers":"vsrx-lab-02","router_count":1,"action":"commit","authorization":"allowed","result":"ok","duration_ms":3456,"error_kind":"","error":"","reason":"","metadata":"config_bytes=1234 dry_run=false"},"message":"audit"}
```

### Example: Failure

```json
{"timestamp":"2026-07-12T18:32:16.500Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805536500000000","caller":"devops","tool":"execute_junos_command","routers":"vsrx-lab-03","router_count":1,"action":"read","authorization":"allowed","result":"error","duration_ms":5001,"error_kind":"timeout","error":"NETCONF session timed out after 5000ms","reason":"","metadata":"format=text"},"message":"audit"}
```

### Example: Denial

```json
{"timestamp":"2026-07-12T18:32:17.250Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805537250000000","caller":"readonly-token","tool":"load_and_commit_config","routers":"vsrx-lab-01","router_count":1,"action":"commit","authorization":"denied","result":"denied","duration_ms":0,"error_kind":"","error":"","reason":"tool_scope","metadata":""},"message":"audit"}
```

## Configuration

Both binaries support identical audit configuration:

### `rust-junosmcp`

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--audit-format` | `JMCP_AUDIT_FORMAT` | `text` | Output format: `text` or `json`. |
| `--audit-log-file` | `JMCP_AUDIT_LOG_FILE` | (none) | Optional file path to append JSON events to (in addition to stderr). |
| `--audit-journald` | `JMCP_AUDIT_JOURNALD` | `false` | Also send `target="audit"` events directly to journald as native structured fields. Startup fails if journald is unavailable. |

### `rust-srxmcp`

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--audit-format` | `JMCP_SRX_AUDIT_FORMAT` | `text` | Output format: `text` or `json`. |
| `--audit-log-file` | `JMCP_SRX_AUDIT_LOG_FILE` | (none) | Optional file path to append JSON events to (in addition to stderr). |
| `--audit-journald` | `JMCP_SRX_AUDIT_JOURNALD` | `false` | Also send `target="audit"` events directly to journald as native structured fields. Startup fails if journald is unavailable. |

## Retention & Forwarding

### journald

By default, services running under systemd write their normal text/JSON stderr
stream into the journal. Set `--audit-journald` (or the binary-specific
environment variable above) to add a second, native journal record for every
`target="audit"` event. The native target is disabled by default and does not
replace stderr or `--audit-log-file`.

Enabling the target probes `/run/systemd/journal/socket` during startup. A
missing or inaccessible socket aborts startup with `initializing audit tracing`
and the operating-system error; the service never silently claims that an
explicitly requested sink is active. The upstream tracing layer cannot return
per-event send failures after initialization, so stderr and the optional file
sink remain the fallback if journald later becomes unavailable.

When systemd also captures stderr, an audit operation can appear twice: once as
the formatted stderr `MESSAGE`, and once as the native entry with indexed
`AUDIT_*` fields. Select `TARGET=audit` to consume only native entries.

#### Native field mapping

| Journal field | Audit value |
|---------------|-------------|
| `TARGET` | `audit` |
| `PRIORITY` | `5` (`NOTICE`; audit events use tracing `INFO`) |
| `SYSLOG_IDENTIFIER` | `rust-junosmcp` or `rust-srxmcp` |
| `MESSAGE` | `audit` |
| `AUDIT_CORRELATION_ID` | `correlation_id` |
| `AUDIT_CALLER` | `caller` |
| `AUDIT_TOOL` | `tool` |
| `AUDIT_ROUTERS` | `routers` |
| `AUDIT_ROUTER_COUNT` | `router_count` |
| `AUDIT_ACTION` | `action` |
| `AUDIT_AUTHORIZATION` | `authorization` |
| `AUDIT_RESULT` | `result` |
| `AUDIT_DURATION_MS` | `duration_ms` |
| `AUDIT_ERROR_KIND` | `error_kind` |
| `AUDIT_ERROR` | `error` |
| `AUDIT_REASON` | `reason` |
| `AUDIT_METADATA` | `metadata` |

The journal stores values as byte strings, but every field remains separately
indexed; consumers do not parse the JSON formatter's nested `fields` object.
Redaction is applied before fan-out, so native values match the redacted stderr
and file values.

Query native Junos and SRX audit entries with:

```bash
journalctl -t rust-junosmcp TARGET=audit
journalctl -t rust-srxmcp TARGET=audit
journalctl -t rust-junosmcp -o json | jq 'select(.TARGET == "audit")'
```

Direct RFC 5424 formatting and remote syslog transport are not implemented by
this option. Forward native journal fields with the host's journald/rsyslog or
SIEM integration when remote delivery is required.

### File sink

When `--audit-log-file` is set, JSON events are appended to the specified file. The file is **append-only** — the server never rotates or truncates it, so retention is handled externally by `logrotate`.

#### Rotation & retention

A ready-to-install fragment ships at [`packaging/logrotate/rust-junosmcp-audit`](../packaging/logrotate/rust-junosmcp-audit). Install it as `/etc/logrotate.d/rust-junosmcp-audit` (owned `root:root`, mode `0644`). It rotates the audit files daily, caps them at 100 MB, keeps 14 compressed generations, and matches the packaged systemd layout (`jmcp:jmcp`, files under `/var/lib/jmcp`). Tune `rotate`/`maxsize`/`daily` to your retention policy.

```
/var/lib/jmcp/audit.jsonl /var/lib/jmcp/srx-audit.jsonl {
    daily
    rotate 14
    maxsize 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    su jmcp jmcp
}
```

**`copytruncate` is required, not optional.** The server holds a single long-lived append (`O_APPEND`) file descriptor for the audit sink and never reopens it — `SIGHUP` is reserved for hot-reloading `devices.json`/`tokens.json` and does **not** reopen the audit file. With plain `create`-mode rotation (rename + create), the server would keep writing to the rotated inode and the active file would stay empty until the next restart. `copytruncate` copies the file, then truncates it in place; because the fd is `O_APPEND`, writes resume cleanly at offset 0 with no sparse gap.

The tradeoff: `copytruncate` has an inherent small race — audit lines written between the copy and the truncate can be **lost** (never duplicated). At typical audit volumes this window is negligible. If zero-loss retention is required, forward events to a SIEM in real time (see below) instead of relying on the rotated files as the system of record.

### Field redaction

By default every audit field is emitted in cleartext. For deployments that treat device identifiers as sensitive, an optional per-field transform can `keep`, `drop`, or `hmac` a **closed set** of fields. Redaction is **off by default** — with no configuration the output is byte-for-byte unchanged.

| Flag | Env (junos / srx) | Meaning |
|------|-------------------|---------|
| `--audit-redact` | `JMCP_AUDIT_REDACT` / `JMCP_SRX_AUDIT_REDACT` | Comma-separated `field=transform` map. Empty = disabled. |
| `--audit-hmac-key-file` | `JMCP_AUDIT_HMAC_KEY_FILE` / `JMCP_SRX_AUDIT_HMAC_KEY_FILE` | Path to a file holding the HMAC key. Required if any field uses `hmac`. The key value is never a flag or env value. |

**Transforms:** `keep` (cleartext), `drop` (omit the field), `hmac` (emit `hmac:<hex>` = HMAC-SHA256 of the value under the key file's bytes). HMAC is deterministic, so a SIEM can still group events by a redacted identifier without learning it; it is keyed, so low-entropy values (IPs/hostnames) are not brute-force-reversible.

**Redactable fields (only these; anything else is a startup error):** `routers`, `host`, `name`, `basename`, `command`, `pfe_command`. The `routers` field is transformed per router name and re-joined (`hmac:<h1>,hmac:<h2>`); `router_count` stays cleartext. `caller` and all structural fields (`result`, `duration_ms`, `error`, etc.) are never redactable.

**Example** — HMAC the router names on every line and drop the device IP recorded by `add_device`:

```
rust-junosmcp \
  --audit-redact 'routers=hmac,host=drop' \
  --audit-hmac-key-file /etc/jmcp/audit-hmac.key \
  ...
```

**Startup validation:** an unknown field, an unknown transform, a malformed entry, `hmac` without a key file, or an unreadable/empty key file all abort startup with a clear message — redaction never silently downgrades.

**Limitation:** the free-text `error` field is bounded and secret-free by construction but may legitimately contain an identifier (e.g. `router 'r1' not found`). It is **not** field-redactable.

### SIEM / forwarding

Ingest via:

- **Filebeat / Fluentd / Vector** — tail the JSON log file or `journalctl` output.
- **Direct RFC 5424 syslog sink** — deferred; native journald forwarding is available above.

Filter on `target == "audit"` to separate audit events from operational logs.

## Deferred Items

The following capabilities are planned but not yet implemented:

1. **Direct RFC 5424 syslog sink** — native journald is implemented via `--audit-journald`, while direct RFC 5424 formatting and remote transport remain unimplemented and can be provided by the host's journald/rsyslog/SIEM integration.
2. **Built-in log rotation** — the server does not manage file rotation in-process; retention is handled by the shipped `logrotate` fragment (see [Rotation & retention](#rotation--retention)). In-process size/age rotation with `SIGHUP`-reopen support remains out of scope by design.
3. **Per-field encryption** — sensitive metadata fields can be dropped or replaced with a keyed HMAC fingerprint via [Field redaction](#field-redaction). *Reversible* envelope encryption (recover the original from logs with a key) remains out of scope.

## Security & Privacy

- **No secrets in audit logs** — credentials, private keys, and passwords are never logged. The `metadata` field is allowlisted per tool (e.g., `command_count`, `dry_run`, `config_bytes`) and excludes all secret material.
- **Error messages are bounded** — the `error` field is truncated at 512 characters to prevent unbounded log growth from pathological failures.
- **Caller attribution** — every event records the bearer-token name or `"stdio"`, enabling per-caller audit trails even when multiple tokens share the same scope.

## Example Queries

### All denied requests in the last hour

```bash
journalctl -u rust-junosmcp.service --since "1 hour ago" --output=json \
  | jq -r 'select(.TARGET == "audit") | select(.AUDIT_RESULT == "denied")'
```

### Top 10 slowest successful commands

```bash
jq -r 'select(.target == "audit") | select(.fields.result == "ok") | "\(.fields.duration_ms) \(.fields.tool) \(.fields.routers)"' \
  /var/lib/jmcp/audit.jsonl \
  | sort -rn | head -10
```

### Failed commits by caller

```bash
jq -r 'select(.target == "audit") | select(.fields.action == "commit") | select(.fields.result == "error") | "\(.fields.caller) \(.fields.routers) \(.fields.error)"' \
  /var/lib/jmcp/audit.jsonl
```
