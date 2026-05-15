# `transfer_file` + `list_staged_files` MCP tools — Design

**Status:** Approved 2026-05-14. Next step: `writing-plans` skill produces an implementation plan.

**Goal:** Add a safe, idempotent file-transfer pathway from the rust-junosmcp host to a Junos device, plus a discovery tool so the LLM can show the user what's already staged before asking them to upload anything new.

**Motivation:** Surfaced during the live vSRX-test18 upgrade on 2026-05-14 (24.4R1.9 → 25.4R1.12). The image had to be `scp`'d manually from a jump host to the device; the existing MCP had no way to do this safely. The future `upgrade_junos` orchestrator (separate plan) cannot exist without this tool.

---

## Architecture

Two new MCP tools in `rust-junosmcp-core/src/tools/`:

| Tool | File | Purpose |
|---|---|---|
| `list_staged_files` | `tools/list_staged_files.rs` | Read-only discovery: lists files in the MCP host staging dir, optionally also lists `/var/tmp/` on a target device |
| `transfer_file` | `tools/transfer_file.rs` | Stages a file from the MCP host to a Junos device's `/var/tmp/`, with pre/post checks and idempotency |

Both tools wired into `rust-junosmcp/src/main.rs` alongside the existing 11 tools.

**Operational additions on the MCP host (LXC 601):**

- New staging directory: `/var/lib/jmcp/staging/`, `root:root`, mode `0755`. Created during deploy.
- New known_hosts file: `/etc/jmcp/known_hosts`, `root:root`, mode `0644`. Created on first connect by SCP itself; deploy step ensures parent dir exists and the file is touch-able.

**No new dependencies.** SCP is shelled out to system `openssh-client` (already present in the LXC). sha256 uses `sha2` (already in tree via rustez). `tokio::process::Command` for the SCP shell-out.

---

## Tool: `list_staged_files`

**Input schema:**

```json
{
  "router_name": "vSRX-test10",   // optional; if present, also list device's /var/tmp/
  "timeout": 30                   // optional; default 30s
}
```

**Output schema (success):**

```json
{
  "staging_dir": "/var/lib/jmcp/staging/",
  "staged_files": [
    {
      "name": "junos-install-vsrx3-x86-64-25.4R1.12.tgz",
      "size_bytes": 1395212800,
      "sha256": "abc123...",
      "mtime_iso": "2026-05-14T17:30:00Z"
    }
  ],
  "device": "vSRX-test10",          // null if router_name omitted
  "device_files": [                 // null if router_name omitted; else lists ALL of /var/tmp/
    {
      "path": "/var/tmp/junos-install-vsrx3-x86-64-25.4R1.12.tgz",
      "size_bytes": 1395212800,
      "mtime_iso": "2026-05-14T18:01:00Z"
    },
    {
      "path": "/var/tmp/core.thingd.12345.gz",
      "size_bytes": 4321,
      "mtime_iso": "2026-05-14T03:14:00Z"
    }
  ]
}
```

**Notes:**

- MCP-host staging entries include `sha256` (computed on demand from disk; cost = ~3 s/GB on the LXC). Operator-acceptable trade for transfer idempotency upstream.
- Device entries deliberately *omit* `sha256` — computing per-file would mean N round-trips. Caller can ask for a specific one via `execute_junos_command(... "file checksum sha-256 /var/tmp/foo")`.
- Device side lists *everything* in `/var/tmp/` (not filtered to `*.tgz`). Rationale: visibility of unrelated files (core dumps, prior rsi.txt, leftover snippets) is real safety context for the LLM ("hold on, this device crashed yesterday — investigate before installing").

**Tool description (LLM-visible, embedded in JsonSchema):**

> Lists files staged on the rust-junosmcp host (`/var/lib/jmcp/staging/`) and optionally on the target device's `/var/tmp/`. **Call this first** whenever a user mentions transferring an image, file, or upgrade — existing staged files may already be what they need, avoiding a redundant upload. If the user has not yet staged the file they want, instruct them to upload it with: `scp -O <local-file> root@<mcp-host>:/var/lib/jmcp/staging/`.

---

## Tool: `transfer_file`

**Input schema:**

```json
{
  "router_name": "vSRX-test10",
  "source_path": "junos-install-vsrx3-x86-64-25.4R1.12.tgz",  // basename only
  "force": false,                                              // optional; overwrite if dest exists with different sha256
  "verify": true,                                              // optional; default true (post-transfer sha256)
  "timeout": 1800                                              // optional; default 600s
}
```

**`source_path` validation rules:**

- Must not contain `/`, `\\`, or `..`
- Must not be empty
- Must not exceed 255 chars
- Must not start with `.`
- Resolves to `/var/lib/jmcp/staging/<source_path>`; the file must exist and be a regular file readable by the MCP process

**Output schema (success — transferred):**

```json
{
  "status": "transferred",
  "router": "vSRX-test10",
  "source_path": "/var/lib/jmcp/staging/junos-install-vsrx3-x86-64-25.4R1.12.tgz",
  "dest_path": "/var/tmp/junos-install-vsrx3-x86-64-25.4R1.12.tgz",
  "bytes": 1395212800,
  "sha256": "abc123...",
  "verified": true,
  "elapsed_s": 19.4
}
```

**Output schema (success — idempotent skip):**

```json
{
  "status": "skipped",
  "router": "vSRX-test10",
  "dest_path": "/var/tmp/junos-install-vsrx3-x86-64-25.4R1.12.tgz",
  "sha256": "abc123...",
  "verified": true,
  "reason": "destination already has identical content"
}
```

**Tool description (LLM-visible):**

> Transfers a pre-staged file from the rust-junosmcp host's staging directory (`/var/lib/jmcp/staging/`) to a Junos device's `/var/tmp/`. The file must already exist in the staging directory — call `list_staged_files` first to confirm, or instruct the user to upload it with `scp -O <local-file> root@<mcp-host>:/var/lib/jmcp/staging/`. Idempotent: if the destination already exists with matching sha256, returns `status: "skipped"` immediately. Large transfers (e.g. 1.3 GB Junos install images) take ~20 s of silent transfer time at lab speeds; the tool returns one structured response when complete (no incremental progress). Requires the device's inventory entry to use `ssh_key` auth (password auth is not supported; returns `unsupported_auth` error pointing at remediation).

---

## Execution Flow (`transfer_file`)

```
1. Validate source_path:
   - Reject if contains '/', '\\', or '..'
   - Reject if empty, >255 chars, or starts with '.'
   - Resolve to /var/lib/jmcp/staging/<basename>
   - Stat: must exist, be regular file, be readable

2. Compute local sha256 + size  (streaming SHA-256 via sha2 crate; ~3-5s for 1.3 GB)

3. Resolve device from inventory:
   - If auth.type != "ssh_key" → error `unsupported_auth`
   - Read auth.private_key_path

4. NETCONF: pre-flight checks via existing pooled session
   a. show system storage no-forwarding   → parse /var free bytes
      - if free_bytes < (size + 50 MB headroom) → error `insufficient_disk`
   b. file checksum sha-256 /var/tmp/<basename>
      - if matches local sha256 → return {status: "skipped"} (FAST PATH; skip steps 5-6)
      - if exists but differs and !force → error `dest_exists_differs`
      - if not exists → continue

5. SCP transfer (shell out, argv-style — never via shell):
   scp -O \
     -i <private_key_path> \
     -o StrictHostKeyChecking=accept-new \
     -o UserKnownHostsFile=/etc/jmcp/known_hosts \
     -o ConnectTimeout=15 \
     -o ServerAliveInterval=10 \
     -o ServerAliveCountMax=3 \
     -P <port> \
     /var/lib/jmcp/staging/<basename> \
     <username>@<ip>:/var/tmp/

   - tokio::process::Command, args passed as Vec<String> (no shell interpretation)
   - capture stdout + stderr for diagnostics
   - exit code != 0 → error `scp_failed` with stderr included verbatim
   - if `ConnectTimeout=15` fires → exit code mapped to `connect_timeout`

6. Post-transfer verification (skipped if verify=false):
   NETCONF: file checksum sha-256 /var/tmp/<basename>
   - if mismatch → file delete /var/tmp/<basename> + error `verify_mismatch`
   - if match → return {status: "transferred", verified: true, ...}

7. Whole flow runs inside MCP per-call timeout (default 600s, capped 3600s by POOL_RPC_TIMEOUT).
```

---

## Error Model

Every failure returns a structured tool error with `code` + `message` + (where applicable) `remediation`:

| `code` | When | Message includes |
|---|---|---|
| `bad_source_path` | Path traversal, slash in basename, missing/non-regular file | The offending value + which rule failed |
| `unsupported_auth` | Device has Password auth | Device name + remediation: "add SshKey to inventory" |
| `insufficient_disk` | `/var` free < (size + 50 MB) | Free bytes / required bytes + suggestion to run `request system storage cleanup` or `file delete` |
| `dest_exists_differs` | Dest sha256 != local, `force=false` | Both sha256 hashes + `force=true` hint |
| `scp_failed` | scp exit != 0 (general case) | Verbatim scp stderr + exit code |
| `connect_timeout` | scp ConnectTimeout fired (exit code 124-ish, or ssh-specific) | Hint "device may be unreachable" |
| `verify_mismatch` | Post-transfer sha256 differs | Both hashes + note "destination file was deleted" |
| `outer_timeout` | MCP per-call `tokio::time::timeout` fired | Hint "raise `timeout` arg or split the file" |

All success and skip responses include `verified: bool` so the caller can never confuse a transfer-without-verify with a verified one.

---

## Documentation Outputs

This is a Q1 first-class requirement — the LLM and user must always know how to stage a file. Three concurrent doc surfaces:

1. **Tool descriptions** (above) — rendered in the MCP tool list every LLM sees.
2. **README section** `## File transfers (transfer_file / list_staged_files)` — covers:
   - Why pre-staging (security model, no HTTP-pull)
   - The exact scp command users run: `scp -O <local-file> root@192.168.1.194:/var/lib/jmcp/staging/`
   - Staging dir conventions (location, ownership, no auto-cleanup)
   - Worked example: end-to-end "upload a Junos image and stage it on a vSRX"
   - Failure-mode glossary mapping the error `code`s to remediation
3. **Memory** — update `rust_junosmcp_container_601.md` to document the new staging dir + known_hosts file as part of the deployment surface.

---

## Testing Strategy

| Layer | Coverage |
|---|---|
| Unit (pure logic) | `validate_source_basename`, free-bytes parsing from `show system storage` text, error → message mapping, sha256 streaming |
| Integration (in-process, no real device) | `list_staged_files` against a temp staging dir; `transfer_file` against a mock that asserts the exact `scp` argv and the pre/post NETCONF call sequence |
| Smoke (subprocess MCP, unreachable host) | `transfer_file` returns `connect_timeout` within ~20s against TEST-NET-1 (192.0.2.1) |
| Real-device (`#[ignore]`-gated, run manually before PR) | Round-trip 1 KB and 200 MB to vSRX-test10; verify sha256; verify idempotent re-call returns `skipped`; verify `force=false` rejection on differing dest |
| Container provisioning verify | Deploy step creates `/var/lib/jmcp/staging/` with correct ownership and `/etc/jmcp/` ready for `known_hosts` |

CI gates unchanged: `cargo fmt -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit`.

---

## Scope Explicitly Excluded

| Out of scope | Why | Future home |
|---|---|---|
| Upload mechanism (HTTP, base64, etc.) | User explicitly chose pre-staged; SCP-to-staging is the upload | Possible later `upload_file` tool if manual scp proves painful |
| Streaming progress reporting | Adds protocol complexity; LLM/user told to expect ~20 s silence | — |
| Password auth via `sshpass` or russh | Adds dep + secret-handling surface; lab inventory uses ssh_key | Inventory-level remediation suggested instead |
| Bidirectional transfer (device → host pull) | Different audit story (download surface, dest path safety on host) | Separate `fetch_file` tool plan |
| Staging dir cleanup / reaping | Operator hygiene; `df -h` + manual `rm` is fine for now | Possible later `delete_staged_file` tool |
| Per-device `host_key` inventory field | TOFU via `accept-new` covers lab; can add later without breaking schema | Inventory schema additive change |
| Destination dirs other than `/var/tmp/` | YAGNI; no current upgrade workflow uses elsewhere | Schema additive change later if needed |

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| `scp -O` not present on older OpenSSH | LXC 601 runs Debian 12 with openssh-client 9.x — `-O` supported. Add a startup self-check: log warning if `scp -h 2>&1 \| grep -q '\\-O'` fails |
| Staging dir fills up over time | README + memory document manual cleanup; `df` check on the dir included in deploy notes |
| `accept-new` first-connect MITM | Documented as the policy in README; future `host_key` inventory field can pin per-device without schema break |
| Forgotten `verify: true` default | Default-on; opt-out via explicit `verify: false`; response always includes `verified: bool` |
| Source file modified between sha256 and SCP | Acceptable race; checksum is computed on the bytes that go into SCP via streaming on the SCP path itself in a future hardening, but not in v1 |
| Concurrent calls to `transfer_file` for the same device | Allowed; each spawns its own `scp` process. NETCONF pre/post checks serialize through the per-device session pool guard. SCP itself doesn't conflict — Junos handles concurrent writes to different paths cleanly. Same-path concurrent writes: last-writer-wins, idempotency check catches mismatches on next call. |

---

## Self-Review Notes

- **Placeholder scan:** None — every section has concrete content.
- **Internal consistency:** Error codes in §"Error Model" all referenced from §"Execution Flow". Tool descriptions in their respective sections match the schemas.
- **Scope check:** Two tightly-coupled tools, ~600 lines of code total. Single PR-sized.
- **Ambiguity check:** `verify: false` skips post-transfer sha256 only — pre-transfer dest sha256 (idempotency check) always runs. Made explicit in step 4b vs step 6.
