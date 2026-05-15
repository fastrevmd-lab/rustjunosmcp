# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] — 2026-05-15

Security + hardening release. No tool API changes; one server-side
response-header change for unauthenticated requests, plus a new response
field on `list_staged_files`.

### Security

- **RFC 6750 bearer challenges on every 401** — the streamable-HTTP
  endpoint now always returns a `WWW-Authenticate: Bearer ...` header on
  `401 Unauthorized`. Wrong-token rejections include
  `error="invalid_token"` per RFC 6750 §3.1 so clients can distinguish
  bearer rejection from an OAuth-discovery prompt (avoids
  `~/.claude/.credentials.json` corruption from clients that retry as
  OAuth on a bare 401). (#27, PR #28)
- **`transfer_file` source-path allowlist tightened** —
  `validate_source_basename` previously rejected `/`, `\`, `..`, leading
  `.`, and >255 bytes but accepted NUL bytes, ASCII control characters,
  shell metacharacters, and arbitrary Unicode (including RTL overrides
  and homoglyph scripts). Now restricts to `[A-Za-z0-9._-]`. Junos image
  / config artifacts are plain ASCII so this is non-restrictive in
  practice. (#26 L2, PR #30)
- **`scp` stderr scrubbed in `ScpFailed` errors** — absolute filesystem
  paths and IPv4 addresses are redacted to `<path>` / `<host>` before
  the error is surfaced to the MCP caller. Diagnostic text is
  preserved. Closes a path/host leak surface in multi-tenant setups.
  (#26 L1, PR #31)

### Reliability

- **`list_staged_files` capped at 256 entries** — `read_staging_dir`
  previously walked every regular file and computed sha256 on each
  (~3 s/GB), producing slow + large responses when an operator dumped
  thousands of files into staging. Now caps at
  `STAGING_DIR_MAX_ENTRIES = 256` (sorted by name, deterministic
  truncation, sha256 skipped for excess files). Response gains two new
  fields: `staged_files_truncated: bool` and
  `staged_files_total_found: usize`. (#26 L5, PR #32)
- **Per-router serialization for `transfer_file`** — new `TransferLocks`
  process-wide map of `Arc<Semaphore(1)>` keyed by router name. Prevents
  a confused or buggy caller from exhausting a device's `/var/tmp` or
  session pool via fan-out. Different routers proceed in parallel; same
  router serializes. Junos serializes on its side anyway, so this caps
  client-side fan-out. (#26 L4, PR #33)

### Operability

- **Actionable EACCES message on `tokens.json`** — when the running
  process can't read the tokens file due to permissions, the server now
  surfaces the file owner uid + mode and the running process's uid plus
  a `sudo -u <service-user>` / `chown` hint. Previously the operator
  saw a bare `Permission denied (os error 13)` with no pointer at the
  underlying ownership mismatch. README also gained a note in the
  "Mint a token" section about running token subcommands as the service
  user. (#22 / #23, PR #29)

### Tooling

- Workspace version bumped to `0.4.1`.

## [0.4.0]

Initial release of the `transfer_file` + `list_staged_files` MCP tools.
See PR #25 for details.
