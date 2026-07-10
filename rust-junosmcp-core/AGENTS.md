# Core Junos library instructions

- Preserve command blocklists, timeouts, host-key verification, bounded output,
  and separation between operational reads and candidate writes.
- Device tests are ignored/opt-in; unit tests must use fixtures or fakes.
- Any configuration path needs diff, commit-check, rollback, and audit coverage.
- Run workspace formatting, Clippy, and tests after changes.
