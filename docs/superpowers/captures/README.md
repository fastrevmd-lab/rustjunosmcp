# Lab-device captures

These directories hold raw NETCONF/XML captures taken against lab vSRX
instances while developing and debugging tool support. They are fixtures
for docs and manual testing, not unit test inputs.

## Sanitization is required before commit

Raw captures from a real device routinely contain credential material:
`encrypted-password` hashes (`$1$`/`$5$`/`$6$`), IKE pre-shared keys
(`$9$`), and SSH host/user keys. None of that may reach a commit as-is,
even from a disposable lab device, even if the device is later
decommissioned or the credential rotated.

Before adding or updating a capture under `docs/superpowers/captures/`:

1. Run `gitleaks dir . -c .gitleaks.toml` locally and confirm it reports
   nothing new for the file you're adding.
2. If the capture legitimately contains one of the vendor secret shapes
   (see `.gitleaks-vendor.toml`), replace the value with a placeholder
   that keeps the same crypt prefix and roughly the same length, and
   inserts an explicit `FAKE` marker immediately after that prefix (for
   example `$6$FAKESALT1$FAKEHASHVALUE...`). `.gitleaks.toml` already
   allowlists the `FAKE` marker itself, so no allowlist edit is needed —
   a real value dropped into any file, including these ones, still fails
   the scan because it won't carry the marker.
