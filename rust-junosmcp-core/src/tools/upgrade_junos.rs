//! `upgrade_junos` MCP tool. Upgrades a standalone Junos device by
//! staging an image via transfer_file, installing it with
//! `request system software add ... reboot`, waiting for NETCONF to
//! reopen, and verifying `show version` matches `target_version`.
//!
//! See docs/superpowers/specs/2026-05-15-upgrade-junos-design.md.
//! Cluster (ISSU) support deferred to v2.
