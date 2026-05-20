//! `fetch_file` MCP tool. SCP a file from a Junos device's /var/tmp/ back
//! to the host's staging directory, with per-router serialization and
//! sha256 verification. Mirror image of `transfer_file`.

// Implementation lands in Task 5; this file exists so the `pub mod
// fetch_file;` declaration in `tools/mod.rs` compiles.
