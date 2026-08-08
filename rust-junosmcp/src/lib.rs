//! Junos MCP server library.
//!
//! Exports the HTTP transport building functions for integration tests.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod http_transport;
pub mod server;
