//! Bearer-token authentication and per-token scopes for rust-junosmcp.
//!
//! Pure data + I/O glue, no async, no HTTP.

pub mod token;
pub mod store;
pub mod file;

pub use store::{ScopeSet, TokenEntry, TokenStore};
pub use file::{TokenStoreError, TokenStoreFile};
