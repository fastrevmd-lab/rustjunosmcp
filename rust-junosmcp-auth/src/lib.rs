//! Bearer-token authentication and per-token scopes for rust-junosmcp.
//!
//! Pure data + I/O glue, no async, no HTTP.

pub mod caller;
pub mod file;
pub mod store;
pub mod token;

pub use file::{TokenStoreError, TokenStoreFile};
pub use store::{ScopeSet, TokenEntry, TokenStore};
