//! HTTP resource, concurrency, and session limits for the streamable-HTTP
//! endpoints shared by `rust-junosmcp` and `rust-srxmcp`.

mod config;
mod concurrency;
mod overload;
mod session;

pub use config::LimitsConfig;
pub use concurrency::{apply_body_limit, concurrency_middleware, ConcurrencyState};
pub use overload::overload_response;
