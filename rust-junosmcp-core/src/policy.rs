//! Pure rule-evaluation logic for the blocklist guardrails.
//!
//! `Policy` is built once at startup from the parsed [`Inventory`](crate::Inventory)
//! and is cheap to clone via `Arc`. Tool handlers consult it before any device
//! interaction.
