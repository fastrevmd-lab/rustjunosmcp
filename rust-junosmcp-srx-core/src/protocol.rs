//! `Protocol` — a closed IP-protocol enum shared by the tools 5/6 (MEC-55)
//! 5-tuple lookups (`srx_flow_sessions`, `srx_policy_match`).
//!
//! "Parse, don't validate": callers hand us a raw string (JSON args have no
//! protocol type), and this is the one place that turns it into a value a
//! malformed RPC call is unrepresentable from. Everything downstream takes
//! `Protocol`, never the original string.

use crate::SrxError;
use schemars::JsonSchema;
use serde::Serialize;

/// IP protocol for a 5-tuple filter or match query.
///
/// The named variants cover the common cases; `Other` is the numeric
/// fallback for any IANA protocol number (e.g. 47 for GRE) so the type stays
/// closed without needing a variant per protocol.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP (6).
    Tcp,
    /// UDP (17).
    Udp,
    /// ICMP (1).
    Icmp,
    /// Any other IANA protocol number, carried through as-is.
    Other(u8),
}

impl Protocol {
    /// Parse a caller-supplied protocol token (`"tcp"`, `"udp"`, `"icmp"`,
    /// case-insensitive, or a bare IANA protocol number such as `"47"`).
    ///
    /// Rejects anything else with a typed `SrxError::InvalidInput` — this is
    /// the pre-RPC validation step, so a malformed token never reaches the
    /// device.
    pub fn parse(s: &str) -> Result<Self, SrxError> {
        let trimmed = s.trim();
        match trimmed.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            _ => trimmed.parse::<u8>().map(Self::Other).map_err(|_| {
                SrxError::InvalidInput(
                    "unrecognised protocol: expected tcp, udp, icmp, or a numeric IANA protocol \
                     number 0-255"
                        .into(),
                )
            }),
        }
    }

    /// Render as the flat string value Junos expects on the wire.
    pub fn rpc_value(&self) -> String {
        match self {
            Self::Tcp => "tcp".to_string(),
            Self::Udp => "udp".to_string(),
            Self::Icmp => "icmp".to_string(),
            Self::Other(n) => n.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_protocols_case_insensitively() {
        assert_eq!(Protocol::parse("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::parse("TCP").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::parse("Udp").unwrap(), Protocol::Udp);
        assert_eq!(Protocol::parse("ICMP").unwrap(), Protocol::Icmp);
    }

    #[test]
    fn parses_numeric_fallback() {
        assert_eq!(Protocol::parse("47").unwrap(), Protocol::Other(47));
        // Numeric tokens are not canonicalised to named variants, even when
        // the number is a well-known IANA alias (1 = ICMP) — the caller gets
        // exactly the closed variant matching what they typed.
        assert_eq!(Protocol::parse(" 1 ").unwrap(), Protocol::Other(1));
    }

    #[test]
    fn rejects_unknown_token() {
        let err = Protocol::parse("bogus").unwrap_err();
        assert!(matches!(err, SrxError::InvalidInput(_)));
    }

    #[test]
    fn rejects_out_of_range_numeric_token() {
        // u8 max is 255; IANA protocol numbers never legitimately need more.
        let err = Protocol::parse("999").unwrap_err();
        assert!(matches!(err, SrxError::InvalidInput(_)));
    }

    #[test]
    fn rpc_value_round_trips() {
        assert_eq!(Protocol::Tcp.rpc_value(), "tcp");
        assert_eq!(Protocol::Other(47).rpc_value(), "47");
    }
}
