//! Absence semantics — `SrxState` + the `SrxToolResponse<T>` envelope.

use schemars::JsonSchema;
use serde::Serialize;

/// Operational state of an SRX feature or capability.
#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SrxState {
    /// Feature is enabled and data was successfully collected.
    Active,
    /// Feature is not configured on the device.
    NotConfigured,
    /// An error occurred while querying the feature.
    Error,
}

/// Standard response envelope for SRX tools.
///
/// Distinguishes successful data collection from feature-not-configured states.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SrxToolResponse<T> {
    /// Operational state of the queried feature.
    pub state: SrxState,
    /// Collected data, present when state is Active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Human-readable explanation, present when state is NotConfigured or Error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Raw XML response from the device, if requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
}

impl<T: JsonSchema + Serialize> SrxToolResponse<T> {
    /// Constructs a response for an active feature with collected data.
    pub fn active(data: T) -> Self {
        Self {
            state: SrxState::Active,
            data: Some(data),
            reason: None,
            raw_xml: None,
        }
    }

    /// Constructs a response for a feature that is not configured.
    pub fn not_configured(reason: impl Into<String>) -> Self {
        Self {
            state: SrxState::NotConfigured,
            data: None,
            reason: Some(reason.into()),
            raw_xml: None,
        }
    }

    /// Attaches the raw XML response from the device.
    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw_xml = Some(raw.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;
    use serde::Serialize;

    #[derive(Debug, Serialize, JsonSchema)]
    struct Body {
        ok: bool,
    }

    #[test]
    fn active_serializes_with_data_no_reason() {
        let r = SrxToolResponse::<Body>::active(Body { ok: true });
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["state"], "active");
        assert_eq!(j["data"]["ok"], true);
        assert!(j.get("reason").is_none());
        assert!(j.get("raw_xml").is_none());
    }

    #[test]
    fn not_configured_serializes_with_reason_no_data() {
        let r = SrxToolResponse::<Body>::not_configured("disabled");
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["state"], "not_configured");
        assert_eq!(j["reason"], "disabled");
        assert!(j.get("data").is_none());
    }

    #[test]
    fn with_raw_attaches_xml() {
        let r = SrxToolResponse::<Body>::active(Body { ok: true }).with_raw("<x/>");
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["raw_xml"], "<x/>");
    }
}
