//! Junos authorization vocabulary over the shared mecmcp auth core.
//!
//! Pure data plus HTTP glue; no async device work.

pub mod tower;

pub use mecmcp_auth::{
    CallerCtx, FileError as TokenStoreError, KnownNames, NoGrant, ScopeSet, StoreError,
    TokenDigest, TokenEntry as SharedTokenEntry, TokenError, TokenSecret,
    TokenStore as SharedStore, TokenStoreFile as SharedFile, filter_device_names,
};

/// Junos token entry. Write authority is not yet modelled per token.
pub type TokenEntry = SharedTokenEntry<NoGrant>;
/// Junos token store.
pub type TokenStore = SharedStore<NoGrant>;
/// Junos token file.
pub type TokenStoreFile = SharedFile<NoGrant>;

/// Generic Junos tool names. The server crate has a drift test that
/// compares its `#[tool]` surface against this registry.
pub const JUNOS_TOOLS: &[&str] = &[
    "add_device",
    "commit_check_config",
    "discard_candidate",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_junos_config",
    "get_router_list",
    "junos_config_diff",
    "list_staged_files",
    "load_and_commit_config",
    "reload_devices",
    "render_and_apply_j2_template",
    "rollback_config",
    "transfer_file",
    "upgrade_junos",
];

/// SRX workflow tool names. Kept separate so the unified registry can enforce
/// per-domain drift checks while using one token file.
pub const SRX_TOOLS: &[&str] = &[
    "check_srx_feature_license",
    "collect_jtac_support_bundle",
    "get_chassis_cluster_status",
    "get_srx_security_services_status",
    "manage_appid_signature_package",
    "manage_idp_security_package",
    "srxmcp_status",
    "validate_chassis_cluster_health",
    "vpn_lifecycle_report",
];

/// All tool names accepted in token scopes, kept globally alphabetized for
/// stable diagnostics. This must remain the exact union of [`JUNOS_TOOLS`] and
/// [`SRX_TOOLS`]; the registry tests below enforce that invariant.
pub const KNOWN_TOOLS: &[&str] = &[
    "add_device",
    "check_srx_feature_license",
    "collect_jtac_support_bundle",
    "commit_check_config",
    "discard_candidate",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_chassis_cluster_status",
    "get_junos_config",
    "get_router_list",
    "get_srx_security_services_status",
    "junos_config_diff",
    "list_staged_files",
    "load_and_commit_config",
    "manage_appid_signature_package",
    "manage_idp_security_package",
    "reload_devices",
    "render_and_apply_j2_template",
    "rollback_config",
    "srxmcp_status",
    "transfer_file",
    "upgrade_junos",
    "validate_chassis_cluster_health",
    "vpn_lifecycle_report",
];

/// Tools that a wildcard tool scope does NOT confer. Granting write authority
/// must always be an explicit, named decision.
pub const WRITE_TOOLS: &[&str] = &[
    "add_device",
    "load_and_commit_config",
    "render_and_apply_j2_template",
    "rollback_config",
    "transfer_file",
    "upgrade_junos",
    "manage_idp_security_package",
    "manage_appid_signature_package",
    "discard_candidate",
    "reload_devices",
];

/// Backwards-compatible alias. `filter_router_names` was the pre-extraction
/// name; the shared crate calls devices devices.
pub use mecmcp_auth::filter_device_names as filter_router_names;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn known_tools_is_alphabetized() {
        let mut sorted = KNOWN_TOOLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            KNOWN_TOOLS,
            sorted.as_slice(),
            "KNOWN_TOOLS must stay alphabetized for easy diff/audit"
        );
    }

    #[test]
    fn known_tools_is_exact_endpoint_union() {
        let known: HashSet<&str> = KNOWN_TOOLS.iter().copied().collect();
        let endpoint_tools: HashSet<&str> = JUNOS_TOOLS
            .iter()
            .chain(SRX_TOOLS.iter())
            .copied()
            .collect();

        assert_eq!(
            known, endpoint_tools,
            "KNOWN_TOOLS must be the exact union of JUNOS_TOOLS and SRX_TOOLS"
        );
        assert_eq!(
            KNOWN_TOOLS.len(),
            JUNOS_TOOLS.len() + SRX_TOOLS.len(),
            "endpoint registries must not contain duplicate tool names"
        );
    }

    #[test]
    fn write_tools_exist_in_known_tools() {
        for tool in WRITE_TOOLS {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "WRITE_TOOLS entry '{tool}' not found in KNOWN_TOOLS"
            );
        }
    }
}
