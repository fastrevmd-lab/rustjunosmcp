//! Pure rule-evaluation logic for the blocklist guardrails.
//!
//! `Policy` is built once at startup from the parsed [`Inventory`](crate::Inventory)
//! and is cheap to clone via `Arc`. Tool handlers consult it before any device
//! interaction.

use crate::error::JmcpError;
use crate::inventory::{Action, RuleSpec};
use globset::{Glob, GlobMatcher};

/// Origin of a rule, used for tiebreaking equal-specificity matches and for
/// the human-readable error message on denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    Defaults,
    Device,
}

impl RuleSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Defaults => "defaults",
            Self::Device => "device",
        }
    }
}

/// A glob rule with its compiled matcher and pre-computed specificity score.
#[derive(Debug)]
pub struct CompiledRule {
    pub pattern: String,
    pub action: Action,
    pub source: RuleSource,
    pub matcher: GlobMatcher,
    /// Higher = more specific. Tuple is `(literal_chars, total_len)`.
    pub specificity: (usize, usize),
}

/// Count non-wildcard, non-character-class literal characters in a glob pattern.
/// `*`, `?`, and `[...]` ranges are wildcards; everything else (including
/// escaped characters) counts.
pub(crate) fn count_literal_chars(pattern: &str) -> usize {
    let mut count = 0usize;
    let mut in_class = false;
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if in_class {
            if c == ']' {
                in_class = false;
            }
            continue;
        }
        match c {
            '*' | '?' => continue,
            '[' => {
                in_class = true;
                continue;
            }
            '\\' => {
                if chars.next().is_some() {
                    count += 1;
                }
            }
            _ => count += 1,
        }
    }
    count
}

/// Compile a list of `RuleSpec`s into `CompiledRule`s, attaching the given
/// `source` and a scope label used in compile-time error messages.
pub(crate) fn compile_rules(
    rules: &[RuleSpec],
    scope: &str,
    source: RuleSource,
) -> Result<Vec<CompiledRule>, JmcpError> {
    rules
        .iter()
        .map(|r| {
            let glob = Glob::new(&r.pattern).map_err(|e| JmcpError::BlocklistRuleInvalid {
                scope: scope.to_string(),
                pattern: r.pattern.clone(),
                source: e,
            })?;
            let literal_chars = count_literal_chars(&r.pattern);
            Ok(CompiledRule {
                pattern: r.pattern.clone(),
                action: r.action,
                source,
                matcher: glob.compile_matcher(),
                specificity: (literal_chars, r.pattern.len()),
            })
        })
        .collect()
}

// BlocklistRules is the return type of inv.blocklist_defaults(); not referenced
// by name in the algorithm but included per spec for reader clarity.
#[allow(unused_imports)]
use crate::inventory::BlocklistRules;
use std::collections::HashMap;

/// Compiled, per-device blocklist policy. Built once at startup from the
/// parsed inventory.
#[derive(Debug)]
pub struct Policy {
    /// Compiled defaults (commands, config) shared by every device.
    default_commands: Vec<CompiledRule>,
    default_config: Vec<CompiledRule>,
    /// Per-device additions to defaults.
    device_commands: HashMap<String, Vec<CompiledRule>>,
    device_config: HashMap<String, Vec<CompiledRule>>,
}

impl Policy {
    /// Compile every glob in the inventory. Returns the first compile error
    /// encountered, scoped to its source location.
    pub fn build(inv: &crate::Inventory) -> Result<Self, JmcpError> {
        let (default_commands, default_config) = match inv.blocklist_defaults() {
            Some(d) => (
                compile_rules(
                    &d.commands,
                    "_blocklist_defaults.commands",
                    RuleSource::Defaults,
                )?,
                compile_rules(
                    &d.config,
                    "_blocklist_defaults.config",
                    RuleSource::Defaults,
                )?,
            ),
            None => (Vec::new(), Vec::new()),
        };

        let mut device_commands = HashMap::new();
        let mut device_config = HashMap::new();
        for name in inv.names() {
            let entry = inv.get(&name)?;
            if let Some(bl) = entry.blocklist.as_ref() {
                let cmd_scope = format!("device '{name}'.blocklist.commands");
                let cfg_scope = format!("device '{name}'.blocklist.config");
                device_commands.insert(
                    name.clone(),
                    compile_rules(&bl.commands, &cmd_scope, RuleSource::Device)?,
                );
                device_config.insert(
                    name.clone(),
                    compile_rules(&bl.config, &cfg_scope, RuleSource::Device)?,
                );
            }
        }

        Ok(Self {
            default_commands,
            default_config,
            device_commands,
            device_config,
        })
    }

    /// Effective command rules for a device = defaults ⊕ device.
    pub fn command_rules_for(&self, router: &str) -> Vec<&CompiledRule> {
        self.default_commands
            .iter()
            .chain(
                self.device_commands
                    .get(router)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Effective config rules for a device = defaults ⊕ device.
    pub fn config_rules_for(&self, router: &str) -> Vec<&CompiledRule> {
        self.default_config
            .iter()
            .chain(
                self.device_config
                    .get(router)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Counts for the startup info log.
    pub fn rule_counts(&self) -> PolicyCounts {
        let devices_with_rules = self
            .device_commands
            .keys()
            .chain(self.device_config.keys())
            .collect::<std::collections::HashSet<_>>()
            .len();
        PolicyCounts {
            default_commands: self.default_commands.len(),
            default_config: self.default_config.len(),
            devices_with_rules,
        }
    }
}

/// Summary numbers for startup logging.
#[derive(Debug, Clone, Copy)]
pub struct PolicyCounts {
    pub default_commands: usize,
    pub default_config: usize,
    pub devices_with_rules: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(action: Action, pattern: &str) -> RuleSpec {
        RuleSpec {
            action,
            pattern: pattern.into(),
        }
    }

    #[test]
    fn count_literals_handles_wildcards_and_classes() {
        assert_eq!(count_literal_chars("request system reboot"), 21);
        assert_eq!(count_literal_chars("request system *"), 15);
        assert_eq!(count_literal_chars("*"), 0);
        assert_eq!(count_literal_chars("?abc"), 3);
        assert_eq!(count_literal_chars("ab[cd]ef"), 4); // class doesn't count
        assert_eq!(count_literal_chars(r"\*literal"), 8); // escaped * counts as literal
    }

    #[test]
    fn compile_rules_succeeds_on_valid_globs() {
        let r = vec![
            spec(Action::Deny, "request system *"),
            spec(Action::Allow, "show version"),
        ];
        let compiled = compile_rules(&r, "test", RuleSource::Defaults).unwrap();
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].specificity, (15, 16));
        assert_eq!(compiled[0].source, RuleSource::Defaults);
    }

    #[test]
    fn compile_rules_errors_with_scope_on_bad_glob() {
        let r = vec![spec(Action::Deny, "[unterminated")];
        let err = compile_rules(&r, "_blocklist_defaults.commands", RuleSource::Defaults)
            .unwrap_err();
        match err {
            JmcpError::BlocklistRuleInvalid {
                scope, pattern, ..
            } => {
                assert_eq!(scope, "_blocklist_defaults.commands");
                assert_eq!(pattern, "[unterminated");
            }
            _ => panic!("expected BlocklistRuleInvalid, got {err:?}"),
        }
    }

    use crate::Inventory;
    use std::io::Write;

    fn inv_from(json: &str) -> Inventory {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Inventory::load(f.path()).unwrap()
    }

    #[test]
    fn build_handles_inventory_with_no_rules() {
        let inv = inv_from(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let p = Policy::build(&inv).unwrap();
        // r1 has no rules of either kind.
        assert!(p.command_rules_for("r1").is_empty());
        assert!(p.config_rules_for("r1").is_empty());
    }

    #[test]
    fn build_merges_defaults_and_device_rules() {
        let inv = inv_from(
            r#"{
                "_blocklist_defaults": {
                    "commands": [{"action":"deny","pattern":"request system *"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [{"action":"allow","pattern":"request system reboot"}]
                    }
                }
            }"#,
        );
        let p = Policy::build(&inv).unwrap();
        let r1_cmds = p.command_rules_for("r1");
        assert_eq!(r1_cmds.len(), 2);
        // One Defaults, one Device.
        assert!(r1_cmds.iter().any(|r| r.source == RuleSource::Defaults));
        assert!(r1_cmds.iter().any(|r| r.source == RuleSource::Device));
    }

    #[test]
    fn build_propagates_compile_error_with_device_scope() {
        let inv = inv_from(
            r#"{
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [{"action":"deny","pattern":"[bad"}]
                    }
                }
            }"#,
        );
        let err = Policy::build(&inv).unwrap_err();
        match err {
            JmcpError::BlocklistRuleInvalid { scope, .. } => {
                assert!(
                    scope.contains("r1"),
                    "scope should mention router name, got {scope}"
                );
                assert!(scope.contains("commands"));
            }
            _ => panic!("expected BlocklistRuleInvalid, got {err:?}"),
        }
    }
}
