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

/// Outcome of a policy check.
#[derive(Debug)]
pub enum Decision<'a> {
    Allow,
    Deny {
        rule: &'a CompiledRule,
        source: RuleSource,
        /// Set only for config-domain checks; identifies the offending line
        /// (1-indexed, comment lines counted).
        line_number: Option<usize>,
    },
}

/// Trim and collapse runs of whitespace to a single space.
pub(crate) fn normalize_input(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_ws = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            if !last_was_ws {
                out.push(' ');
                last_was_ws = true;
            }
        } else {
            out.push(c);
            last_was_ws = false;
        }
    }
    out
}

/// Pick the most-specific matching rule. Tiebreak: device > defaults.
fn evaluate<'r>(rules: &[&'r CompiledRule], candidate: &str) -> Option<&'r CompiledRule> {
    rules
        .iter()
        .filter(|r| r.matcher.is_match(candidate))
        .copied()
        .max_by(|a, b| {
            a.specificity
                .cmp(&b.specificity)
                .then_with(|| match (a.source, b.source) {
                    (RuleSource::Device, RuleSource::Defaults) => std::cmp::Ordering::Greater,
                    (RuleSource::Defaults, RuleSource::Device) => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Equal,
                })
        })
}

use std::collections::HashMap;

/// Compiled, per-device blocklist policy. Built once at startup from the
/// parsed inventory.
#[derive(Debug)]
pub struct Policy {
    /// Compiled defaults (commands, config, pfe_commands) shared by every device.
    default_commands: Vec<CompiledRule>,
    default_config: Vec<CompiledRule>,
    default_pfe_commands: Vec<CompiledRule>,
    /// Per-device additions to defaults.
    device_commands: HashMap<String, Vec<CompiledRule>>,
    device_config: HashMap<String, Vec<CompiledRule>>,
    device_pfe_commands: HashMap<String, Vec<CompiledRule>>,
}

impl Policy {
    /// Compile every glob in the inventory. Returns the first compile error
    /// encountered, scoped to its source location.
    pub fn build(inv: &crate::Inventory) -> Result<Self, JmcpError> {
        let (default_commands, default_config, default_pfe_commands) =
            match inv.blocklist_defaults() {
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
                    compile_rules(
                        &d.pfe_commands,
                        "_blocklist_defaults.pfe_commands",
                        RuleSource::Defaults,
                    )?,
                ),
                None => (Vec::new(), Vec::new(), Vec::new()),
            };

        let mut device_commands = HashMap::new();
        let mut device_config = HashMap::new();
        let mut device_pfe_commands = HashMap::new();
        for name in inv.names() {
            let entry = inv.get(&name)?;
            if let Some(bl) = entry.blocklist.as_ref() {
                let cmd_scope = format!("device '{name}'.blocklist.commands");
                let cfg_scope = format!("device '{name}'.blocklist.config");
                let pfe_scope = format!("device '{name}'.blocklist.pfe_commands");
                let cmds = compile_rules(&bl.commands, &cmd_scope, RuleSource::Device)?;
                if !cmds.is_empty() {
                    device_commands.insert(name.clone(), cmds);
                }
                let cfgs = compile_rules(&bl.config, &cfg_scope, RuleSource::Device)?;
                if !cfgs.is_empty() {
                    device_config.insert(name.clone(), cfgs);
                }
                let pfes = compile_rules(&bl.pfe_commands, &pfe_scope, RuleSource::Device)?;
                if !pfes.is_empty() {
                    device_pfe_commands.insert(name.clone(), pfes);
                }
            }
        }

        Ok(Self {
            default_commands,
            default_config,
            default_pfe_commands,
            device_commands,
            device_config,
            device_pfe_commands,
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

    /// True if the per-router effective config rule list is non-empty.
    pub fn has_config_rules_for(&self, router: &str) -> bool {
        !self.default_config.is_empty()
            || self
                .device_config
                .get(router)
                .is_some_and(|v| !v.is_empty())
    }

    /// Effective PFE-command rules for a device = defaults ⊕ device.
    pub fn pfe_command_rules_for(&self, router: &str) -> Vec<&CompiledRule> {
        self.default_pfe_commands
            .iter()
            .chain(
                self.device_pfe_commands
                    .get(router)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Decide whether `command` is allowed on `router`. Whitespace-normalized
    /// before matching.
    pub fn check_command<'a>(&'a self, router: &str, command: &str) -> Decision<'a> {
        let normalized = normalize_input(command);
        let rules = self.command_rules_for(router);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == Action::Deny => Decision::Deny {
                rule,
                source: rule.source,
                line_number: None,
            },
            _ => Decision::Allow,
        }
    }

    /// Decide whether `pfe_command` is allowed on `router`. Whitespace-normalized
    /// before matching. Independent from `check_command`.
    pub fn check_pfe_command<'a>(&'a self, router: &str, pfe_command: &str) -> Decision<'a> {
        let normalized = normalize_input(pfe_command);
        let rules = self.pfe_command_rules_for(router);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == Action::Deny => Decision::Deny {
                rule,
                source: rule.source,
                line_number: None,
            },
            _ => Decision::Allow,
        }
    }

    /// Decide whether `config_text` is allowed on `router` for the given
    /// `config_format`. Returns `Err` if `config_format != "set"` and the
    /// device has any effective config rules.
    pub fn check_config<'a>(
        &'a self,
        router: &str,
        config_format: &str,
        config_text: &str,
    ) -> Result<Decision<'a>, JmcpError> {
        let rules = self.config_rules_for(router);
        if rules.is_empty() {
            return Ok(Decision::Allow);
        }
        if config_format != "set" {
            return Err(JmcpError::ConfigFormatNotAllowedWithRules {
                format: config_format.to_string(),
            });
        }

        for (idx, raw_line) in config_text.lines().enumerate() {
            let line = normalize_input(raw_line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rule) = evaluate(&rules, &line) {
                if rule.action == Action::Deny {
                    return Ok(Decision::Deny {
                        rule,
                        source: rule.source,
                        line_number: Some(idx + 1),
                    });
                }
            }
        }
        Ok(Decision::Allow)
    }

    /// Counts for the startup info log.
    pub fn rule_counts(&self) -> PolicyCounts {
        let devices_with_rules = self
            .device_commands
            .keys()
            .chain(self.device_config.keys())
            .chain(self.device_pfe_commands.keys())
            .collect::<std::collections::HashSet<_>>()
            .len();
        PolicyCounts {
            default_commands: self.default_commands.len(),
            default_config: self.default_config.len(),
            default_pfe_commands: self.default_pfe_commands.len(),
            devices_with_rules,
        }
    }
}

/// Summary numbers for startup logging.
#[derive(Debug, Clone, Copy)]
pub struct PolicyCounts {
    pub default_commands: usize,
    pub default_config: usize,
    pub default_pfe_commands: usize,
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
        let err =
            compile_rules(&r, "_blocklist_defaults.commands", RuleSource::Defaults).unwrap_err();
        match err {
            JmcpError::BlocklistRuleInvalid { scope, pattern, .. } => {
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
    fn empty_per_device_blocklist_does_not_inflate_rule_counts() {
        let inv = inv_from(
            r#"{
                "_blocklist_defaults": {
                    "commands": [{"action":"deny","pattern":"x"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {}
                }
            }"#,
        );
        let p = Policy::build(&inv).unwrap();
        let counts = p.rule_counts();
        assert_eq!(counts.default_commands, 1);
        assert_eq!(counts.default_config, 0);
        assert_eq!(
            counts.devices_with_rules, 0,
            "r1 has empty blocklist; should not count"
        );
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

    use crate::policy::Decision;

    fn build_policy(json: &str) -> Policy {
        Policy::build(&inv_from(json)).unwrap()
    }

    #[test]
    fn no_rules_allows() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        assert!(matches!(
            p.check_command("r1", "show version"),
            Decision::Allow
        ));
    }

    #[test]
    fn equal_specificity_device_wins() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {"commands":[{"action":"allow","pattern":"request system *"}]}
                }
            }"#,
        );
        assert!(matches!(
            p.check_command("r1", "request system reboot"),
            Decision::Allow
        ));
    }

    #[test]
    fn more_specific_device_allow_overrides_broader_top_deny() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {"commands":[{"action":"allow","pattern":"request system reboot"}]}
                }
            }"#,
        );
        assert!(matches!(
            p.check_command("r1", "request system reboot"),
            Decision::Allow
        ));
        assert!(matches!(
            p.check_command("r1", "request system halt"),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn whitespace_is_normalized() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system reboot"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(matches!(
            p.check_command("r1", "  request   system\treboot  "),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn deny_carries_matched_rule_metadata() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        match p.check_command("r1", "request system reboot") {
            Decision::Deny {
                rule,
                source,
                line_number,
            } => {
                assert_eq!(rule.pattern, "request system *");
                assert_eq!(source, RuleSource::Defaults);
                assert!(line_number.is_none());
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn config_no_rules_allows_any_format() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let r = p.check_config("r1", "xml", "<configuration/>").unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn config_non_set_format_with_rules_present_errors() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let err = p.check_config("r1", "xml", "<x/>").unwrap_err();
        match err {
            JmcpError::ConfigFormatNotAllowedWithRules { format } => {
                assert_eq!(format, "xml");
            }
            other => panic!("expected ConfigFormatNotAllowedWithRules, got {other:?}"),
        }
    }

    #[test]
    fn config_per_line_match_rejects_first_offending_line() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let payload =
            "set interfaces ge-0/0/0 description ok\ndelete protocols bgp\nset system host-name r1";
        match p.check_config("r1", "set", payload).unwrap() {
            Decision::Deny {
                line_number, rule, ..
            } => {
                assert_eq!(line_number, Some(2));
                assert_eq!(rule.pattern, "delete *");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn config_comment_lines_are_skipped() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let payload = "# delete this is just a comment\nset system host-name r1";
        let r = p.check_config("r1", "set", payload).unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn config_per_line_allow_carve_out_works() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {"config":[{"action":"allow","pattern":"delete interfaces ge-0/0/0"}]}
                }
            }"#,
        );
        let payload = "delete interfaces ge-0/0/0\nset interfaces ge-0/0/0 description new";
        let r = p.check_config("r1", "set", payload).unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn build_collects_pfe_commands_from_defaults_and_device() {
        let inv = inv_from(
            r#"{
                "_blocklist_defaults": {
                    "pfe_commands": [{"action":"deny","pattern":"set *"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "pfe_commands": [{"action":"allow","pattern":"set debug *"}]
                    }
                }
            }"#,
        );
        let p = Policy::build(&inv).unwrap();
        let r1_pfe = p.pfe_command_rules_for("r1");
        assert_eq!(r1_pfe.len(), 2);
        assert!(r1_pfe.iter().any(|r| r.source == RuleSource::Defaults));
        assert!(r1_pfe.iter().any(|r| r.source == RuleSource::Device));
    }

    #[test]
    fn pfe_rules_independent_from_command_rules() {
        let inv = inv_from(
            r#"{
                "_blocklist_defaults": {
                    "commands": [{"action":"deny","pattern":"request system *"}],
                    "pfe_commands": [{"action":"deny","pattern":"set *"}]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let p = Policy::build(&inv).unwrap();
        assert_eq!(p.command_rules_for("r1").len(), 1);
        assert_eq!(p.pfe_command_rules_for("r1").len(), 1);
        assert_eq!(p.command_rules_for("r1")[0].pattern, "request system *");
        assert_eq!(p.pfe_command_rules_for("r1")[0].pattern, "set *");
    }

    #[test]
    fn check_pfe_command_denies_when_pattern_matches() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"pfe_commands":[{"action":"deny","pattern":"set *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        match p.check_pfe_command("r1", "set jnh 0 debug") {
            Decision::Deny { rule, .. } => assert_eq!(rule.pattern, "set *"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn check_pfe_command_allows_when_no_rules() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        assert!(matches!(
            p.check_pfe_command("r1", "show jnh 0 stats"),
            Decision::Allow
        ));
    }

    #[test]
    fn check_pfe_command_does_not_consult_command_rules() {
        // A `commands` deny does NOT block a PFE call; the two rule lists are independent.
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"set *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(matches!(
            p.check_pfe_command("r1", "set anything"),
            Decision::Allow
        ));
    }
}
