//! Describe `#[serde(alias = "...")]` keys in the generated JSON schema.
//!
//! `schemars` derives a schema from the Rust field names and has no visibility
//! into serde's aliases. That was harmless while the schemas were open: an
//! alias key was simply undescribed, and a client could send it anyway.
//!
//! It stops being harmless once the schemas close with
//! `additionalProperties: false` (#253). A closed schema is a promise that the
//! listed properties are the accepted ones, so every alias the deserializer
//! honours has to appear — otherwise the server advertises its own documented
//! backward-compatible spellings (`router`, `router_name`, `routers`, …) as
//! invalid, and a client that validates before calling would refuse to send
//! them.

use schemars::Schema;
use serde_json::{Map, Value, json};

/// Mirror serde aliases into a generated schema.
///
/// For each `(canonical, aliases)` group this:
///
/// - copies the canonical property's subschema under each alias name, noting in
///   the description which property it is an alias for, and
/// - if `canonical` appears in `required`, moves that requirement into a
///   `oneOf` over the whole group — any one of the names satisfies the
///   deserializer, and only one of them may be supplied, since serde maps them
///   all onto the same field and rejects a second as a duplicate; or
/// - if the group is optional, publishes the same mutual exclusion as pairwise
///   `not` constraints.
///
/// A group naming a property the schema does not have is a bug in the caller —
/// the transform silently does nothing, which is exactly the failure it exists
/// to prevent. It trips a `debug_assert` so tests catch it, and degrades to
/// "alias not advertised" in release rather than producing a malformed schema.
///
/// Intended as a `#[schemars(transform = ...)]` target; see [`device_aliases`].
///
/// # Panics
///
/// In debug builds, if a group names a property the schema does not define.
pub fn describe_aliases(schema: &mut Schema, groups: &[(&str, &[&str])]) {
    // Snapshot first: aliases are copied from the *original* properties, so a
    // group cannot pick up a subschema another group just inserted.
    let Some(original) = schema.get("properties").and_then(Value::as_object).cloned() else {
        return;
    };

    let mut required_choices: Vec<Value> = Vec::new();

    for (canonical, aliases) in groups {
        let Some(subschema) = original.get(*canonical) else {
            debug_assert!(
                false,
                "alias group names `{canonical}`, which this schema does not define. \
                 The transform would silently do nothing and the aliases {aliases:?} \
                 would stay unadvertised. Known properties: {:?}",
                original.keys().collect::<Vec<_>>()
            );
            continue;
        };

        let properties = schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .expect("`properties` was read above");
        for alias in *aliases {
            let mut copy = subschema.clone();
            annotate_as_alias(&mut copy, canonical);
            properties.insert((*alias).to_string(), copy);
        }

        let mut names = vec![(*canonical).to_string()];
        names.extend(aliases.iter().map(|alias| (*alias).to_string()));

        let was_required = schema
            .get_mut("required")
            .and_then(Value::as_array_mut)
            .is_some_and(|required| {
                let present = required
                    .iter()
                    .any(|name| name.as_str() == Some(*canonical));
                if present {
                    required.retain(|name| name.as_str() != Some(*canonical));
                }
                present
            });

        if was_required {
            // `oneOf`, not `anyOf`: serde maps every spelling onto the same
            // field, so supplying two of them is a duplicate-field error at
            // runtime. `anyOf` would validate that request and the server would
            // then reject it. `oneOf` means exactly one branch may match, which
            // is precisely "one spelling, and it is not optional".
            required_choices.push(json!({
                "oneOf": names
                    .into_iter()
                    .map(|name| json!({ "required": [name] }))
                    .collect::<Vec<_>>()
            }));
        } else {
            // Optional group: nothing has to be supplied, but supplying two
            // spellings is the same duplicate-field error. Exclude each pair.
            for (index, first) in names.iter().enumerate() {
                for second in &names[index + 1..] {
                    required_choices.push(json!({
                        "not": { "required": [first, second] }
                    }));
                }
            }
        }
    }

    // Drop an emptied `required` rather than publishing `"required": []`.
    if schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        schema.remove("required");
    }

    if !required_choices.is_empty() {
        // Always `allOf`, even for a single group, so the shape does not depend
        // on how many aliased properties a struct happens to have. Safe
        // alongside `additionalProperties: false`: these subschemas carry only
        // `required`, never `properties`.
        schema.insert("allOf".to_string(), Value::Array(required_choices));
    }
}

/// Record in the copied subschema that it is an alternative spelling, so the
/// duplicate properties read as intentional to anyone inspecting the schema.
///
/// A subschema that is not an object (`true`/`false`) has nowhere to put a
/// description; the alias property itself is what matters.
fn annotate_as_alias(subschema: &mut Value, canonical: &str) {
    let note = format!("Alias for `{canonical}`; accepted for backward compatibility.");
    if let Value::Object(fields) = subschema {
        let description = match fields.get("description").and_then(Value::as_str) {
            Some(existing) => format!("{existing}\n\n{note}"),
            None => note,
        };
        fields.insert("description".to_string(), Value::String(description));
    }
}

/// The overwhelmingly common case: a `device` field aliased as `router_name`
/// and `router`.
pub fn device_aliases(schema: &mut Schema) {
    describe_aliases(schema, &[("device", &["router_name", "router"])]);
}

/// The SRX workflow argument types kept `router` as the canonical field name
/// and alias it as `router_name` — the mirror image of the Junos tools, whose
/// canonical name is `device`.
pub fn router_name_alias(schema: &mut Schema) {
    describe_aliases(schema, &[("router", &["router_name"])]);
}

/// Assert that a schema describes every key its deserializer accepts.
///
/// Shared by the argument-type tripwire tests in this crate and the SRX crate:
/// a closed schema that omits an accepted alias is the defect this module
/// exists to prevent, and it is invisible until a validating client tries the
/// call.
///
/// # Panics
///
/// Panics if `properties` is missing an expected key, naming the type.
pub fn assert_describes_keys(schema: &Map<String, Value>, type_name: &str, expected: &[&str]) {
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{type_name} schema has no `properties`"));

    for key in expected {
        assert!(
            properties.contains_key(*key),
            "{type_name} accepts `{key}` but its schema does not describe it. With \
             additionalProperties: false, a validating client would refuse to send it. \
             Add the alias to the type's #[schemars(transform = ...)] group."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_schema() -> Schema {
        Schema::try_from(json!({
            "type": "object",
            "properties": {
                "device": { "type": "string", "description": "The name of the device." },
                "timeout": { "type": "integer" }
            },
            "required": ["device"],
            "additionalProperties": false
        }))
        .unwrap()
    }

    #[test]
    fn alias_properties_are_added_with_the_canonical_subschema() {
        let mut schema = object_schema();
        describe_aliases(&mut schema, &[("device", &["router_name", "router"])]);

        let properties = schema.get("properties").unwrap().as_object().unwrap();
        for alias in ["router_name", "router"] {
            let subschema = properties
                .get(alias)
                .unwrap_or_else(|| panic!("{alias} must be described"));
            assert_eq!(subschema.get("type").unwrap(), "string");
            assert!(
                subschema
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap()
                    .contains("Alias for `device`"),
                "the copy must say what it is an alias for"
            );
        }
    }

    /// The point of the `anyOf`: a caller supplying only `router_name` must
    /// validate, which a bare `required: ["device"]` would reject.
    #[test]
    fn a_required_property_becomes_a_choice_across_its_aliases() {
        let mut schema = object_schema();
        describe_aliases(&mut schema, &[("device", &["router_name", "router"])]);

        assert!(
            schema.get("required").is_none(),
            "`device` was the only required property, so `required` should be gone"
        );

        let choices = schema.get("allOf").unwrap().as_array().unwrap();
        assert_eq!(choices.len(), 1);
        let one_of = choices[0].get("oneOf").unwrap().as_array().unwrap();
        let names: Vec<&str> = one_of
            .iter()
            .map(|choice| choice["required"][0].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["device", "router_name", "router"]);
    }

    #[test]
    fn other_required_properties_are_left_alone() {
        let mut schema = Schema::try_from(json!({
            "type": "object",
            "properties": {
                "devices": { "type": "array" },
                "commands": { "type": "array" }
            },
            "required": ["devices", "commands"],
            "additionalProperties": false
        }))
        .unwrap();
        describe_aliases(&mut schema, &[("devices", &["routers"])]);

        assert_eq!(
            schema.get("required").unwrap().as_array().unwrap(),
            &vec![json!("commands")],
            "`commands` has no aliases and must stay a plain requirement"
        );
        assert!(schema.get("allOf").is_some());
    }

    #[test]
    fn an_optional_property_gains_aliases_without_an_any_of() {
        let mut schema = object_schema();
        describe_aliases(&mut schema, &[("timeout", &["timeout_secs"])]);

        assert!(
            schema
                .get("properties")
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("timeout_secs")
        );
        // Optional, so nothing becomes required — but the two spellings still
        // may not both be supplied.
        assert_eq!(
            schema.get("allOf").unwrap().as_array().unwrap(),
            &vec![json!({ "not": { "required": ["timeout", "timeout_secs"] } })]
        );
        assert_eq!(
            schema.get("required").unwrap().as_array().unwrap(),
            &vec![json!("device")]
        );
    }

    /// Naming a property the schema does not define makes the whole transform a
    /// no-op while the schema still closes — aliases quietly disappear and
    /// nothing else fails. Debug builds refuse it so tests catch the mistake.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "which this schema does not define")]
    fn an_unknown_canonical_name_trips_a_debug_assert() {
        let mut schema = object_schema();
        describe_aliases(&mut schema, &[("nonexistent", &["whatever"])]);
    }
}
