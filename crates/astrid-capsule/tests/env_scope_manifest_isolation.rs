//! Operator-only contract for `EnvDef.scope`.
//!
//! A capsule manifest must not be able to set its own scope — otherwise a
//! malicious capsule could mark its credentials `Shared` and pull host-wide
//! values into its sandbox. `#[serde(skip_deserializing)]` on the field
//! enforces this at the parser; the tests below pin the contract so a
//! refactor can't quietly regress it.

use astrid_capsule::manifest::{EnvDef, EnvScope};

#[test]
fn env_def_scope_is_not_deserialized_from_manifest() {
    let toml = r#"
        type = "secret"
        scope = "shared"
    "#;
    let def: EnvDef = toml::from_str(toml).expect("EnvDef should parse");
    assert_eq!(
        def.scope,
        EnvScope::Agent,
        "scope must default to Agent regardless of manifest input; operator-only field"
    );
}

#[test]
fn env_def_scope_round_trips_when_constructed_in_rust() {
    let def = EnvDef {
        env_type: "secret".into(),
        request: None,
        description: None,
        default: None,
        enum_values: vec![],
        placeholder: None,
        scope: EnvScope::Shared,
    };
    let toml = toml::to_string(&def).expect("EnvDef should serialize");
    assert!(toml.contains("scope = \"shared\""), "{toml}");
}
