use super::*;

#[test]
fn native_input_bindings_are_explicit_and_validated() {
    assert!(NativeInputConfig::default().bindings().unwrap().is_empty());
    for (principal, device) in [
        ("anonymous", "0123456789abcdef"),
        ("alice", "bad"),
        ("../alice", "0123456789abcdef"),
    ] {
        let config = NativeInputConfig {
            responders: [(principal.into(), device.into())].into(),
        };
        assert!(config.bindings().is_err());
    }
    let config = NativeInputConfig {
        responders: [("alice".into(), "0123456789abcdef".into())].into(),
    };
    assert_eq!(config.bindings().unwrap().len(), 1);
}

#[test]
fn workspace_cannot_add_replace_or_remove_native_input_bindings() {
    for baseline in ["", "[native_input.responders]\nalice = '0123456789abcdef'"] {
        for overlay in [
            "[native_input.responders]\nalice = 'fedcba9876543210'",
            "[native_input.responders]\nbob = '0123456789abcdef'",
            "native_input = {}",
        ] {
            let baseline: toml::Value = toml::from_str(baseline).unwrap();
            let overlay: toml::Value = toml::from_str(overlay).unwrap();
            let mut merged = baseline.clone();
            crate::merge::deep_merge(&mut merged, &overlay);
            crate::merge::enforce_restrictions(&mut merged, &baseline, &overlay);
            assert_eq!(merged.get("native_input"), baseline.get("native_input"));
        }
    }
}
