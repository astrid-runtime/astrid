use super::*;

fn capsule(template: &str) -> DistroCapsule {
    let mut capsule: DistroCapsule =
        toml::from_str("name = 'provider'\nsource = './provider.capsule'\nversion = '1.0.0'")
            .unwrap();
    capsule.env.insert("model".into(), template.into());
    capsule
}

#[test]
fn distro_defaults_preserve_existing_config_and_seed_missing_keys() {
    for template in ["{{ model }}", "literal-default"] {
        for already_set in [false, true] {
            let vars = ResolvedVariables {
                values: HashMap::from([("model".into(), "default-model".into())]),
                ..Default::default()
            };
            let mut writes = Vec::new();
            write_env_with(
                &[capsule(template)],
                &HashMap::new(),
                &vars,
                |_| {
                    Ok(if already_set {
                        HashSet::from(["model".into()])
                    } else {
                        HashSet::new()
                    })
                },
                |_, _, value, _| {
                    writes.push(value.to_owned());
                    Ok(())
                },
            )
            .unwrap();
            if already_set {
                assert!(writes.is_empty(), "init must not reset an operator value");
            } else {
                assert_eq!(writes, [resolve_template(template, &vars.values)]);
            }
        }
    }
}

#[test]
fn explicit_variable_overrides_existing_config_even_if_equal_to_default() {
    let vars = ResolvedVariables {
        values: HashMap::from([("model".into(), "default-model".into())]),
        explicit: HashSet::from(["model".into()]),
    };
    let mut writes = Vec::new();
    write_env_with(
        &[capsule("prefix-{{ model }}")],
        &HashMap::new(),
        &vars,
        |_| Ok(HashSet::from(["model".into()])),
        |_, _, value, _| {
            writes.push(value.to_owned());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(writes, ["prefix-default-model"]);
}

#[test]
fn failed_existing_config_lookup_never_overwrites_with_defaults() {
    let mut writes = 0;
    let result = write_env_with(
        &[capsule("literal-default")],
        &HashMap::new(),
        &ResolvedVariables::default(),
        |_| anyhow::bail!("daemon unavailable"),
        |_, _, _, _| {
            writes += 1;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(writes, 0);
}

#[test]
fn explicit_empty_nonsecret_value_is_not_treated_as_missing() {
    let vars = ResolvedVariables {
        values: HashMap::from([("model".into(), String::new())]),
        explicit: HashSet::from(["model".into()]),
    };
    let mut writes = Vec::new();
    write_env_with(
        &[capsule("{{ model }}")],
        &HashMap::new(),
        &vars,
        |_| panic!("explicit input does not need a default lookup"),
        |_, _, value, _| {
            writes.push(value.to_owned());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(writes, [""]);
}

#[test]
fn optional_empty_secret_still_does_not_read_or_write_daemon_state() {
    let vars = ResolvedVariables {
        values: HashMap::from([("model".into(), String::new())]),
        explicit: HashSet::from(["model".into()]),
    };
    let variables = HashMap::from([(
        "model".into(),
        VariableDef {
            secret: true,
            default: Some(String::new()),
            description: None,
        },
    )]);
    write_env_with(
        &[capsule("Bearer {{ model }}")],
        &variables,
        &vars,
        |_| panic!("empty optional credential must not access daemon"),
        |_, _, _, _| panic!("empty optional credential must not overwrite"),
    )
    .unwrap();
}
