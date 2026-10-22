use super::*;

fn capsule(template: &str) -> DistroCapsule {
    let mut capsule: DistroCapsule =
        toml::from_str("name = 'provider'\nsource = './provider.capsule'\nversion = '1.0.0'")
            .unwrap();
    capsule.env.insert("model".into(), template.into());
    capsule
}

#[test]
fn distro_defaults_request_conditional_writes_but_explicit_input_overrides() {
    for template in ["{{ model }}", "literal-default", "prefix-{{ model }}"] {
        for explicit in [false, true] {
            for value in ["default-model", ""] {
                let vars = ResolvedVariables {
                    values: HashMap::from([("model".into(), value.into())]),
                    explicit: if explicit {
                        HashSet::from(["model".into()])
                    } else {
                        HashSet::new()
                    },
                };
                let mut writes = Vec::new();
                write_env_with(
                    &[capsule(template)],
                    &HashMap::new(),
                    &vars,
                    |_, _, value, kind, overwrite| {
                        writes.push((value.to_owned(), kind, overwrite));
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(
                    writes,
                    [(
                        resolve_template(template, &vars.values),
                        EnvValueKind::Text,
                        explicit && template.contains("{{ model }}")
                    )]
                );
            }
        }
    }
}

#[test]
fn optional_empty_secret_still_does_not_write() {
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
        |_, _, _, _, _| panic!("empty optional credential must not overwrite"),
    )
    .unwrap();
}

#[test]
fn conditional_write_errors_propagate_without_unconditional_retry() {
    let mut calls = 0;
    let result = write_env_with(
        &[capsule("literal-default")],
        &HashMap::new(),
        &ResolvedVariables::default(),
        |_, _, _, _, explicit| {
            assert!(!explicit);
            calls += 1;
            anyhow::bail!("unsupported operation");
        },
    );
    assert!(result.is_err());
    assert_eq!(calls, 1);
}
