use toml::Value;

#[test]
fn e2e_waiter_manifest_documents_correlation_and_recovery_contracts() {
    let parsed: Value = toml::from_str(include_str!("../../../e2e/waiter-surfaces.toml"))
        .expect("waiter-surfaces.toml parses");
    let waiters = parsed
        .get("waiters")
        .and_then(Value::as_table)
        .expect("waiter-surfaces.toml must contain a [waiters] table");

    for required in [
        "approval_host",
        "elicit_host",
        "session_gateway_bus",
        "model_registry_bus",
        "grant_on_use",
        "local_egress_consent",
    ] {
        assert!(
            waiters.contains_key(required),
            "waiter manifest is missing required surface {required:?}"
        );
    }

    for (name, entry) in waiters {
        let table = entry
            .as_table()
            .unwrap_or_else(|| panic!("waiter {name:?} must be a table"));
        for field in [
            "owner",
            "status",
            "request",
            "response",
            "correlation",
            "timeout",
            "cancel",
            "runtime_coverage",
            "unit_coverage",
            "remaining",
        ] {
            assert!(
                table.contains_key(field),
                "waiter {name:?} is missing required field {field:?}"
            );
        }

        let status = table
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("waiter {name:?} has non-string status"));
        assert!(
            matches!(status, "covered" | "mapped" | "waived" | "future"),
            "waiter {name:?} has invalid status {status:?}"
        );

        assert!(
            non_empty_string(table, "owner")
                && non_empty_string(table, "request")
                && non_empty_string(table, "response")
                && non_empty_string(table, "timeout")
                && non_empty_string(table, "cancel"),
            "waiter {name:?} must describe owner/request/response/timeout/cancel"
        );
        for field in [
            "correlation",
            "runtime_coverage",
            "unit_coverage",
            "remaining",
        ] {
            assert_string_array(name, table, field);
        }
        assert!(
            non_empty_array(table, "correlation"),
            "waiter {name:?} must name its correlation keys"
        );

        let runtime = non_empty_array(table, "runtime_coverage");
        let unit = non_empty_array(table, "unit_coverage");
        let remaining = non_empty_array(table, "remaining");
        match status {
            "covered" => {
                assert!(
                    runtime || unit,
                    "covered waiter {name:?} needs runtime or unit coverage evidence"
                );
                assert!(
                    !remaining,
                    "covered waiter {name:?} must not carry remaining work"
                );
            },
            "mapped" => {
                assert!(
                    remaining,
                    "mapped waiter {name:?} needs explicit remaining work"
                );
            },
            "waived" | "future" => {
                assert!(
                    remaining,
                    "{status} waiter {name:?} needs an explicit reason in remaining"
                );
            },
            _ => unreachable!(),
        }
    }
}

fn non_empty_string(table: &toml::value::Table, field: &str) -> bool {
    table
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

fn non_empty_array(table: &toml::value::Table, field: &str) -> bool {
    table
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.as_str().is_some_and(|value| !value.trim().is_empty()))
        })
}

fn assert_string_array(name: &str, table: &toml::value::Table, field: &str) {
    let values = table
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("waiter {name:?} must have array field {field:?}"));
    for value in values {
        let Some(item) = value.as_str() else {
            panic!("waiter {name:?} has non-string {field:?} item");
        };
        assert!(
            !item.trim().is_empty(),
            "waiter {name:?} has empty {field:?} item"
        );
    }
}
