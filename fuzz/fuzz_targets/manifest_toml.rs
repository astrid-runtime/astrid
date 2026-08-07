#![no_main]

use astrid_capsule::manifest::{CapsuleManifest, PublishDef, SubscribeDef};
use libfuzzer_sys::fuzz_target;
use toml::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };

    let value_result = toml::from_str::<Value>(src);
    let manifest_result = toml::from_str::<CapsuleManifest>(src);

    if let Ok(manifest) = manifest_result {
        assert!(
            value_result.is_ok(),
            "typed manifest deserialization implies syntactically valid TOML"
        );

        assert_eq!(
            manifest.effective_ipc_publish_patterns().len(),
            manifest.publishes.len()
        );
        assert_eq!(
            manifest.effective_ipc_subscribe_patterns().len(),
            manifest.subscribes.len()
        );

        for publish in manifest.publishes.values() {
            assert_at_most_one_publish_pin(publish);
        }

        for subscribe in manifest.subscribes.values() {
            assert_at_most_one_subscribe_pin(subscribe);
            assert!(
                subscribe.priority.is_none() || subscribe.handler.is_some(),
                "handler-less subscribe entries must not carry priority"
            );
        }

        for interceptor in manifest.effective_interceptors() {
            let Some(subscribe) = manifest.subscribes.get(&interceptor.event) else {
                panic!("effective interceptor must come from a subscribe entry");
            };
            assert!(subscribe.handler.is_some());
        }
    } else if let Ok(value) = value_result {
        assert_malformed_security_shapes_fail_closed(src, &value);
    }
});

fn assert_at_most_one_publish_pin(def: &PublishDef) {
    let pins = [
        def.version.as_ref(),
        def.tag.as_ref(),
        def.rev.as_ref(),
        def.branch.as_ref(),
        def.path.as_ref(),
    ]
    .into_iter()
    .flatten()
    .count();
    assert!(pins <= 1, "publish entry accepted multiple source pins");
}

fn assert_at_most_one_subscribe_pin(def: &SubscribeDef) {
    let pins = [
        def.version.as_ref(),
        def.tag.as_ref(),
        def.rev.as_ref(),
        def.branch.as_ref(),
        def.path.as_ref(),
    ]
    .into_iter()
    .flatten()
    .count();
    assert!(pins <= 1, "subscribe entry accepted multiple source pins");
}

fn assert_malformed_security_shapes_fail_closed(src: &str, value: &Value) {
    if section_has_multi_pin(value, "publish") || section_has_multi_pin(value, "subscribe") {
        assert!(
            toml::from_str::<CapsuleManifest>(src).is_err(),
            "ambiguous source pins must fail manifest parsing"
        );
    }

    if subscribe_has_priority_without_handler(value) {
        assert!(
            toml::from_str::<CapsuleManifest>(src).is_err(),
            "handler-less subscribe priority must fail manifest parsing"
        );
    }
}

fn section_has_multi_pin(value: &Value, section: &str) -> bool {
    value
        .get(section)
        .and_then(Value::as_table)
        .is_some_and(|table| table.values().any(entry_has_multi_pin))
}

fn entry_has_multi_pin(value: &Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };

    ["version", "tag", "rev", "branch", "path"]
        .into_iter()
        .filter(|key| table.contains_key(*key))
        .count()
        > 1
}

fn subscribe_has_priority_without_handler(value: &Value) -> bool {
    value
        .get("subscribe")
        .and_then(Value::as_table)
        .is_some_and(|table| {
            table.values().any(|entry| {
                entry.as_table().is_some_and(|entry| {
                    entry.contains_key("priority") && !entry.contains_key("handler")
                })
            })
        })
}
