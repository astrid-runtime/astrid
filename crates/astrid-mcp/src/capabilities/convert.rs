//! rmcp ↔ core conversion helpers.
//!
//! These are internal helpers used by `client.rs` to bridge the rmcp elicitation
//! schema format with the canonical `astrid-core` types.

use astrid_core::{ElicitationSchema, SelectOption};
use serde_json::Value;

/// Convert an rmcp elicitation schema to a core elicitation schema.
///
/// The rmcp schema is a JSON Schema object with typed properties, while the core
/// schema is a simple enum (`Text`/`Secret`/`Select`/`Confirm`). This does a
/// best-effort conversion based on the first property's type.
///
/// Returns `(core_schema, first_property_name)` where the property name is used
/// to wrap single-value responses back into the object format rmcp expects.
pub(super) fn convert_rmcp_schema(
    schema: &rmcp::model::ElicitationSchema,
) -> (ElicitationSchema, Option<String>) {
    // RMCP records the peer's wire order separately from the compatibility
    // map. Prefer that order so "first property" follows the offered schema,
    // then fall back to map order for explicitly constructed schemas.
    let first = schema
        .property_order
        .as_ref()
        .and_then(|names| {
            names
                .iter()
                .find_map(|name| schema.properties.get_key_value(name))
        })
        .map(|(name, definition)| (name.clone(), definition))
        .or_else(|| {
            schema
                .properties
                .iter()
                .next()
                .map(|(name, definition)| (name.clone(), definition))
        });
    let prop_name = first.as_ref().map(|(name, _)| name.clone());

    if let Some((_, primitive)) = first {
        // Serialize the PrimitiveSchema to JSON to inspect its type without
        // depending on rmcp's internal enum variant structure.
        if let Ok(json) = serde_json::to_value(primitive) {
            let type_str = json.get("type").and_then(|t| t.as_str()).unwrap_or("");

            match type_str {
                "boolean" => {
                    let default = json
                        .get("default")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    return (ElicitationSchema::Confirm { default }, prop_name);
                },
                "string" => {
                    let placeholder = json
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from);
                    #[expect(clippy::cast_possible_truncation)]
                    let max_length = json
                        .get("maxLength")
                        .and_then(serde_json::Value::as_u64)
                        .map(|m| m as usize);
                    return (
                        ElicitationSchema::Text {
                            placeholder,
                            max_length,
                        },
                        prop_name,
                    );
                },
                _ => {},
            }

            // Check for enum type (no "type" field, has "enum" array)
            if let Some(enum_values) = json.get("enum").and_then(|e| e.as_array()) {
                let options: Vec<SelectOption> = enum_values
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| SelectOption::new(s, s))
                    .collect();
                if !options.is_empty() {
                    return (
                        ElicitationSchema::Select {
                            options,
                            multiple: false,
                        },
                        prop_name,
                    );
                }
            }
        }
    }

    // Fallback: text input with schema description as placeholder
    let placeholder = schema
        .description
        .as_ref()
        .map(std::string::ToString::to_string);
    (
        ElicitationSchema::Text {
            placeholder,
            max_length: None,
        },
        prop_name,
    )
}

/// Wrap a single response value into the object format rmcp expects.
///
/// If the value is already an object, it's returned as-is. Otherwise, it's wrapped
/// using the original property name from the schema.
pub(super) fn wrap_response_value(value: Value, prop_name: Option<&str>) -> Value {
    if value.is_object() {
        // Already an object, assume it matches the expected schema
        value
    } else if let Some(name) = prop_name {
        let mut map = serde_json::Map::new();
        map.insert(name.to_string(), value);
        Value::Object(map)
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_rmcp_schema_boolean() {
        let rmcp_schema: rmcp::model::ElicitationSchema =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "confirmed": {
                        "type": "boolean",
                        "description": "Confirm the action"
                    }
                }
            }))
            .unwrap();

        let (schema, prop_name) = convert_rmcp_schema(&rmcp_schema);
        assert!(matches!(
            schema,
            ElicitationSchema::Confirm { default: false }
        ));
        assert_eq!(prop_name, Some("confirmed".to_string()));
    }

    #[test]
    fn test_convert_rmcp_schema_string() {
        let rmcp_schema: rmcp::model::ElicitationSchema =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Enter your API key",
                        "maxLength": 128
                    }
                }
            }))
            .unwrap();

        let (schema, prop_name) = convert_rmcp_schema(&rmcp_schema);
        assert!(matches!(
            schema,
            ElicitationSchema::Text {
                placeholder: Some(_),
                max_length: Some(128),
            }
        ));
        assert_eq!(prop_name, Some("api_key".to_string()));
    }

    #[test]
    fn test_convert_rmcp_schema_honors_property_order_and_dialect() {
        // Parse from text: the project's JSON map is order-insensitive.
        let mut rmcp_schema: rmcp::model::ElicitationSchema = serde_json::from_str(
            r#"{
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "alphabetical": {"type": "boolean"},
                    "offered": {"type": "boolean"}
                }
            }"#,
        )
        .unwrap();
        rmcp_schema.property_order = Some(vec!["offered".to_owned(), "alphabetical".to_owned()]);

        assert_eq!(
            rmcp_schema.schema.as_deref(),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        let (schema, prop_name) = convert_rmcp_schema(&rmcp_schema);
        assert!(matches!(
            schema,
            ElicitationSchema::Confirm { default: false }
        ));
        assert_eq!(prop_name.as_deref(), Some("offered"));
    }

    #[test]
    fn test_wrap_response_value_primitive() {
        let value = Value::String("hello".to_string());
        let wrapped = wrap_response_value(value, Some("key"));
        assert_eq!(wrapped, serde_json::json!({"key": "hello"}));
    }

    #[test]
    fn test_wrap_response_value_object_passthrough() {
        let obj = serde_json::json!({"a": 1, "b": 2});
        let passthrough = wrap_response_value(obj.clone(), Some("key"));
        assert_eq!(passthrough, obj);
    }

    #[test]
    fn test_wrap_response_value_no_prop_name() {
        let value = Value::String("hello".to_string());
        let result = wrap_response_value(value.clone(), None);
        assert_eq!(result, value);
    }
}
