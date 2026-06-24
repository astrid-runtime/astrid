//! WIT record → JSON Schema converter.
//!
//! Parses `.wit` files from a capsule's `wit/` directory and converts named
//! record types to JSON Schema objects. Field-level `///` doc comments become
//! `"description"` entries in the schema, flowing WIT documentation into the
//! schema catalog for LLM consumption (A2UI).
//!
//! The converter handles WIT primitive types, `option<T>`, `list<T>`, `tuple`,
//! and nested records. Unsupported types (resources, handles, functions) are
//! represented as opaque strings.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use wit_parser::{Resolve, Type, TypeDefKind};

/// Parsed WIT records from a capsule's `wit/` directory.
///
/// Maps kebab-case record names (e.g. `"provider-entry"`) to their JSON Schema
/// representation, including field descriptions from `///` doc comments.
pub struct WitSchemas {
    records: HashMap<String, serde_json::Value>,
}

impl WitSchemas {
    /// Parse all `.wit` files in `wit_dir` and extract record definitions.
    ///
    /// Returns an empty set if `wit_dir` does not exist or contains no `.wit` files.
    ///
    /// # Errors
    /// Returns an error if any `.wit` file fails to parse.
    pub fn from_dir(wit_dir: &Path) -> anyhow::Result<Self> {
        let mut records = HashMap::new();

        if !wit_dir.is_dir() {
            return Ok(Self { records });
        }

        // Check if there are any .wit files before calling push_dir
        // (push_dir errors on directories with no WIT package).
        let has_wit = std::fs::read_dir(wit_dir).ok().is_some_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("wit"))
        });

        if !has_wit {
            return Ok(Self { records });
        }

        let mut resolve = Resolve::default();

        // push_dir handles multi-file packages correctly (a single package
        // split across several .wit files in the same directory).
        resolve
            .push_dir(wit_dir)
            .with_context(|| format!("failed to parse WIT directory: {}", wit_dir.display()))?;

        // Extract all record type definitions.
        for (_, type_def) in &resolve.types {
            if let TypeDefKind::Record(record) = &type_def.kind {
                let name = match &type_def.name {
                    Some(n) => n.clone(),
                    None => continue, // Anonymous records are skipped.
                };

                let schema = record_to_json_schema(&resolve, record, &type_def.docs);
                records.insert(name, schema);
            }
        }

        Ok(Self { records })
    }

    /// Look up the JSON Schema for a WIT record by its kebab-case name.
    ///
    /// Returns `None` if no record with that name was found in the parsed WIT files.
    #[must_use]
    pub fn get(&self, record_name: &str) -> Option<&serde_json::Value> {
        self.records.get(record_name)
    }

    /// Returns `true` if no records were parsed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Maximum recursion depth for type resolution. Prevents stack overflow on
/// deeply nested type aliases or (hypothetical) circular references.
const MAX_TYPE_DEPTH: u32 = 32;

/// Convert a WIT record to a JSON Schema object.
fn record_to_json_schema(
    resolve: &Resolve,
    record: &wit_parser::Record,
    docs: &wit_parser::Docs,
) -> serde_json::Value {
    record_to_json_schema_depth(resolve, record, docs, 0)
}

/// Depth-limited record → JSON Schema conversion.
fn record_to_json_schema_depth(
    resolve: &Resolve,
    record: &wit_parser::Record,
    docs: &wit_parser::Docs,
    depth: u32,
) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for field in &record.fields {
        let (field_schema, is_optional) = type_to_json_schema(resolve, &field.ty, depth);

        let mut schema = field_schema;
        if let Some(ref doc) = field.docs.contents {
            let trimmed = doc.trim();
            if !trimmed.is_empty() {
                schema
                    .as_object_mut()
                    .expect("type_to_json_schema always returns an object")
                    .insert("description".into(), trimmed.into());
            }
        }

        // Convert WIT kebab-case field names to snake_case to match the
        // serde `rename_all = "snake_case"` convention used by wit_events!
        // generated Rust structs on the wire.
        let rust_field_name = field.name.replace('-', "_");

        if !is_optional {
            required.push(rust_field_name.clone());
        }

        properties.insert(rust_field_name, schema);
    }

    let mut schema = serde_json::json!({
        "type": "object",
        "properties": properties,
    });

    if !required.is_empty() {
        schema
            .as_object_mut()
            .expect("just created")
            .insert("required".into(), required.into());
    }

    // Include record-level doc comment as the schema description.
    if let Some(ref doc) = docs.contents {
        let trimmed = doc.trim();
        if !trimmed.is_empty() {
            schema
                .as_object_mut()
                .expect("just created")
                .insert("description".into(), trimmed.into());
        }
    }

    schema
}

/// Convert a WIT type to a JSON Schema type object.
///
/// Returns `(schema, is_optional)` where `is_optional` is true for `option<T>`.
fn type_to_json_schema(resolve: &Resolve, ty: &Type, depth: u32) -> (serde_json::Value, bool) {
    if depth > MAX_TYPE_DEPTH {
        return (serde_json::json!({"type": "string"}), false);
    }
    match ty {
        Type::Bool => (serde_json::json!({"type": "boolean"}), false),
        Type::U8 | Type::U16 | Type::U32 | Type::S8 | Type::S16 | Type::S32 => {
            (serde_json::json!({"type": "integer"}), false)
        },
        Type::U64 | Type::S64 => (
            serde_json::json!({"type": "integer", "format": "int64"}),
            false,
        ),
        Type::F32 | Type::F64 => (serde_json::json!({"type": "number"}), false),
        Type::Char | Type::String | Type::ErrorContext => {
            (serde_json::json!({"type": "string"}), false)
        },
        Type::Id(id) => {
            typedef_to_json_schema(resolve, &resolve.types[*id], depth.saturating_add(1))
        },
    }
}

/// Convert a named WIT type definition to JSON Schema.
fn typedef_to_json_schema(
    resolve: &Resolve,
    type_def: &wit_parser::TypeDef,
    depth: u32,
) -> (serde_json::Value, bool) {
    match &type_def.kind {
        TypeDefKind::Record(record) => (
            record_to_json_schema_depth(resolve, record, &type_def.docs, depth),
            false,
        ),
        TypeDefKind::List(inner) => {
            let (item_schema, _) = type_to_json_schema(resolve, inner, depth);
            (
                serde_json::json!({"type": "array", "items": item_schema}),
                false,
            )
        },
        TypeDefKind::Option(inner) => {
            let (inner_schema, _) = type_to_json_schema(resolve, inner, depth);
            (inner_schema, true)
        },
        TypeDefKind::Tuple(tuple) => {
            let items: Vec<serde_json::Value> = tuple
                .types
                .iter()
                .map(|t| type_to_json_schema(resolve, t, depth).0)
                .collect();
            (
                serde_json::json!({"type": "array", "prefixItems": items}),
                false,
            )
        },
        TypeDefKind::Enum(enum_def) => {
            let cases: Vec<&str> = enum_def.cases.iter().map(|c| c.name.as_str()).collect();
            (serde_json::json!({"type": "string", "enum": cases}), false)
        },
        TypeDefKind::Flags(flags_def) => {
            let names: Vec<&str> = flags_def.flags.iter().map(|f| f.name.as_str()).collect();
            (
                serde_json::json!({"type": "array", "items": {"type": "string", "enum": names}}),
                false,
            )
        },
        TypeDefKind::Variant(variant) => (variant_to_json_schema(resolve, variant, depth), false),
        TypeDefKind::Result(result_ty) => {
            let ok = result_ty.ok.as_ref().map_or_else(
                || serde_json::json!({"type": "null"}),
                |t| type_to_json_schema(resolve, t, depth).0,
            );
            let err = result_ty.err.as_ref().map_or_else(
                || serde_json::json!({"type": "null"}),
                |t| type_to_json_schema(resolve, t, depth).0,
            );
            (
                serde_json::json!({
                    "oneOf": [
                        {"type": "object", "properties": {"ok": ok}, "required": ["ok"]},
                        {"type": "object", "properties": {"err": err}, "required": ["err"]}
                    ]
                }),
                false,
            )
        },
        // Type aliases — follow the chain.
        TypeDefKind::Type(inner) => type_to_json_schema(resolve, inner, depth),
        // Anything else (resource, handle, future, stream) — opaque.
        _ => (serde_json::json!({"type": "string"}), false),
    }
}

/// Convert a WIT variant to a JSON Schema `oneOf` with tag discriminators.
fn variant_to_json_schema(
    resolve: &Resolve,
    variant: &wit_parser::Variant,
    depth: u32,
) -> serde_json::Value {
    let schemas: Vec<serde_json::Value> = variant
        .cases
        .iter()
        .map(|case| {
            if let Some(ref ty) = case.ty {
                let (inner, _) = type_to_json_schema(resolve, ty, depth);
                serde_json::json!({
                    "type": "object",
                    "properties": {"tag": {"const": case.name}, "value": inner},
                    "required": ["tag", "value"]
                })
            } else {
                serde_json::json!({
                    "type": "object",
                    "properties": {"tag": {"const": case.name}},
                    "required": ["tag"]
                })
            }
        })
        .collect();
    serde_json::json!({"oneOf": schemas})
}

/// Resolve a `wit_type` name against parsed WIT schemas for a capsule.
///
/// Reads all `.wit` files from `capsule_dir/wit/`, finds the named record,
/// and returns its JSON Schema.
///
/// # Errors
/// Returns an error if the WIT directory can't be read, WIT files fail to parse,
/// or the named record is not found.
pub fn resolve_wit_type(
    capsule_dir: &Path,
    wit_type: &str,
    topic_name: &str,
) -> anyhow::Result<serde_json::Value> {
    let wit_dir = capsule_dir.join("wit");
    let schemas = WitSchemas::from_dir(&wit_dir)?;

    schemas.get(wit_type).cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "[[topic]] '{}' references wit_type '{}' but no WIT record with that name \
             was found in {}",
            topic_name,
            wit_type,
            wit_dir.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_record() {
        let wit = r"
package test:events@1.0.0;

interface events {
    /// A test event published on the bus.
    record my-event {
        /// Unique identifier.
        id: string,
        /// Event count.
        count: u32,
        /// Optional label.
        label: option<string>,
        /// Nested list of tags.
        tags: list<string>,
    }
}
";

        let dir = tempfile::tempdir().unwrap();
        let wit_path = dir.path().join("events.wit");
        std::fs::write(&wit_path, wit).unwrap();

        let schemas = WitSchemas::from_dir(dir.path()).unwrap();
        let schema = schemas.get("my-event").unwrap();

        let obj = schema.as_object().unwrap();
        assert_eq!(obj["type"], "object");
        assert_eq!(obj["description"], "A test event published on the bus.");

        let props = obj["properties"].as_object().unwrap();
        assert_eq!(props["id"]["type"], "string");
        assert_eq!(props["id"]["description"], "Unique identifier.");
        assert_eq!(props["count"]["type"], "integer");
        assert_eq!(props["count"]["description"], "Event count.");
        assert_eq!(props["label"]["type"], "string");
        assert_eq!(props["label"]["description"], "Optional label.");
        assert_eq!(props["tags"]["type"], "array");
        assert_eq!(props["tags"]["items"]["type"], "string");

        // `label` is option<string> so should NOT be in required
        let required = obj["required"].as_array().unwrap();
        let required_names: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_names.contains(&"id"));
        assert!(required_names.contains(&"count"));
        assert!(required_names.contains(&"tags"));
        assert!(!required_names.contains(&"label"));
    }

    #[test]
    fn empty_dir_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let schemas = WitSchemas::from_dir(dir.path()).unwrap();
        assert!(schemas.is_empty());
    }

    #[test]
    fn nonexistent_dir_returns_empty() {
        let schemas = WitSchemas::from_dir(Path::new("/nonexistent/path")).unwrap();
        assert!(schemas.is_empty());
    }

    #[test]
    fn resolve_wit_type_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let wit_dir = dir.path().join("wit");
        std::fs::create_dir(&wit_dir).unwrap();
        std::fs::write(
            wit_dir.join("events.wit"),
            "package test:events@1.0.0;\ninterface events { record foo { x: string, } }",
        )
        .unwrap();

        let result = resolve_wit_type(dir.path(), "bar", "test.v1.topic");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no WIT record with that name")
        );
    }
}
