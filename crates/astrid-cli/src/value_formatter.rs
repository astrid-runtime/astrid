//! One-shot value formatting for admin command output.
//!
//! Distinct from [`crate::formatter`] which renders streaming chat
//! events. Admin commands return a single typed result and emit
//! `pretty`, `json`, `yaml`, or `toml` representations of it.
//!
//! Pretty rendering is per-command (table layout, colours) so this
//! module only covers the structured formats. The pretty path is the
//! command's responsibility.

use anyhow::{Context, Result};
use serde::Serialize;

/// Output format selected by `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ValueFormat {
    /// Human-friendly default — per-command rendering.
    #[default]
    Pretty,
    /// JSON, pretty-printed with two-space indent.
    Json,
    /// YAML, default `serde_yaml` layout.
    Yaml,
    /// TOML, default `toml::to_string_pretty` layout.
    Toml,
}

impl ValueFormat {
    /// Parse `--format` argument string. Defaults to [`Self::Pretty`].
    /// Unknown values yield `Self::Pretty` rather than an error to keep
    /// the CLI permissive — invalid values are caught by clap when the
    /// flag uses `value_parser!(ValueFormat)`.
    pub(crate) fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            "yaml" | "yml" => Self::Yaml,
            "toml" => Self::Toml,
            _ => Self::Pretty,
        }
    }

    /// Whether this format expects the caller to render pretty output
    /// itself (table, colours). True only for [`Self::Pretty`].
    pub(crate) const fn is_pretty(self) -> bool {
        matches!(self, Self::Pretty)
    }
}

/// Render `value` to stdout in the chosen structured format. Returns
/// `Ok(false)` for [`ValueFormat::Pretty`] — the caller must render its
/// own pretty output. Returns `Ok(true)` after writing for the
/// structured variants.
///
/// # Errors
///
/// Returns an error if serialization fails for the chosen format.
pub(crate) fn emit_structured<T: Serialize>(value: &T, format: ValueFormat) -> Result<bool> {
    match format {
        ValueFormat::Pretty => Ok(false),
        ValueFormat::Json => {
            let s = serde_json::to_string_pretty(value).context("Failed to render JSON")?;
            println!("{s}");
            Ok(true)
        },
        ValueFormat::Yaml => {
            let s = serde_yaml::to_string(value).context("Failed to render YAML")?;
            print!("{s}");
            Ok(true)
        },
        ValueFormat::Toml => {
            // toml::to_string_pretty refuses non-table top-levels; fall
            // back to wrapping primitives in a `{ value = ... }` table
            // so we can format every shape, not just structs.
            let try_direct = toml::to_string_pretty(value);
            let s = if let Ok(direct) = try_direct {
                direct
            } else {
                let wrapper = TomlWrapper { value };
                toml::to_string_pretty(&wrapper).context("Failed to render TOML")?
            };
            print!("{s}");
            Ok(true)
        },
    }
}

/// Single-field wrapper used to coerce non-table values into TOML.
#[derive(Serialize)]
struct TomlWrapper<'a, T: Serialize> {
    value: &'a T,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Sample {
        name: String,
        n: u32,
    }

    #[test]
    fn parse_recognises_known_formats() {
        assert_eq!(ValueFormat::parse("json"), ValueFormat::Json);
        assert_eq!(ValueFormat::parse("YAML"), ValueFormat::Yaml);
        assert_eq!(ValueFormat::parse("yml"), ValueFormat::Yaml);
        assert_eq!(ValueFormat::parse("toml"), ValueFormat::Toml);
        assert_eq!(ValueFormat::parse("pretty"), ValueFormat::Pretty);
        assert_eq!(ValueFormat::parse("anything-else"), ValueFormat::Pretty);
    }

    #[test]
    fn pretty_returns_false_so_caller_renders() {
        let s = Sample {
            name: "x".into(),
            n: 1,
        };
        let written = emit_structured(&s, ValueFormat::Pretty).unwrap();
        assert!(!written);
    }

    #[test]
    fn json_round_trip_is_parseable() {
        // Serialize to a string via the same logic emit_structured uses,
        // then re-parse to confirm the output is valid JSON. Ensures the
        // CI-pipe case (`astrid agent list --format json | jq ...`)
        // doesn't regress to a non-parseable shape.
        let s = Sample {
            name: "alice".into(),
            n: 42,
        };
        let json = serde_json::to_string_pretty(&s).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "alice");
        assert_eq!(parsed["n"], 42);
    }

    #[test]
    fn yaml_serialization_is_parseable() {
        let s = Sample {
            name: "bob".into(),
            n: 7,
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed["name"].as_str(), Some("bob"));
    }

    #[test]
    fn toml_handles_struct_round_trip() {
        let s = Sample {
            name: "c".into(),
            n: 3,
        };
        let toml = toml::to_string_pretty(&s).unwrap();
        assert!(toml.contains("name = \"c\""));
        assert!(toml.contains("n = 3"));
    }
}
