//! Cargo-shaped `[publish]` / `[subscribe]` tables.
//!
//! Each entry carries a typed WIT payload reference plus optional source
//! pinning (`version` / `tag` / `rev` / `branch` / `path`). Two TOML
//! surfaces accepted per entry: a bare WIT-ref string (short form) or a
//! full inline table (long form). Exactly one source pin may be set on
//! the long form; the deserializer rejects ambiguous manifests at parse
//! time.

use serde::{Deserialize, Serialize};

/// A topic this capsule publishes (RFC: cargo-like-manifest).
///
/// Carries a typed WIT payload reference plus optional source pinning. The
/// containing key in `[publish]` is the topic name (or wildcard pattern).
///
/// Two TOML surfaces accepted:
///   - Short:  `"topic" = "@scope/repo/iface/record"` — bare WIT ref string
///   - Long:   `"topic" = { wit = "...", version = "^1.0", fanout = true, ... }`
///
/// Exactly one of `version` / `tag` / `rev` / `branch` / `path` may be set
/// for any external (`@scope/...`) reference. Bare-name local refs (no `@`)
/// need no source pin. The kernel does not yet enforce these constraints —
/// future resolver work (registry + lockfile + BLAKE3 verification) lives
/// behind the same RFC.
#[derive(Debug, Clone, Serialize)]
pub struct PublishDef {
    /// Required typed payload reference. Either a bare local record name
    /// (looks in this capsule's `wit/`) or `@scope/repo/<iface>/<record>`
    /// (resolves through the registry / git source). The literal string
    /// `"opaque"` marks an entry whose payload is not type-checked — used
    /// by uplink/proxy capsules that route opaque bytes.
    pub wit: String,
    /// Registry-resolved version requirement (semver).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Git tag pin (registry bypass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Git SHA pin (registry bypass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    /// Git branch pin (floating; lockfile pins SHA at lock-time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Local filesystem path (development; no checksum verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Marks a wildcard publish where the suffix segment names a recipient
    /// (e.g. `llm.v1.request.generate.*` per provider). Documentation hint
    /// for tooling — kernel routes wildcards either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fanout: bool,
}

impl<'de> Deserialize<'de> for PublishDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept either a bare WIT ref string (short form) or a full table.
        // Defining the long form via #[derive] would recursively call this
        // impl — use a private mirror struct with the derived impl instead.
        #[derive(Deserialize)]
        struct LongForm {
            wit: String,
            #[serde(default)]
            version: Option<String>,
            #[serde(default)]
            tag: Option<String>,
            #[serde(default)]
            rev: Option<String>,
            #[serde(default)]
            branch: Option<String>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default)]
            fanout: bool,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Short(String),
            Long(LongForm),
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(match raw {
            Raw::Short(wit) => PublishDef {
                wit,
                version: None,
                tag: None,
                rev: None,
                branch: None,
                path: None,
                fanout: false,
            },
            Raw::Long(l) => {
                let pins = [&l.version, &l.tag, &l.rev, &l.branch, &l.path]
                    .iter()
                    .filter(|o| o.is_some())
                    .count();
                if pins > 1 {
                    return Err(serde::de::Error::custom(
                        "[publish] entry: at most one of version / tag / rev / branch / path may be set",
                    ));
                }
                PublishDef {
                    wit: l.wit,
                    version: l.version,
                    tag: l.tag,
                    rev: l.rev,
                    branch: l.branch,
                    path: l.path,
                    fanout: l.fanout,
                }
            },
        })
    }
}

/// A topic this capsule subscribes to (RFC: cargo-like-manifest).
///
/// Mirrors [`PublishDef`] plus an optional `handler` field that binds the
/// topic to a `#[astrid::interceptor("...")]` export in the WASM guest.
/// Entries without `handler` grant ACL only — the guest must still call
/// `ipc::subscribe()` to actually receive events.
///
/// Same dual TOML surface as [`PublishDef`] (short string or table form).
#[derive(Debug, Clone, Serialize)]
pub struct SubscribeDef {
    /// Required typed payload reference. See [`PublishDef::wit`].
    pub wit: String,
    /// Registry-resolved version requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Git tag pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Git SHA pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    /// Git branch pin (floating).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Local filesystem path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Name of the `#[astrid::interceptor("...")]` export to bind. A
    /// `[subscribe]` entry with a `handler` is the single way to declare an
    /// interceptor binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
    /// Dispatch priority for the bound interceptor — lower values fire first
    /// (default 100). Enables layered interception (e.g. an input guard at 10
    /// ahead of the react loop at 100). Only meaningful alongside a `handler`;
    /// a `priority` on a handler-less (ACL-only) entry is rejected at parse
    /// time. `None` means the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

impl<'de> Deserialize<'de> for SubscribeDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct LongForm {
            wit: String,
            #[serde(default)]
            version: Option<String>,
            #[serde(default)]
            tag: Option<String>,
            #[serde(default)]
            rev: Option<String>,
            #[serde(default)]
            branch: Option<String>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default)]
            handler: Option<String>,
            #[serde(default)]
            priority: Option<u32>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Short(String),
            Long(LongForm),
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(match raw {
            Raw::Short(wit) => SubscribeDef {
                wit,
                version: None,
                tag: None,
                rev: None,
                branch: None,
                path: None,
                handler: None,
                priority: None,
            },
            Raw::Long(l) => {
                let pins = [&l.version, &l.tag, &l.rev, &l.branch, &l.path]
                    .iter()
                    .filter(|o| o.is_some())
                    .count();
                if pins > 1 {
                    return Err(serde::de::Error::custom(
                        "[subscribe] entry: at most one of version / tag / rev / branch / path may be set",
                    ));
                }
                if l.priority.is_some() && l.handler.is_none() {
                    return Err(serde::de::Error::custom(
                        "[subscribe] entry: `priority` requires a `handler` — a handler-less \
                         subscribe is ACL-only and has no dispatch order",
                    ));
                }
                SubscribeDef {
                    wit: l.wit,
                    version: l.version,
                    tag: l.tag,
                    rev: l.rev,
                    branch: l.branch,
                    path: l.path,
                    handler: l.handler,
                    priority: l.priority,
                }
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_publish(entry: &str) -> Result<PublishDef, toml::de::Error> {
        let toml = format!("\"x.v1.y\" = {entry}\n");
        let map: std::collections::HashMap<String, PublishDef> = toml::from_str(&toml)?;
        Ok(map.into_iter().next().unwrap().1)
    }

    fn parse_subscribe(entry: &str) -> Result<SubscribeDef, toml::de::Error> {
        let toml = format!("\"x.v1.y\" = {entry}\n");
        let map: std::collections::HashMap<String, SubscribeDef> = toml::from_str(&toml)?;
        Ok(map.into_iter().next().unwrap().1)
    }

    #[test]
    fn publish_short_form_parses() {
        let p = parse_publish("\"@scope/wit/iface/rec\"").unwrap();
        assert_eq!(p.wit, "@scope/wit/iface/rec");
        assert!(p.version.is_none() && p.tag.is_none() && p.rev.is_none());
    }

    #[test]
    fn publish_long_form_zero_pins_parses() {
        let p = parse_publish("{ wit = \"r\" }").unwrap();
        assert_eq!(p.wit, "r");
    }

    #[test]
    fn publish_long_form_one_pin_parses() {
        let p = parse_publish("{ wit = \"r\", version = \"1.0\" }").unwrap();
        assert_eq!(p.version.as_deref(), Some("1.0"));
    }

    #[test]
    fn publish_long_form_two_pins_rejected() {
        let err = parse_publish("{ wit = \"r\", version = \"1.0\", tag = \"v1\" }").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("at most one of version / tag / rev / branch / path"),
            "missing invariant message: {msg}"
        );
        assert!(
            msg.contains("x.v1.y"),
            "TOML deserializer should include the topic key in the error context: {msg}"
        );
    }

    #[test]
    fn subscribe_short_form_parses() {
        let s = parse_subscribe("\"r\"").unwrap();
        assert_eq!(s.wit, "r");
        assert!(s.handler.is_none());
    }

    #[test]
    fn subscribe_long_form_one_pin_with_handler_parses() {
        let s = parse_subscribe("{ wit = \"r\", rev = \"abc123\", handler = \"on_x\" }").unwrap();
        assert_eq!(s.rev.as_deref(), Some("abc123"));
        assert_eq!(s.handler.as_deref(), Some("on_x"));
    }

    #[test]
    fn subscribe_long_form_two_pins_rejected() {
        let err =
            parse_subscribe("{ wit = \"r\", branch = \"main\", path = \"./local\" }").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("at most one of version / tag / rev / branch / path"),
            "missing invariant message: {msg}"
        );
    }

    #[test]
    fn subscribe_priority_with_handler_parses() {
        let s = parse_subscribe("{ wit = \"r\", handler = \"on_x\", priority = 10 }").unwrap();
        assert_eq!(s.handler.as_deref(), Some("on_x"));
        assert_eq!(s.priority, Some(10));
    }

    #[test]
    fn subscribe_handler_without_priority_leaves_priority_unset() {
        let s = parse_subscribe("{ wit = \"r\", handler = \"on_x\" }").unwrap();
        assert_eq!(s.handler.as_deref(), Some("on_x"));
        assert!(s.priority.is_none());
    }

    #[test]
    fn subscribe_priority_without_handler_rejected() {
        let err = parse_subscribe("{ wit = \"r\", priority = 10 }").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("`priority` requires a `handler`"),
            "missing priority-needs-handler message: {msg}"
        );
    }
}
