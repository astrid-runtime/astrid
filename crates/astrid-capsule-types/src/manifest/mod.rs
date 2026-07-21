//! Capsule manifest types.
//!
//! A capsule manifest (`Capsule.toml`) describes a capsule's identity, entry point,
//! required capabilities, integrations, and configuration settings. Manifests are
//! loaded from disk during capsule discovery.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use astrid_core::UplinkProfile;
use astrid_core::kernel_api::CommandKind;

mod capabilities;
mod topics;

pub use capabilities::CapabilitiesDef;
pub use topics::{PublishDef, SubscribeDef};
/// A capsule manifest loaded from `Capsule.toml`.
///
/// Describes everything the runtime needs to know about a capsule before
/// loading it: identity, component entry point, capability requirements,
/// settings, and OS integrations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapsuleManifest {
    /// The package definition including name and version.
    pub package: PackageDef,
    /// The WASM components provided by this capsule.
    #[serde(default, rename = "component")]
    pub components: Vec<ComponentDef>,
    /// Namespaced interface imports — what this capsule needs from others.
    ///
    /// Outer key = namespace (e.g. `"astrid"`), inner key = interface name
    /// (e.g. `"session"`), value = version requirement and optional flag.
    ///
    /// Two TOML surface forms are accepted at deserialize time and normalized
    /// to this nested representation:
    ///   - Nested:  `[imports.astrid]` then `session = "^1.0"`
    ///   - Flat:    `[imports]` then `"astrid:session" = "^1.0"` (RFC: cargo-like-manifest)
    #[serde(default, deserialize_with = "deserialize_imports_map")]
    pub imports: ImportsMap,
    /// Namespaced interface exports — what this capsule provides.
    ///
    /// Outer key = namespace, inner key = interface name, value = exact version.
    ///
    /// Same dual-form acceptance as `imports`: either `[exports.astrid] foo = "1.0.0"`
    /// or `[exports] "astrid:foo" = "1.0.0"`.
    #[serde(default, deserialize_with = "deserialize_exports_map")]
    pub exports: ExportsMap,
    /// Topics this capsule publishes (RFC: cargo-like-manifest).
    ///
    /// Each entry is keyed by the topic name (or wildcard pattern) and carries
    /// the typed WIT payload reference plus optional source pinning. The keys
    /// are the IPC publish ACL — the only way a capsule declares what it may
    /// publish (an empty table = may not publish, fail-closed).
    #[serde(default, rename = "publish")]
    pub publishes: HashMap<String, PublishDef>,
    /// Topics this capsule subscribes to (RFC: cargo-like-manifest).
    ///
    /// Same shape as `publishes`. An entry with a `handler = "..."` field (and
    /// optional `priority`) binds the topic to a `#[astrid::interceptor("...")]`
    /// export — the single interceptor-binding form. An entry without a handler
    /// is ACL-only (use `wit = "opaque"` for an untyped proxy subscription). The
    /// keys are the IPC subscribe ACL (an empty table = may not subscribe).
    #[serde(default, rename = "subscribe")]
    pub subscribes: HashMap<String, SubscribeDef>,
    /// Tools this capsule surfaces to the LLM (RFC: cargo-like-manifest).
    ///
    /// `description_for_llm` is the only capsule-author-controlled string that
    /// reaches the LLM unattended. Operators review verbatim at install time.
    #[serde(default, rename = "tool")]
    pub tools: Vec<ToolDef>,
    /// Capabilities requested by this capsule.
    #[serde(default)]
    pub capabilities: CapabilitiesDef,
    /// Environment variables configurable by the user during docking.
    #[serde(default)]
    pub env: HashMap<String, EnvDef>,
    /// Context files to inject.
    #[serde(default, rename = "context_file")]
    pub context_files: Vec<ContextFileDef>,
    /// Commands this capsule provides.
    #[serde(default, rename = "command")]
    pub commands: Vec<CommandDef>,
    /// MCP servers this capsule exposes.
    #[serde(default, rename = "mcp_server")]
    pub mcp_servers: Vec<McpServerDef>,
    /// Source-compatibility field retained for callers that construct manifests.
    ///
    /// Astrid does not deserialize, serialize, package, or interpret this field.
    /// Agent Skills are user-space assets rather than a capsule manifest
    /// protocol. New code should leave it empty.
    #[serde(skip)]
    pub skills: Vec<SkillDef>,
    /// Uplinks this capsule provides (e.g. Telegram, CLI).
    #[serde(default, rename = "uplink")]
    pub uplinks: Vec<UplinkDef>,
}

/// Reflexive `AsRef` so the readiness functions' `M: AsRef<CapsuleManifest>`
/// bound accepts both owned slices (`&[CapsuleManifest]`, used by tests) and
/// borrowed slices (`&[&CapsuleManifest]`, used by the kernel handler and the
/// boot path that read the live registry) — without cloning every manifest on
/// each prompt probe or boot check.
impl AsRef<CapsuleManifest> for CapsuleManifest {
    fn as_ref(&self) -> &CapsuleManifest {
        self
    }
}

impl CapsuleManifest {
    /// Returns `true` if this capsule declares any imports.
    #[must_use]
    pub fn has_imports(&self) -> bool {
        self.imports.values().any(|ns| !ns.is_empty())
    }

    /// Returns `true` if this capsule declares any exports.
    #[must_use]
    pub fn has_exports(&self) -> bool {
        self.exports.values().any(|ns| !ns.is_empty())
    }

    /// Iterate all exported interfaces as `(namespace, name, version)` triples.
    pub fn export_triples(&self) -> impl Iterator<Item = (&str, &str, &semver::Version)> {
        self.exports.iter().flat_map(|(ns, ifaces)| {
            ifaces
                .iter()
                .map(move |(name, def)| (ns.as_str(), name.as_str(), &def.version))
        })
    }

    /// Iterate all imported interfaces as `(namespace, name, version_req, optional)` tuples.
    pub fn import_tuples(&self) -> impl Iterator<Item = (&str, &str, &semver::VersionReq, bool)> {
        self.imports.iter().flat_map(|(ns, ifaces)| {
            ifaces
                .iter()
                .map(move |(name, def)| (ns.as_str(), name.as_str(), &def.version, def.optional))
        })
    }

    /// IPC publish ACL patterns the kernel enforces against this capsule —
    /// the keys of the `[publish]` table. An empty list means the capsule may
    /// not publish to any topic (fail-closed). The order of the returned vector
    /// is unspecified, since the backing `[publish]` table is a `HashMap`.
    #[must_use]
    pub fn effective_ipc_publish_patterns(&self) -> Vec<String> {
        self.publishes.keys().cloned().collect()
    }

    /// IPC subscribe ACL patterns — the keys of the `[subscribe]` table. An
    /// empty list means the capsule may not subscribe to any topic
    /// (fail-closed).
    #[must_use]
    pub fn effective_ipc_subscribe_patterns(&self) -> Vec<String> {
        self.subscribes.keys().cloned().collect()
    }

    /// Interceptor bindings declared in `[subscribe]`: every entry that
    /// carries a `handler` binds that topic to a `#[astrid::interceptor]`
    /// export in the guest. The entry's optional `priority` controls dispatch
    /// order (lower fires first; `None` means the default, 100).
    ///
    /// This is the single interceptor-binding form — the legacy
    /// `[[interceptor]]` block was removed (see #858). The manifest does not set
    /// `deny_unknown_fields`, so a stray `[[interceptor]]` table is an unknown
    /// field that is silently ignored rather than rejected at load: it simply
    /// has no effect. Capsule authors must migrate any such bindings to
    /// `[subscribe]` entries that carry a `handler`.
    #[must_use]
    pub fn effective_interceptors(&self) -> Vec<InterceptorDef> {
        self.subscribes
            .iter()
            .filter_map(|(topic, def)| {
                def.handler.as_ref().map(|action| InterceptorDef {
                    event: topic.clone(),
                    action: action.clone(),
                    priority: def.priority.unwrap_or_else(default_interceptor_priority),
                })
            })
            .collect()
    }
}

/// Custom deserializer for `[imports]` accepting either the legacy nested
/// form (`[imports.astrid] session = "^1.0"`) or the cargo-like flat form
/// (`[imports] "astrid:session" = "^1.0"`). The flat form requires a colon
/// between namespace and interface name.
fn deserialize_imports_map<'de, D>(de: D) -> Result<ImportsMap, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_dual_form_map::<D, ImportDef>(de, "imports")
}

/// Custom deserializer for `[exports]` accepting either the legacy nested
/// form or the cargo-like flat form. Mirrors [`deserialize_imports_map`].
fn deserialize_exports_map<'de, D>(de: D) -> Result<ExportsMap, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_dual_form_map::<D, ExportDef>(de, "exports")
}

/// Shared dual-form (flat / nested) deserializer for the imports + exports
/// tables. Both top-level structures are
/// `HashMap<namespace, HashMap<interface, T>>`. We accept two TOML surfaces
/// and normalize to the nested representation:
///
///   - Flat:    `[imports] "namespace:interface" = T` (key has a colon)
///   - Nested:  `[imports.namespace] interface = T` (no colon in top key)
///
/// Each top-level entry tries flat-form parsing first (treats the value as
/// a `T`); if that fails AND the key has no colon, falls back to parsing
/// the value as a nested `HashMap<String, T>`. Mixed forms in one table
/// are tolerated — different entries can use different surfaces.
fn deserialize_dual_form_map<'de, D, T>(
    de: D,
    section: &'static str,
) -> Result<HashMap<String, HashMap<String, T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned + Clone,
{
    use serde::de::Error;
    let raw: HashMap<String, toml::Value> = HashMap::deserialize(de)?;
    let mut out: HashMap<String, HashMap<String, T>> = HashMap::new();
    for (key, value) in raw {
        // Flat form: key contains ':' — split into (namespace, interface).
        if let Some((ns, iface)) = key.split_once(':') {
            if ns.is_empty() || iface.is_empty() {
                return Err(D::Error::custom(format!(
                    "[{section}] key '{key}' has empty namespace or interface segment"
                )));
            }
            let def: T = T::deserialize(value)
                .map_err(|e| D::Error::custom(format!("[{section}] flat-form '{key}': {e}")))?;
            out.entry(ns.to_string())
                .or_default()
                .insert(iface.to_string(), def);
        } else {
            // Nested form: value should be a table of (interface → T).
            let inner: HashMap<String, T> = HashMap::deserialize(value).map_err(|e| {
                D::Error::custom(format!(
                    "[{section}.{key}]: expected table of interface declarations: {e}"
                ))
            })?;
            out.entry(key).or_default().extend(inner);
        }
    }
    Ok(out)
}

/// Namespaced interface imports. Outer key = namespace, inner key = interface name.
pub type ImportsMap = HashMap<String, HashMap<String, ImportDef>>;

/// Namespaced interface exports. Outer key = namespace, inner key = interface name.
pub type ExportsMap = HashMap<String, HashMap<String, ExportDef>>;

/// An imported interface — version requirement with optional flag.
///
/// Deserializes from either a version string (`"^1.0"`) or a table
/// (`{ version = "^1.0", optional = true }`).
#[derive(Debug, Clone, Serialize)]
pub struct ImportDef {
    /// Semver version requirement (e.g. `^1.0`, `>=1.0, <2.0`, `*`).
    pub version: semver::VersionReq,
    /// If `true`, the capsule boots even if no provider is loaded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
}

impl<'de> Deserialize<'de> for ImportDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Short(String),
            Full {
                version: String,
                #[serde(default)]
                optional: bool,
            },
        }
        let raw = Raw::deserialize(deserializer)?;
        let (version_str, optional) = match raw {
            Raw::Short(s) => (s, false),
            Raw::Full { version, optional } => (version, optional),
        };
        let version = semver::VersionReq::parse(&version_str).map_err(|e| {
            serde::de::Error::custom(format!("invalid semver requirement '{version_str}': {e}"))
        })?;
        Ok(Self { version, optional })
    }
}

/// An exported interface — exact version declaration.
///
/// Deserializes from either a version string (`"1.0.0"`) or a table
/// (`{ version = "1.0.0" }`).
#[derive(Debug, Clone, Serialize)]
pub struct ExportDef {
    /// Exact semver version this capsule provides.
    pub version: semver::Version,
}

impl<'de> Deserialize<'de> for ExportDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Short(String),
            Full { version: String },
        }
        let raw = Raw::deserialize(deserializer)?;
        let version_str = match raw {
            Raw::Short(s) => s,
            Raw::Full { version } => version,
        };
        let version = semver::Version::parse(&version_str).map_err(|e| {
            serde::de::Error::custom(format!("invalid semver version '{version_str}': {e}"))
        })?;
        Ok(Self { version })
    }
}

/// Package identity metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageDef {
    /// The capsule's unique name.
    pub name: String,
    /// The semantic version.
    pub version: String,
    /// Optional description of the capsule.
    pub description: Option<String>,
    /// Optional authors of the capsule.
    #[serde(default)]
    pub authors: Vec<String>,
    /// Optional repository URL.
    pub repository: Option<String>,
    /// Optional homepage URL.
    pub homepage: Option<String>,
    /// Optional documentation URL.
    pub documentation: Option<String>,
    /// Optional license identifier (e.g., "MIT OR Apache-2.0").
    pub license: Option<String>,
    /// Optional path to a non-standard license file.
    #[serde(rename = "license-file")]
    pub license_file: Option<PathBuf>,
    /// Optional path to a README file.
    pub readme: Option<PathBuf>,
    /// Search keywords (up to 5).
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Registry categories (up to 5).
    #[serde(default)]
    pub categories: Vec<String>,
    /// The required version of the Astrid OS (e.g., ">=0.1.0").
    #[serde(rename = "astrid-version")]
    pub astrid_version: Option<String>,
    /// Whether this capsule is allowed to be published to a registry (defaults to true).
    pub publish: Option<bool>,
    /// Glob patterns of files to explicitly include when packing the capsule.
    pub include: Option<Vec<String>>,
    /// Glob patterns of files to exclude when packing the capsule.
    pub exclude: Option<Vec<String>>,
    /// A catch-all table for custom, tool-specific metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Defines an executable, library, or compute-worker component in a capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentDef {
    /// Unique identifier for this component within the capsule.
    #[serde(default)]
    pub id: String,
    /// Path to the WASM file.
    #[serde(rename = "file", alias = "entrypoint")]
    pub path: PathBuf,
    /// Expected hash for security verification.
    pub hash: Option<String>,
    /// Type of component: "executable" (default), "library", or
    /// "compute-worker". Compute workers are hash-pinned core-Wasm modules;
    /// they are not controller Components.
    #[serde(default)]
    pub r#type: String,
    /// List of component IDs this component dynamically links to.
    #[serde(default)]
    pub link: Vec<String>,
    /// Capabilities specifically requested by this component.
    #[serde(default)]
    pub capabilities: Option<CapabilitiesDef>,
}

/// An environment variable required by the capsule.
///
/// These are securely elicited from the user during `capsule install` (docking).
/// This prevents developers from shipping hardcoded API keys in their manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvDef {
    /// The type of the environment variable. Accepted values: `"text"`,
    /// `"secret"`, `"select"`, `"array"`.
    ///
    /// `"secret"` is the load-bearing case: the operator-facing surface
    /// elicits with a masked prompt at install time and stores the value
    /// through [`astrid_storage::FileSecretStore`]
    /// (`~/.astrid/secrets/<scope>/<capsule>/<key>`, 0600) instead of
    /// the plaintext
    /// `<principal_home>/.config/env/<capsule>.env.json` path that
    /// non-secret keys use. `"text"`, `"select"`, and `"array"` all land
    /// in the env JSON; `"select"` elicits with `enum_values` choices,
    /// `"array"` accepts a comma-separated list.
    #[serde(rename = "type")]
    pub env_type: String,
    /// The specific prompt or question to ask the user when eliciting this value.
    pub request: Option<String>,
    /// The human-readable description.
    pub description: Option<String>,
    /// An optional default value.
    pub default: Option<serde_json::Value>,
    /// Valid choices for enum fields.
    #[serde(default)]
    pub enum_values: Vec<String>,
    /// Placeholder hint text shown in an empty input field (e.g. `"sk-..."`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Dynamic-select source. When present, this field is a SELECT whose
    /// options are fetched live at prompt time from an HTTP endpoint
    /// (typically the provider's `/v1/models`) rather than enumerated
    /// statically in `enum_values`.
    ///
    /// The fetch runs in the operator-facing **installer** (the native
    /// CLI, which has network access) — never inside the sandboxed
    /// capsule. Resolution is best-effort: any failure falls back to a
    /// free-text prompt. See [`OptionsFrom`].
    ///
    /// Keyed `options_from` to match the snake-case convention of the
    /// sibling `enum_values` field; the kebab `options-from` form is
    /// accepted as an alias for author convenience.
    #[serde(
        default,
        alias = "options-from",
        skip_serializing_if = "Option::is_none"
    )]
    pub options_from: Option<OptionsFrom>,
    /// Sharing model for this env variable across principals on the
    /// same host. Defaults to [`EnvScope::Agent`] (fail-closed: every
    /// principal has their own isolated value, miss = no value).
    /// [`EnvScope::Shared`] opts the key into a host-wide fall-through
    /// — used for credentials the operator runs as a single account
    /// for the whole host (LLM provider keys, OAuth client IDs). For
    /// `env_type = "secret"`, the scope determines which
    /// [`astrid_storage::SecretStore`] namespace the value lives in.
    ///
    /// **Operator-only contract:** this field is deliberately skipped at
    /// deserialize time. A capsule manifest cannot set its own scope —
    /// otherwise a malicious capsule could mark its credentials
    /// `Shared` and pull host-wide values into its sandbox. The kernel
    /// resolves scope from operator action (`astrid secret set --scope
    /// shared ...`) at runtime, not from manifest declaration.
    #[serde(
        default,
        skip_serializing_if = "EnvScope::is_default",
        skip_deserializing
    )]
    pub scope: EnvScope,
}

/// Dynamic-select source for an [`EnvDef`].
///
/// Declares an HTTP endpoint whose JSON response enumerates the valid
/// choices for a field. At prompt time, the installer substitutes the
/// already-collected env values into the `http`/`bearer` templates,
/// performs `GET <http>` (with `Authorization: Bearer <bearer>` only
/// when `bearer` resolves to a non-empty value), and parses the response
/// shape named by `select`.
///
/// Template placeholders use `{key}` syntax, where `key` is the name of
/// another `[env]` field. Fields named in [`Self::after`] are guaranteed
/// to be collected before this field is prompted, so their values are
/// available for substitution.
///
/// # Security
///
/// This resolution is performed by the native installer, which has
/// network access — **never** by the sandboxed capsule. A capsule
/// cannot make outbound requests through this mechanism; it only
/// declares the shape of the discovery call the operator's installer
/// performs on its behalf. Failure is non-fatal: the field degrades to
/// a free-text prompt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OptionsFrom {
    /// HTTP endpoint template, e.g. `"{base_url}/v1/models"`. Resolved
    /// against the already-collected env values at prompt time.
    pub http: String,
    /// Optional bearer-token template, e.g. `"{api_key}"`. The
    /// `Authorization: Bearer` header is sent **only** when this
    /// resolves to a non-empty value after trimming.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    /// JSON shape hint identifying the option list in the response.
    /// Defaults to `"data[].id"` — the standard OpenAI `/v1/models`
    /// shape (`{ "data": [ { "id": "..." } ] }`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select: Option<String>,
    /// Env keys that must be collected before this field is prompted.
    /// Ensures dependency values (base URL, API key) are available for
    /// template substitution. The installer orders prompts so that
    /// fields with `after` dependencies come after their dependencies.
    #[serde(default)]
    pub after: Vec<String>,
}

impl OptionsFrom {
    /// The default JSON shape hint when `select` is unset: the standard
    /// OpenAI `/v1/models` response (`data[].id`).
    pub const DEFAULT_SELECT: &'static str = "data[].id";

    /// The configured `select` shape hint, or [`Self::DEFAULT_SELECT`]
    /// when unset.
    #[must_use]
    pub fn select_or_default(&self) -> &str {
        self.select.as_deref().unwrap_or(Self::DEFAULT_SELECT)
    }
}

/// Sharing model for an env / secret value across principals.
///
/// Lookup precedence is always per-agent first; [`EnvScope::Shared`]
/// only changes the *fall-through* behaviour on miss. An agent that
/// has set their own override of a `shared` key wins over the host-
/// wide value at read time, so per-agent isolation is preserved even
/// when the manifest declares sharing as the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvScope {
    /// Strictly per-invoking-principal. Miss = no value, no fall-
    /// through. The fail-closed default — appropriate for anything an
    /// end-user must not be able to act-as another user with
    /// (per-agent API keys, OAuth tokens, Telegram bot tokens).
    #[default]
    Agent,
    /// Per-agent first, then a host-wide fall-through on miss. The
    /// host-wide value is set by the operator once (`astrid secret
    /// set --scope shared ...`) and shared by every agent that hasn't
    /// set their own override. Appropriate for credentials the
    /// operator runs as a single account for the whole host (LLM
    /// provider keys, OAuth client IDs).
    Shared,
}

impl EnvScope {
    /// Returns `true` for the default scope so serializers can omit
    /// it (matches the rest of the manifest fields' conventions).
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Agent)
    }
}

/// A context file provided by the capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextFileDef {
    /// The name of the context block.
    pub name: String,
    /// The path to the context file.
    pub file: PathBuf,
}

/// A command provided by the capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDef {
    /// The command trigger (slash command, or CLI verb when
    /// `kind = "cli"`).
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Path to the declarative command TOML (if static).
    pub file: Option<PathBuf>,
    /// How the command is surfaced. `kind = "slash"` (the default when
    /// absent) is an in-TUI slash command; `kind = "cli"` is a top-level
    /// CLI verb dispatched to this capsule over IPC as a non-interactive
    /// one-shot.
    ///
    /// For the CLI-verb wire contract (run/result topic shapes, the
    /// provider-targeted-topic security rationale, and the fact that the
    /// kernel does not interpret the payloads) see [`CommandKind`].
    ///
    /// `kind = "cli"` names are validated at manifest parse time (by the
    /// capsule discovery loader): they must
    /// match `[a-z][a-z0-9-]*`, be 1-32 chars, and must not collide with a
    /// built-in `astrid capsule` subcommand
    /// ([`RESERVED_CAPSULE_VERBS`]). Slash commands are not subject to this
    /// validation and parse exactly as before.
    #[serde(default, skip_serializing_if = "CommandKind::is_default")]
    pub kind: CommandKind,
}

/// An MCP server provided by the capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerDef {
    /// Unique ID for the MCP server.
    pub id: String,
    /// Optional description.
    pub description: Option<String>,
    /// Server type: "wasm-ipc", "stdio".
    #[serde(rename = "type")]
    pub server_type: Option<String>,
    /// The host command (if type = stdio).
    pub command: Option<String>,
    /// The host arguments (if type = stdio).
    #[serde(default)]
    pub args: Vec<String>,
}

/// Source-compatibility shape for the former manifest Skill declaration.
///
/// This type has no manifest or runtime semantics. It remains public only so
/// downstream Rust code compiled against the previous API does not break.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDef {
    /// Name of the legacy Skill declaration.
    pub name: String,
    /// Description carried by the legacy declaration.
    pub description: Option<String>,
    /// Former asset path, no longer interpreted by Astrid.
    pub file: PathBuf,
}

/// An uplink provided by the capsule (e.g., Telegram, CLI).
///
/// This allows the LLM agent to route messages out to a specific platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkDef {
    /// Unique name of the uplink.
    pub name: String,
    /// The platform identifier (e.g., "telegram", "cli").
    pub platform: String,
    /// The interaction profile (e.g., "human", "bridge").
    pub profile: UplinkProfile,
}

/// A resolved interceptor binding.
///
/// This is the kernel-internal representation produced by
/// [`CapsuleManifest::effective_interceptors`] from each `[subscribe]` entry
/// that carries a `handler`; it is not parsed directly from the manifest. The
/// event dispatcher matches incoming IPC events against the `event` pattern
/// and invokes `astrid_hook_trigger` with the `action` name and payload.
///
/// Topic patterns support single-segment wildcards: `tool.execute.*.result`
/// matches `tool.execute.search.result` but not `tool.execute.result`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptorDef {
    /// IPC topic pattern to match (the `[subscribe]` key).
    pub event: String,
    /// Name of the handler function inside the WASM guest — the
    /// `[subscribe]` entry's `handler` (must match an
    /// `#[astrid::interceptor("...")]` annotation).
    pub action: String,
    /// Dispatch priority — lower values fire first. Default 100.
    /// Enables layered interception (e.g. input guard at 10 fires before
    /// react loop at 100). Sourced from the `[subscribe]` entry's optional
    /// `priority`.
    #[serde(default = "default_interceptor_priority")]
    pub priority: u32,
}

/// Default interceptor priority.
const fn default_interceptor_priority() -> u32 {
    100
}

/// A tool this capsule surfaces to the LLM (RFC: cargo-like-manifest).
///
/// `description_for_llm` is the *only* capsule-author-controlled string
/// that reaches the LLM unattended. Operators see and approve it verbatim
/// at install time — keeps capsule-author prose out of model context
/// unless explicitly authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    /// Tool name as it appears to the LLM.
    pub name: String,
    /// Verbatim description shown to the model. Operator approves at install.
    pub description_for_llm: String,
    /// Optional WIT record describing the tool input shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema_wit: Option<String>,
    /// Whether this tool may mutate state (drives the approval-prompt copy).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mutable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_def_parses_options_from() {
        let toml_src = r#"
type = "select"
description = "Default model"
default = "gpt-4o"
options-from = { http = "{base_url}/v1/models", bearer = "{api_key}", select = "data[].id", after = ["base_url", "api_key"] }
"#;
        let def: EnvDef = toml::from_str(toml_src).expect("env def with options-from parses");
        let opts = def.options_from.expect("options_from present");
        assert_eq!(opts.http, "{base_url}/v1/models");
        assert_eq!(opts.bearer.as_deref(), Some("{api_key}"));
        assert_eq!(opts.select.as_deref(), Some("data[].id"));
        assert_eq!(opts.after, vec!["base_url", "api_key"]);
    }

    #[test]
    fn options_from_select_defaults_when_absent() {
        let toml_src = r#"
type = "select"
options-from = { http = "https://api.example.com/v1/models" }
"#;
        let def: EnvDef = toml::from_str(toml_src).unwrap();
        let opts = def.options_from.expect("options_from present");
        assert_eq!(opts.bearer, None);
        assert!(opts.after.is_empty());
        assert_eq!(opts.select_or_default(), OptionsFrom::DEFAULT_SELECT);
        assert_eq!(opts.select_or_default(), "data[].id");
    }

    #[test]
    fn env_def_without_options_from_is_none() {
        let toml_src = r#"
type = "text"
description = "Base URL"
"#;
        let def: EnvDef = toml::from_str(toml_src).unwrap();
        assert!(def.options_from.is_none());
    }

    #[test]
    fn legacy_skill_declarations_have_no_manifest_semantics() {
        let manifest: CapsuleManifest = toml::from_str(
            r#"
[package]
name = "legacy-skill"
version = "1.0.0"

[[skill]]
name = "ignored"
file = "skills/ignored/SKILL.md"
"#,
        )
        .unwrap();

        assert!(manifest.skills.is_empty());
        let encoded = toml::to_string(&manifest).unwrap();
        assert!(!encoded.contains("[[skill]]"));
        assert!(!encoded.contains("skills/ignored/SKILL.md"));
    }
}
