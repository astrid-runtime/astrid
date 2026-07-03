//! Agent-loop readiness — name-agnostic introspection over the loaded
//! capsule manifest set.
//!
//! The kernel hard-requires only the socket uplink, so a fresh daemon boots
//! clean yet may produce no agent replies: `user.v1.prompt` is published, but
//! if no capsule subscribes it (or the LLM chain is incomplete) the publish
//! silently no-ops and the client waits out a timeout with no signal.
//!
//! A working agent loop is computable from the manifest set alone, without
//! hardcoding any capsule name:
//!
//! 1. Some loaded capsule's `[subscribe]` matches [`AGENT_PROMPT_TOPIC`] —
//!    the entry point exists.
//! 2. Some loaded capsule's `[publish]` matches [`AGENT_RESPONSE_TOPIC`] —
//!    a terminal reply is producible.
//! 3. No required (non-optional) `[imports]` entry across the loaded set is
//!    unsatisfied by another loaded capsule's `[exports]`.
//!
//! Topic matching uses the ROUTE-LAYER matcher
//! ([`astrid_events::topic_pattern_matches`]) so a declared
//! `user.v1.*` (subtree) counts as a subscriber to `user.v1.prompt`, matching
//! actual delivery semantics — never the strict interceptor-dispatch matcher.
//! Import satisfaction reuses [`crate::toposort::import_satisfied_by`] so there
//! is exactly one source of truth for `(namespace, interface, semver)`
//! matching.

use astrid_core::kernel_api::{AgentLoopReadiness, MissingImport};
// The ROUTE-LAYER matcher (re-exported at the crate root): trailing `.*` is a
// subtree match, agreeing with how the bus actually routes — so a declared
// `user.v1.*` matches `user.v1.prompt`. NOT the strict interceptor-dispatch
// matcher in `crate::topic`.
use astrid_events::topic_pattern_matches;

use crate::manifest::CapsuleManifest;
use crate::toposort::import_satisfied_by;

/// IPC topic a user prompt is published on. A capsule that subscribes a
/// pattern matching this topic is the agent loop's entry point.
pub const AGENT_PROMPT_TOPIC: &str = "user.v1.prompt";

/// IPC topic the terminal agent reply is published on. A capsule that
/// publishes a pattern matching this topic can produce a final response.
pub const AGENT_RESPONSE_TOPIC: &str = "agent.v1.response";

/// True if `manifest`'s `[subscribe]` patterns match `topic`.
///
/// The short-circuiting, allocation-free predicate behind
/// [`topic_subscribers`] — a caller that only needs *existence* (e.g. a
/// capability probe checking whether any loaded capsule serves a verb) uses
/// this to avoid materialising the full subscriber list. Route-layer subtree
/// semantics, so a declared `user.v1.*` matches `user.v1.prompt`.
#[must_use]
pub fn manifest_subscribes_topic(manifest: &CapsuleManifest, topic: &str) -> bool {
    manifest
        .subscribes
        .keys()
        .any(|pattern| topic_pattern_matches(pattern, topic))
}

/// Names of loaded capsules whose `[subscribe]` patterns match `topic`.
///
/// Uses route-layer subtree semantics, so a declared `user.v1.*` matches
/// `user.v1.prompt`.
#[must_use]
pub fn topic_subscribers<'a, M: AsRef<CapsuleManifest>>(
    manifests: &'a [M],
    topic: &str,
) -> Vec<&'a str> {
    manifests
        .iter()
        .filter(|m| manifest_subscribes_topic(m.as_ref(), topic))
        .map(|m| m.as_ref().package.name.as_str())
        .collect()
}

/// Names of loaded capsules whose `[publish]` patterns match `topic`.
///
/// Uses route-layer subtree semantics, mirroring [`topic_subscribers`].
#[must_use]
pub fn topic_publishers<'a, M: AsRef<CapsuleManifest>>(
    manifests: &'a [M],
    topic: &str,
) -> Vec<&'a str> {
    manifests
        .iter()
        .filter(|m| {
            m.as_ref()
                .publishes
                .keys()
                .any(|pattern| topic_pattern_matches(pattern, topic))
        })
        .map(|m| m.as_ref().package.name.as_str())
        .collect()
}

/// Required imports that no OTHER loaded capsule exports.
///
/// For each manifest, each non-optional import is checked against every other
/// manifest's exports via [`import_satisfied_by`] (namespace + name + semver).
/// An import satisfied only by the importing capsule's own exports does not
/// count — a capsule cannot self-satisfy a cross-capsule dependency.
///
/// This is the single source of truth for "which required imports are
/// unmet"; the kernel boot validator delegates here so its warnings and this
/// readiness report can never diverge.
#[must_use]
pub fn unsatisfied_required_imports<M: AsRef<CapsuleManifest>>(
    manifests: &[M],
) -> Vec<MissingImport> {
    unsatisfied_imports(manifests, false)
}

/// Optional imports that no OTHER loaded capsule exports.
///
/// Same cross-capsule self-exclusion rule as [`unsatisfied_required_imports`]
/// (a capsule cannot self-satisfy its own import), applied to `optional`
/// imports. The kernel boot validator uses this for its optional-import
/// "reduced functionality" diagnostics so the optional and required paths share
/// one definition of "satisfied" and can never disagree.
#[must_use]
pub fn unsatisfied_optional_imports<M: AsRef<CapsuleManifest>>(
    manifests: &[M],
) -> Vec<MissingImport> {
    unsatisfied_imports(manifests, true)
}

/// Shared body for [`unsatisfied_required_imports`] /
/// [`unsatisfied_optional_imports`]: missing imports of the requested
/// optionality, with cross-capsule self-exclusion (`other_idx != idx`). One
/// definition so the required and optional diagnostics never diverge on what
/// "satisfied" means.
fn unsatisfied_imports<M: AsRef<CapsuleManifest>>(
    manifests: &[M],
    want_optional: bool,
) -> Vec<MissingImport> {
    let mut missing = Vec::new();
    for (idx, manifest) in manifests.iter().enumerate() {
        let manifest = manifest.as_ref();
        for (imp_ns, imp_name, imp_req, optional) in manifest.import_tuples() {
            if optional != want_optional {
                continue;
            }
            let satisfied = manifests.iter().enumerate().any(|(other_idx, other)| {
                other_idx != idx
                    && other.as_ref().export_triples().any(|(ns, name, ver)| {
                        import_satisfied_by(imp_ns, imp_name, imp_req, ns, name, ver)
                    })
            });
            if !satisfied {
                missing.push(MissingImport {
                    capsule: manifest.package.name.clone(),
                    namespace: imp_ns.to_string(),
                    interface: imp_name.to_string(),
                    requirement: imp_req.to_string(),
                });
            }
        }
    }
    missing
}

/// Compute whether the loaded capsule set can serve an agent chat turn.
///
/// Name-agnostic: derived purely from the manifests' `[subscribe]`,
/// `[publish]`, and `[imports]`/`[exports]` tables against the two well-known
/// topic constants. `ready` is the conjunction of all three checks.
#[must_use]
pub fn agent_loop_readiness<M: AsRef<CapsuleManifest>>(manifests: &[M]) -> AgentLoopReadiness {
    let prompt_subscribers: Vec<String> = topic_subscribers(manifests, AGENT_PROMPT_TOPIC)
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let response_publishers: Vec<String> = topic_publishers(manifests, AGENT_RESPONSE_TOPIC)
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let unsatisfied = unsatisfied_required_imports(manifests);
    let loaded_capsules: Vec<String> = manifests
        .iter()
        .map(|m| m.as_ref().package.name.clone())
        .collect();

    let ready =
        !prompt_subscribers.is_empty() && !response_publishers.is_empty() && unsatisfied.is_empty();

    // Sort every collection: the loaded set is iterated from a `HashMap`, so
    // raw order is nondeterministic run-to-run. This is an ops-facing API/CLI
    // surface (`GET /api/sys/readiness`, `astrid doctor`), so a stable order
    // keeps output diffable and downstream assertions non-flaky.
    let mut prompt_subscribers = prompt_subscribers;
    let mut response_publishers = response_publishers;
    let mut loaded_capsules = loaded_capsules;
    let mut unsatisfied = unsatisfied;
    prompt_subscribers.sort();
    response_publishers.sort();
    loaded_capsules.sort();
    unsatisfied.sort();

    AgentLoopReadiness {
        ready,
        prompt_subscribers,
        response_publishers,
        unsatisfied_required_imports: unsatisfied,
        loaded_capsules,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::manifest::{ExportDef, ImportDef, PublishDef, SubscribeDef};

    /// Build a minimal `PublishDef` (opaque payload, no pins) for a topic.
    /// Mirrors the `publish()` helper in `schema_catalog.rs` — readiness only
    /// reads the `[publish]` table KEYS, so the value shape is irrelevant.
    fn publish_def() -> PublishDef {
        PublishDef {
            wit: "opaque".to_string(),
            version: None,
            tag: None,
            rev: None,
            branch: None,
            path: None,
            fanout: false,
        }
    }

    /// Build a minimal `SubscribeDef` (opaque payload, ACL-only) for a topic.
    fn subscribe_def() -> SubscribeDef {
        SubscribeDef {
            wit: "opaque".to_string(),
            version: None,
            tag: None,
            rev: None,
            branch: None,
            path: None,
            handler: None,
            priority: None,
        }
    }

    /// Build a manifest with the given name, subscribe topics, publish
    /// topics, imports, and exports. Mirrors the helper style in
    /// `toposort.rs` / `schema_catalog.rs`, extended to also carry topic
    /// tables since readiness reads them.
    fn manifest(
        name: &str,
        subscribes: &[&str],
        publishes: &[&str],
        imports: &[(&str, &str, &str, bool)],
        exports: &[(&str, &str, &str)],
    ) -> CapsuleManifest {
        let mut import_map: HashMap<String, HashMap<String, ImportDef>> = HashMap::new();
        for &(ns, iface, req, optional) in imports {
            import_map.entry(ns.to_string()).or_default().insert(
                iface.to_string(),
                ImportDef {
                    version: semver::VersionReq::parse(req).unwrap(),
                    optional,
                },
            );
        }
        let mut export_map: HashMap<String, HashMap<String, ExportDef>> = HashMap::new();
        for &(ns, iface, ver) in exports {
            export_map.entry(ns.to_string()).or_default().insert(
                iface.to_string(),
                ExportDef {
                    version: semver::Version::parse(ver).unwrap(),
                },
            );
        }
        let mut manifest = CapsuleManifest {
            imports: import_map,
            exports: export_map,
            ..Default::default()
        };
        manifest.package.name = name.to_string();
        for &topic in subscribes {
            manifest
                .subscribes
                .insert(topic.to_string(), subscribe_def());
        }
        for &topic in publishes {
            manifest.publishes.insert(topic.to_string(), publish_def());
        }
        manifest
    }

    /// A healthy three-capsule set: a "loop" capsule subscribes the prompt
    /// topic, publishes the response topic, and imports an interface the
    /// "provider" capsule exports; an unrelated capsule rounds out the set.
    fn healthy_set() -> Vec<CapsuleManifest> {
        vec![
            manifest(
                "loop",
                &[AGENT_PROMPT_TOPIC],
                &[AGENT_RESPONSE_TOPIC],
                &[("astrid", "llm", "^1.0", false)],
                &[],
            ),
            manifest("provider", &[], &[], &[], &[("astrid", "llm", "1.0.0")]),
            manifest("bystander", &[], &[], &[], &[]),
        ]
    }

    #[test]
    fn healthy_set_is_ready() {
        let r = agent_loop_readiness(&healthy_set());
        assert!(r.ready, "healthy set must be ready: {r:?}");
        assert!(r.unsatisfied_required_imports.is_empty());
        assert_eq!(r.prompt_subscribers, vec!["loop".to_string()]);
        assert_eq!(r.response_publishers, vec!["loop".to_string()]);
    }

    #[test]
    fn not_ready_when_prompt_subscriber_absent() {
        // Drop the prompt subscriber: the loop capsule no longer subscribes
        // ANY topic. This is the silent-failure bug — a daemon that accepts
        // prompts no capsule will ever receive. Regression guard: would FAIL
        // if `agent_loop_readiness` always returned `ready: true`.
        let mut set = healthy_set();
        set[0].subscribes.clear();
        let r = agent_loop_readiness(&set);
        assert!(!r.ready, "no prompt subscriber must be not-ready");
        assert!(
            r.prompt_subscribers.is_empty(),
            "prompt_subscribers must be empty"
        );
        // The response publisher is still present — only the entry point is gone.
        assert_eq!(r.response_publishers, vec!["loop".to_string()]);
    }

    #[test]
    fn not_ready_when_required_import_unsatisfied() {
        // The provider capsule that exports `astrid:llm` is removed. The loop
        // capsule still subscribes the prompt topic and publishes the response
        // topic, so checks 1 and 2 pass — but its required import is now
        // unmet, so the loop can't actually function. This is the regression
        // case for the silent-failure bug: it MUST fail without the import
        // check, and would FAIL if `agent_loop_readiness` always returned
        // `ready: true`.
        let mut set = healthy_set();
        set.retain(|m| m.package.name != "provider");
        let r = agent_loop_readiness(&set);
        assert!(!r.ready, "unsatisfied required import must be not-ready");
        assert!(
            !r.prompt_subscribers.is_empty(),
            "entry point still present"
        );
        assert!(
            !r.response_publishers.is_empty(),
            "response publisher still present"
        );
        assert_eq!(r.unsatisfied_required_imports.len(), 1);
        let missing = &r.unsatisfied_required_imports[0];
        assert_eq!(missing.capsule, "loop");
        assert_eq!(missing.namespace, "astrid");
        assert_eq!(missing.interface, "llm");
    }

    #[test]
    fn optional_import_absent_stays_ready() {
        // The loop's dependency is OPTIONAL and no one exports it. An absent
        // optional import must NOT make the loop unready.
        let set = vec![
            manifest(
                "loop",
                &[AGENT_PROMPT_TOPIC],
                &[AGENT_RESPONSE_TOPIC],
                &[("astrid", "telemetry", "^1.0", true)],
                &[],
            ),
            manifest("bystander", &[], &[], &[], &[]),
        ];
        let r = agent_loop_readiness(&set);
        assert!(r.ready, "absent optional import must stay ready: {r:?}");
        assert!(r.unsatisfied_required_imports.is_empty());
    }

    #[test]
    fn subtree_subscribe_counts_as_prompt_subscriber() {
        // A capsule that declares a trailing-`*` subtree pattern covering the
        // prompt topic counts as a prompt subscriber (route-layer semantics).
        let set = vec![manifest(
            "loop",
            &["user.v1.*"],
            &[AGENT_RESPONSE_TOPIC],
            &[],
            &[],
        )];
        let subs = topic_subscribers(&set, AGENT_PROMPT_TOPIC);
        assert_eq!(subs, vec!["loop"], "user.v1.* must match user.v1.prompt");
        let r = agent_loop_readiness(&set);
        assert!(r.ready, "subtree subscriber + publisher is ready: {r:?}");
    }

    #[test]
    fn import_satisfied_only_by_self_is_unsatisfied() {
        // A capsule that exports the very interface it imports does not
        // self-satisfy — the cross-capsule dependency is still unmet.
        let set = vec![manifest(
            "solo",
            &[AGENT_PROMPT_TOPIC],
            &[AGENT_RESPONSE_TOPIC],
            &[("astrid", "llm", "^1.0", false)],
            &[("astrid", "llm", "1.0.0")],
        )];
        let missing = unsatisfied_required_imports(&set);
        assert_eq!(missing.len(), 1, "self-export must not satisfy own import");
        assert_eq!(missing[0].capsule, "solo");
    }

    #[test]
    fn optional_import_satisfied_only_by_self_is_unsatisfied() {
        // Parity with the required case: a capsule that self-exports an
        // interface it OPTIONALLY imports does not self-satisfy either — the
        // optional and required diagnostics share one self-exclusion rule, so
        // the boot validator's two branches can never disagree.
        let set = vec![manifest(
            "solo",
            &[AGENT_PROMPT_TOPIC],
            &[AGENT_RESPONSE_TOPIC],
            &[("astrid", "telemetry", "^1.0", true)],
            &[("astrid", "telemetry", "1.0.0")],
        )];
        let missing = unsatisfied_optional_imports(&set);
        assert_eq!(
            missing.len(),
            1,
            "self-export must not satisfy own optional import"
        );
        assert_eq!(missing[0].interface, "telemetry");
        // The same self-only optional import is NOT counted as a required miss.
        assert!(unsatisfied_required_imports(&set).is_empty());
    }

    #[test]
    fn readiness_collections_are_sorted() {
        // The loaded set is HashMap-iterated (nondeterministic order), so
        // agent_loop_readiness sorts every collection for stable, diffable
        // ops output. Pass capsules out of order and assert sorted results.
        let set = vec![
            manifest(
                "zeta",
                &[AGENT_PROMPT_TOPIC],
                &[AGENT_RESPONSE_TOPIC],
                &[],
                &[],
            ),
            manifest(
                "alpha",
                &[AGENT_PROMPT_TOPIC],
                &[AGENT_RESPONSE_TOPIC],
                &[],
                &[],
            ),
            manifest("mid", &[], &[], &[], &[]),
        ];
        let r = agent_loop_readiness(&set);
        assert_eq!(r.loaded_capsules, vec!["alpha", "mid", "zeta"]);
        assert_eq!(r.prompt_subscribers, vec!["alpha", "zeta"]);
        assert_eq!(r.response_publishers, vec!["alpha", "zeta"]);
    }
}
