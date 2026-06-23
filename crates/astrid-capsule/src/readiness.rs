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

/// Names of loaded capsules whose `[subscribe]` patterns match `topic`.
///
/// Uses route-layer subtree semantics, so a declared `user.v1.*` matches
/// `user.v1.prompt`.
#[must_use]
pub fn topic_subscribers<'a>(manifests: &'a [CapsuleManifest], topic: &str) -> Vec<&'a str> {
    manifests
        .iter()
        .filter(|m| {
            m.subscribes
                .keys()
                .any(|pattern| topic_pattern_matches(pattern, topic))
        })
        .map(|m| m.package.name.as_str())
        .collect()
}

/// Names of loaded capsules whose `[publish]` patterns match `topic`.
///
/// Uses route-layer subtree semantics, mirroring [`topic_subscribers`].
#[must_use]
pub fn topic_publishers<'a>(manifests: &'a [CapsuleManifest], topic: &str) -> Vec<&'a str> {
    manifests
        .iter()
        .filter(|m| {
            m.publishes
                .keys()
                .any(|pattern| topic_pattern_matches(pattern, topic))
        })
        .map(|m| m.package.name.as_str())
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
pub fn unsatisfied_required_imports(manifests: &[CapsuleManifest]) -> Vec<MissingImport> {
    let mut missing = Vec::new();
    for (idx, manifest) in manifests.iter().enumerate() {
        for (imp_ns, imp_name, imp_req, optional) in manifest.import_tuples() {
            if optional {
                continue;
            }
            let satisfied = manifests.iter().enumerate().any(|(other_idx, other)| {
                other_idx != idx
                    && other.export_triples().any(|(ns, name, ver)| {
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
pub fn agent_loop_readiness(manifests: &[CapsuleManifest]) -> AgentLoopReadiness {
    let prompt_subscribers: Vec<String> = topic_subscribers(manifests, AGENT_PROMPT_TOPIC)
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let response_publishers: Vec<String> = topic_publishers(manifests, AGENT_RESPONSE_TOPIC)
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let unsatisfied = unsatisfied_required_imports(manifests);
    let loaded_capsules: Vec<String> = manifests.iter().map(|m| m.package.name.clone()).collect();

    let ready =
        !prompt_subscribers.is_empty() && !response_publishers.is_empty() && unsatisfied.is_empty();

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
}
