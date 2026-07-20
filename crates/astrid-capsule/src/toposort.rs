//! Topological sort for capsule dependency ordering.
//!
//! Implements Kahn's algorithm to order capsules so that dependencies load
//! before their dependents. Edges are derived from `[imports]`/`[exports]`
//! interface declarations with semver matching.

use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;

use crate::manifest::CapsuleManifest;

/// A manifest paired with its capsule directory path.
pub(crate) type ManifestEntry = (CapsuleManifest, PathBuf);

/// Error returned when the dependency graph contains a cycle.
#[derive(Debug, Clone)]
pub struct CycleError {
    /// Names of capsules involved in the cycle.
    pub cycle: Vec<String>,
}

impl fmt::Display for CycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dependency cycle detected (involved nodes): {}",
            self.cycle.join(", ")
        )
    }
}

impl std::error::Error for CycleError {}

/// Check whether an imported interface requirement is satisfied by an export.
///
/// Matches when namespace and name are equal and the import's `VersionReq`
/// matches the export's `Version`.
pub fn import_satisfied_by(
    import_ns: &str,
    import_name: &str,
    import_req: &semver::VersionReq,
    export_ns: &str,
    export_name: &str,
    export_ver: &semver::Version,
) -> bool {
    import_ns == export_ns && import_name == export_name && import_req.matches(export_ver)
}

/// Sort capsule manifests in dependency order using Kahn's algorithm.
///
/// Capsules with no imports come first. Dependencies are resolved by
/// matching each capsule's imports against other capsules' exports
/// using [`import_satisfied_by`] for namespace + semver matching.
///
/// Uses any-satisfies semantics: an import is met when ANY single
/// capsule exports a matching interface.
///
/// Unsatisfied requirements are logged as warnings and treated as met -
/// the capsule still loads, it just won't have that capability guaranteed.
///
/// # Errors
///
/// Returns [`CycleError`] paired with the original unsorted vector if the
/// dependency graph contains a cycle. This avoids cloning the input as a
/// fallback buffer.
pub fn toposort_manifests(
    manifests: Vec<ManifestEntry>,
) -> Result<Vec<ManifestEntry>, (CycleError, Vec<ManifestEntry>)> {
    if manifests.len() <= 1 {
        return Ok(manifests);
    }

    let len = manifests.len();
    // adjacency[i] = list of indices that depend on i (i.e., i must load before them)
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); len];
    let mut in_degree: Vec<usize> = vec![0; len];

    // Build import/export adjacency list in a scoped block so the
    // borrows on `manifests` are released before the error path needs
    // to return ownership.
    {
        // Collect all exports: Vec of Vec<(namespace, name, version)>
        let all_exports: Vec<Vec<(&str, &str, &semver::Version)>> = manifests
            .iter()
            .map(|(m, _)| m.export_triples().collect())
            .collect();

        for (idx, (manifest, _)) in manifests.iter().enumerate() {
            for (imp_ns, imp_name, imp_req, _optional) in manifest.import_tuples() {
                let mut satisfied = false;
                for (prov_idx, exports) in all_exports.iter().enumerate() {
                    if prov_idx == idx {
                        continue;
                    }
                    if exports.iter().any(|(ns, name, ver)| {
                        import_satisfied_by(imp_ns, imp_name, imp_req, ns, name, ver)
                    }) {
                        // prov_idx must load before idx
                        dependents[prov_idx].push(idx);
                        in_degree[idx] += 1;
                        satisfied = true;
                        // Continue: all providers get an ordering edge.
                    }
                }
                if !satisfied {
                    tracing::warn!(
                        capsule = %manifest.package.name,
                        import_ns = imp_ns,
                        import_name = imp_name,
                        import_version = %imp_req,
                        "Imported interface not exported by any loaded capsule"
                    );
                }
            }
        }
    }

    // BFS from zero-in-degree nodes
    let mut queue: VecDeque<usize> = in_degree
        .iter()
        .enumerate()
        .filter(|(_, d)| **d == 0)
        .map(|(i, _)| i)
        .collect();

    let mut order: Vec<usize> = Vec::with_capacity(len);

    while let Some(idx) = queue.pop_front() {
        order.push(idx);
        for &dependent in &dependents[idx] {
            in_degree[dependent] -= 1;
            if in_degree[dependent] == 0 {
                queue.push_back(dependent);
            }
        }
    }

    if order.len() != len {
        // Extract cycle members (nodes with remaining in-degree > 0)
        let cycle: Vec<String> = in_degree
            .iter()
            .enumerate()
            .filter(|(_, d)| **d > 0)
            .map(|(i, _)| manifests[i].0.package.name.clone())
            .collect();
        return Err((CycleError { cycle }, manifests));
    }

    // Reorder manifests according to topological order.
    // Convert to Option so we can take() by index without cloning.
    let mut slots: Vec<Option<ManifestEntry>> = manifests.into_iter().map(Some).collect();
    let sorted = order
        .into_iter()
        .map(|i| slots[i].take().expect("each index visited exactly once"))
        .collect();

    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::manifest::{ExportDef, ImportDef};

    /// Helper: build an exports map from `(namespace, interface, version)` triples.
    fn make_exports(triples: &[(&str, &str, &str)]) -> crate::manifest::ExportsMap {
        let mut map: HashMap<String, HashMap<String, ExportDef>> = HashMap::new();
        for &(ns, iface, ver) in triples {
            map.entry(ns.to_string()).or_default().insert(
                iface.to_string(),
                ExportDef {
                    version: semver::Version::parse(ver).unwrap(),
                },
            );
        }
        map
    }

    /// Helper: build an imports map from `(namespace, interface, version_req)` triples.
    fn make_imports(triples: &[(&str, &str, &str)]) -> crate::manifest::ImportsMap {
        let mut map: HashMap<String, HashMap<String, ImportDef>> = HashMap::new();
        for &(ns, iface, req) in triples {
            map.entry(ns.to_string()).or_default().insert(
                iface.to_string(),
                ImportDef {
                    version: semver::VersionReq::parse(req).unwrap(),
                    optional: false,
                },
            );
        }
        map
    }

    /// Create a manifest with explicit imports and exports.
    fn make_manifest(
        name: &str,
        exports: &[(&str, &str, &str)],
        imports: &[(&str, &str, &str)],
    ) -> ManifestEntry {
        let m = CapsuleManifest {
            package: crate::manifest::PackageDef {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                description: None,
                authors: Vec::new(),
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: Vec::new(),
                categories: Vec::new(),
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: Vec::new(),
            imports: make_imports(imports),
            exports: make_exports(exports),
            capabilities: Default::default(),
            env: HashMap::new(),
            context_files: Vec::new(),
            commands: Vec::new(),
            mcp_servers: Vec::new(),
            uplinks: Vec::new(),
            publishes: ::std::collections::HashMap::new(),
            subscribes: ::std::collections::HashMap::new(),
            tools: ::std::vec::Vec::new(),
        };
        (m, PathBuf::from(format!("/capsules/{name}")))
    }

    /// Create a manifest with no imports or exports.
    fn manifest_bare(name: &str) -> ManifestEntry {
        make_manifest(name, &[], &[])
    }

    fn names(manifests: &[ManifestEntry]) -> Vec<&str> {
        manifests
            .iter()
            .map(|(m, _)| m.package.name.as_str())
            .collect()
    }

    // -- import_satisfied_by tests --

    #[test]
    fn import_satisfied_exact_match() {
        let req = semver::VersionReq::parse("^1.0").unwrap();
        let ver = semver::Version::parse("1.2.3").unwrap();
        assert!(import_satisfied_by(
            "astrid", "session", &req, "astrid", "session", &ver
        ));
    }

    #[test]
    fn import_satisfied_version_mismatch() {
        let req = semver::VersionReq::parse("^2.0").unwrap();
        let ver = semver::Version::parse("1.2.3").unwrap();
        assert!(!import_satisfied_by(
            "astrid", "session", &req, "astrid", "session", &ver
        ));
    }

    #[test]
    fn import_satisfied_namespace_mismatch() {
        let req = semver::VersionReq::parse("^1.0").unwrap();
        let ver = semver::Version::parse("1.0.0").unwrap();
        assert!(!import_satisfied_by(
            "astrid", "session", &req, "other", "session", &ver
        ));
    }

    #[test]
    fn import_satisfied_name_mismatch() {
        let req = semver::VersionReq::parse("^1.0").unwrap();
        let ver = semver::Version::parse("1.0.0").unwrap();
        assert!(!import_satisfied_by(
            "astrid", "session", &req, "astrid", "identity", &ver
        ));
    }

    #[test]
    fn import_satisfied_wildcard_version() {
        let req = semver::VersionReq::parse("*").unwrap();
        let ver = semver::Version::parse("99.0.0").unwrap();
        assert!(import_satisfied_by(
            "ns", "iface", &req, "ns", "iface", &ver
        ));
    }

    // -- toposort tests --

    #[test]
    fn empty_graph() {
        let result = toposort_manifests(vec![]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn single_node() {
        let input = vec![manifest_bare("a")];
        let result = toposort_manifests(input).unwrap();
        assert_eq!(names(&result), vec!["a"]);
    }

    #[test]
    fn import_export_edge() {
        // B imports astrid/foo ^1.0, A exports astrid/foo 1.0.0 => A before B
        let input = vec![
            make_manifest("b", &[], &[("astrid", "foo", "^1.0")]),
            make_manifest("a", &[("astrid", "foo", "1.0.0")], &[]),
        ];
        let result = toposort_manifests(input).unwrap();
        let n = names(&result);
        assert!(
            n.iter().position(|&x| x == "a").unwrap() < n.iter().position(|&x| x == "b").unwrap()
        );
    }

    #[test]
    fn semver_range_match() {
        // B imports ^1.0, A exports 1.5.3 => satisfied
        let input = vec![
            make_manifest("b", &[], &[("ns", "iface", "^1.0")]),
            make_manifest("a", &[("ns", "iface", "1.5.3")], &[]),
        ];
        let result = toposort_manifests(input).unwrap();
        let n = names(&result);
        assert!(
            n.iter().position(|&x| x == "a").unwrap() < n.iter().position(|&x| x == "b").unwrap()
        );
    }

    #[test]
    fn all_providers_ordered_before_consumer() {
        // C imports ns/stream ^1.0, both A and B export it.
        // All providers get ordering edges, so both A and B load before C.
        let input = vec![
            make_manifest("c", &[], &[("ns", "stream", "^1.0")]),
            make_manifest("a", &[("ns", "stream", "1.0.0")], &[]),
            make_manifest("b", &[("ns", "stream", "1.1.0")], &[]),
        ];
        let result = toposort_manifests(input).unwrap();
        let n = names(&result);
        let c_pos = n.iter().position(|&x| x == "c").unwrap();
        let a_pos = n.iter().position(|&x| x == "a").unwrap();
        let b_pos = n.iter().position(|&x| x == "b").unwrap();
        assert!(a_pos < c_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn unsatisfied_requirement_still_succeeds() {
        // B imports ns/missing ^1.0 - no provider exists, B still loads
        let input = vec![
            manifest_bare("a"),
            make_manifest("b", &[], &[("ns", "missing", "^1.0")]),
        ];
        let result = toposort_manifests(input).unwrap();
        assert_eq!(names(&result).len(), 2);
    }

    #[test]
    fn cycle_detected() {
        // A exports x, imports y; B exports y, imports x => cycle
        let input = vec![
            make_manifest("a", &[("ns", "x", "1.0.0")], &[("ns", "y", "^1.0")]),
            make_manifest("b", &[("ns", "y", "1.0.0")], &[("ns", "x", "^1.0")]),
        ];
        let (err, original) = toposort_manifests(input).unwrap_err();
        assert!(err.cycle.contains(&"a".to_string()));
        assert!(err.cycle.contains(&"b".to_string()));
        assert!(err.to_string().contains("dependency cycle detected"));
        assert_eq!(original.len(), 2);
    }

    #[test]
    fn three_node_cycle() {
        let input = vec![
            make_manifest("a", &[("ns", "x", "1.0.0")], &[("ns", "z", "^1.0")]),
            make_manifest("b", &[("ns", "y", "1.0.0")], &[("ns", "x", "^1.0")]),
            make_manifest("c", &[("ns", "z", "1.0.0")], &[("ns", "y", "^1.0")]),
        ];
        let (err, original) = toposort_manifests(input).unwrap_err();
        assert_eq!(err.cycle.len(), 3);
        assert_eq!(original.len(), 3);
    }

    #[test]
    fn no_dependencies_preserves_all() {
        let input = vec![manifest_bare("x"), manifest_bare("y"), manifest_bare("z")];
        let result = toposort_manifests(input).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn diamond_dependency() {
        // d imports b + c, b and c both import a
        let input = vec![
            make_manifest(
                "d",
                &[("ns", "d", "1.0.0")],
                &[("ns", "b", "^1.0"), ("ns", "c", "^1.0")],
            ),
            make_manifest("b", &[("ns", "b", "1.0.0")], &[("ns", "a", "^1.0")]),
            make_manifest("c", &[("ns", "c", "1.0.0")], &[("ns", "a", "^1.0")]),
            make_manifest("a", &[("ns", "a", "1.0.0")], &[]),
        ];
        let result = toposort_manifests(input).unwrap();
        let n = names(&result);
        let pos = |name: &str| n.iter().position(|&x| x == name).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    // -- export_triples tests --

    #[test]
    fn export_triples_returns_all_entries() {
        let (m, _) = make_manifest(
            "test",
            &[
                ("astrid", "session", "1.0.0"),
                ("astrid", "identity", "2.0.0"),
            ],
            &[],
        );
        let triples: Vec<_> = m.export_triples().collect();
        assert_eq!(triples.len(), 2);
    }

    #[test]
    fn export_triples_empty_when_no_exports() {
        let (m, _) = manifest_bare("test");
        assert_eq!(m.export_triples().count(), 0);
    }

    // -- shipped capsule integration tests --

    #[test]
    fn react_requires_satisfied_by_identity_and_session() {
        // Identity exports astrid/identity 1.0.0
        // Session exports astrid/session 1.0.0
        // React imports both ^1.0
        let identity = make_manifest(
            "astrid-capsule-identity",
            &[("astrid", "identity", "1.0.0")],
            &[],
        );
        let session = make_manifest(
            "astrid-capsule-session",
            &[("astrid", "session", "1.0.0")],
            &[],
        );
        let react = make_manifest(
            "astrid-capsule-react",
            &[],
            &[
                ("astrid", "identity", "^1.0"),
                ("astrid", "session", "^1.0"),
            ],
        );

        let input = vec![react, identity, session];
        let result = toposort_manifests(input).unwrap();
        let n = names(&result);
        let pos = |name: &str| n.iter().position(|&x| x == name).unwrap();

        // React must load after both identity and session
        assert!(pos("astrid-capsule-identity") < pos("astrid-capsule-react"));
        assert!(pos("astrid-capsule-session") < pos("astrid-capsule-react"));
    }
}
