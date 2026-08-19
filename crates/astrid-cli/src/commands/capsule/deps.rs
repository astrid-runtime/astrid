//! `astrid capsule tree` - visualize the capsule imports/exports dependency graph.

use std::collections::HashMap;

use anyhow::bail;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use colored::Colorize;

use crate::theme::Theme;

// ---------------------------------------------------------------------------
// Graph data types (testable core) - borrowed string slices
// ---------------------------------------------------------------------------

/// A single satisfied import edge.
#[derive(Debug)]
struct ProviderMatch<'a> {
    /// Name of the capsule that exports the interface.
    capsule_name: &'a str,
    /// The version exported.
    exported_version: &'a str,
}

/// One export declared by a capsule.
#[derive(Debug)]
struct ExportEntry<'a> {
    namespace: &'a str,
    interface: &'a str,
    version: &'a str,
}

/// All dependency edges for one capsule.
#[derive(Debug)]
struct CapsuleTree<'a> {
    name: &'a str,
    exports: Vec<ExportEntry<'a>>,
    imports: Vec<ImportEdge<'a>>,
}

/// One import and its resolved providers.
#[derive(Debug)]
struct ImportEdge<'a> {
    namespace: &'a str,
    interface: &'a str,
    version: &'a str,
    providers: Vec<ProviderMatch<'a>>,
}

/// An unsatisfied import.
#[derive(Debug)]
struct Unsatisfied<'a> {
    capsule_name: &'a str,
    namespace: &'a str,
    interface: &'a str,
    version: &'a str,
}

#[derive(Debug)]
struct CapsuleDependencyMetadata {
    name: String,
    imports: HashMap<String, HashMap<String, String>>,
    exports: HashMap<String, HashMap<String, String>>,
}

/// Build the dependency graph from installed capsule metadata.
///
/// For each capsule's imports, finds ALL capsules whose exports match
/// the namespace and interface name. Returns the per-capsule tree
/// (exports + resolved imports) and any imports that no installed capsule
/// satisfies.
fn build_dep_graph(
    capsules: &[CapsuleDependencyMetadata],
) -> (Vec<CapsuleTree<'_>>, Vec<Unsatisfied<'_>>) {
    let mut all_trees = Vec::new();
    let mut unsatisfied = Vec::new();

    for cap in capsules {
        let mut exports = Vec::new();
        let mut imports = Vec::new();

        // Collect exports.
        for (ns, ifaces) in &cap.exports {
            for (iface_name, version) in ifaces {
                exports.push(ExportEntry {
                    namespace: ns,
                    interface: iface_name,
                    version,
                });
            }
        }

        // Collect imports and resolve providers.
        for (ns, ifaces) in &cap.imports {
            for (iface_name, version) in ifaces {
                let mut providers = Vec::new();

                for other in capsules {
                    if other.name == cap.name {
                        continue;
                    }
                    if let Some(other_ns) = other.exports.get(ns.as_str())
                        && let Some(exported_ver) = other_ns.get(iface_name.as_str())
                    {
                        providers.push(ProviderMatch {
                            capsule_name: &other.name,
                            exported_version: exported_ver,
                        });
                    }
                }

                if providers.is_empty() {
                    unsatisfied.push(Unsatisfied {
                        capsule_name: &cap.name,
                        namespace: ns,
                        interface: iface_name,
                        version,
                    });
                }

                imports.push(ImportEdge {
                    namespace: ns,
                    interface: iface_name,
                    version,
                    providers,
                });
            }
        }

        all_trees.push(CapsuleTree {
            name: &cap.name,
            exports,
            imports,
        });
    }

    (all_trees, unsatisfied)
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// Show the capsule dependency tree (imports/exports graph).
pub(crate) async fn show_tree() -> anyhow::Result<()> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let capsules = match client.request(KernelRequest::GetCapsuleMetadata).await? {
        KernelResponse::CapsuleMetadata(entries) => entries
            .into_iter()
            .map(|entry| CapsuleDependencyMetadata {
                name: entry.name,
                imports: entry.imports,
                exports: entry.exports,
            })
            .collect::<Vec<_>>(),
        KernelResponse::Error(error) => bail!("daemon metadata lookup failed: {error}"),
        other => bail!("unexpected daemon metadata response: {other:?}"),
    };

    if capsules.is_empty() {
        println!("{}", Theme::info("No capsules installed."));
        return Ok(());
    }

    let (all_trees, unsatisfied) = build_dep_graph(&capsules);

    for (i, tree) in all_trees.iter().enumerate() {
        if i > 0 {
            println!();
        }

        println!("{}", tree.name.bold());

        // Show exports.
        if tree.exports.is_empty() && tree.imports.is_empty() {
            println!("  {}", Theme::dimmed("(no imports or exports)"));
            continue;
        }

        for exp in &tree.exports {
            let iface = format!("{}/{}", exp.namespace, exp.interface);
            println!("  exports: {} {}", iface.cyan(), exp.version);
        }

        // Show imports with provider resolution.
        if tree.imports.is_empty() {
            println!("  imports: {}", Theme::dimmed("(none)"));
        } else {
            for edge in &tree.imports {
                let iface = format!("{}/{}", edge.namespace, edge.interface);
                println!("  imports: {} {}", iface.cyan(), edge.version);
                if edge.providers.is_empty() {
                    println!("    {}", "exported by: (none - unsatisfied)".red());
                } else {
                    for pm in &edge.providers {
                        println!(
                            "    exported by: {} ({})",
                            pm.capsule_name.bold(),
                            pm.exported_version,
                        );
                    }
                }
            }
        }
    }

    if !unsatisfied.is_empty() {
        println!();
        println!("{}", Theme::header("Unsatisfied Imports"));
        for u in &unsatisfied {
            let iface = format!("{}/{} {}", u.namespace, u.interface, u.version);
            println!("  {} imports {}", u.capsule_name.bold(), iface.red());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_capsule(
        name: &str,
        exports: &[(&str, &str, &str)],
        imports: &[(&str, &str, &str)],
    ) -> CapsuleDependencyMetadata {
        let mut export_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (ns, iface, ver) in exports {
            export_map
                .entry(ns.to_string())
                .or_default()
                .insert(iface.to_string(), ver.to_string());
        }
        let mut import_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (ns, iface, ver) in imports {
            import_map
                .entry(ns.to_string())
                .or_default()
                .insert(iface.to_string(), ver.to_string());
        }
        CapsuleDependencyMetadata {
            name: name.to_string(),
            imports: import_map,
            exports: export_map,
        }
    }

    #[test]
    fn test_build_dep_graph_basic() {
        let capsules = vec![
            make_capsule("provider", &[("astrid", "session", "1.0.0")], &[]),
            make_capsule("consumer", &[], &[("astrid", "session", "^1.0")]),
        ];
        let (trees, unsatisfied) = build_dep_graph(&capsules);

        assert!(unsatisfied.is_empty());
        let consumer = trees
            .iter()
            .find(|d| d.name == "consumer")
            .expect("consumer");
        assert_eq!(consumer.imports.len(), 1);
        assert_eq!(consumer.imports[0].interface, "session");
        assert_eq!(consumer.imports[0].providers.len(), 1);
        assert_eq!(consumer.imports[0].providers[0].capsule_name, "provider");

        let provider = trees
            .iter()
            .find(|d| d.name == "provider")
            .expect("provider");
        assert_eq!(provider.exports.len(), 1);
        assert_eq!(provider.exports[0].interface, "session");
        assert_eq!(provider.exports[0].version, "1.0.0");
    }

    #[test]
    fn test_build_dep_graph_unsatisfied() {
        let capsules = vec![make_capsule(
            "consumer",
            &[],
            &[("astrid", "missing", "^1.0")],
        )];
        let (trees, unsatisfied) = build_dep_graph(&capsules);

        assert_eq!(unsatisfied.len(), 1);
        assert_eq!(unsatisfied[0].capsule_name, "consumer");
        assert_eq!(unsatisfied[0].interface, "missing");
        assert_eq!(trees[0].imports[0].providers.len(), 0);
    }

    #[test]
    fn test_build_dep_graph_multiple_providers() {
        let capsules = vec![
            make_capsule("openai", &[("astrid", "llm", "1.0.0")], &[]),
            make_capsule("ollama", &[("astrid", "llm", "1.0.0")], &[]),
            make_capsule("consumer", &[], &[("astrid", "llm", "^1.0")]),
        ];
        let (trees, unsatisfied) = build_dep_graph(&capsules);

        assert!(unsatisfied.is_empty());
        let consumer = trees
            .iter()
            .find(|d| d.name == "consumer")
            .expect("consumer");
        assert_eq!(consumer.imports[0].providers.len(), 2);
    }

    #[test]
    fn test_build_dep_graph_no_imports() {
        let capsules = vec![make_capsule(
            "standalone",
            &[("astrid", "session", "1.0.0")],
            &[],
        )];
        let (trees, unsatisfied) = build_dep_graph(&capsules);

        assert!(unsatisfied.is_empty());
        assert!(trees[0].imports.is_empty());
        assert_eq!(trees[0].exports.len(), 1);
    }

    #[test]
    fn test_build_dep_graph_no_interfaces() {
        let capsules = vec![CapsuleDependencyMetadata {
            name: "legacy".to_string(),
            imports: HashMap::new(),
            exports: HashMap::new(),
        }];
        let (trees, unsatisfied) = build_dep_graph(&capsules);

        assert!(unsatisfied.is_empty());
        assert!(trees[0].imports.is_empty());
        assert!(trees[0].exports.is_empty());
    }
}
