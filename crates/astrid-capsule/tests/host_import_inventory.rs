//! Detect changes to the import surface used by the production linker.

use std::collections::BTreeMap;
use std::path::Path;

use wit_parser::{Resolve, TypeDefKind, WorldItem};

#[test]
fn kernel_world_matches_the_host_import_inventory() {
    let mut resolve = Resolve::default();
    let wit = Path::new(env!("CARGO_MANIFEST_DIR")).join("wit-staging");
    let (package, _) = resolve.push_dir(wit).unwrap();
    let world = resolve.packages[package].worlds["kernel"];
    let mut rows = BTreeMap::new();
    for item in resolve.worlds[world].imports.values() {
        let WorldItem::Interface { id, .. } = item else {
            panic!("classify the new world-level import in the hosted security contract");
        };
        let name = resolve.id_of(*id).unwrap();
        let interface = &resolve.interfaces[*id];
        let mut operations: Vec<String> = interface.functions.keys().cloned().collect();
        for (resource, ty) in &interface.types {
            if matches!(resolve.types[*ty].kind, TypeDefKind::Resource) {
                operations.push(format!("[drop]{resource}"));
            }
        }
        operations.sort_unstable();
        assert!(rows.insert(name, operations).is_none());
    }
    let mut inventory = String::new();
    for (name, operations) in rows {
        if !inventory.is_empty() {
            inventory.push('\n');
        }
        inventory.push_str(&name);
        inventory.push('\n');
        for operation in operations {
            inventory.push_str("  ");
            inventory.push_str(&operation);
            inventory.push('\n');
        }
    }
    assert_eq!(inventory, include_str!("fixtures/host-imports.txt"));
}
