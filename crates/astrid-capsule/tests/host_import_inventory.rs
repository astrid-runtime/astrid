//! Detect changes to the import surface used by the production linker.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use wit_component::WitPrinter;
use wit_parser::{Resolve, TypeDefKind, WorldId, WorldItem};

#[test]
fn kernel_world_matches_the_host_import_inventory() {
    let mut resolve = Resolve::default();
    let wit = Path::new(env!("CARGO_MANIFEST_DIR")).join("wit-staging");
    let (package, _) = resolve.push_dir(wit).unwrap();
    let world = resolve.packages[package].worlds["kernel"];
    assert_eq!(
        inventory(&resolve, world),
        include_str!("fixtures/host-imports.txt")
    );
}

fn inventory(resolve: &Resolve, world: WorldId) -> String {
    let mut rows = BTreeMap::new();
    for item in resolve.worlds[world].imports.values() {
        let WorldItem::Interface { id, .. } = item else {
            panic!("classify the new world-level import in the hosted security contract");
        };
        let name = resolve.id_of(*id).unwrap();
        let interface = &resolve.interfaces[*id];
        let mut printer = WitPrinter::default();
        printer
            .emit_docs(false)
            .print_interface(resolve, *id)
            .unwrap();
        let mut surface = String::from(printer.output);
        // A resource has an implicit host destructor even if it has no methods.
        for (resource, ty) in &interface.types {
            if matches!(resolve.types[*ty].kind, TypeDefKind::Resource) {
                writeln!(surface, "[drop]{resource}").unwrap();
            }
        }
        assert!(rows.insert(name, surface).is_none());
    }
    let mut inventory = String::new();
    for (name, surface) in rows {
        if !inventory.is_empty() {
            inventory.push('\n');
        }
        writeln!(inventory, "## {name}\n\n{}", surface.trim_end()).unwrap();
    }
    inventory
}

#[test]
fn changing_resource_ownership_changes_the_inventory() {
    fn inventory_for(parameter: &str, docs: &str) -> String {
        let source = format!(
            "package test:inventory;
            interface storage {{
                resource file;
                /// {docs}
                read: func(target: {parameter});
            }}
            world kernel {{ import storage; }}"
        );
        let mut resolve = Resolve::default();
        let package = resolve.push_str("storage.wit", &source).unwrap();
        inventory(&resolve, resolve.packages[package].worlds["kernel"])
    }
    let borrowed = inventory_for("borrow<file>", "Read a file.");
    assert_ne!(borrowed, inventory_for("own<file>", "Read a file."));
    assert_eq!(
        borrowed,
        inventory_for("borrow<file>", "Read its contents.")
    );
}
