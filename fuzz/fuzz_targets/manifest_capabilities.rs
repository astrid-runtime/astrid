#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use astrid_capsule_types::capability_presentation::{semantic_capabilities, semantic_expansion};
use astrid_capsule_types::manifest::CapabilitiesDef;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

#[derive(Debug, Arbitrary)]
struct Input {
    requested: Vec<u8>,
    approved: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let mut data = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut data) else {
        return;
    };

    let Some(requested) = decode_capabilities(&input.requested) else {
        return;
    };
    let Some(approved) = decode_capabilities(&input.approved) else {
        return;
    };

    assert_semantics_match_held_capabilities(&requested);
    assert_semantics_match_held_capabilities(&approved);

    for expansion in requested.expansions_from(&approved) {
        let semantic = semantic_expansion(&expansion);
        assert!(!semantic.action.is_empty());
        assert!(!semantic.impact.is_empty());
        assert_eq!(semantic.scope.len(), expansion.added.len());
        assert!(semantic.scope.iter().all(|scope| !scope.is_empty()));
    }

    let mut union = approved.clone();
    union.merge_from(&requested);
    assert!(
        requested.expansions_from(&union).is_empty(),
        "merging a requested capability set must make it a subset of the union"
    );
});

fn decode_capabilities(bytes: &[u8]) -> Option<CapabilitiesDef> {
    let text = std::str::from_utf8(bytes).ok()?;
    toml::from_str(text).ok()
}

fn assert_semantics_match_held_capabilities(capabilities: &CapabilitiesDef) {
    let held = capabilities
        .held_names()
        .into_iter()
        .collect::<HashSet<_>>();
    let semantic_names = semantic_capabilities(capabilities)
        .into_iter()
        .map(|card| {
            assert!(!card.capability.is_empty());
            assert!(!card.action.is_empty());
            assert!(!card.impact.is_empty());
            assert!(card.scope.iter().all(|scope| !scope.is_empty()));
            card.capability
        })
        .collect::<HashSet<_>>();

    assert!(
        held.iter().all(|name| semantic_names.contains(name)),
        "every held manifest capability must have a human-facing card"
    );
    assert!(
        semantic_names.iter().all(|name| held.contains(name)),
        "semantic cards must not claim authority absent from the manifest"
    );
}
