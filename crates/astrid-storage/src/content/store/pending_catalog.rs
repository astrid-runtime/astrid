//! Keep only catalog nodes reachable from the final root of a path-copy batch.

use std::collections::{BTreeMap, BTreeSet};

use super::{CatalogRoot, ObjectId, ObjectRecord, ObjectReference, ReferenceKind};

pub(super) fn retain_final_catalog_records(
    catalog: Option<CatalogRoot>,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) {
    let mut reachable = BTreeSet::new();
    let mut pending = catalog
        .map(|root| root.object)
        .into_iter()
        .collect::<Vec<_>>();
    while let Some(object) = pending.pop() {
        if !reachable.insert(object) {
            continue;
        }
        let Some(record) = records.get(&object) else {
            continue;
        };
        pending.extend(
            record
                .references()
                .iter()
                .filter(|reference| reference.kind() == ReferenceKind::Owns)
                .map(ObjectReference::target),
        );
    }
    records.retain(|object, _| reachable.contains(object));
}
