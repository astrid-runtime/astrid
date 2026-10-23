use super::{
    BTreeMap, BranchState, CatalogRoot, CatalogValue, ContentName, DIRECTORY_LABEL, DirectoryProof,
    ObjectId, ObjectRecord, ObjectReference, PrincipalContentError, ReferenceKind, WorkspaceLayout,
    WorkspaceUid, binding_key, decode_row, hydrate_root, inventory_key, key, row_charge, tree,
    validate_catalog,
};
use crate::storage_model::ReferenceLabel;

pub(super) fn validate_row(
    name: &ContentName,
    value: CatalogValue,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(), PrincipalContentError> {
    let record = load(value.file)?;
    let (branch, promoted) = decode_row(value.file, &record)?;
    let expected = key(if promoted { "r" } else { "b" }, branch.id)?;
    let binding = binding_key(&branch)?;
    let charge = if name == &expected {
        if !promoted {
            let base = validate_catalog(hydrate_root(branch.base, load)?, load)?;
            let working = validate_catalog(hydrate_root(branch.working, load)?, load)?;
            if base.root != branch.base.map(|root| root.object)
                || working.root != branch.working.map(|root| root.object)
            {
                return Err(PrincipalContentError::InvalidGraph {
                    object: value.file,
                    detail: "workspace catalog roots disagree",
                });
            }
        }
        let mut hydrated = branch;
        if !promoted {
            hydrated.working = hydrate_root(hydrated.working, load)?;
        }
        row_charge(&record, &hydrated, promoted)?
    } else if binding.as_ref() == Some(name) || inventory_key(&branch)?.as_ref() == Some(name) {
        0
    } else {
        return Err(PrincipalContentError::InvalidGraph {
            object: value.file,
            detail: "workspace directory key and record disagree",
        });
    };
    if value.logical_bytes != charge {
        return Err(PrincipalContentError::InvalidGraph {
            object: value.file,
            detail: "workspace directory quota disagrees",
        });
    }
    Ok(())
}

pub(super) fn validate(
    reference: &ObjectReference,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<DirectoryProof, PrincipalContentError> {
    #[cfg(test)]
    super::FULL_DIRECTORY_VALIDATIONS.with(|calls| calls.set(calls.get().strict_add(1)));
    let object = reference.target();
    if reference.label().as_bytes() != DIRECTORY_LABEL || reference.kind() != ReferenceKind::Owns {
        return Err(PrincipalContentError::InvalidGraph {
            object,
            detail: "invalid workspace directory reference",
        });
    }
    let root = tree::root_from_record_with_layout::<WorkspaceLayout>(object, &load(object)?)?;
    tree::validate_catalog_with_layout::<WorkspaceLayout>(Some(root), load)?;
    let entries = tree::list_with_layout::<WorkspaceLayout>(Some(root), load)?;
    let mut groups = BTreeMap::<ContentName, Vec<(ObjectId, bool)>>::new();
    let mut expected_inventory = BTreeMap::new();
    let mut actual_inventory = BTreeMap::new();
    let mut selectors = BTreeMap::new();
    let mut ids = std::collections::BTreeSet::new();
    for entry in entries {
        if entry.name().as_str().starts_with("u/") {
            selectors.insert(entry.name().clone(), entry.file());
        } else if entry.name().as_str().starts_with("a/") {
            actual_inventory.insert(entry.name().clone(), entry.file());
        } else {
            let record = load(entry.file())?;
            let (branch, promoted) = decode_row(entry.file(), &record)?;
            if !ids.insert(branch.id) {
                return Err(PrincipalContentError::InvalidGraph {
                    object,
                    detail: "workspace is both live and promoted",
                });
            }
            if let Some(binding) = binding_key(&branch)? {
                groups
                    .entry(binding)
                    .or_default()
                    .push((entry.file(), promoted));
                if let Some(inventory) = inventory_key(&branch)? {
                    expected_inventory.insert(inventory, entry.file());
                }
            }
        }
    }
    if actual_inventory != expected_inventory || groups.len() != selectors.len() {
        return Err(PrincipalContentError::InvalidGraph {
            object,
            detail: "workspace directory binding inventory disagrees",
        });
    }
    for (binding, members) in groups {
        verify_binding_members(object, &binding, &members, &selectors)?;
    }
    Ok(DirectoryProof { root })
}

fn verify_binding_members(
    object: ObjectId,
    binding: &ContentName,
    members: &[(ObjectId, bool)],
    selectors: &BTreeMap<ContentName, ObjectId>,
) -> Result<(), PrincipalContentError> {
    let live = members
        .iter()
        .filter(|(_, promoted)| !promoted)
        .map(|(member, _)| *member)
        .collect::<Vec<_>>();
    let selected = selectors.get(binding).copied();
    if live.len() > 1
        || selected.is_none()
        || !members.iter().any(|(member, _)| Some(*member) == selected)
        || live.first().is_some_and(|member| Some(*member) != selected)
    {
        return Err(PrincipalContentError::InvalidGraph {
            object,
            detail: "workspace directory current binding disagrees",
        });
    }
    Ok(())
}

/// Prove a post-edit directory. Migration/cold paths full-validate; otherwise
/// only the touched primary and affected UID/prefix groups are rechecked.
pub(super) fn prove_commit(
    prior: Option<DirectoryProof>,
    root: Option<CatalogRoot>,
    id: WorkspaceUid,
    old_primary: Option<&(BranchState, bool)>,
    new_primary: Option<&(BranchState, bool)>,
    selectors: &BTreeMap<ContentName, Option<ObjectId>>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Option<DirectoryProof>, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(None);
    };
    if prior.is_none() {
        return full_proof(root, load).map(Some);
    }
    authenticate_primary(root, id, load)?;
    ensure_inventory_transition(root, old_primary, new_primary, load)?;
    let mut bindings = BTreeMap::new();
    for primary in [old_primary, new_primary].into_iter().flatten() {
        if let Some(binding) = binding_key(&primary.0)? {
            bindings.insert(binding, primary.0.binding_uid);
        }
    }
    if bindings.is_empty() {
        // Unbound primary rows must not gain a/u aliases for this id.
        ensure_unbound_primary(root, id, load)?;
    }
    for binding in bindings.keys() {
        let expected = selectors
            .get(binding)
            .ok_or(PrincipalContentError::InvalidGraph {
                object: root.object,
                detail: "workspace selector transition is missing",
            })?;
        let actual = tree::lookup_with_layout::<WorkspaceLayout>(Some(root), binding, load)?
            .map(|value| value.file);
        if &actual != expected {
            return Err(PrincipalContentError::InvalidGraph {
                object: root.object,
                detail: "workspace selector transition disagrees",
            });
        }
        verify_selector(root, binding, load)?;
    }
    Ok(Some(DirectoryProof { root }))
}

fn full_proof(
    root: CatalogRoot,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<DirectoryProof, PrincipalContentError> {
    let reference =
        ObjectReference::owns(ReferenceLabel::new(DIRECTORY_LABEL.to_vec()), root.object);
    let proof = validate(&reference, load)?;
    if proof.root != root {
        return Err(PrincipalContentError::InvalidGraph {
            object: root.object,
            detail: "workspace directory proof root disagrees",
        });
    }
    Ok(proof)
}

fn authenticate_primary(
    root: CatalogRoot,
    id: WorkspaceUid,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(), PrincipalContentError> {
    let live = primary_value(root, id, false, load)?;
    let receipt = primary_value(root, id, true, load)?;
    if live.is_some() && receipt.is_some() {
        return Err(PrincipalContentError::InvalidGraph {
            object: root.object,
            detail: "workspace is both live and promoted",
        });
    }
    if let Some((name, value)) = live.or(receipt) {
        validate_row(&name, value, load)?;
    }
    Ok(())
}

fn primary_value(
    root: CatalogRoot,
    id: WorkspaceUid,
    promoted: bool,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Option<(ContentName, CatalogValue)>, PrincipalContentError> {
    let name = key(if promoted { "r" } else { "b" }, id)?;
    Ok(
        tree::lookup_with_layout::<WorkspaceLayout>(Some(root), &name, load)?
            .map(|value| (name, value)),
    )
}

fn ensure_inventory_transition(
    root: CatalogRoot,
    old_primary: Option<&(BranchState, bool)>,
    new_primary: Option<&(BranchState, bool)>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(), PrincipalContentError> {
    let old_inventory = old_primary
        .map(|(branch, _)| inventory_key(branch))
        .transpose()?
        .flatten();
    let new_inventory = new_primary
        .map(|(branch, _)| inventory_key(branch))
        .transpose()?
        .flatten();
    if let Some(inventory) = old_inventory.as_ref()
        && new_inventory.as_ref() != Some(inventory)
        && tree::lookup_with_layout::<WorkspaceLayout>(Some(root), inventory, load)?.is_some()
    {
        return Err(PrincipalContentError::InvalidGraph {
            object: root.object,
            detail: "workspace inventory was not removed",
        });
    }
    if let Some((branch, promoted)) = new_primary
        && let Some(inventory) = new_inventory
    {
        let Some(value) =
            tree::lookup_with_layout::<WorkspaceLayout>(Some(root), &inventory, load)?
        else {
            return Err(PrincipalContentError::InvalidGraph {
                object: root.object,
                detail: "workspace inventory missing after edit",
            });
        };
        validate_row(&inventory, value, load)?;
        let expected = key(if *promoted { "r" } else { "b" }, branch.id)?;
        let Some(primary) =
            tree::lookup_with_layout::<WorkspaceLayout>(Some(root), &expected, load)?
        else {
            return Err(PrincipalContentError::InvalidGraph {
                object: value.file,
                detail: "workspace inventory primary missing",
            });
        };
        if primary.file != value.file {
            return Err(PrincipalContentError::InvalidGraph {
                object: value.file,
                detail: "workspace inventory primary disagrees",
            });
        }
    }
    Ok(())
}

fn ensure_unbound_primary(
    root: CatalogRoot,
    id: WorkspaceUid,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(), PrincipalContentError> {
    for promoted in [false, true] {
        let Some((_, value)) = primary_value(root, id, promoted, load)? else {
            continue;
        };
        let (branch, _) = decode_row(value.file, &load(value.file)?)?;
        if branch.binding_uid.is_some() || inventory_key(&branch)?.is_some() {
            return Err(PrincipalContentError::InvalidGraph {
                object: value.file,
                detail: "unbound workspace gained inventory state",
            });
        }
    }
    Ok(())
}

/// The prior proof establishes uniqueness and complete a/u membership.
/// Path-copy edits change only the named primary, its a row and its selector.
/// Validate the selected row's exact primary/inventory links without rescanning
/// historical receipts for this UID on every ordinary file update.
fn verify_selector(
    root: CatalogRoot,
    binding: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(), PrincipalContentError> {
    let Some(value) = tree::lookup_with_layout::<WorkspaceLayout>(Some(root), binding, load)?
    else {
        return Ok(());
    };
    validate_row(binding, value, load)?;
    let (branch, promoted) = decode_row(value.file, &load(value.file)?)?;
    let primary = key(if promoted { "r" } else { "b" }, branch.id)?;
    let inventory = inventory_key(&branch)?.ok_or(PrincipalContentError::InvalidGraph {
        object: value.file,
        detail: "selected workspace has no inventory",
    })?;
    for name in [primary, inventory] {
        if tree::lookup_with_layout::<WorkspaceLayout>(Some(root), &name, load)?
            .map(|entry| entry.file)
            != Some(value.file)
        {
            return Err(PrincipalContentError::InvalidGraph {
                object: value.file,
                detail: "selected workspace primary/inventory disagrees",
            });
        }
    }
    Ok(())
}
