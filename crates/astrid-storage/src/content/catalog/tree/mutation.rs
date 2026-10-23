use super::{
    BTreeMap, BuildTask, CatalogMutation, CatalogRoot, CatalogValue, ContentName, DirectoryLayout,
    Node, ObjectId, ObjectRecord, PathBranch, PrincipalContentError, decode_node_with_layout,
    first_differing_bit, intern_branch_with_layout, intern_leaf_with_layout, key_bit,
};

pub(crate) fn insert_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    name: &ContentName,
    value: CatalogValue,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<CatalogMutation, PrincipalContentError> {
    let mut records = BTreeMap::new();
    let leaf = intern_leaf_with_layout::<L>(name, value, identify, &mut records)?;
    let Some(root) = root else {
        return Ok(CatalogMutation {
            root: Some(leaf),
            previous: None,
            records,
        });
    };

    let (path, existing_name, previous) = descend_with_layout::<L>(root, name, load)?;
    if existing_name == *name {
        if previous == value {
            return Ok(CatalogMutation {
                root: Some(root),
                previous: Some(previous),
                records: BTreeMap::new(),
            });
        }
        let rebuilt = rebuild_path_with_layout::<L>(&path, leaf, identify, &mut records)?;
        return Ok(CatalogMutation {
            root: Some(rebuilt),
            previous: Some(previous),
            records,
        });
    }

    let differing_bit = first_differing_bit(&existing_name, name)?;
    let split = path
        .iter()
        .position(|branch| branch.bit >= differing_bit)
        .unwrap_or(path.len());
    let existing = if split == 0 {
        root
    } else {
        let parent = split
            .checked_sub(1)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        path[parent].selected()
    };
    let inserted = if key_bit(name, differing_bit)? {
        intern_branch_with_layout::<L>(differing_bit, existing, leaf, identify, &mut records)?
    } else {
        intern_branch_with_layout::<L>(differing_bit, leaf, existing, identify, &mut records)?
    };
    let rebuilt = rebuild_path_with_layout::<L>(&path[..split], inserted, identify, &mut records)?;
    Ok(CatalogMutation {
        root: Some(rebuilt),
        previous: None,
        records,
    })
}

pub(crate) fn delete_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<CatalogMutation, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(CatalogMutation {
            root: None,
            previous: None,
            records: BTreeMap::new(),
        });
    };
    let (path, existing_name, previous) = descend_with_layout::<L>(root, name, load)?;
    if existing_name != *name {
        return Ok(CatalogMutation {
            root: Some(root),
            previous: None,
            records: BTreeMap::new(),
        });
    }
    if path.is_empty() {
        return Ok(CatalogMutation {
            root: None,
            previous: Some(previous),
            records: BTreeMap::new(),
        });
    }
    let mut records = BTreeMap::new();
    let replacement = path
        .last()
        .copied()
        .ok_or(PrincipalContentError::AccountingOverflow)?
        .sibling();
    let rebuilt = rebuild_path_with_layout::<L>(
        &path[..path.len().saturating_sub(1)],
        replacement,
        identify,
        &mut records,
    )?;
    Ok(CatalogMutation {
        root: Some(rebuilt),
        previous: Some(previous),
        records,
    })
}

pub(crate) fn build_catalog_with_layout<L: DirectoryLayout>(
    entries: &BTreeMap<ContentName, CatalogValue>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<(Option<CatalogRoot>, BTreeMap<ObjectId, ObjectRecord>), PrincipalContentError> {
    if entries.is_empty() {
        return Ok((None, BTreeMap::new()));
    }
    let entries: Vec<_> = entries.iter().map(|(name, value)| (name, *value)).collect();
    let mut tasks = vec![BuildTask::Range(0, entries.len())];
    let mut results = Vec::new();
    let mut records = BTreeMap::new();
    while let Some(task) = tasks.pop() {
        match task {
            BuildTask::Range(start, end) if end.saturating_sub(start) == 1 => {
                let (name, value) = entries[start];
                results.push(intern_leaf_with_layout::<L>(
                    name,
                    value,
                    identify,
                    &mut records,
                )?);
            },
            BuildTask::Range(start, end) => {
                let last = end
                    .checked_sub(1)
                    .ok_or(PrincipalContentError::AccountingOverflow)?;
                let bit = first_differing_bit(entries[start].0, entries[last].0)?;
                let mut split = start.saturating_add(1);
                while split < end && !key_bit(entries[split].0, bit)? {
                    split = split.saturating_add(1);
                }
                if split == end {
                    return Err(PrincipalContentError::AccountingOverflow);
                }
                tasks.push(BuildTask::Join(bit));
                tasks.push(BuildTask::Range(split, end));
                tasks.push(BuildTask::Range(start, split));
            },
            BuildTask::Join(bit) => {
                let right = results
                    .pop()
                    .ok_or(PrincipalContentError::AccountingOverflow)?;
                let left = results
                    .pop()
                    .ok_or(PrincipalContentError::AccountingOverflow)?;
                results.push(intern_branch_with_layout::<L>(
                    bit,
                    left,
                    right,
                    identify,
                    &mut records,
                )?);
            },
        }
    }
    let root = results
        .pop()
        .ok_or(PrincipalContentError::AccountingOverflow)?;
    if !results.is_empty() {
        return Err(PrincipalContentError::AccountingOverflow);
    }
    Ok((Some(root), records))
}

pub(super) fn descend_with_layout<L: DirectoryLayout>(
    root: CatalogRoot,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(Vec<PathBranch>, ContentName, CatalogValue), PrincipalContentError> {
    let mut current = root;
    let mut path = Vec::new();
    loop {
        match decode_node_with_layout::<L>(current.object, &load(current.object)?)? {
            Node::Leaf {
                name: existing,
                value,
            } => return Ok((path, existing, value)),
            Node::Branch {
                bit, left, right, ..
            } => {
                let descended_right = key_bit(name, bit)?;
                path.push(PathBranch {
                    bit,
                    left,
                    right,
                    descended_right,
                });
                current = if descended_right { right } else { left };
            },
        }
    }
}

pub(super) fn rebuild_path_with_layout<L: DirectoryLayout>(
    path: &[PathBranch],
    mut child: CatalogRoot,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CatalogRoot, PrincipalContentError> {
    for branch in path.iter().rev() {
        child = if branch.descended_right {
            intern_branch_with_layout::<L>(branch.bit, branch.left, child, identify, records)?
        } else {
            intern_branch_with_layout::<L>(branch.bit, child, branch.right, identify, records)?
        };
    }
    Ok(child)
}
