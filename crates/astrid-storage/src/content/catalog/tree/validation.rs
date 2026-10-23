use super::{
    BTreeMap, BTreeSet, CatalogRoot, CatalogSummary, CatalogValidation, DirectoryLayout, Node,
    ObjectId, ObjectRecord, PrincipalContentError, ValidatedRange, ValidationVisit,
    decode_node_with_layout, first_differing_bit, invalid, key_bit,
};

pub(crate) fn validate_catalog_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<CatalogValidation, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(CatalogValidation::default());
    };
    validate_catalog_root_with_layout::<L>(root, load)
}

pub(super) fn validate_catalog_root_with_layout<L: DirectoryLayout>(
    root: CatalogRoot,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<CatalogValidation, PrincipalContentError> {
    let mut stack = vec![ValidationVisit::Enter(root, None)];
    let mut seen = BTreeSet::new();
    let mut values = BTreeMap::<ObjectId, ValidatedRange>::new();
    while let Some(visit) = stack.pop() {
        match visit {
            ValidationVisit::Enter(current, parent_bit) => validate_enter_with_layout::<L>(
                current,
                parent_bit,
                load,
                &mut seen,
                &mut stack,
                &mut values,
            )?,
            ValidationVisit::Exit(object, node) => {
                validate_exit(object, &node, &mut values)?;
            },
        }
    }
    let validated = values
        .remove(&root.object)
        .ok_or_else(|| invalid(root.object, "content catalog root was not validated"))?;
    if !values.is_empty() || validated.summary != root.summary {
        return Err(invalid(
            root.object,
            "content catalog validation is incomplete",
        ));
    }
    Ok(CatalogValidation {
        root: Some(root.object),
        summary: validated.summary,
    })
}

pub(super) fn validate_enter_with_layout<L: DirectoryLayout>(
    current: CatalogRoot,
    parent_bit: Option<u64>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    seen: &mut BTreeSet<ObjectId>,
    stack: &mut Vec<ValidationVisit>,
    values: &mut BTreeMap<ObjectId, ValidatedRange>,
) -> Result<(), PrincipalContentError> {
    if !seen.insert(current.object) {
        return Err(invalid(
            current.object,
            "content catalog reuses a node or contains a cycle",
        ));
    }
    let node = decode_node_with_layout::<L>(current.object, &load(current.object)?)?;
    if node.summary::<L>()? != current.summary {
        return Err(invalid(
            current.object,
            "content catalog parent summary disagrees",
        ));
    }
    match &node {
        Node::Leaf { name, value } => {
            L::validate_value(name, *value, load)?;
            values.insert(
                current.object,
                ValidatedRange {
                    summary: current.summary,
                    min: name.clone(),
                    max: name.clone(),
                },
            );
        },
        Node::Branch {
            bit, left, right, ..
        } => {
            if parent_bit.is_some_and(|parent| *bit <= parent) {
                return Err(invalid(
                    current.object,
                    "content catalog branch bits do not increase",
                ));
            }
            stack.push(ValidationVisit::Exit(current.object, node.clone()));
            stack.push(ValidationVisit::Enter(*right, Some(*bit)));
            stack.push(ValidationVisit::Enter(*left, Some(*bit)));
        },
    }
    Ok(())
}

pub(super) fn validate_exit(
    object: ObjectId,
    node: &Node,
    values: &mut BTreeMap<ObjectId, ValidatedRange>,
) -> Result<(), PrincipalContentError> {
    let Node::Branch {
        bit, left, right, ..
    } = node
    else {
        return Err(invalid(object, "invalid content catalog traversal state"));
    };
    let right_value = values
        .remove(&right.object)
        .ok_or_else(|| invalid(object, "content catalog right child is missing"))?;
    let left_value = values
        .remove(&left.object)
        .ok_or_else(|| invalid(object, "content catalog left child is missing"))?;
    if left_value.summary != left.summary || right_value.summary != right.summary {
        return Err(invalid(object, "content catalog child totals disagree"));
    }
    validate_partition(object, *bit, &left_value, &right_value)?;
    values.insert(
        object,
        ValidatedRange {
            summary: CatalogSummary::combine(left_value.summary, right_value.summary)?,
            min: left_value.min,
            max: right_value.max,
        },
    );
    Ok(())
}

pub(super) fn validate_partition(
    object: ObjectId,
    bit: u64,
    left: &ValidatedRange,
    right: &ValidatedRange,
) -> Result<(), PrincipalContentError> {
    if left.max >= right.min
        || key_bit(&left.min, bit)?
        || key_bit(&left.max, bit)?
        || !key_bit(&right.min, bit)?
        || !key_bit(&right.max, bit)?
        || first_differing_bit(&left.max, &right.min)? != bit
    {
        return Err(invalid(object, "content catalog branch is not canonical"));
    }
    Ok(())
}
