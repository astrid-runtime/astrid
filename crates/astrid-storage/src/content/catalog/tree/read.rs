use super::{
    CatalogRoot, CatalogValue, ContentEntry, ContentName, DirectoryLayout, Node, ObjectId,
    ObjectRecord, PrincipalContentError, decode_node_with_layout, key_bit,
};

pub(crate) fn root_from_record_with_layout<L: DirectoryLayout>(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<CatalogRoot, PrincipalContentError> {
    let node = decode_node_with_layout::<L>(object, record)?;
    Ok(CatalogRoot {
        object,
        summary: node.summary::<L>()?,
    })
}

pub(crate) fn lookup_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Option<CatalogValue>, PrincipalContentError> {
    let Some(mut current) = root else {
        return Ok(None);
    };
    loop {
        match decode_node_with_layout::<L>(current.object, &load(current.object)?)? {
            Node::Leaf {
                name: existing,
                value,
            } => return Ok((existing == *name).then_some(value)),
            Node::Branch {
                bit, left, right, ..
            } => {
                current = if key_bit(name, bit)? { right } else { left };
            },
        }
    }
}

pub(crate) fn list_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Vec<ContentEntry>, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(Vec::new());
    };
    let capacity = usize::try_from(root.summary.entries)
        .map_err(|_| PrincipalContentError::AccountingOverflow)?;
    let mut entries = Vec::with_capacity(capacity);
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        match decode_node_with_layout::<L>(current.object, &load(current.object)?)? {
            Node::Leaf { name, value } => {
                entries.push(ContentEntry::new(name, value.file, value.logical_bytes));
            },
            Node::Branch { left, right, .. } => {
                stack.push(right);
                stack.push(left);
            },
        }
    }
    Ok(entries)
}

/// List a canonical byte-prefix without descending catalog branches that are
/// known to disagree before the prefix ends. The catalog's Patricia branches
/// split on the first differing byte bit, so an unrelated top-level subtree
/// can be skipped without materializing its leaves.
pub(crate) fn list_prefix_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    prefix: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Vec<ContentEntry>, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(Vec::new());
    };
    let prefix_bits = u64::try_from(prefix.as_str().len())
        .map_err(|_| PrincipalContentError::AccountingOverflow)?
        .checked_mul(8)
        .ok_or(PrincipalContentError::AccountingOverflow)?;
    let mut entries = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        match decode_node_with_layout::<L>(current.object, &load(current.object)?)? {
            Node::Leaf { name, value } => {
                if name.as_str().starts_with(prefix.as_str()) {
                    entries.push(ContentEntry::new(name, value.file, value.logical_bytes));
                }
            },
            Node::Branch { bit, left, right } if bit < prefix_bits => {
                if key_bit(prefix, bit)? {
                    stack.push(right);
                } else {
                    stack.push(left);
                }
            },
            Node::Branch { left, right, .. } => {
                stack.push(right);
                stack.push(left);
            },
        }
    }
    Ok(entries)
}

/// Return whether any catalog name begins with `prefix` without materializing
/// the matching leaves. The walk is the same Patricia skip as [`list_prefix`],
/// but it stops at the first hit so parent-exists checks stay O(log N).
pub(crate) fn prefix_exists_with_layout<L: DirectoryLayout>(
    root: Option<CatalogRoot>,
    prefix: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<bool, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(false);
    };
    let prefix_bits = u64::try_from(prefix.as_str().len())
        .map_err(|_| PrincipalContentError::AccountingOverflow)?
        .checked_mul(8)
        .ok_or(PrincipalContentError::AccountingOverflow)?;
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        match decode_node_with_layout::<L>(current.object, &load(current.object)?)? {
            Node::Leaf { name, .. } => {
                if name.as_str().starts_with(prefix.as_str()) {
                    return Ok(true);
                }
            },
            Node::Branch { bit, left, right } if bit < prefix_bits => {
                if key_bit(prefix, bit)? {
                    stack.push(right);
                } else {
                    stack.push(left);
                }
            },
            Node::Branch { left, right, .. } => {
                stack.push(right);
                stack.push(left);
            },
        }
    }
    Ok(false)
}
