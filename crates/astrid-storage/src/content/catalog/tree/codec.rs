use super::{
    BRANCH_BYTES, BRANCH_TAG, BTreeMap, CatalogRoot, CatalogSummary, CatalogValue, ContentName,
    DirectoryLayout, LEAF_FIXED_BYTES, LEAF_TAG, LEFT_LABEL, Node, ObjectClass, ObjectId,
    ObjectKind, ObjectRecord, ObjectReference, PrincipalContentError, RIGHT_LABEL, ReferenceKind,
    ReferenceLabel, decode_summary, encode_summary, invalid, read_u64,
};

pub(super) fn intern_leaf_with_layout<L: DirectoryLayout>(
    name: &ContentName,
    value: CatalogValue,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CatalogRoot, PrincipalContentError> {
    let name_len = u64::try_from(name.as_str().len())
        .map_err(|_| PrincipalContentError::AccountingOverflow)?;
    let mut bytes = Vec::with_capacity(LEAF_FIXED_BYTES.saturating_add(name.as_str().len()));
    bytes.push(LEAF_TAG);
    bytes.extend_from_slice(&value.logical_bytes.to_le_bytes());
    bytes.extend_from_slice(&name_len.to_le_bytes());
    bytes.extend_from_slice(name.as_str().as_bytes());
    let record = ObjectRecord::new(
        ObjectKind::Directory,
        L::VERSION,
        bytes,
        vec![ObjectReference::owns(
            ReferenceLabel::new(L::VALUE_LABEL.to_vec()),
            value.file,
        )],
        value.logical_bytes,
        ObjectClass::Metadata,
    )
    .map_err(|error| PrincipalContentError::Projection(error.into()))?;
    let summary = L::summarize(name, value)?;
    intern(record, summary, identify, records)
}

pub(super) fn intern_branch_with_layout<L: DirectoryLayout>(
    bit: u64,
    left: CatalogRoot,
    right: CatalogRoot,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CatalogRoot, PrincipalContentError> {
    let summary = CatalogSummary::combine(left.summary, right.summary)?;
    let mut bytes = Vec::with_capacity(BRANCH_BYTES);
    bytes.push(BRANCH_TAG);
    bytes.extend_from_slice(&bit.to_le_bytes());
    encode_summary(&mut bytes, left.summary);
    encode_summary(&mut bytes, right.summary);
    let record = ObjectRecord::new(
        ObjectKind::Directory,
        L::VERSION,
        bytes,
        vec![
            ObjectReference::owns(ReferenceLabel::new(LEFT_LABEL.to_vec()), left.object),
            ObjectReference::owns(ReferenceLabel::new(RIGHT_LABEL.to_vec()), right.object),
        ],
        0,
        ObjectClass::Metadata,
    )
    .map_err(|error| PrincipalContentError::Projection(error.into()))?;
    intern(record, summary, identify, records)
}

pub(super) fn intern(
    record: ObjectRecord,
    summary: CatalogSummary,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CatalogRoot, PrincipalContentError> {
    let object = identify(&record);
    match records.get(&object) {
        Some(existing) if existing == &record => {},
        Some(_) => return Err(invalid(object, "content catalog identity collision")),
        None => {
            records.insert(object, record);
        },
    }
    Ok(CatalogRoot { object, summary })
}

pub(super) fn decode_node_with_layout<L: DirectoryLayout>(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<Node, PrincipalContentError> {
    if record.kind() != ObjectKind::Directory
        || record.format_version() != L::VERSION
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(object, "invalid content catalog node type"));
    }
    match record.canonical_bytes().first().copied() {
        Some(LEAF_TAG) => decode_leaf_with_layout::<L>(object, record),
        Some(BRANCH_TAG) => decode_branch_with_layout::<L>(object, record),
        _ => Err(invalid(object, "invalid content catalog node tag")),
    }
}

pub(super) fn decode_leaf_with_layout<L: DirectoryLayout>(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<Node, PrincipalContentError> {
    let bytes = record.canonical_bytes();
    if bytes.len() < LEAF_FIXED_BYTES || record.references().len() != 1 {
        return Err(invalid(object, "invalid content catalog leaf"));
    }
    let logical_bytes = read_u64(bytes, 1)?;
    let name_len = usize::try_from(read_u64(bytes, 9)?)
        .map_err(|_| PrincipalContentError::AccountingOverflow)?;
    if bytes.len() != LEAF_FIXED_BYTES.saturating_add(name_len) {
        return Err(invalid(
            object,
            "content catalog leaf name length disagrees",
        ));
    }
    let reference = &record.references()[0];
    if reference.kind() != ReferenceKind::Owns || reference.label().as_bytes() != L::VALUE_LABEL {
        return Err(invalid(
            object,
            "content catalog leaf has invalid file reference",
        ));
    }
    if record.logical_bytes() != logical_bytes {
        return Err(invalid(
            object,
            "content catalog leaf logical length disagrees",
        ));
    }
    let name = ContentName::from_bytes(&bytes[LEAF_FIXED_BYTES..])?;
    Ok(Node::Leaf {
        name,
        value: CatalogValue {
            file: reference.target(),
            logical_bytes,
        },
    })
}

pub(super) fn decode_branch_with_layout<L: DirectoryLayout>(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<Node, PrincipalContentError> {
    let bytes = record.canonical_bytes();
    if bytes.len() != BRANCH_BYTES || record.references().len() != 2 {
        return Err(invalid(object, "invalid content catalog branch"));
    }
    let left_reference = &record.references()[0];
    let right_reference = &record.references()[1];
    if left_reference.kind() != ReferenceKind::Owns
        || left_reference.label().as_bytes() != LEFT_LABEL
        || right_reference.kind() != ReferenceKind::Owns
        || right_reference.label().as_bytes() != RIGHT_LABEL
    {
        return Err(invalid(
            object,
            "content catalog branch has invalid child references",
        ));
    }
    let bit = read_u64(bytes, 1)?;
    let left_summary = decode_summary(bytes, 9)?;
    let right_summary = decode_summary(bytes, 33)?;
    CatalogSummary::combine(left_summary, right_summary)?;
    if record.logical_bytes() != 0 {
        return Err(invalid(
            object,
            "content catalog branch contributes visible bytes",
        ));
    }
    Ok(Node::Branch {
        bit,
        left: CatalogRoot {
            object: left_reference.target(),
            summary: left_summary,
        },
        right: CatalogRoot {
            object: right_reference.target(),
            summary: right_summary,
        },
    })
}
