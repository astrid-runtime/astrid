use super::{
    BRANCH_BASE_LABEL, BRANCH_FORMAT, BRANCH_MAGIC, BRANCH_RECEIPT_MAGIC, BRANCH_WORKING_LABEL,
    BranchState, CatalogRoot, CatalogSummary, ContentName, ObjectClass, ObjectId, ObjectKind,
    ObjectRecord, ObjectReference, PrincipalProjectionError, PrincipalUid, ReferenceKind,
    ReferenceLabel, UID_BYTES, WorkspaceBranchError, WorkspaceUid, validate_target_prefix,
};

pub(super) fn make_branch_record(
    id: WorkspaceUid,
    target_prefix: Option<&ContentName>,
    base: Option<CatalogRoot>,
    working: Option<CatalogRoot>,
) -> Result<ObjectRecord, WorkspaceBranchError> {
    make_workspace_record(None, BRANCH_MAGIC, id, target_prefix, base, working, true)
}

pub(super) fn make_branch_record_for_uid(
    binding_uid: PrincipalUid,
    id: WorkspaceUid,
    target_prefix: Option<&ContentName>,
    base: Option<CatalogRoot>,
    working: Option<CatalogRoot>,
) -> Result<ObjectRecord, WorkspaceBranchError> {
    make_workspace_record(
        Some(binding_uid),
        BRANCH_MAGIC,
        id,
        target_prefix,
        base,
        working,
        true,
    )
}

pub(super) fn make_promotion_receipt_for_uid(
    binding_uid: Option<PrincipalUid>,
    id: WorkspaceUid,
    target_prefix: Option<&ContentName>,
    base: Option<CatalogRoot>,
    working: Option<CatalogRoot>,
) -> Result<ObjectRecord, WorkspaceBranchError> {
    make_workspace_record(
        binding_uid,
        BRANCH_RECEIPT_MAGIC,
        id,
        target_prefix,
        base,
        working,
        false,
    )
}

pub(super) fn make_workspace_record(
    binding_uid: Option<PrincipalUid>,
    magic: &[u8],
    id: WorkspaceUid,
    target_prefix: Option<&ContentName>,
    base: Option<CatalogRoot>,
    working: Option<CatalogRoot>,
    own_roots: bool,
) -> Result<ObjectRecord, WorkspaceBranchError> {
    if let Some(prefix) = target_prefix {
        validate_target_prefix(Some(prefix.clone()))?;
    }
    let prefix_bytes = target_prefix.map_or(&[][..], |prefix| prefix.as_str().as_bytes());
    let prefix_len = u32::try_from(prefix_bytes.len()).map_err(|_| {
        WorkspaceBranchError::InvalidTargetPrefix {
            detail: "prefix exceeds the canonical length bound",
        }
    })?;
    let mut bytes = Vec::with_capacity(
        magic
            .len()
            .saturating_add(UID_BYTES)
            .saturating_add(binding_uid.map_or(0, |_| 1 + 32))
            .saturating_add(4)
            .saturating_add(prefix_bytes.len())
            .saturating_add(1 + 32)
            .saturating_add(1 + 32),
    );
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&id.as_bytes());
    if let Some(binding_uid) = binding_uid {
        bytes.push(1);
        bytes.extend_from_slice(binding_uid.as_bytes());
    }
    bytes.extend_from_slice(&prefix_len.to_le_bytes());
    bytes.extend_from_slice(prefix_bytes);
    append_root_encoding(&mut bytes, base);
    append_root_encoding(&mut bytes, working);
    let mut references = Vec::new();
    if own_roots && let Some(root) = base {
        references.push(ObjectReference::owns(
            ReferenceLabel::new(BRANCH_BASE_LABEL.to_vec()),
            root.object,
        ));
    }
    if own_roots && let Some(root) = working {
        references.push(ObjectReference::owns(
            ReferenceLabel::new(BRANCH_WORKING_LABEL.to_vec()),
            root.object,
        ));
    }
    ObjectRecord::new(
        ObjectKind::WorkspaceBranch,
        BRANCH_FORMAT,
        bytes,
        references,
        0,
        ObjectClass::Metadata,
    )
    .map_err(|error| WorkspaceBranchError::Projection(PrincipalProjectionError::Model(error)))
}

#[allow(clippy::too_many_lines)]
pub(super) fn decode_branch_record(
    object: ObjectId,
    record: &ObjectRecord,
    expected_id: WorkspaceUid,
) -> Result<BranchState, WorkspaceBranchError> {
    decode_workspace_record(object, record, expected_id, BRANCH_MAGIC, true)
}

pub(super) fn decode_promotion_receipt(
    object: ObjectId,
    record: &ObjectRecord,
    expected_id: WorkspaceUid,
) -> Result<BranchState, WorkspaceBranchError> {
    decode_workspace_record(object, record, expected_id, BRANCH_RECEIPT_MAGIC, false)
}

#[allow(clippy::too_many_lines)]
pub(super) fn decode_workspace_record(
    object: ObjectId,
    record: &ObjectRecord,
    expected_id: WorkspaceUid,
    magic: &[u8],
    require_root_references: bool,
) -> Result<BranchState, WorkspaceBranchError> {
    if record.kind() != ObjectKind::WorkspaceBranch
        || record.format_version() != BRANCH_FORMAT
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
    {
        return Err(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch record has invalid type",
        });
    }
    let bytes = record.canonical_bytes();
    let legacy_prefix_len_offset = magic.len().saturating_add(UID_BYTES);
    let legacy_prefix_len = bytes
        .get(legacy_prefix_len_offset..legacy_prefix_len_offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes);
    let legacy_roots_offset = legacy_prefix_len
        .and_then(|prefix_len| usize::try_from(prefix_len).ok())
        .map(|prefix_len| {
            legacy_prefix_len_offset
                .saturating_add(4)
                .saturating_add(prefix_len)
        });
    let legacy_fixed = legacy_roots_offset
        .map(|roots_offset| roots_offset.saturating_add(1 + 32).saturating_add(1 + 32));
    let legacy_encoding = legacy_fixed == Some(bytes.len());
    let (binding_uid, prefix_len_offset) = if legacy_encoding {
        (None, legacy_prefix_len_offset)
    } else {
        let binding_flag =
            *bytes
                .get(legacy_prefix_len_offset)
                .ok_or(WorkspaceBranchError::InvalidGraph {
                    object,
                    detail: "workspace branch binding UID flag is missing",
                })?;
        let binding_bytes = bytes
            .get(
                legacy_prefix_len_offset.saturating_add(1)
                    ..legacy_prefix_len_offset.saturating_add(1 + 32),
            )
            .ok_or(WorkspaceBranchError::InvalidGraph {
                object,
                detail: "workspace branch binding UID is missing",
            })?;
        let binding_uid = match binding_flag {
            1 => Some(PrincipalUid::from_bytes(binding_bytes.try_into().map_err(
                |_| WorkspaceBranchError::InvalidGraph {
                    object,
                    detail: "workspace branch binding UID is malformed",
                },
            )?)),
            0 if binding_bytes.iter().all(|byte| *byte == 0) => None,
            _ => {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object,
                    detail: "workspace branch binding UID flag is invalid",
                });
            },
        };
        (binding_uid, legacy_prefix_len_offset.saturating_add(1 + 32))
    };
    let prefix_len_bytes = bytes
        .get(prefix_len_offset..prefix_len_offset.saturating_add(4))
        .ok_or(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch target prefix length is missing",
        })?;
    let prefix_len = usize::try_from(u32::from_le_bytes(prefix_len_bytes.try_into().map_err(
        |_| WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch target prefix length is malformed",
        },
    )?))
    .map_err(|_| WorkspaceBranchError::InvalidGraph {
        object,
        detail: "workspace branch target prefix length overflows",
    })?;
    let roots_offset = prefix_len_offset
        .saturating_add(4)
        .saturating_add(prefix_len);
    let fixed = roots_offset.saturating_add(1 + 32).saturating_add(1 + 32);
    if bytes.len() != fixed || !bytes.starts_with(magic) {
        return Err(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch record bytes are malformed",
        });
    }
    let uid_start = magic.len();
    let uid = WorkspaceUid::from_bytes(
        bytes
            .get(uid_start..uid_start.saturating_add(UID_BYTES))
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(WorkspaceBranchError::InvalidGraph {
                object,
                detail: "workspace branch record id is missing",
            })?,
    );
    if uid != expected_id {
        return Err(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch label and record id disagree",
        });
    }
    let prefix_bytes = bytes
        .get(prefix_len_offset.saturating_add(4)..roots_offset)
        .ok_or(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch target prefix bytes are missing",
        })?;
    let target_prefix = if prefix_bytes.is_empty() {
        None
    } else {
        let prefix = ContentName::from_bytes(prefix_bytes).map_err(|_| {
            WorkspaceBranchError::InvalidGraph {
                object,
                detail: "workspace branch target prefix is not valid UTF-8",
            }
        })?;
        validate_target_prefix(Some(prefix.clone())).map_err(|_| {
            WorkspaceBranchError::InvalidGraph {
                object,
                detail: "workspace branch target prefix is not canonical",
            }
        })?;
        Some(prefix)
    };
    let mut offset = roots_offset;
    let base_id = decode_root_id(bytes, &mut offset)
        .map_err(|detail| WorkspaceBranchError::InvalidGraph { object, detail })?;
    let working_id = decode_root_id(bytes, &mut offset)
        .map_err(|detail| WorkspaceBranchError::InvalidGraph { object, detail })?;
    if offset != bytes.len() {
        return Err(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch record has trailing bytes",
        });
    }
    let expected_labels: Vec<&[u8]> = [
        base_id.is_some().then_some(BRANCH_BASE_LABEL),
        working_id.is_some().then_some(BRANCH_WORKING_LABEL),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut base = None;
    let mut working = None;
    for reference in record.references() {
        if reference.kind() != ReferenceKind::Owns {
            return Err(WorkspaceBranchError::InvalidGraph {
                object,
                detail: "workspace branch root reference is not owning",
            });
        }
        match reference.label().as_bytes() {
            BRANCH_BASE_LABEL if base_id == Some(reference.target()) => {
                base = Some(reference.target());
            },
            BRANCH_WORKING_LABEL if working_id == Some(reference.target()) => {
                working = Some(reference.target());
            },
            _ => {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object,
                    detail: "workspace branch root reference disagrees with bytes",
                });
            },
        }
    }
    let expected_reference_count = match (base_id.is_some(), working_id.is_some()) {
        (false, false) => 0,
        (true, false) | (false, true) => 1,
        (true, true) => 2,
    };
    if (require_root_references
        && (record.references().len() != expected_reference_count
            || record
                .references()
                .iter()
                .zip(expected_labels)
                .any(|(reference, expected)| reference.label().as_bytes() != expected)))
        || (!require_root_references && !record.references().is_empty())
    {
        return Err(WorkspaceBranchError::InvalidGraph {
            object,
            detail: "workspace branch root references are not canonical",
        });
    }
    Ok(BranchState {
        id: uid,
        binding_uid,
        target_prefix,
        base: base.or(base_id).map(|object| CatalogRoot {
            object,
            summary: CatalogSummary::default(),
        }),
        working: working.or(working_id).map(|object| CatalogRoot {
            object,
            summary: CatalogSummary::default(),
        }),
    })
}

pub(super) fn append_root_encoding(bytes: &mut Vec<u8>, root: Option<CatalogRoot>) {
    if let Some(root) = root {
        bytes.push(1);
        bytes.extend_from_slice(root.object.as_bytes());
    } else {
        bytes.push(0);
        bytes.extend_from_slice(&[0; 32]);
    }
}

pub(super) fn decode_root_id(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<Option<ObjectId>, &'static str> {
    let present = *bytes
        .get(*offset)
        .ok_or("workspace branch root flag is missing")?;
    *offset = offset.saturating_add(1);
    let id = bytes
        .get(*offset..offset.saturating_add(32))
        .ok_or("workspace branch root id is missing")?;
    *offset = offset.saturating_add(32);
    match present {
        0 if id.iter().all(|byte| *byte == 0) => Ok(None),
        1 => Ok(Some(ObjectId::new(
            id.try_into()
                .map_err(|_| "workspace branch root id is malformed")?,
        ))),
        _ => Err("workspace branch root flag is invalid"),
    }
}
