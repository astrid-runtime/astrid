use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use crate::content_dag::{ContentReadError, ContentSource, describe_content};
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel,
};

use super::super::{ContentEntry, ContentName, PrincipalContentError};

const CATALOG_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(2) {
    Some(version) => version,
    None => unreachable!(),
};
const LEAF_TAG: u8 = 0;
const BRANCH_TAG: u8 = 1;
const LEAF_FIXED_BYTES: usize = 17;
const BRANCH_BYTES: usize = 57;
const FILE_LABEL: &[u8] = b"file";
const LEFT_LABEL: &[u8] = b"left";
const RIGHT_LABEL: &[u8] = b"right";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CatalogSummary {
    pub(crate) logical_bytes: u64,
    pub(crate) quota_bytes: u64,
    pub(crate) entries: u64,
}

impl CatalogSummary {
    fn combine(left: Self, right: Self) -> Result<Self, PrincipalContentError> {
        Ok(Self {
            logical_bytes: left
                .logical_bytes
                .checked_add(right.logical_bytes)
                .ok_or(PrincipalContentError::AccountingOverflow)?,
            quota_bytes: left
                .quota_bytes
                .checked_add(right.quota_bytes)
                .ok_or(PrincipalContentError::AccountingOverflow)?,
            entries: left
                .entries
                .checked_add(right.entries)
                .ok_or(PrincipalContentError::AccountingOverflow)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogValue {
    pub(crate) file: ObjectId,
    pub(crate) logical_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogRoot {
    pub(crate) object: ObjectId,
    pub(crate) summary: CatalogSummary,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CatalogValidation {
    pub(crate) root: Option<ObjectId>,
    pub(crate) summary: CatalogSummary,
}

#[derive(Debug)]
pub(crate) struct CatalogMutation {
    pub(crate) root: Option<CatalogRoot>,
    pub(crate) previous: Option<CatalogValue>,
    pub(crate) records: BTreeMap<ObjectId, ObjectRecord>,
}

#[derive(Clone, Debug)]
enum Node {
    Leaf {
        name: ContentName,
        value: CatalogValue,
    },
    Branch {
        bit: u64,
        left: CatalogRoot,
        right: CatalogRoot,
    },
}

impl Node {
    fn summary(&self) -> Result<CatalogSummary, PrincipalContentError> {
        match self {
            Self::Leaf { name, value } => leaf_summary(name, *value),
            Self::Branch { left, right, .. } => {
                CatalogSummary::combine(left.summary, right.summary)
            },
        }
    }
}

#[derive(Clone, Copy)]
struct PathBranch {
    bit: u64,
    left: CatalogRoot,
    right: CatalogRoot,
    descended_right: bool,
}

impl PathBranch {
    const fn selected(self) -> CatalogRoot {
        if self.descended_right {
            self.right
        } else {
            self.left
        }
    }

    const fn sibling(self) -> CatalogRoot {
        if self.descended_right {
            self.left
        } else {
            self.right
        }
    }
}

enum BuildTask {
    Range(usize, usize),
    Join(u64),
}

enum ValidationVisit {
    Enter(CatalogRoot, Option<u64>),
    Exit(ObjectId, Node),
}

struct ValidatedRange {
    summary: CatalogSummary,
    min: ContentName,
    max: ContentName,
}

pub(crate) fn root_from_record(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<CatalogRoot, PrincipalContentError> {
    let node = decode_node(object, record)?;
    Ok(CatalogRoot {
        object,
        summary: node.summary()?,
    })
}

pub(crate) fn lookup(
    root: Option<CatalogRoot>,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Option<CatalogValue>, PrincipalContentError> {
    let Some(mut current) = root else {
        return Ok(None);
    };
    loop {
        match decode_node(current.object, &load(current.object)?)? {
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

pub(crate) fn list(
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
        match decode_node(current.object, &load(current.object)?)? {
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
pub(crate) fn list_prefix(
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
        match decode_node(current.object, &load(current.object)?)? {
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

pub(crate) fn insert(
    root: Option<CatalogRoot>,
    name: &ContentName,
    value: CatalogValue,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<CatalogMutation, PrincipalContentError> {
    let mut records = BTreeMap::new();
    let leaf = intern_leaf(name, value, identify, &mut records)?;
    let Some(root) = root else {
        return Ok(CatalogMutation {
            root: Some(leaf),
            previous: None,
            records,
        });
    };

    let (path, existing_name, previous) = descend(root, name, load)?;
    if existing_name == *name {
        if previous == value {
            return Ok(CatalogMutation {
                root: Some(root),
                previous: Some(previous),
                records: BTreeMap::new(),
            });
        }
        let rebuilt = rebuild_path(&path, leaf, identify, &mut records)?;
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
        intern_branch(differing_bit, existing, leaf, identify, &mut records)?
    } else {
        intern_branch(differing_bit, leaf, existing, identify, &mut records)?
    };
    let rebuilt = rebuild_path(&path[..split], inserted, identify, &mut records)?;
    Ok(CatalogMutation {
        root: Some(rebuilt),
        previous: None,
        records,
    })
}

pub(crate) fn delete(
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
    let (path, existing_name, previous) = descend(root, name, load)?;
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
    let rebuilt = rebuild_path(
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

pub(crate) fn build_catalog(
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
                results.push(intern_leaf(name, value, identify, &mut records)?);
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
                results.push(intern_branch(bit, left, right, identify, &mut records)?);
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

pub(crate) fn validate_catalog(
    root: Option<CatalogRoot>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<CatalogValidation, PrincipalContentError> {
    let Some(root) = root else {
        return Ok(CatalogValidation::default());
    };
    validate_catalog_root(root, load)
}

fn validate_catalog_root(
    root: CatalogRoot,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<CatalogValidation, PrincipalContentError> {
    let mut stack = vec![ValidationVisit::Enter(root, None)];
    let mut seen = BTreeSet::new();
    let mut values = BTreeMap::<ObjectId, ValidatedRange>::new();
    while let Some(visit) = stack.pop() {
        match visit {
            ValidationVisit::Enter(current, parent_bit) => validate_enter(
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

fn validate_enter(
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
    let node = decode_node(current.object, &load(current.object)?)?;
    if node.summary()? != current.summary {
        return Err(invalid(
            current.object,
            "content catalog parent summary disagrees",
        ));
    }
    match &node {
        Node::Leaf { name, value } => {
            validate_file_length(*value, load)?;
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

fn validate_exit(
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

fn validate_partition(
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

fn validate_file_length(
    value: CatalogValue,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(), PrincipalContentError> {
    let record = load(value.file)?;
    let source = SingleObjectSource {
        object: value.file,
        record,
    };
    let descriptor = describe_content(&source, value.file).map_err(|error| match error {
        ContentReadError::Content(error) => PrincipalContentError::Content(error),
        ContentReadError::Source(error) => match error {},
    })?;
    if descriptor.logical_bytes() != value.logical_bytes {
        return Err(invalid(
            value.file,
            "content catalog and file logical lengths disagree",
        ));
    }
    Ok(())
}

struct SingleObjectSource {
    object: ObjectId,
    record: ObjectRecord,
}

impl ContentSource for SingleObjectSource {
    type Error = Infallible;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        Ok((id == self.object).then(|| self.record.clone()))
    }
}

fn descend(
    root: CatalogRoot,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<(Vec<PathBranch>, ContentName, CatalogValue), PrincipalContentError> {
    let mut current = root;
    let mut path = Vec::new();
    loop {
        match decode_node(current.object, &load(current.object)?)? {
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

fn rebuild_path(
    path: &[PathBranch],
    mut child: CatalogRoot,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CatalogRoot, PrincipalContentError> {
    for branch in path.iter().rev() {
        child = if branch.descended_right {
            intern_branch(branch.bit, branch.left, child, identify, records)?
        } else {
            intern_branch(branch.bit, child, branch.right, identify, records)?
        };
    }
    Ok(child)
}

fn intern_leaf(
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
        CATALOG_VERSION,
        bytes,
        vec![ObjectReference::owns(
            ReferenceLabel::new(FILE_LABEL.to_vec()),
            value.file,
        )],
        value.logical_bytes,
        ObjectClass::Metadata,
    )
    .map_err(|error| PrincipalContentError::Projection(error.into()))?;
    let summary = leaf_summary(name, value)?;
    intern(record, summary, identify, records)
}

fn intern_branch(
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
        CATALOG_VERSION,
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

fn intern(
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

fn decode_node(object: ObjectId, record: &ObjectRecord) -> Result<Node, PrincipalContentError> {
    if record.kind() != ObjectKind::Directory
        || record.format_version() != CATALOG_VERSION
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(object, "invalid content catalog node type"));
    }
    match record.canonical_bytes().first().copied() {
        Some(LEAF_TAG) => decode_leaf(object, record),
        Some(BRANCH_TAG) => decode_branch(object, record),
        _ => Err(invalid(object, "invalid content catalog node tag")),
    }
}

fn decode_leaf(object: ObjectId, record: &ObjectRecord) -> Result<Node, PrincipalContentError> {
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
    if reference.kind() != ReferenceKind::Owns || reference.label().as_bytes() != FILE_LABEL {
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

fn decode_branch(object: ObjectId, record: &ObjectRecord) -> Result<Node, PrincipalContentError> {
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

fn leaf_summary(
    name: &ContentName,
    value: CatalogValue,
) -> Result<CatalogSummary, PrincipalContentError> {
    let name_bytes = u64::try_from(name.as_str().len())
        .map_err(|_| PrincipalContentError::AccountingOverflow)?;
    Ok(CatalogSummary {
        logical_bytes: value.logical_bytes,
        quota_bytes: value
            .logical_bytes
            .checked_add(name_bytes)
            .ok_or(PrincipalContentError::AccountingOverflow)?,
        entries: 1,
    })
}

fn encode_summary(bytes: &mut Vec<u8>, summary: CatalogSummary) {
    bytes.extend_from_slice(&summary.logical_bytes.to_le_bytes());
    bytes.extend_from_slice(&summary.quota_bytes.to_le_bytes());
    bytes.extend_from_slice(&summary.entries.to_le_bytes());
}

fn decode_summary(bytes: &[u8], offset: usize) -> Result<CatalogSummary, PrincipalContentError> {
    Ok(CatalogSummary {
        logical_bytes: read_u64(bytes, offset)?,
        quota_bytes: read_u64(bytes, offset.saturating_add(8))?,
        entries: read_u64(bytes, offset.saturating_add(16))?,
    })
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PrincipalContentError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset.saturating_add(8))
            .ok_or(PrincipalContentError::AccountingOverflow)?
            .try_into()
            .map_err(|_| PrincipalContentError::AccountingOverflow)?,
    ))
}

fn first_differing_bit(
    left: &ContentName,
    right: &ContentName,
) -> Result<u64, PrincipalContentError> {
    let limit = left
        .as_str()
        .len()
        .max(right.as_str().len())
        .checked_add(1)
        .ok_or(PrincipalContentError::AccountingOverflow)?;
    for byte_index in 0..limit {
        let left_byte = terminated_byte(left, byte_index);
        let right_byte = terminated_byte(right, byte_index);
        let difference = left_byte ^ right_byte;
        if difference != 0 {
            let leading = u64::from(difference.leading_zeros());
            let byte_bits = u64::try_from(byte_index)
                .map_err(|_| PrincipalContentError::AccountingOverflow)?
                .checked_mul(8)
                .ok_or(PrincipalContentError::AccountingOverflow)?;
            return byte_bits
                .checked_add(leading)
                .ok_or(PrincipalContentError::AccountingOverflow);
        }
    }
    Err(PrincipalContentError::AccountingOverflow)
}

fn key_bit(name: &ContentName, bit: u64) -> Result<bool, PrincipalContentError> {
    let byte_index =
        usize::try_from(bit / 8).map_err(|_| PrincipalContentError::AccountingOverflow)?;
    let within = u8::try_from(bit % 8).map_err(|_| PrincipalContentError::AccountingOverflow)?;
    let mask = 0x80_u8 >> within;
    Ok(terminated_byte(name, byte_index) & mask != 0)
}

fn terminated_byte(name: &ContentName, index: usize) -> u8 {
    name.as_str().as_bytes().get(index).copied().unwrap_or(0)
}

fn invalid(object: ObjectId, detail: &'static str) -> PrincipalContentError {
    PrincipalContentError::InvalidGraph { object, detail }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
