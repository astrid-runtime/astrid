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
    fn summary<L: DirectoryLayout>(&self) -> Result<CatalogSummary, PrincipalContentError> {
        match self {
            Self::Leaf { name, value } => L::summarize(name, *value),
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

/// Private typed grammar for a canonical object directory. Content catalogs
/// retain their frozen format; other directories must select a distinct domain
/// and validate their own values. Tree structure validation is always shared.
pub(crate) trait DirectoryLayout {
    const VERSION: ObjectFormatVersion;
    const VALUE_LABEL: &'static [u8];

    fn summarize(
        name: &ContentName,
        value: CatalogValue,
    ) -> Result<CatalogSummary, PrincipalContentError> {
        leaf_summary(name, value)
    }

    fn validate_value(
        name: &ContentName,
        value: CatalogValue,
        load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    ) -> Result<(), PrincipalContentError>;
}

struct ContentLayout;

impl DirectoryLayout for ContentLayout {
    const VERSION: ObjectFormatVersion = CATALOG_VERSION;
    const VALUE_LABEL: &'static [u8] = FILE_LABEL;

    fn validate_value(
        _name: &ContentName,
        value: CatalogValue,
        load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    ) -> Result<(), PrincipalContentError> {
        validate_file_length(value, load)
    }
}

mod codec;
mod mutation;
mod read;
mod validation;

use codec::{decode_node_with_layout, intern_branch_with_layout, intern_leaf_with_layout};
pub(crate) use mutation::{build_catalog_with_layout, delete_with_layout, insert_with_layout};
use read::prefix_exists_with_layout;
pub(crate) use read::{
    list_prefix_with_layout, list_with_layout, lookup_with_layout, root_from_record_with_layout,
};
pub(crate) use validation::validate_catalog_with_layout;

pub(crate) fn root_from_record(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<CatalogRoot, PrincipalContentError> {
    root_from_record_with_layout::<ContentLayout>(object, record)
}

pub(crate) fn lookup(
    root: Option<CatalogRoot>,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Option<CatalogValue>, PrincipalContentError> {
    lookup_with_layout::<ContentLayout>(root, name, load)
}

pub(crate) fn list(
    root: Option<CatalogRoot>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Vec<ContentEntry>, PrincipalContentError> {
    list_with_layout::<ContentLayout>(root, load)
}

pub(crate) fn list_prefix(
    root: Option<CatalogRoot>,
    prefix: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Vec<ContentEntry>, PrincipalContentError> {
    list_prefix_with_layout::<ContentLayout>(root, prefix, load)
}

pub(crate) fn prefix_exists(
    root: Option<CatalogRoot>,
    prefix: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<bool, PrincipalContentError> {
    prefix_exists_with_layout::<ContentLayout>(root, prefix, load)
}

pub(crate) fn insert(
    root: Option<CatalogRoot>,
    name: &ContentName,
    value: CatalogValue,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<CatalogMutation, PrincipalContentError> {
    insert_with_layout::<ContentLayout>(root, name, value, load, identify)
}

pub(crate) fn delete(
    root: Option<CatalogRoot>,
    name: &ContentName,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<CatalogMutation, PrincipalContentError> {
    delete_with_layout::<ContentLayout>(root, name, load, identify)
}

pub(crate) fn build_catalog(
    entries: &BTreeMap<ContentName, CatalogValue>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<(Option<CatalogRoot>, BTreeMap<ObjectId, ObjectRecord>), PrincipalContentError> {
    build_catalog_with_layout::<ContentLayout>(entries, identify)
}

pub(crate) fn validate_catalog(
    root: Option<CatalogRoot>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<CatalogValidation, PrincipalContentError> {
    validate_catalog_with_layout::<ContentLayout>(root, load)
}

#[cfg(test)]
fn intern_branch(
    bit: u64,
    left: CatalogRoot,
    right: CatalogRoot,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CatalogRoot, PrincipalContentError> {
    intern_branch_with_layout::<ContentLayout>(bit, left, right, identify, records)
}

#[cfg(test)]
fn decode_node(object: ObjectId, record: &ObjectRecord) -> Result<Node, PrincipalContentError> {
    decode_node_with_layout::<ContentLayout>(object, record)
}

#[cfg(test)]
#[path = "../tree_tests.rs"]
mod tests;
