use std::collections::BTreeMap;

use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel,
};

use super::{ContentEntry, ContentName, PrincipalContentError};

pub(crate) const CONTENT_COMPONENT_LABEL: &[u8] = b"content";
const CATALOG_HEADER_BYTES: usize = 12;
const CATALOG_VERSION: ObjectFormatVersion = ObjectFormatVersion::V1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogValue {
    pub(crate) file: ObjectId,
    pub(crate) logical_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Catalog {
    pub(crate) entries: BTreeMap<ContentName, CatalogValue>,
    pub(crate) logical_bytes: u64,
    pub(crate) quota_bytes: u64,
}

impl Catalog {
    pub(crate) fn insert(
        &mut self,
        name: ContentName,
        value: CatalogValue,
    ) -> Result<Option<CatalogValue>, PrincipalContentError> {
        let previous = self.entries.insert(name, value);
        self.recalculate()?;
        Ok(previous)
    }

    pub(crate) fn remove(
        &mut self,
        name: &ContentName,
    ) -> Result<Option<CatalogValue>, PrincipalContentError> {
        let previous = self.entries.remove(name);
        self.recalculate()?;
        Ok(previous)
    }

    pub(crate) fn list(&self) -> Vec<ContentEntry> {
        self.entries
            .iter()
            .map(|(name, value)| ContentEntry::new(name.clone(), value.file, value.logical_bytes))
            .collect()
    }

    fn recalculate(&mut self) -> Result<(), PrincipalContentError> {
        let (logical, quota) =
            self.entries
                .iter()
                .try_fold((0_u64, 0_u64), |(logical, quota), (name, value)| {
                    let name_bytes = u64::try_from(name.as_str().len())
                        .map_err(|_| PrincipalContentError::AccountingOverflow)?;
                    let logical = logical
                        .checked_add(value.logical_bytes)
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    let quota = quota
                        .checked_add(value.logical_bytes)
                        .and_then(|total| total.checked_add(name_bytes))
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    Ok((logical, quota))
                })?;
        self.logical_bytes = logical;
        self.quota_bytes = quota;
        Ok(())
    }
}

pub(crate) fn encode_catalog(catalog: &Catalog) -> Result<ObjectRecord, PrincipalContentError> {
    let count = u32::try_from(catalog.entries.len())
        .map_err(|_| PrincipalContentError::AccountingOverflow)?;
    let mut bytes = Vec::with_capacity(
        CATALOG_HEADER_BYTES.saturating_add(catalog.entries.len().saturating_mul(8)),
    );
    bytes.extend_from_slice(&catalog.quota_bytes.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    let mut references = Vec::with_capacity(catalog.entries.len());
    for (name, value) in &catalog.entries {
        bytes.extend_from_slice(&value.logical_bytes.to_le_bytes());
        references.push(ObjectReference::owns(
            ReferenceLabel::new(name.as_str().as_bytes().to_vec()),
            value.file,
        ));
    }
    ObjectRecord::new(
        ObjectKind::Directory,
        CATALOG_VERSION,
        bytes,
        references,
        catalog.logical_bytes,
        ObjectClass::Metadata,
    )
    .map_err(|error| PrincipalContentError::Projection(error.into()))
}

pub(crate) fn decode_catalog(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<Catalog, PrincipalContentError> {
    let bytes = record.canonical_bytes();
    if record.kind() != ObjectKind::Directory
        || record.format_version() != CATALOG_VERSION
        || record.class() != ObjectClass::Metadata
        || bytes.len() < CATALOG_HEADER_BYTES
    {
        return Err(invalid(object, "invalid content catalog object"));
    }
    let quota_bytes = u64::from_le_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|_| PrincipalContentError::AccountingOverflow)?,
    );
    let count = usize::try_from(u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| PrincipalContentError::AccountingOverflow)?,
    ))
    .map_err(|_| PrincipalContentError::AccountingOverflow)?;
    if count != record.references().len()
        || bytes.len() != CATALOG_HEADER_BYTES.saturating_add(count.saturating_mul(8))
    {
        return Err(invalid(object, "content catalog count is inconsistent"));
    }
    let mut catalog = Catalog::default();
    for (index, reference) in record.references().iter().enumerate() {
        if reference.kind() != ReferenceKind::Owns {
            return Err(invalid(object, "content catalog entry is not owning"));
        }
        let name = ContentName::from_bytes(reference.label().as_bytes())?;
        let offset = CATALOG_HEADER_BYTES.saturating_add(index.saturating_mul(8));
        let logical_bytes = u64::from_le_bytes(
            bytes[offset..offset.saturating_add(8)]
                .try_into()
                .map_err(|_| PrincipalContentError::AccountingOverflow)?,
        );
        if catalog
            .entries
            .insert(
                name,
                CatalogValue {
                    file: reference.target(),
                    logical_bytes,
                },
            )
            .is_some()
        {
            return Err(invalid(object, "duplicate content catalog name"));
        }
    }
    catalog.recalculate()?;
    if catalog.logical_bytes != record.logical_bytes() || catalog.quota_bytes != quota_bytes {
        return Err(invalid(object, "content catalog accounting disagrees"));
    }
    Ok(catalog)
}

pub(crate) fn catalog_quota(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<u64, PrincipalContentError> {
    decode_catalog(object, record).map(|catalog| catalog.quota_bytes)
}

fn invalid(object: ObjectId, detail: &'static str) -> PrincipalContentError {
    PrincipalContentError::InvalidGraph { object, detail }
}
