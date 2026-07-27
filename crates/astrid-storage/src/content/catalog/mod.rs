//! Canonical path-copy catalog for principal-owned named content.

mod legacy;
mod tree;

pub(crate) const CONTENT_COMPONENT_LABEL: &[u8] = b"content";

pub(crate) use legacy::decode_catalog as decode_legacy_catalog;
#[cfg(test)]
pub(crate) use legacy::{LegacyCatalog, encode_catalog as encode_legacy_catalog};
pub(crate) use tree::{
    CatalogRoot, CatalogSummary, CatalogValidation, CatalogValue, build_catalog, delete, insert,
    list, lookup, root_from_record, validate_catalog,
};
