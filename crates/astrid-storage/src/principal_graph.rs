//! Shared format version for principal commit/state/component envelopes.

use crate::storage_model::ObjectFormatVersion;

pub(crate) const PRINCIPAL_GRAPH_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(4) {
    Some(version) => version,
    None => unreachable!(),
};

pub(crate) const LEGACY_PRINCIPAL_GRAPH_VERSION: ObjectFormatVersion =
    match ObjectFormatVersion::new(3) {
        Some(version) => version,
        None => unreachable!(),
    };
