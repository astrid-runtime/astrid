//! Derive ACTIVE inventory from prepared files and retained materialized names.

use super::{ActiveProjectionEntry, AstridHome, ContentName, ReceiptPhase, active};
use crate::content::PrepareDerivedBatchContent;
use crate::engine::PrincipalProjectionError;

pub(super) struct ActiveReceiptDeriver<'a> {
    pub(super) home: AstridHome,
    pub(super) entries: Vec<(ContentName, u64)>,
    pub(super) retained: &'a [ActiveProjectionEntry],
}

impl PrepareDerivedBatchContent for ActiveReceiptDeriver<'_> {
    fn prepare(
        &mut self,
        prepared: &std::collections::BTreeMap<ContentName, crate::content::ContentDescriptor>,
    ) -> Result<(ContentName, Vec<u8>), crate::content::PrincipalContentError> {
        let mut entries = self
            .entries
            .iter()
            .map(|(name, logical_bytes)| {
                let descriptor = prepared.get(name).ok_or_else(|| {
                    PrincipalProjectionError::Engine(format!(
                        "prepared runtime projection omitted {}",
                        name.as_str()
                    ))
                })?;
                if descriptor.logical_bytes() != *logical_bytes {
                    return Err(PrincipalProjectionError::Engine(format!(
                        "prepared runtime projection changed {}",
                        name.as_str()
                    )));
                }
                Ok(ActiveProjectionEntry {
                    name: name.clone(),
                    file: descriptor.file(),
                    logical_bytes: *logical_bytes,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.extend(
            self.retained
                .iter()
                .filter(|entry| !prepared.contains_key(&entry.name))
                .filter(|entry| {
                    !entry.name.as_str().ends_with('/')
                        || super::projection::surviving_directory(
                            self.home.root(),
                            entry.name.as_str(),
                        )
                })
                .cloned(),
        );
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let bytes = active::encode(&self.home, ReceiptPhase::Active, &entries, None)
            .map_err(|error| PrincipalProjectionError::Engine(error.to_string()))?;
        let name = active::active_projection_name()
            .map_err(|error| PrincipalProjectionError::Engine(error.to_string()))?;
        Ok((name, bytes))
    }
}
