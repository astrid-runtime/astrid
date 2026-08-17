{
let legacy_path = legacy_path.as_ref().to_path_buf();
let marker_before = self.storage.migration_marker().await?;

let source_present = migration::validate_legacy_source_path(&legacy_path)?;
if !source_present {
    let Some(marker_bytes) = marker_before else {
        return Ok(LegacyAuditImportReport {
            source_entries: 0,
            imported_entries: 0,
            marker_installed: false,
            source_digest: String::new(),
        });
    };
    let marker = decode_receipt(&marker_bytes)?;
    validate_destination(&marker, destination_identity)?;
    self.verify_receipted_destination(&marker).await?;
    return Ok(LegacyAuditImportReport {
        source_entries: marker.source_entries,
        imported_entries: 0,
        marker_installed: false,
        source_digest: marker.source_digest,
    });
}

let source = KvAuditStorage::open_legacy_source(&legacy_path)?;
// Estimate the destination footprint in a source-only pass before creating
// migration scratch keys. The source remains in place until the final
// digest/read-back, so an unobservable or insufficient medium must fail
// before any destination mutation.
let source_estimate = digest_legacy_source(&source, destination_identity).await?;
self.ensure_migration_capacity(&source_estimate)?;
// Preflight is a bounded streaming pass. It verifies every signature and
// predecessor while accumulating only one digest and one terminal hash/count
// tuple per chain.
let receipt = scan_legacy_source(&source, self.storage.as_ref(), destination_identity).await?;
let marker = serde_json::to_vec(&receipt)
    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
if let Some(existing) = marker_before.as_deref()
    && existing != marker
{
    return Err(AuditError::StorageError(
        "legacy audit migration receipt conflicts with source or destination".to_owned(),
    ));
}

// Verify the source digest immediately before forward import.
let second_receipt = digest_legacy_source(&source, destination_identity).await?;
if second_receipt.schema != receipt.schema
    || second_receipt.destination != receipt.destination
    || second_receipt.source_entries != receipt.source_entries
    || second_receipt.source_bytes != receipt.source_bytes
    || second_receipt.source_digest != receipt.source_digest
{
    return Err(AuditError::StorageError(
        "legacy audit source changed during streaming import".to_owned(),
    ));
}

// The preflight left a disposable hash/predecessor index in the destination.
// Walk every chain forward from its genesis so each append observes the
// signed predecessor and the durable head CAS can never reject a valid source
// merely because UUID ordering differs from insertion ordering.
let imported_entries = import_legacy_chains(self, &source).await?;
// The source remains authoritative until this second read-back digest matches
// the preflight receipt; mutation during a long copy fails closed and leaves
// the native source available for retry.
let final_receipt = digest_legacy_source(&source, destination_identity).await?;
if final_receipt.schema != receipt.schema
    || final_receipt.destination != receipt.destination
    || final_receipt.source_entries != receipt.source_entries
    || final_receipt.source_bytes != receipt.source_bytes
    || final_receipt.source_digest != receipt.source_digest
{
    return Err(AuditError::StorageError(
        "legacy audit source changed during forward import".to_owned(),
    ));
}
self.storage.clear_migration_temp().await?;

self.verify_receipted_destination(&receipt).await?;
let marker_installed = if marker_before.is_none() {
    if self
        .storage
        .compare_and_swap_migration_marker(None, marker.clone())
        .await?
    {
        true
    } else {
        let Some(existing) = self.storage.migration_marker().await? else {
            return Err(AuditError::StorageError(
                "audit migration marker CAS failed without a durable marker".to_owned(),
            ));
        };
        if existing != marker {
            return Err(AuditError::StorageError(
                "audit migration marker conflict".to_owned(),
            ));
        }
        false
    }
} else {
    false
};

Ok(LegacyAuditImportReport {
    source_entries: receipt.source_entries,
    imported_entries,
    marker_installed,
    source_digest: receipt.source_digest,
})
}
