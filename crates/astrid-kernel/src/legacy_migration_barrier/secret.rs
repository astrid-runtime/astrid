//! Ledger-bound legacy-secret provenance used by principal deletion.

use std::fs;
use std::io;

use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;

use super::host_fs::read_bounded_file;
use super::ledger::{MigrationLedger, decode_canonical};
use super::{MAX_BYTES, ledger_path, reject_incomplete_layout_v2};

#[cfg(test)]
use super::ledger::{DestinationProof, MigrationComponent, SourceIdentity, canonical_json};

/// Return whether migration provenance forbids a legacy secret source for a
/// principal that participated in migration.
pub(crate) fn legacy_secret_source_must_be_absent(
    home: &AstridHome,
    uid: PrincipalUid,
) -> io::Result<bool> {
    reject_incomplete_layout_v2(home)?;
    let path = ledger_path(home);
    let bytes = read_bounded_file(&path, MAX_BYTES)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("component migration ledger is missing: {}", path.display()),
        )
    })?;
    let ledger: MigrationLedger = decode_canonical(&bytes, &path)?;
    let name = format!("principal:{uid}:secrets");
    let component = ledger
        .components
        .iter()
        .find(|component| component.name == name);
    Ok(component.is_some_and(|component| !component.source.present))
}

pub(crate) fn ensure_legacy_secret_deletion_allowed(
    home: &AstridHome,
    principal: &PrincipalId,
    uid: PrincipalUid,
) -> io::Result<()> {
    let path = home.secrets_dir().join(principal.as_str());
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if legacy_secret_source_must_be_absent(home, uid)? {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "legacy secret source reappeared after completed migration: {}",
                        path.display()
                    ),
                ));
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn record_absent_legacy_secret_for_test(
    home: &AstridHome,
    uid: PrincipalUid,
) -> io::Result<()> {
    let path = ledger_path(home);
    let bytes = read_bounded_file(&path, MAX_BYTES)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("component migration ledger is missing: {}", path.display()),
        )
    })?;
    let mut ledger: MigrationLedger = decode_canonical(&bytes, &path)?;
    ledger.components.push(MigrationComponent {
        name: format!("principal:{uid}:secrets"),
        source: SourceIdentity::absent(),
        destination_proof: DestinationProof::absent(),
    });
    ledger
        .components
        .sort_by(|left, right| left.name.cmp(&right.name));
    let bytes = canonical_json(&ledger)?;
    astrid_core::platform_fs::atomic_write_private_file(&path, &bytes)
}
