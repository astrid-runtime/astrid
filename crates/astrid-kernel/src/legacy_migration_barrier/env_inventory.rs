//! Retry inventory for scopes whose native files may already be retired.
//!
//! This is scope discovery, not an import receipt or an authorization grant.
//! Every recovered scope still crosses the normal importer and receipt check.

use std::{collections::BTreeMap, io};

use astrid_capsule_types::CapsuleId;
use astrid_core::{dirs::AstridHome, identity::PrincipalUid};

use super::{
    MAX_BYTES,
    host_fs::read_bounded_file,
    ledger::{canonical_json, decode_canonical},
    source::SourceIdentity,
};

pub(super) fn read(home: &AstridHome, uid: PrincipalUid) -> io::Result<Vec<CapsuleId>> {
    let path = home.migrations_dir().join(format!("env-scopes-{uid}.json"));
    let Some(bytes) = read_bounded_file(&path, MAX_BYTES)? else {
        return Ok(Vec::new());
    };
    let scopes: Vec<CapsuleId> = decode_canonical(&bytes, &path)?;
    if scopes
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "migration scope inventory is not sorted and unique: {}",
                path.display()
            ),
        ));
    }
    Ok(scopes)
}

/// Called under the boot singleton before any scope source is retired.
/// Atomic replacement and parent sync make the name set survive a later
/// importer or barrier failure, including scopes with no capsule package.
pub(super) fn record(
    home: &AstridHome,
    uid: PrincipalUid,
    scopes: &[CapsuleId],
    sources: &BTreeMap<String, SourceIdentity>,
) -> io::Result<Vec<CapsuleId>> {
    let mut inventory = read(home, uid)?;
    // Installed scopes with no legacy inputs may legitimately need their
    // first empty receipt on retry. Only scopes that had native data require
    // a pre-existing completion receipt once both native inputs are absent.
    inventory.extend(
        scopes
            .iter()
            .filter(|scope| {
                ["env", "secret"].iter().any(|kind| {
                    sources
                        .get(&format!("principal:{uid}:{kind}:{scope}"))
                        .is_some_and(|source| source.present)
                })
            })
            .cloned(),
    );
    inventory.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    inventory.dedup();
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(
        &home.migrations_dir().join(format!("env-scopes-{uid}.json")),
        &canonical_json(&inventory)?,
    )?;
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_is_uid_bound_and_does_not_record_empty_installed_scopes() {
        let root = tempfile::tempdir().expect("temporary home");
        let home = AstridHome::from_path(root.path());
        let uid = PrincipalUid::from_bytes([0x87; 32]);
        let capsule = CapsuleId::new("removed-provider").expect("scope");
        let mut sources = BTreeMap::new();
        assert!(
            record(&home, uid, std::slice::from_ref(&capsule), &sources)
                .expect("no native input")
                .is_empty()
        );
        let source = root.path().join("original.env.json");
        astrid_core::platform_fs::atomic_write_private_file(&source, b"{}\n")
            .expect("native input");
        sources.insert(
            format!("principal:{uid}:env:{capsule}"),
            super::super::host_fs::snapshot_path(&source).expect("identity"),
        );
        let expected = vec![capsule];
        assert_eq!(
            record(&home, uid, &expected, &sources).expect("record"),
            expected
        );
        assert_eq!(read(&home, uid).expect("persisted"), expected);
        assert!(
            read(&home, PrincipalUid::from_bytes([0x88; 32]))
                .expect("other owner")
                .is_empty()
        );
        assert_eq!(
            record(&home, uid, &[], &BTreeMap::new()).expect("retry"),
            expected
        );
    }

    #[test]
    fn inventory_rejects_invalid_names_order_duplicates_and_noncanonical_json() {
        let root = tempfile::tempdir().expect("temporary home");
        let home = AstridHome::from_path(root.path());
        let uid = PrincipalUid::from_bytes([0x89; 32]);
        astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())
            .expect("directory");
        let path = home.migrations_dir().join(format!("env-scopes-{uid}.json"));
        for bytes in [
            b"[\"../foreign\"]\n".as_slice(),
            b"[\"b\",\"a\"]\n",
            b"[\"a\",\"a\"]\n",
            b"[ \"a\" ]\n",
            b"{\"scopes\":[\"a\"]}\n",
        ] {
            astrid_core::platform_fs::atomic_write_private_file(&path, bytes).expect("fixture");
            assert!(read(&home, uid).is_err(), "must reject {bytes:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn inventory_redirect_is_rejected_without_mutating_target() {
        let root = tempfile::tempdir().expect("temporary home");
        let home = AstridHome::from_path(root.path());
        let uid = PrincipalUid::from_bytes([0x8a; 32]);
        astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())
            .expect("directory");
        let target = root.path().join("unrelated.json");
        astrid_core::platform_fs::atomic_write_private_file(&target, b"[]\n").expect("target");
        std::os::unix::fs::symlink(
            &target,
            home.migrations_dir().join(format!("env-scopes-{uid}.json")),
        )
        .expect("redirect fixture");
        assert!(read(&home, uid).is_err());
        assert!(record(&home, uid, &[], &BTreeMap::new()).is_err());
        assert_eq!(std::fs::read(&target).expect("unchanged target"), b"[]\n");
    }
}
