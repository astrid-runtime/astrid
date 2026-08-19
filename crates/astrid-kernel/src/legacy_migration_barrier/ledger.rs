//! Canonical migration ledger, source proofs, and component import receipts.

pub(super) use super::source::{SourceCount, SourceDigest, SourceIdentity};
use super::{
    AstridHome, BTreeMap, CAPSULE_AUTHORITY_RECEIPT_NAME, HOST_SECRET_RECEIPT_NAME, LEDGER_SCHEMA,
    MAX_BYTES, PrincipalDirectory, PrincipalId, PrincipalUid, REVOCATION_NAMESPACE,
    REVOCATION_RECEIPT_KEY, RuntimePrincipalStore, io, path_exists, read_bounded_file,
    retire_empty_directory, snapshot_path, storage_io,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[allow(
    clippy::too_many_lines,
    reason = "the proof pass keeps component reads in canonical order"
)]
pub(super) async fn collect_destination_proofs(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
    sources: &BTreeMap<String, SourceIdentity>,
    strict_env_markers: bool,
) -> io::Result<BTreeMap<String, String>> {
    let mut proofs = BTreeMap::new();
    proofs.insert(
        "system:state-db".to_owned(),
        destination_file_proof(&home.migrations_dir().join("layout-v1-to-v2.intent"))?,
    );
    let cow_source = sources.get("system:cow").ok_or_else(|| {
        io::Error::other("migration source inventory is missing the CoW component")
    })?;
    proofs.insert(
        "system:cow".to_owned(),
        format!(
            "verified-discard-v1:source-digest={}:layout-receipt=layout-v1-to-v2.complete",
            cow_source.digest
        ),
    );

    for (name, namespace, key) in [
        (
            "system:invites",
            crate::invite::SYSTEM_KV_NAMESPACE,
            "migration:legacy-v1",
        ),
        (
            "system:pair-tokens",
            crate::pair_token::SYSTEM_KV_NAMESPACE,
            "migration:legacy-v1",
        ),
        (
            "system:gateway-revocations",
            REVOCATION_NAMESPACE,
            REVOCATION_RECEIPT_KEY,
        ),
    ] {
        let proof = store
            .kv()
            .get(namespace, key)
            .await
            .map_err(storage_io)?
            .map_or_else(
                || "absent".to_owned(),
                |bytes| format!("blake3:{}", blake3::hash(&bytes).to_hex()),
            );
        proofs.insert(name.to_owned(), proof);
    }
    if let Some(host_source) = sources.get("system:host-secrets") {
        proofs.insert(
            "system:host-secrets".to_owned(),
            if host_source.present {
                let receipt = fs::read(home.migrations_dir().join(HOST_SECRET_RECEIPT_NAME))
                    .map_err(io::Error::other)?;
                format!(
                    "verified-system-env-v1:source-digest={}:markers=blake3:{}",
                    host_source.digest,
                    blake3::hash(&receipt).to_hex()
                )
            } else {
                "absent".to_owned()
            },
        );
    }
    if let Some(authority_source) = sources.get("system:capsule-authority") {
        let proof = if authority_source.present {
            let path = home.migrations_dir().join(CAPSULE_AUTHORITY_RECEIPT_NAME);
            let proof = fs::read_to_string(&path).map_err(io::Error::other)?;
            if !proof.starts_with("verified-capsule-authority-v1:")
                || !proof.contains(&format!("source-digest={}", authority_source.digest))
                || proof.contains('\n')
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid capsule authority migration receipt: {}",
                        path.display()
                    ),
                ));
            }
            proof
        } else {
            "absent".to_owned()
        };
        proofs.insert("system:capsule-authority".to_owned(), proof);
    }

    let audit = store.system_control_kv("audit").map_err(storage_io)?;
    let audit_proof = audit
        .get("audit:migrations:legacy-principal-home-v1")
        .await
        .map_err(storage_io)?
        .map_or_else(
            || "absent".to_owned(),
            |bytes| format!("blake3:{}", blake3::hash(&bytes).to_hex()),
        );
    for (alias, uid) in directory.bindings() {
        let home_component = format!("principal:{uid}:home");
        if !sources.contains_key(&home_component) {
            // The ledger records only principals that existed at cut-over.
            // Principals admitted later are ordinary v2 state and must not be
            // mistaken for missing legacy-source inventory on every restart.
            // A surviving ordinary-home receipt proves the UID did participate
            // in migration, so omitting its ledger component still fails closed.
            let receipt = home
                .migrations_dir()
                .join(format!("principal-home-{uid}.json"));
            if path_exists(&receipt)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "principal migration ledger is missing the ordinary-home component for {alias}/{uid}"
                    ),
                ));
            }
            continue;
        }
        proofs.insert(
            home_component,
            destination_file_proof(
                &home
                    .migrations_dir()
                    .join(format!("principal-home-{uid}.json")),
            )?,
        );
        proofs.insert(
            format!("principal:{uid}:profile"),
            destination_file_proof(&home.profile_path(&alias))?,
        );
        proofs.insert(
            format!("principal:{uid}:distro-lock"),
            crate::principal_distro_migration::legacy_distro_destination_proof(home, uid)?,
        );
        proofs.insert(
            format!("principal:{uid}:distro-init"),
            crate::principal_distro_migration::legacy_distro_init_destination_proof(home, uid)?,
        );
        let owner = astrid_storage::StateOwner::Principal(uid);
        let summaries = store.capsules().list(&owner).map_err(storage_io)?;
        let summary_bytes = summaries
            .iter()
            .map(|summary| {
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    summary.id(),
                    hex::encode(summary.archive_digest()),
                    hex::encode(summary.metadata_digest()),
                    hex::encode(summary.authority_digest()),
                    summary.archive_bytes(),
                    summary.metadata_bytes(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        proofs.insert(
            format!("principal:{uid}:capsules"),
            format!("blake3:{}", blake3::hash(summary_bytes.as_bytes()).to_hex()),
        );
        proofs.insert(
            format!("principal:{uid}:secrets"),
            principal_secret_migration_proof(store, uid, sources).await?,
        );
        for summary in &summaries {
            let marker = astrid_storage::env::principal_env_store(store.kv(), uid, summary.id())
                .map_err(storage_io)?
                .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                .await
                .map_err(storage_io)?;
            let Some(marker) = marker else {
                if strict_env_markers {
                    return Err(io::Error::other(format!(
                        "environment destination receipt is missing for {alias}/{}",
                        summary.id()
                    )));
                }
                continue;
            };
            let proof = format!("blake3:{}", blake3::hash(&marker).to_hex());
            proofs.insert(
                format!("principal:{uid}:env:{}", summary.id()),
                proof.clone(),
            );
            proofs.insert(format!("principal:{uid}:secret:{}", summary.id()), proof);
        }
        proofs.insert(
            format!("principal:{uid}:audit"),
            if alias == PrincipalId::default() {
                audit_proof.clone()
            } else {
                match sources.get(&format!("principal:{uid}:audit")) {
                    Some(source) if source.present => {
                        format!("verified-empty-v1:source-digest={}", source.digest)
                    },
                    _ => "absent".to_owned(),
                }
            },
        );
        proofs.insert(
            format!("principal:{uid}:logs"),
            crate::principal_log_migration::legacy_log_destination_proof(home, uid)?,
        );
        let tmp = sources
            .get(&format!("principal:{uid}:tmp"))
            .ok_or_else(|| io::Error::other("migration source inventory is missing tmp"))?;
        proofs.insert(
            format!("principal:{uid}:tmp"),
            if tmp.present {
                format!(
                    "verified-discard-v1:source-digest={}:disposable=tmp",
                    tmp.digest
                )
            } else {
                "absent".to_owned()
            },
        );
    }
    // Recompute immutable receipts for principals that were deleted or
    // renamed after cut-over.  Their live alias is gone, but their UID-bound
    // migration records remain durable evidence and must not become an
    // unchecked historical hole.
    for name in sources.keys() {
        let Some((uid, kind, capsule)) = principal_component_parts(name) else {
            continue;
        };
        if directory.contains_uid(uid) {
            continue;
        }
        let proof = match (kind, capsule) {
            ("home", None) => destination_file_proof(
                &home
                    .migrations_dir()
                    .join(format!("principal-home-{uid}.json")),
            )?,
            ("logs", None) => {
                crate::principal_log_migration::legacy_log_destination_proof(home, uid)?
            },
            ("distro-lock", None) => {
                crate::principal_distro_migration::legacy_distro_destination_proof(home, uid)?
            },
            ("distro-init", None) => {
                crate::principal_distro_migration::legacy_distro_init_destination_proof(home, uid)?
            },
            ("tmp", None) => {
                let source = sources
                    .get(name)
                    .ok_or_else(|| io::Error::other("migration source inventory is missing tmp"))?;
                if source.present {
                    format!(
                        "verified-discard-v1:source-digest={}:disposable=tmp",
                        source.digest
                    )
                } else {
                    "absent".to_owned()
                }
            },
            ("audit", None) => {
                let source = sources.get(name).ok_or_else(|| {
                    io::Error::other("migration source inventory is missing audit")
                })?;
                if source.present {
                    // The barrier rejects non-default audit sources before
                    // migration, so a historical present audit component is
                    // necessarily the shared system chain and uses its
                    // durable audit receipt proof.
                    audit_proof.clone()
                } else {
                    "absent".to_owned()
                }
            },
            ("env" | "secret", Some(capsule)) => {
                let marker = astrid_storage::env::principal_env_store(store.kv(), uid, capsule)
                    .map_err(storage_io)?
                    .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                    .await
                    .map_err(storage_io)?;
                marker.map_or_else(
                    || "absent".to_owned(),
                    |bytes| format!("blake3:{}", blake3::hash(&bytes).to_hex()),
                )
            },
            ("secrets", None) => principal_secret_migration_proof(store, uid, sources).await?,
            _ => continue,
        };
        proofs.insert(name.clone(), proof);
    }
    Ok(proofs)
}

fn principal_component_parts(name: &str) -> Option<(PrincipalUid, &str, Option<&str>)> {
    let mut parts = name.split(':');
    if parts.next()? != "principal" {
        return None;
    }
    let uid = PrincipalUid::from_str(parts.next()?).ok()?;
    let kind = parts.next()?;
    let capsule = parts.next();
    if parts.next().is_some() {
        return None;
    }
    Some((uid, kind, capsule))
}

async fn principal_secret_migration_proof(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    sources: &BTreeMap<String, SourceIdentity>,
) -> io::Result<String> {
    let aggregate_name = format!("principal:{uid}:secrets");
    let source = sources.get(&aggregate_name).ok_or_else(|| {
        io::Error::other(format!(
            "migration source inventory is missing secrets for principal {uid}"
        ))
    })?;
    if !source.present {
        return Ok("absent".to_owned());
    }
    if source.entries == 0 && source.bytes == 0 {
        return Ok(format!("verified-empty-v1:source-digest={}", source.digest));
    }

    // This proof describes the frozen legacy import, not the mutable capsule
    // registry. Capsules installed after cut-over must not invalidate the
    // migration ledger on restart. Each imported legacy secret scope has an
    // immutable marker, and the source inventory fixes the exact capsule set.
    let prefix = format!("principal:{uid}:secret:");
    let mut rows = Vec::new();
    for name in sources.keys().filter(|name| name.starts_with(&prefix)) {
        let capsule = name
            .strip_prefix(&prefix)
            .ok_or_else(|| io::Error::other("invalid secret migration component"))?;
        let marker = astrid_storage::env::principal_env_store(store.kv(), uid, capsule)
            .map_err(storage_io)?
            .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
            .await
            .map_err(storage_io)?
            .ok_or_else(|| {
                io::Error::other(format!(
                    "secret destination receipt is missing for principal {uid}/{capsule}"
                ))
            })?;
        rows.push(format!("{capsule}:{}", hex::encode(marker)));
    }
    if rows.is_empty() {
        return Err(io::Error::other(format!(
            "present legacy secret source has no imported capsule scopes for principal {uid}"
        )));
    }
    let marker_digest = blake3::hash(rows.join("\n").as_bytes()).to_hex();
    Ok(format!(
        "verified-secret-import-v1:source-digest={}:markers-digest={marker_digest}",
        source.digest
    ))
}

pub(super) fn mutable_component(name: &str) -> bool {
    name.ends_with(":profile") || name.ends_with(":capsules")
}

pub(super) fn validate_existing_proofs(
    home: &AstridHome,
    existing: &MigrationLedger,
    proofs: &BTreeMap<String, String>,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    // The ledger is historical: mutable profile/package summaries and deleted
    // principal UIDs are not required to be present on a later boot.
    let mut principal_homes = std::collections::BTreeSet::new();
    for component in &existing.components {
        if let Some(uid) = principal_component_uid(&component.name)
            && component.name.ends_with(":home")
        {
            principal_homes.insert(uid);
        }
    }
    for component in &existing.components {
        if mutable_component(&component.name) {
            continue;
        }
        if let Some(uid) = principal_component_uid(&component.name)
            && !principal_homes.contains(&uid)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "principal migration component has no ordinary-home receipt: {}",
                    component.name
                ),
            ));
        }
        if let Some(current) = proofs.get(&component.name) {
            if current != &component.destination_proof {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "destination receipt changed for migration component {}",
                        component.name
                    ),
                ));
            }
            continue;
        }
        if component.name.starts_with("system:") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "required system migration receipt is missing: {}",
                    component.name
                ),
            ));
        }
        // A current UID's immutable receipt/marker cannot silently disappear.
        // Deleted historical UIDs are intentionally allowed to have no live
        // projection, and an originally absent component remains absent when
        // its ledger proof was explicitly recorded as such.
        if is_live_principal_component(&component.name, directory)
            && (component.source.present || component.destination_proof != "absent")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "live principal migration receipt is missing: {}",
                    component.name
                ),
            ));
        }
        if let Some(uid) = principal_component_uid(&component.name)
            && !directory.contains_uid(uid)
            && component.name.ends_with(":home")
        {
            let receipt = home
                .migrations_dir()
                .join(format!("principal-home-{uid}.json"));
            let actual = destination_file_proof(&receipt)?;
            if actual != component.destination_proof {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "historical principal home receipt is missing or changed: {}",
                        receipt.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn principal_component_uid(name: &str) -> Option<PrincipalUid> {
    name.strip_prefix("principal:")
        .and_then(|rest| rest.split(':').next())
        .and_then(|text| text.parse::<PrincipalUid>().ok())
}

fn is_live_principal_component(name: &str, directory: &PrincipalDirectory) -> bool {
    principal_component_uid(name).is_some_and(|uid| directory.contains_uid(uid))
}

pub(super) fn reject_unsupported_sources(
    home: &AstridHome,
    directory: &PrincipalDirectory,
    snapshots: &BTreeMap<String, SourceIdentity>,
) -> io::Result<()> {
    for (alias, uid) in directory.bindings() {
        if alias != PrincipalId::default()
            && snapshots
                .get(&format!("principal:{uid}:audit"))
                .is_some_and(|source| source.present)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "legacy audit source for non-default principal {alias} has no importer; refusing cutover"
                ),
            ));
        }
        for (name, path) in [
            ("kv", home.principal_home(&alias).kv_dir()),
            ("tokens", home.principal_home(&alias).tokens_dir()),
        ] {
            if path_exists(&path)? && snapshot_path(&path)?.entries != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "legacy principal {alias} retains unsupported {name} state; no authoritative migration API exists: {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_component_name(name: &str) -> io::Result<()> {
    match name {
        "system:state-db"
        | "system:cow"
        | "system:invites"
        | "system:pair-tokens"
        | "system:gateway-revocations"
        | "system:host-secrets"
        | "system:capsule-authority"
        | "system:fresh-layout" => return Ok(()),
        _ => {},
    }
    let parts = name.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || parts[0] != "principal" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown migration component name: {name}"),
        ));
    }
    PrincipalUid::from_str(parts[1]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("migration component has a non-canonical principal UID: {name}"),
        )
    })?;
    let valid_shape = match parts[2] {
        "home" | "profile" | "capsules" | "secrets" | "audit" | "logs" | "tmp" | "distro-lock"
        | "distro-init" => parts.len() == 3,
        "env" | "secret" => parts.len() == 4 && !parts[3].is_empty(),
        _ => false,
    };
    if !valid_shape {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown migration component name: {name}"),
        ));
    }
    Ok(())
}

fn valid_source_digest(digest: &str) -> bool {
    if digest == "absent" {
        return true;
    }
    let hex = digest.strip_prefix("blake3:").unwrap_or(digest);
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn destination_file_proof(path: &Path) -> io::Result<String> {
    Ok(match read_bounded_file(path, MAX_BYTES)? {
        Some(bytes) => format!("blake3:{}", blake3::hash(&bytes).to_hex()),
        None => "absent".to_owned(),
    })
}

pub(super) fn decode_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    path: &Path,
) -> io::Result<T> {
    let value = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode migration ledger {}: {error}", path.display()),
        )
    })?;
    if canonical_json(&value)? != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("migration ledger is not canonical: {}", path.display()),
        ));
    }
    Ok(value)
}

pub(super) fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[allow(
    clippy::too_many_lines,
    reason = "all ledger invariants are checked before admission"
)]
pub(super) fn validate_ledger_shape(ledger: &MigrationLedger) -> io::Result<()> {
    let mut names = std::collections::BTreeSet::new();
    let mut previous = None;
    for component in &ledger.components {
        validate_component_name(&component.name)?;
        if !names.insert(component.name.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "migration ledger contains duplicate component: {}",
                    component.name
                ),
            ));
        }
        if previous
            .as_ref()
            .is_some_and(|previous: &String| previous >= &component.name)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "migration ledger components are not canonically sorted",
            ));
        }
        previous = Some(component.name.clone());
        if !valid_source_digest(component.source.digest.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid migration source digest: {}", component.name),
            ));
        }
        if component.source.present && component.source.digest == "absent" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "present migration source has absent digest: {}",
                    component.name
                ),
            ));
        }
        if !component.source.present && component.source.digest != "absent" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("absent migration source has a digest: {}", component.name),
            ));
        }
        let valid_proof = (component.destination_proof == "absent" && !component.source.present)
            || component.destination_proof.starts_with("blake3:")
            || component
                .destination_proof
                .starts_with("verified-empty-v1:")
            || component
                .destination_proof
                .starts_with("verified-discard-v1:")
            || component
                .destination_proof
                .starts_with("verified-capsule-authority-v1:")
            || component
                .destination_proof
                .starts_with("verified-system-env-v1:")
            || component
                .destination_proof
                .starts_with("verified-secret-import-v1:")
            || component.destination_proof.starts_with("fresh-layout-v1:");
        if !valid_proof || component.destination_proof.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid destination proof for component {}", component.name),
            ));
        }
        if component.name == "system:cow" {
            let expected = format!("source-digest={}", component.source.digest);
            if !component
                .destination_proof
                .starts_with("verified-discard-v1:")
                || !component.destination_proof.contains(&expected)
                || !component
                    .destination_proof
                    .contains("layout-receipt=layout-v1-to-v2.complete")
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CoW ledger component is not a source-bound verified discard",
                ));
            }
        }
        if component.name == "system:capsule-authority" && component.source.present {
            let expected = format!("source-digest={}", component.source.digest);
            if !component
                .destination_proof
                .starts_with("verified-capsule-authority-v1:")
                || !component.destination_proof.contains(&expected)
                || !component.destination_proof.contains(":rows-digest")
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "capsule-authority ledger component is not source-bound",
                ));
            }
        }
        if component.name.ends_with(":secrets") && component.source.present {
            let expected = format!("source-digest={}", component.source.digest);
            let empty_source = component.source.entries == 0 && component.source.bytes == 0;
            let verified_empty = empty_source
                && component.destination_proof == format!("verified-empty-v1:{expected}");
            let verified_import = component
                .destination_proof
                .starts_with("verified-secret-import-v1:")
                && component.destination_proof.contains(&expected)
                && component.destination_proof.contains(":markers-digest=");
            if !verified_empty && !verified_import {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "principal secrets component is not bound to imported source receipts: {}",
                        component.name
                    ),
                ));
            }
        }
        if component.name == "system:host-secrets" && component.source.present {
            let expected = format!("source-digest={}", component.source.digest);
            if !component
                .destination_proof
                .starts_with("verified-system-env-v1:")
                || !component.destination_proof.contains(&expected)
                || !component.destination_proof.contains(":markers=blake3:")
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "host secret ledger component is not source-bound",
                ));
            }
        }
        if component.name.starts_with("principal:") && component.name.ends_with(":tmp") {
            let expected = format!("source-digest={}", component.source.digest);
            if component.source.present
                && (!component
                    .destination_proof
                    .starts_with("verified-discard-v1:")
                    || !component.destination_proof.contains(&expected)
                    || !component.destination_proof.contains("disposable=tmp"))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "temporary source is not a source-bound verified discard",
                ));
            }
        }
        if component.name.starts_with("principal:")
            && component.name.ends_with(":distro-init")
            && component.source.present
        {
            let expected = format!("source-digest={}", component.source.digest);
            if !component
                .destination_proof
                .starts_with("verified-discard-v1:")
                || !component.destination_proof.contains(&expected)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "distro init source is not a source-bound verified discard",
                ));
            }
        }
        if component.name == "system:fresh-layout"
            && (component.source.present
                || component.destination_proof
                    != "fresh-layout-v1:initialized-without-legacy-sources")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fresh-layout ledger component is not an explicit empty-home receipt",
            ));
        }
    }
    let required_system = [
        "system:state-db",
        "system:cow",
        "system:invites",
        "system:pair-tokens",
        "system:gateway-revocations",
        "system:host-secrets",
        "system:capsule-authority",
    ];
    if required_system.iter().any(|name| !names.contains(*name)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "migration ledger is missing one or more required system components",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationComponent {
    pub(super) name: String,
    pub(super) source: SourceIdentity,
    pub(super) destination_proof: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationLedger {
    pub(super) schema: u32,
    pub(super) complete: bool,
    pub(super) components: Vec<MigrationComponent>,
}

pub(super) fn write_ledger(
    home: &AstridHome,
    snapshots: BTreeMap<String, SourceIdentity>,
    proofs: &BTreeMap<String, String>,
) -> io::Result<()> {
    let mut components = Vec::with_capacity(snapshots.len());
    for (name, source) in snapshots {
        let destination_proof = proofs.get(&name).cloned().ok_or_else(|| {
            io::Error::other(format!(
                "migration component has no verified destination proof: {name}"
            ))
        })?;
        if source.present && !matches!(name.as_str(), "system:cow") && destination_proof == "absent"
        {
            return Err(io::Error::other(format!(
                "migration component {name} has a source but no destination receipt"
            )));
        }
        components.push(MigrationComponent {
            name,
            source,
            destination_proof,
        });
    }
    components.sort_by(|left, right| left.name.cmp(&right.name));
    let record = MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components,
    };
    validate_ledger_shape(&record)?;
    let bytes = canonical_json(&record)?;
    let ledger = super::ledger_path(home);
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(&ledger, &bytes)
}

#[allow(
    clippy::too_many_lines,
    reason = "host secret import validates and receipts every scope before retirement"
)]
pub(super) async fn import_legacy_system_secrets(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    handle: tokio::runtime::Handle,
    expected: &SourceIdentity,
) -> io::Result<()> {
    let host_root = home.secrets_dir().join("__host__");
    let metadata = match fs::symlink_metadata(&host_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if expected.present {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "legacy host secret source disappeared before import: {}",
                        host_root.display()
                    ),
                ));
            }
            return Ok(());
        },
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy host secret root is not a regular directory: {}",
                host_root.display()
            ),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(&host_root)?;
    let actual = snapshot_path(&host_root)?;
    if !expected.present || actual != *expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy host secret source changed before import: {}",
                host_root.display()
            ),
        ));
    }
    let mut entries = fs::read_dir(&host_root)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut marker_rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(io::Error::other)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy host secret scope is not a regular directory: {}",
                    path.display()
                ),
            ));
        }
        astrid_core::platform_fs::verify_no_redirects(&path)?;
        let capsule = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("legacy host secret scope has a non-UTF-8 name"))?
            .to_owned();
        astrid_capsule_types::CapsuleId::new(capsule.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("legacy host secret scope has an invalid capsule id {capsule:?}: {error}"),
            )
        })?;
        astrid_storage::env::import_legacy_system_scope(
            store.kv(),
            &capsule,
            None,
            Some(path),
            true,
            handle.clone(),
        )
        .await
        .map_err(storage_io)?;
        let scope =
            astrid_storage::env::system_env_store(store.kv(), &capsule).map_err(storage_io)?;
        let marker = scope
            .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
            .await
            .map_err(storage_io)?
            .ok_or_else(|| io::Error::other("system environment destination receipt is missing"))?;
        marker_rows.push(format!("{capsule}:{}", blake3::hash(&marker).to_hex()));
    }
    marker_rows.sort();
    let receipt_path = home.migrations_dir().join(HOST_SECRET_RECEIPT_NAME);
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(
        &receipt_path,
        marker_rows.join("\n").as_bytes(),
    )?;
    if path_exists(&host_root)? {
        let remaining = snapshot_path(&host_root)?;
        if remaining.entries != 0 {
            return Err(io::Error::other(format!(
                "legacy host secret scopes remain after migration: {}",
                host_root.display()
            )));
        }
        retire_empty_directory(&host_root)?;
    }
    Ok(())
}
