//! Offline distro install from a signed `.shuttle` archive.
//!
//! Pipeline (all offline — no network is ever touched here):
//! 1. Unpack the `.shuttle` to a temporary mirror (hardened unpack).
//! 2. Load `Distro.toml`, `Distro.lock`, `Distro.sig` from the mirror.
//! 3. **Verify the signature and apply the trust policy BEFORE
//!    installing anything** (Part D — [`super::trust`]).
//! 4. Verify the manifest hash recorded in the lock matches the
//!    manifest bytes in the archive (tamper detection).
//! 5. Select capsules (`--yes` aware) and collect variables.
//! 6. For each selected capsule: verify its blake3 against the lock,
//!    then install from the mirror file with provenance recorded.
//! 7. Write the user's `Distro.lock`.
//!
//! Fail-hard rules: an invalid signature, a missing-but-required
//! signature without `--allow-unsigned`, a capsule absent from the
//! mirror, or a capsule blake3 that disagrees with the lock all abort
//! the install before (or without) writing anything to the user's
//! capsule store.

use std::path::Path;

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;

use super::lock::{
    DistroLock, DistroLockMeta, LockedCapsule, manifest_hash, write_lock,
};
use super::manifest::parse_manifest;
use super::{shuttle, trust};
use crate::commands::init::InitOpts;
use crate::theme::Theme;

/// Install a distro from a `.shuttle` archive.
///
/// Synchronous: every step (unpack, verify, install from local files)
/// is offline and blocking. The caller awaits the surrounding init
/// future, but no `.await` happens inside.
#[allow(
    clippy::too_many_lines,
    reason = "intentional linear unpack→verify→install→lock pipeline; \
              the security ordering is clearer kept in one place"
)]
pub(crate) fn install_from_shuttle(shuttle_path: &Path, opts: &InitOpts) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    home.ensure()?;

    if !shuttle_path.is_file() {
        bail!("shuttle archive not found: {}", shuttle_path.display());
    }

    // 1. Unpack to a temporary mirror (no install yet).
    let mirror_tmp = tempfile::tempdir().context("failed to create shuttle mirror dir")?;
    let mirror = mirror_tmp.path();
    shuttle::unpack(shuttle_path, mirror)?;

    // 2. Load manifest / lock / sig from the mirror.
    let manifest_bytes = std::fs::read(mirror.join(shuttle::MANIFEST_NAME))
        .context("shuttle is missing Distro.toml")?;
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).context("Distro.toml is not valid UTF-8")?;
    let manifest = parse_manifest(manifest_text)?;

    let lock_text = std::fs::read_to_string(mirror.join(shuttle::LOCK_NAME))
        .context("shuttle is missing Distro.lock")?;
    let lock: DistroLock =
        toml::from_str(&lock_text).context("failed to parse Distro.lock from shuttle")?;

    let sig = match std::fs::read_to_string(mirror.join(shuttle::SIG_NAME)) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("failed to read Distro.sig"),
    };

    let distro_id = manifest.distro.id.clone();

    // 3. Trust gate. A sealed `.shuttle` is a remote-origin artifact:
    //    a missing signature is refused unless --allow-unsigned.
    let (signer, signature) = if let (Some(signing), Some(sig_hex)) =
        (&manifest.distro.signing, &sig)
    {
        let outcome = trust::verify_and_pin(
            &home,
            &distro_id,
            &signing.pubkey,
            sig_hex,
            &lock,
            opts.accept_new_key,
        )?;
        report_trust(&outcome);
        (Some(outcome.key_str), Some(sig_hex.trim().to_string()))
    } else {
        if !opts.allow_unsigned {
            bail!(
                "shuttle for '{distro_id}' is unsigned (no [distro.signing] or Distro.sig) — \
                 refusing. Re-run with --allow-unsigned to install anyway."
            );
        }
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "installing UNSIGNED distro '{distro_id}' (--allow-unsigned)"
            ))
        );
        (None, None)
    };

    // 4. Manifest-hash integrity: the lock's manifest_hash must match
    //    the manifest bytes the archive actually carries.
    if let Some(recorded) = &lock.manifest_hash {
        let actual = manifest_hash(&manifest_bytes);
        if recorded != &actual {
            bail!(
                "manifest hash mismatch: lock records {recorded}, archive Distro.toml hashes to \
                 {actual} — the shuttle is inconsistent or tampered"
            );
        }
    }

    eprintln!(
        "{}",
        Theme::header(&format!(
            "Installing {} {} (offline)",
            manifest.distro.pretty_name.as_deref().unwrap_or(&manifest.distro.name),
            manifest.distro.version,
        ))
    );

    // Integrity: every capsule the lock claims must match its bytes in
    // the mirror, checked up front so a tampered archive aborts before
    // any install side effect.
    verify_capsule_hashes(mirror, &lock)?;

    // 5. Select capsules + collect variables (headless-aware).
    let variables = manifest.variables.clone();
    let selected = crate::commands::init::select_capsules(manifest.capsules.clone(), opts.yes)?;
    let vars = crate::commands::init::collect_variables(
        &variables,
        &selected,
        opts.yes,
        &opts.vars,
    )?;
    crate::commands::init::write_env_files(&home, &selected, &vars)?;

    // 6. Install each selected capsule from the verified mirror.
    let locked = install_selected_capsules(
        &home,
        mirror,
        &selected,
        signer.as_deref(),
        signature.as_deref(),
    )?;

    // 7. Write the user's Distro.lock, carrying the sealed manifest hash.
    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");
    let user_lock = DistroLock {
        schema_version: manifest.schema_version,
        distro: DistroLockMeta {
            id: distro_id,
            version: manifest.distro.version,
            resolved_at: chrono::Utc::now().to_rfc3339(),
        },
        capsules: locked,
        manifest_hash: lock.manifest_hash,
    };
    write_lock(&lock_path, &user_lock)?;

    eprintln!();
    eprintln!("{}", Theme::success("Offline installation complete."));
    Ok(())
}

/// Install each selected capsule from the verified mirror and return
/// the resolved [`LockedCapsule`] entries for the user's lock.
///
/// Capsule blake3 was already validated against the lock up front by
/// [`verify_capsule_hashes`]; this re-reads the installed `meta.json` to
/// record the content-addressed WASM hash (falling back to the archive
/// blake3 if meta is absent).
fn install_selected_capsules(
    home: &AstridHome,
    mirror: &Path,
    selected: &[super::manifest::DistroCapsule],
    signer: Option<&str>,
    signature: Option<&str>,
) -> anyhow::Result<Vec<LockedCapsule>> {
    let mut locked: Vec<LockedCapsule> = Vec::with_capacity(selected.len());
    for cap in selected {
        let file = shuttle::capsule_mirror_path(mirror, &cap.name);
        if !file.is_file() {
            bail!(
                "capsule '{}' is not present in the shuttle (offline install cannot fetch it)",
                cap.name
            );
        }
        let archive_hash = {
            let bytes = std::fs::read(&file)
                .with_context(|| format!("failed to read mirrored capsule {}", cap.name))?;
            format!("blake3:{}", blake3::hash(&bytes).to_hex())
        };

        let resolved_ref = cap.resolved_ref();
        crate::commands::capsule::install::install_offline_capsule(
            &file,
            home,
            &cap.name,
            &cap.source,
            resolved_ref.as_deref(),
            signer,
            signature,
        )
        .with_context(|| format!("failed to install capsule {}", cap.name))?;

        // Record the installed content-addressed WASM hash from meta,
        // falling back to the archive blake3.
        let target_dir =
            crate::commands::capsule::install::resolve_target_dir(home, &cap.name, false)?;
        let installed_hash = crate::commands::capsule::meta::read_meta(&target_dir)
            .and_then(|m| m.wasm_hash)
            .map_or(archive_hash, |h| format!("blake3:{h}"));

        locked.push(LockedCapsule {
            name: cap.name.clone(),
            version: cap.version.clone(),
            source: cap.source.clone(),
            hash: installed_hash,
            resolved_ref,
        });
        eprintln!("  installed {}", cap.name);
    }
    Ok(locked)
}

/// Verify the per-capsule blake3 of every lock entry against the bytes
/// actually present in the mirror. Returns an error on the first
/// mismatch or missing file. Pure (no install side effects) so the
/// integrity gate is unit-testable.
fn verify_capsule_hashes(mirror: &Path, lock: &DistroLock) -> anyhow::Result<()> {
    for entry in &lock.capsules {
        let file = shuttle::capsule_mirror_path(mirror, &entry.name);
        if !file.is_file() {
            bail!("capsule '{}' is missing from the shuttle mirror", entry.name);
        }
        let bytes = std::fs::read(&file)
            .with_context(|| format!("failed to read mirrored capsule {}", entry.name))?;
        let actual = format!("blake3:{}", blake3::hash(&bytes).to_hex());
        if entry.hash != actual {
            bail!(
                "capsule '{}' hash mismatch: lock has {}, archive has {actual}",
                entry.name,
                entry.hash
            );
        }
    }
    Ok(())
}

/// Report a trust outcome to the operator.
fn report_trust(outcome: &trust::TrustOutcome) {
    let msg = match outcome.action {
        trust::TrustAction::PinnedMatch => {
            format!("signature verified against pinned key {}", outcome.key_str)
        },
        trust::TrustAction::OfficialPinned => {
            format!("verified and pinned official key {}", outcome.key_str)
        },
        trust::TrustAction::ToFuTrusted => format!(
            "trusting key {} on first use — verify it out of band",
            outcome.key_str
        ),
        trust::TrustAction::NewKeyAccepted => {
            format!("re-pinned to new key {} (--accept-new-key)", outcome.key_str)
        },
    };
    eprintln!("{}", Theme::info(&msg));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::distro::sign;
    use astrid_crypto::KeyPair;

    /// Build a signed `.shuttle` with one fake capsule, returning the
    /// path and the keypair it was signed with. The capsule bytes are
    /// arbitrary (the integrity gate hashes bytes; it does not parse
    /// WASM), so this exercises everything up to the actual install.
    fn make_signed_shuttle(dir: &Path, capsule_bytes: &[u8]) -> (std::path::PathBuf, KeyPair) {
        let kp = KeyPair::generate();
        let pubkey = sign::pubkey_to_wire(&kp.export_public_key());
        let manifest = format!(
            "schema-version = 1\n\n\
             [distro]\nid = \"test\"\nname = \"Test\"\nversion = \"0.1.0\"\n\n\
             [distro.signing]\npubkey = \"{pubkey}\"\n\n\
             [[capsule]]\nname = \"astrid-capsule-cli\"\nsource = \"@org/cli\"\n\
             version = \"0.1.0\"\nrole = \"uplink\"\n"
        );
        let manifest_bytes = manifest.into_bytes();
        let cap_hash = format!("blake3:{}", blake3::hash(capsule_bytes).to_hex());

        let lock = DistroLock {
            schema_version: 1,
            distro: DistroLockMeta {
                id: "test".into(),
                version: "0.1.0".into(),
                resolved_at: "1970-01-01T00:00:00+00:00".into(),
            },
            capsules: vec![LockedCapsule {
                name: "astrid-capsule-cli".into(),
                version: "0.1.0".into(),
                source: "@org/cli".into(),
                hash: cap_hash,
                resolved_ref: Some("v0.1.0".into()),
            }],
            manifest_hash: Some(manifest_hash(&manifest_bytes)),
        };
        let sig = sign::sign_lock(&lock, &kp).unwrap();
        let lock_toml = toml::to_string_pretty(&lock).unwrap();

        let entries = vec![
            shuttle::ShuttleEntry {
                path: shuttle::MANIFEST_NAME.into(),
                bytes: manifest_bytes,
            },
            shuttle::ShuttleEntry {
                path: shuttle::LOCK_NAME.into(),
                bytes: lock_toml.into_bytes(),
            },
            shuttle::ShuttleEntry {
                path: shuttle::SIG_NAME.into(),
                bytes: sig.into_bytes(),
            },
            shuttle::ShuttleEntry {
                path: shuttle::capsule_member_path("astrid-capsule-cli"),
                bytes: capsule_bytes.to_vec(),
            },
        ];
        let out = dir.join("test.shuttle");
        shuttle::pack(&out, entries).unwrap();
        (out, kp)
    }

    fn load_mirror(shuttle_path: &Path, dir: &Path) -> (DistroLock, std::path::PathBuf) {
        let mirror = dir.join("mirror");
        shuttle::unpack(shuttle_path, &mirror).unwrap();
        let lock_text = std::fs::read_to_string(mirror.join(shuttle::LOCK_NAME)).unwrap();
        let lock: DistroLock = toml::from_str(&lock_text).unwrap();
        (lock, mirror)
    }

    #[test]
    fn valid_shuttle_passes_all_gates() {
        let dir = tempfile::tempdir().unwrap();
        let (shuttle_path, kp) = make_signed_shuttle(dir.path(), b"FAKE CAPSULE");
        let (lock, mirror) = load_mirror(&shuttle_path, dir.path());

        // Manifest-hash gate.
        let manifest_bytes = std::fs::read(mirror.join(shuttle::MANIFEST_NAME)).unwrap();
        assert_eq!(lock.manifest_hash.as_deref().unwrap(), manifest_hash(&manifest_bytes));
        // Signature gate.
        let sig = std::fs::read_to_string(mirror.join(shuttle::SIG_NAME)).unwrap();
        assert!(sign::verify_lock(&lock, &sig, &kp.export_public_key()).is_ok());
        // Capsule-hash gate.
        assert!(verify_capsule_hashes(&mirror, &lock).is_ok());
    }

    #[test]
    fn capsule_hash_mismatch_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (shuttle_path, _kp) = make_signed_shuttle(dir.path(), b"FAKE CAPSULE");
        let (lock, mirror) = load_mirror(&shuttle_path, dir.path());

        // Corrupt the capsule bytes in the mirror after unpack.
        std::fs::write(
            shuttle::capsule_mirror_path(&mirror, "astrid-capsule-cli"),
            b"TAMPERED",
        )
        .unwrap();
        let err = verify_capsule_hashes(&mirror, &lock).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"), "got: {err}");
    }

    #[test]
    fn missing_capsule_in_mirror_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (shuttle_path, _kp) = make_signed_shuttle(dir.path(), b"FAKE CAPSULE");
        let (lock, mirror) = load_mirror(&shuttle_path, dir.path());

        std::fs::remove_file(shuttle::capsule_mirror_path(&mirror, "astrid-capsule-cli"))
            .unwrap();
        let err = verify_capsule_hashes(&mirror, &lock).unwrap_err();
        assert!(err.to_string().contains("missing"), "got: {err}");
    }

    #[test]
    fn signature_fails_under_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let (shuttle_path, _kp) = make_signed_shuttle(dir.path(), b"FAKE CAPSULE");
        let (lock, mirror) = load_mirror(&shuttle_path, dir.path());
        let sig = std::fs::read_to_string(mirror.join(shuttle::SIG_NAME)).unwrap();

        let attacker = KeyPair::generate();
        assert!(sign::verify_lock(&lock, &sig, &attacker.export_public_key()).is_err());
    }
}
