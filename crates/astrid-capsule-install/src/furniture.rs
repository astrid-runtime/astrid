//! Mirror the read-only introspection "furniture" into every principal's home.
//!
//! Capsules are deployed once and shared across the daemon, but the
//! read-only *view* of that set — the installed-capsule registry under
//! `home://.local/capsules/` and the human-named WIT mirror under
//! `home://wit/` — is materialized only into the authoritative
//! [`crate::paths::install_principal`]'s home (see [`crate::local`] /
//! [`crate::wit::materialize_wit_mirror`]). A freshly-provisioned
//! principal (e.g. `claude-code`) therefore gets an *empty* home, so the
//! system capsule's `system_status` reports `capsule_count: 0` and
//! `list_interfaces` reports "WIT directory not found" even though the
//! kernel has every capsule loaded globally.
//!
//! [`materialize_principal_furniture`] closes that gap by copying the two
//! read-only mirror subdirectories from the install principal's home into a
//! target principal's home.
//!
//! ## Security
//!
//! This copies ONLY public, non-secret material: capsule manifests /
//! `meta.json` and WIT interface definitions. It deliberately NEVER touches
//! the target's `.config/env/` (per-principal secrets — API keys), nor its
//! `.local/kv`, `.local/audit`, `.local/tokens`, `.local/log`, or anything
//! else under the home. Only the two mirror subdirectories
//! (`.local/capsules` and `wit`) are ever removed or written under the
//! target. Crossing the `.config/env/` boundary would leak one principal's
//! secrets into another's home, so it is hard-excluded by construction.

use std::path::Path;

use anyhow::Context;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

/// Mirror the read-only introspection view (installed-capsule registry +
/// `home://wit/`) from the authoritative install principal's home into
/// `target`'s home, so a non-install principal's `system_status` /
/// `list_interfaces` reflect the globally-loaded capsule set.
///
/// SECURITY: copies ONLY public capsule metadata (manifests, meta.json) and
/// WIT interface definitions. It MUST NOT copy `.config/env/` — that holds
/// per-principal secrets (API keys) that must never cross principal
/// boundaries. Idempotent. No-op when `target` is the install principal
/// (that home is authoritative, not a mirror).
pub fn materialize_principal_furniture(
    home: &AstridHome,
    target: &PrincipalId,
) -> anyhow::Result<()> {
    // The install principal's home is the authoritative source — it is the
    // mirror's origin, never its destination. Refuse to overwrite it.
    if *target == crate::paths::install_principal() {
        return Ok(());
    }

    let src = home.principal_home(&crate::paths::install_principal());
    let dst = home.principal_home(target);

    // `.local/capsules/` — the installed-capsule registry (per-capsule
    // dirs + meta.json) the system capsule's `system_status` counts.
    mirror_subtree(&src.capsules_dir(), &dst.capsules_dir())
        .context("failed to mirror .local/capsules into principal home")?;

    // `wit/` — the human-named WIT interface mirror `list_interfaces` /
    // `read_interface` read.
    mirror_subtree(&src.root().join("wit"), &dst.root().join("wit"))
        .context("failed to mirror wit/ into principal home")?;

    // Furniture = the blessed introspection set. The mirror copies the capsule
    // DIRECTORY but never the approval store (which lives under `.config/`, the
    // hard-excluded secret boundary), so a freshly-seeded principal would see
    // every furniture capsule as unapproved → inert (#995). Auto-approve each
    // seeded capsule for the target principal at its current fingerprint, so a
    // new principal's introspection tools work exactly as the install
    // principal's do. Best-effort per capsule: a single unreadable manifest is
    // skipped, never failing the whole sync.
    approve_furniture_capsules(home, target, &dst.capsules_dir());

    Ok(())
}

/// Approve every capsule under `capsules_dir` for `target` at its current
/// capability fingerprint. Used to bless the furniture set after it is mirrored
/// into a new principal's home (#995).
fn approve_furniture_capsules(home: &AstridHome, target: &PrincipalId, capsules_dir: &Path) {
    let entries = match std::fs::read_dir(capsules_dir) {
        Ok(entries) => entries,
        // No capsules mirrored (fresh system) → nothing to approve.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(
                dir = %capsules_dir.display(),
                error = %e,
                "furniture approval: failed to enumerate mirrored capsules"
            );
            return;
        },
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let capsule_id = entry.file_name().to_string_lossy().into_owned();
        let manifest_path = entry.path().join("Capsule.toml");
        let manifest = match astrid_capsule::discovery::load_manifest(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    capsule = %capsule_id,
                    %target,
                    error = %e,
                    "furniture approval: skipping capsule with unreadable manifest"
                );
                continue;
            },
        };
        let fingerprint = astrid_capsule::security::approval::capability_fingerprint(&manifest);
        // Key on the manifest's package name — the id the engine consults at
        // load — not the on-disk directory name, so they can never diverge.
        if let Err(e) = astrid_capsule::security::approval::approve(
            home,
            target,
            &manifest.package.name,
            fingerprint,
        ) {
            tracing::warn!(
                capsule = %capsule_id,
                %target,
                error = %e,
                "furniture approval: failed to write approval; capsule will load inert for this principal"
            );
        }
    }
}

/// Replace `dst` with a fresh recursive copy of `src`.
///
/// Idempotent and self-healing: `dst` is removed first so capsules dropped
/// from the authoritative set don't linger in the mirror. When `src` does
/// not exist (fresh system, nothing installed), `dst` is left absent rather
/// than erroring — an empty mirror is the correct end state.
fn mirror_subtree(src: &Path, dst: &Path) -> anyhow::Result<()> {
    // Always clear the destination first so this is a true mirror, not an
    // accreting union. Removing a non-existent path is a no-op for us.
    if dst.exists() {
        std::fs::remove_dir_all(dst)
            .with_context(|| format!("failed to remove stale mirror {}", dst.display()))?;
    }

    // Nothing to mirror — leave `dst` absent. `system_status` /
    // `list_interfaces` treat a missing dir as "empty", which is exactly
    // right when the authoritative set is empty.
    if !src.is_dir() {
        return Ok(());
    }

    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    copy_dir_recursive(src, dst)
}

/// Plain recursive directory copy. Regular files are copied byte-for-byte;
/// subdirectories recurse. Symlinks and other special files are skipped —
/// the source is the install principal's own mirror (`meta.json`,
/// `Capsule.toml`, `.wit`), which contains only regular files and dirs by
/// construction, so there is nothing legitimate to follow.
fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;

    for entry in
        std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)
                .with_context(|| format!("failed to copy {}", src_path.display()))?;
        }
        // Symlinks / sockets / fifos: skipped — not part of the mirror.
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir parent");
        }
        std::fs::write(path, contents).expect("write file");
    }

    /// Seed the install principal's home with a couple of installed-capsule
    /// registry entries and a WIT file, returning the `AstridHome`.
    fn seed_install_home(home: &AstridHome) {
        let install = home.principal_home(&crate::paths::install_principal());

        write_file(
            &install.capsules_dir().join("alpha").join("meta.json"),
            r#"{"version":"1.0.0"}"#,
        );
        write_file(
            &install.capsules_dir().join("bravo").join("meta.json"),
            r#"{"version":"2.0.0"}"#,
        );
        write_file(
            &install.root().join("wit").join("system.wit"),
            "interface system {}",
        );
    }

    #[test]
    fn mirrors_registry_and_wit_into_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        // Seed a target-side secret to prove it is never touched.
        let secret_path = target_home.env_dir().join("secret.env.json");
        write_file(&secret_path, r#"{"API_KEY":"top-secret"}"#);

        materialize_principal_furniture(&home, &target).expect("materialize");

        // Registry entries mirrored.
        assert_eq!(
            std::fs::read_to_string(target_home.capsules_dir().join("alpha").join("meta.json"))
                .expect("alpha meta"),
            r#"{"version":"1.0.0"}"#
        );
        assert_eq!(
            std::fs::read_to_string(target_home.capsules_dir().join("bravo").join("meta.json"))
                .expect("bravo meta"),
            r#"{"version":"2.0.0"}"#
        );

        // WIT mirrored.
        assert_eq!(
            std::fs::read_to_string(target_home.root().join("wit").join("system.wit"))
                .expect("system wit"),
            "interface system {}"
        );

        // CRITICAL: the per-principal secret was neither deleted nor
        // overwritten — env config never crosses the principal boundary.
        assert_eq!(
            std::fs::read_to_string(&secret_path).expect("secret survives"),
            r#"{"API_KEY":"top-secret"}"#
        );
    }

    #[test]
    fn install_principal_is_a_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let install = crate::paths::install_principal();
        let install_home = home.principal_home(&install);

        // Snapshot the authoritative registry before the call.
        let before =
            std::fs::read_to_string(install_home.capsules_dir().join("alpha").join("meta.json"))
                .expect("alpha meta before");

        // No-op: returns Ok, does not error, does not duplicate or disturb.
        materialize_principal_furniture(&home, &install).expect("noop");

        let after =
            std::fs::read_to_string(install_home.capsules_dir().join("alpha").join("meta.json"))
                .expect("alpha meta after");
        assert_eq!(before, after);

        // Exactly the two seeded entries remain — nothing duplicated.
        let count = std::fs::read_dir(install_home.capsules_dir())
            .expect("read capsules")
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        materialize_principal_furniture(&home, &target).expect("first");
        materialize_principal_furniture(&home, &target).expect("second");

        // Same end state after two runs: exactly the two seeded entries and
        // the single WIT file.
        let capsule_count = std::fs::read_dir(target_home.capsules_dir())
            .expect("read capsules")
            .count();
        assert_eq!(capsule_count, 2);

        let wit_count = std::fs::read_dir(target_home.root().join("wit"))
            .expect("read wit")
            .count();
        assert_eq!(wit_count, 1);
    }

    #[test]
    fn dropped_capsules_are_pruned_from_mirror() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        materialize_principal_furniture(&home, &target).expect("first");

        // Authoritative set shrinks: drop `bravo`.
        std::fs::remove_dir_all(
            home.principal_home(&crate::paths::install_principal())
                .capsules_dir()
                .join("bravo"),
        )
        .expect("remove bravo");

        materialize_principal_furniture(&home, &target).expect("re-mirror");

        // Mirror reflects the shrink — `bravo` is gone, `alpha` remains.
        assert!(target_home.capsules_dir().join("alpha").exists());
        assert!(!target_home.capsules_dir().join("bravo").exists());
    }

    #[test]
    fn seeded_furniture_capsule_is_approved_for_target_principal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());

        // The install principal has a capsule with a real manifest (a furniture
        // capsule declaring a capability) plus its content.
        let install = home.principal_home(&crate::paths::install_principal());
        write_file(
            &install.capsules_dir().join("furn").join("Capsule.toml"),
            "[package]\nname = \"furn\"\nversion = \"0.1.0\"\n\n[capabilities]\nnet = [\"example.com\"]\n",
        );

        let target = PrincipalId::new("claude-code").expect("principal id");
        materialize_principal_furniture(&home, &target).expect("materialize");

        // The mirrored capsule is now APPROVED for the target principal at the
        // fingerprint of its manifest — so it loads with its capabilities, not
        // inert. Without this write, a furniture-seeded capsule would be inert
        // (the approval store lives under .config/, which is never mirrored).
        let manifest = astrid_capsule::discovery::load_manifest(
            &home
                .principal_home(&target)
                .capsules_dir()
                .join("furn")
                .join("Capsule.toml"),
        )
        .expect("load mirrored manifest");
        let fp = astrid_capsule::security::approval::capability_fingerprint(&manifest);
        assert!(
            astrid_capsule::security::approval::is_approved(&home, &target, "furn", &fp),
            "a furniture-seeded capsule must be auto-approved for the target principal"
        );
    }

    #[test]
    fn empty_source_yields_no_mirror() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        // Do NOT seed — fresh system, nothing installed.

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        // Must not error even though the source mirror dirs don't exist.
        materialize_principal_furniture(&home, &target).expect("empty ok");

        assert!(!target_home.capsules_dir().exists());
        assert!(!target_home.root().join("wit").exists());
    }
}
