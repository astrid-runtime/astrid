//! Explicit helper for materializing a principal's capsule introspection view.
//!
//! This module is for callers that explicitly need to expose public capsule
//! introspection metadata from the install principal's home to another
//! principal. In addition to manifests and `meta.json`, the capsule registry
//! may contain generic declarative public assets. The kernel does not call it
//! during boot or principal creation:
//! `default` is a principal, not a shared tenant, and fresh principals must
//! not implicitly receive a copy of its installed-capsule registry.
//!
//! [`materialize_principal_introspection`] copies the two read-only
//! introspection subdirectories from the install principal's home into a
//! target principal's home when invoked deliberately.
//!
//! ## Security
//!
//! This copies ONLY public, non-secret material: capsule manifests,
//! `meta.json`, declarative capsule assets, and WIT interface definitions. It
//! deliberately NEVER touches the target's `.config/env/` (per-principal
//! secrets — API keys), nor its
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
/// `home://wit/`) from the install principal's home into `target`'s home.
///
/// SECURITY: copies ONLY public capsule introspection content (manifests,
/// meta.json, declarative assets) and WIT interface definitions. It MUST NOT
/// copy `.config/env/` — that holds per-principal secrets (API keys) that must
/// never cross principal boundaries. Idempotent. No-op when `target` is the
/// install principal (that home is authoritative, not a mirror).
pub fn materialize_principal_introspection(
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
    // dirs + meta.json) that explicit metadata mirrors expose to the target.
    mirror_subtree(&src.capsules_dir(), &dst.capsules_dir())
        .context("failed to mirror .local/capsules into principal home")?;

    // `wit/` — the human-named WIT interface mirror `list_interfaces` /
    // `read_interface` read.
    mirror_subtree(&src.root().join("wit"), &dst.root().join("wit"))
        .context("failed to mirror wit/ into principal home")?;

    Ok(())
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
            &install
                .capsules_dir()
                .join("alpha")
                .join("assets")
                .join("alpha")
                .join("README.md"),
            "# Alpha asset",
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

        materialize_principal_introspection(&home, &target).expect("materialize");

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
        assert_eq!(
            std::fs::read_to_string(
                target_home
                    .capsules_dir()
                    .join("alpha")
                    .join("assets")
                    .join("alpha")
                    .join("README.md")
            )
            .expect("alpha asset"),
            "# Alpha asset"
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
        materialize_principal_introspection(&home, &install).expect("noop");

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

        materialize_principal_introspection(&home, &target).expect("first");
        materialize_principal_introspection(&home, &target).expect("second");

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

        materialize_principal_introspection(&home, &target).expect("first");

        // Authoritative set shrinks: drop `bravo`.
        std::fs::remove_dir_all(
            home.principal_home(&crate::paths::install_principal())
                .capsules_dir()
                .join("bravo"),
        )
        .expect("remove bravo");

        materialize_principal_introspection(&home, &target).expect("re-mirror");

        // Mirror reflects the shrink — `bravo` is gone, `alpha` remains.
        assert!(target_home.capsules_dir().join("alpha").exists());
        assert!(!target_home.capsules_dir().join("bravo").exists());
    }

    #[test]
    fn empty_source_yields_no_mirror() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        // Do NOT seed — fresh system, nothing installed.

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        // Must not error even though the source mirror dirs don't exist.
        materialize_principal_introspection(&home, &target).expect("empty ok");

        assert!(!target_home.capsules_dir().exists());
        assert!(!target_home.root().join("wit").exists());
    }
}
