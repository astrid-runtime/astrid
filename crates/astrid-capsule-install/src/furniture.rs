//! Seed the read-only introspection "furniture" into a principal's home.
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
//! [`materialize_principal_furniture`] closes that gap by **seeding** the two
//! read-only mirror subdirectories from the install principal's home into a
//! target principal's home.
//!
//! ## Seed, not mirror (issue #1069)
//!
//! Per-principal capsule loading makes each principal's `.local/capsules/` set
//! AUTHORITATIVE for that principal: a principal may install its own capsule,
//! diverging from the install principal's set. A recurring destructive
//! full-mirror would clobber that divergence on every boot. So this is a
//! one-time **seed**:
//!
//! - **Capsules registry** (`.local/capsules/`): seeded ONLY when the target's
//!   set is empty/absent (a fresh principal). An existing — possibly diverged —
//!   per-principal set is NEVER overwritten or pruned.
//! - **WIT mirror** (`wit/`): UNIONED in — missing files are copied, existing
//!   files left untouched. WIT is content-addressed interface metadata, so a
//!   union is safe and never destructive.
//!
//! Provisioning a new principal and the boot sweep both call this: the new
//! principal hits the empty-target seed path (full set), while the boot sweep
//! skips any principal whose set is already populated.
//!
//! ## Security
//!
//! This copies ONLY public, non-secret material: capsule manifests /
//! `meta.json` and WIT interface definitions. It deliberately NEVER touches
//! the target's `.config/env/` (per-principal secrets — API keys), nor its
//! `.local/kv`, `.local/audit`, `.local/tokens`, `.local/log`, or anything
//! else under the home. Only the two mirror subdirectories
//! (`.local/capsules` and `wit`) are ever written under the target, and the
//! capsules set is only ever WRITTEN when empty (never removed). Crossing the
//! `.config/env/` boundary would leak one principal's secrets into another's
//! home, so it is hard-excluded by construction.

use std::path::Path;

use anyhow::Context;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

/// Seed the read-only introspection view (installed-capsule registry +
/// `home://wit/`) from the authoritative install principal's home into
/// `target`'s home, so a freshly-provisioned principal's `system_status` /
/// `list_interfaces` reflect the loaded capsule set.
///
/// SEED, NOT MIRROR (#1069): the capsules registry is written ONLY when the
/// target's set is empty/absent — an existing (possibly diverged) per-principal
/// set is never overwritten or pruned. The WIT mirror is unioned (missing files
/// copied, existing left untouched). This makes both provisioning (empty target
/// → full seed) and the boot sweep (populated target → no-op) safe to run
/// through one function.
///
/// SECURITY: copies ONLY public capsule metadata (manifests, meta.json) and
/// WIT interface definitions. It MUST NOT copy `.config/env/` — that holds
/// per-principal secrets (API keys) that must never cross principal
/// boundaries. Idempotent. No-op when `target` is the install principal
/// (that home is authoritative, not a seed destination).
pub fn materialize_principal_furniture(
    home: &AstridHome,
    target: &PrincipalId,
) -> anyhow::Result<()> {
    // The install principal's home is the authoritative source — it is the
    // seed's origin, never its destination. Refuse to overwrite it.
    if *target == crate::paths::install_principal() {
        return Ok(());
    }

    let src = home.principal_home(&crate::paths::install_principal());
    let dst = home.principal_home(target);

    // `.local/capsules/` — the installed-capsule registry (per-capsule
    // dirs + meta.json) the system capsule's `system_status` counts. SEED
    // ONLY: never clobber a diverged per-principal set.
    seed_capsules_registry(&src.capsules_dir(), &dst.capsules_dir())
        .context("failed to seed .local/capsules into principal home")?;

    // `wit/` — the human-named WIT interface mirror `list_interfaces` /
    // `read_interface` read. UNION: content-addressed, safe to merge.
    union_subtree(&src.root().join("wit"), &dst.root().join("wit"))
        .context("failed to seed wit/ into principal home")?;

    Ok(())
}

/// Seed the per-principal installed-capsule registry from `src` into `dst`,
/// ONLY when `dst` is empty or absent.
///
/// A populated `dst` is the principal's own AUTHORITATIVE set — it may have
/// diverged from the install principal's set (the principal installed or
/// removed its own capsules). Overwriting it would clobber that divergence on
/// every boot, which is exactly what per-principal loading must not do. So a
/// non-empty `dst` is left completely untouched. When `src` is absent (fresh
/// system, nothing installed) the seed is a no-op — an empty registry is the
/// correct end state.
fn seed_capsules_registry(src: &Path, dst: &Path) -> anyhow::Result<()> {
    // Populated target → already seeded (or diverged) → never touch it.
    if dir_is_populated(dst) {
        return Ok(());
    }

    // Nothing to seed from — leave `dst` absent. `system_status` treats a
    // missing dir as "empty", which is right when the authoritative set is
    // empty.
    if !src.is_dir() {
        return Ok(());
    }

    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    copy_dir_recursive(src, dst)
}

/// Whether `dir` exists and contains at least one entry.
fn dir_is_populated(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// Union `src` into `dst`: copy every file from `src` that is missing in `dst`,
/// recursing into subdirectories; existing files in `dst` are left untouched.
///
/// Non-destructive — nothing in `dst` is removed. Used for the WIT mirror,
/// whose files are content-addressed interface metadata, so merging the
/// authoritative set into a principal's home can never produce an inconsistent
/// result. When `src` is absent the union is a no-op.
fn union_subtree(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if !src.is_dir() {
        return Ok(());
    }

    std::fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;

    for entry in
        std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            union_subtree(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            // Union: only copy what the target is missing — never overwrite.
            if !dst_path.exists() {
                std::fs::copy(&src_path, &dst_path)
                    .with_context(|| format!("failed to copy {}", src_path.display()))?;
            }
        }
        // Symlinks / sockets / fifos: skipped — not part of the mirror.
    }

    Ok(())
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
    fn seeds_registry_and_wit_into_empty_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        // Seed a target-side secret to prove it is never touched.
        let secret_path = target_home.env_dir().join("secret.env.json");
        write_file(&secret_path, r#"{"API_KEY":"top-secret"}"#);

        materialize_principal_furniture(&home, &target).expect("materialize");

        // Registry entries seeded (target started empty).
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

        // WIT seeded.
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
    fn is_idempotent_on_empty_then_populated_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        materialize_principal_furniture(&home, &target).expect("first");
        materialize_principal_furniture(&home, &target).expect("second");

        // Same end state after two runs: exactly the two seeded entries and
        // the single WIT file. The second run is a no-op because the target is
        // now populated.
        let capsule_count = std::fs::read_dir(target_home.capsules_dir())
            .expect("read capsules")
            .count();
        assert_eq!(capsule_count, 2);

        let wit_count = std::fs::read_dir(target_home.root().join("wit"))
            .expect("read wit")
            .count();
        assert_eq!(wit_count, 1);
    }

    /// SEED, NOT MIRROR (#1069): once a principal has a populated capsules set,
    /// the boot sweep must NOT clobber it even when the authoritative install
    /// set changes. This is the divergence the whole per-principal change
    /// exists to protect.
    #[test]
    fn populated_target_is_never_clobbered() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        // First seed: target gets alpha + bravo.
        materialize_principal_furniture(&home, &target).expect("first seed");

        // The principal DIVERGES: it removes `bravo` and installs its own
        // `charlie` (a capsule the install principal never had).
        std::fs::remove_dir_all(target_home.capsules_dir().join("bravo")).expect("remove bravo");
        write_file(
            &target_home.capsules_dir().join("charlie").join("meta.json"),
            r#"{"version":"9.9.9"}"#,
        );

        // The authoritative install set ALSO changes (drops bravo, adds delta).
        let install_home = home.principal_home(&crate::paths::install_principal());
        std::fs::remove_dir_all(install_home.capsules_dir().join("bravo")).expect("install drop");
        write_file(
            &install_home.capsules_dir().join("delta").join("meta.json"),
            r#"{"version":"4.0.0"}"#,
        );

        // Boot sweep runs again → MUST be a no-op for this populated target.
        materialize_principal_furniture(&home, &target).expect("boot sweep");

        // The principal's diverged set is intact, untouched by the sweep:
        assert!(
            target_home.capsules_dir().join("alpha").exists(),
            "alpha (seeded, kept) survives"
        );
        assert!(
            target_home.capsules_dir().join("charlie").exists(),
            "charlie (principal's own install) survives — never pruned"
        );
        assert!(
            !target_home.capsules_dir().join("bravo").exists(),
            "bravo (principal removed it) stays removed — not re-seeded"
        );
        assert!(
            !target_home.capsules_dir().join("delta").exists(),
            "delta (added to install set after seed) must NOT leak in — no re-mirror"
        );
    }

    /// The WIT mirror is UNIONED, not destructively replaced: a principal's
    /// own WIT file survives a sweep, and a new authoritative WIT file is added
    /// without disturbing existing ones.
    #[test]
    fn wit_is_unioned_not_clobbered() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(tmp.path());
        seed_install_home(&home);

        let target = PrincipalId::new("claude-code").expect("principal id");
        let target_home = home.principal_home(&target);

        materialize_principal_furniture(&home, &target).expect("first seed");

        // Principal-local WIT file the install set never had.
        write_file(
            &target_home.root().join("wit").join("local.wit"),
            "interface local {}",
        );
        // Install set gains a new WIT file.
        write_file(
            &home
                .principal_home(&crate::paths::install_principal())
                .root()
                .join("wit")
                .join("extra.wit"),
            "interface extra {}",
        );

        materialize_principal_furniture(&home, &target).expect("union sweep");

        // All three survive: the original seed, the principal's own, the new
        // authoritative one — and nothing was overwritten.
        assert_eq!(
            std::fs::read_to_string(target_home.root().join("wit").join("system.wit"))
                .expect("system wit"),
            "interface system {}"
        );
        assert_eq!(
            std::fs::read_to_string(target_home.root().join("wit").join("local.wit"))
                .expect("local wit survives"),
            "interface local {}"
        );
        assert_eq!(
            std::fs::read_to_string(target_home.root().join("wit").join("extra.wit"))
                .expect("extra wit unioned in"),
            "interface extra {}"
        );
    }

    #[test]
    fn empty_source_yields_no_seed() {
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
