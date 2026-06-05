//! Capsule build dispatch — routes to the appropriate builder by project type.

use anyhow::{Result, bail};
use std::path::Path;
use tracing::info;

/// Main entrypoint for the `astrid build` Universal Packager command.
pub(crate) fn run_build(
    path: Option<&str>,
    output: Option<&str>,
    project_type: Option<&str>,
    from_mcp_json: Option<&str>,
) -> Result<()> {
    let target_dir = match path {
        Some(p) => Path::new(p).to_path_buf(),
        None => std::env::current_dir()?,
    };

    if !target_dir.exists() {
        bail!("Directory does not exist: {}", target_dir.display());
    }

    // Early exit for legacy `mcp.json` or `gemini-extension.json` quick convert
    if let Some(json_path_str) = from_mcp_json {
        let json_path = Path::new(json_path_str);
        let dir = json_path.parent().unwrap_or(Path::new(""));
        let file_name = json_path.file_name().unwrap_or_default().to_string_lossy();
        return crate::mcp::convert(dir, &file_name, output);
    }

    // Detect the project type if not explicitly provided
    let detected_type = if let Some(explicit) = project_type {
        explicit.to_string()
    } else {
        detect_project_type(&target_dir)?
    };

    info!("Detected project type: {detected_type}");

    // Route to the appropriate builder
    match detected_type.as_str() {
        "rust" => crate::rust::build(&target_dir, output)?,
        "mcp" => crate::mcp::convert(&target_dir, "mcp.json", output)?,
        "extension" => crate::mcp::convert(&target_dir, "gemini-extension.json", output)?,
        "js" | "ts" | "node" => {
            bail!("Native JS/TS capsule SDK is not yet implemented.");
        },
        "static" => {
            bail!("Static No-Code building is not yet implemented in the CLI.");
        },
        unknown => {
            bail!(
                "Unknown project type: {unknown}. \
                 Supported types: rust, mcp, extension"
            );
        },
    }

    Ok(())
}

fn detect_project_type(dir: &Path) -> Result<String> {
    if dir.join("Cargo.toml").exists() {
        return Ok("rust".to_string());
    }

    if dir.join("gemini-extension.json").exists() {
        return Ok("extension".to_string());
    }

    if dir.join("package.json").exists() {
        return Ok("js".to_string());
    }

    if dir.join("mcp.json").exists() {
        return Ok("mcp".to_string());
    }

    if dir.join("Capsule.toml").exists() {
        return Ok("static".to_string());
    }

    bail!(
        "Could not automatically detect the project type. \
         Please ensure a Cargo.toml, gemini-extension.json, \
         package.json, or Capsule.toml exists in the directory, or use the --type flag."
    );
}

#[cfg(test)]
mod tests {
    use crate::archiver::pack_capsule_archive;
    use std::fs;
    use std::path::Path;

    /// Unpack a .capsule archive into a directory (mirrors install.rs logic).
    fn unpack_capsule(archive_path: &Path, dest: &Path) {
        let tar_gz = fs::File::open(archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(decoder);

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_path_buf();

            assert!(
                !path.is_absolute(),
                "archive contains absolute path: {}",
                path.display()
            );
            assert!(
                !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "archive contains path traversal: {}",
                path.display()
            );
            assert!(
                !entry.header().entry_type().is_symlink()
                    && !entry.header().entry_type().is_hard_link(),
                "archive contains symlink: {}",
                path.display()
            );

            let out_path = dest.join(&path);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            entry.unpack(&out_path).unwrap();
        }
    }

    fn assert_symlinks_dereferenced(symlink_fn: impl FnOnce(&Path, &Path)) {
        let build_dir = tempfile::tempdir().unwrap();
        let base = build_dir.path();

        let bin_dir = base.join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let real_script = base.join("node_modules/somepkg/cli.js");
        fs::create_dir_all(real_script.parent().unwrap()).unwrap();
        fs::write(&real_script, "#!/usr/bin/env node\nconsole.log('hello');").unwrap();

        symlink_fn(&real_script, &bin_dir.join("somepkg"));

        let archive_path = base.join("test.capsule");
        pack_capsule_archive(
            &archive_path,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
            None,
            base,
            &[&base.join("node_modules")],
            None,
        )
        .expect("archiving should succeed");

        let tar_gz = fs::File::open(&archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(decoder);

        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            assert!(
                !entry.header().entry_type().is_symlink()
                    && !entry.header().entry_type().is_hard_link(),
                "archive must not contain symlinks, found: {}",
                entry.path().unwrap().display()
            );
        }

        let unpack_dir = tempfile::tempdir().unwrap();
        unpack_capsule(&archive_path, unpack_dir.path());

        let dereferenced = unpack_dir.path().join("node_modules/.bin/somepkg");
        assert!(dereferenced.exists());
        let content = fs::read_to_string(&dereferenced).unwrap();
        assert!(content.contains("hello"));
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn archive_dereferences_absolute_symlinks() {
        assert_symlinks_dereferenced(|target, link| {
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, link).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(target, link).unwrap();
        });
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn archive_dereferences_relative_symlinks() {
        assert_symlinks_dereferenced(|_target, link| {
            let relative = Path::new("../somepkg/cli.js");
            #[cfg(unix)]
            std::os::unix::fs::symlink(relative, link).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(relative, link).unwrap();
        });
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn archive_detects_symlink_cycle_without_hanging() {
        let build_dir = tempfile::tempdir().unwrap();
        let base = build_dir.path();

        let evil_dir = base.join("node_modules/evil");
        fs::create_dir_all(&evil_dir).unwrap();
        fs::write(evil_dir.join("legit.js"), "// not malicious").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(Path::new("../../"), evil_dir.join("loop")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(Path::new("../../"), evil_dir.join("loop")).unwrap();

        let archive_path = base.join("cycle-test.capsule");
        pack_capsule_archive(
            &archive_path,
            "[package]\nname = \"cycle-test\"\nversion = \"0.1.0\"\n",
            None,
            base,
            &[&base.join("node_modules")],
            None,
        )
        .expect("archiving must not hang on symlink cycles");

        let tar_gz = fs::File::open(&archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(decoder);

        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path().unwrap().to_path_buf())
            .collect();

        assert!(entries.iter().any(|p| p.ends_with("legit.js")));
        assert!(
            entries.len() < 50,
            "archive has {} entries — cycle detection may have failed",
            entries.len()
        );
    }
}
