//! `astrid capsule list` - display all installed capsules with interface metadata.

#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use colored::Colorize;

#[cfg(test)]
use super::meta::scan_installed_capsules_in_home_for_with_layout;
use crate::theme::Theme;

/// List all installed capsules with their provides/requires metadata.
///
/// In default mode, shows a compact one-line-per-capsule view with capability
/// counts. With `--verbose`, expands each capsule to show the full capability
/// list and install source.
pub(crate) async fn list_capsules(verbose: bool) -> anyhow::Result<()> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let entries = match client.request(KernelRequest::GetCapsuleMetadata).await? {
        KernelResponse::CapsuleMetadata(entries) => entries,
        KernelResponse::Error(message) => {
            anyhow::bail!("daemon rejected capsule metadata request: {message}")
        },
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    };

    if entries.is_empty() {
        println!("{}", Theme::info("No capsules installed."));
        return Ok(());
    }

    println!(
        "{} ({})",
        Theme::header("Installed Capsules"),
        entries.len()
    );
    println!("{}", Theme::separator());
    for entry in &entries {
        let source = entry
            .source_id
            .map_or_else(|| "unloaded".to_owned(), |id| id.to_string());
        if verbose {
            println!("{}", entry.name.bold());
            println!("  {}", Theme::kv("Source", &source));
            if !entry.interceptor_events.is_empty() {
                println!(
                    "  {}: {}",
                    "Interceptors".bold(),
                    entry.interceptor_events.join(", ")
                );
            }
            println!("  {}: {}", "Env fields".bold(), entry.env.len());
        } else {
            println!("  {:<32} {}", entry.name.bold(), Theme::dimmed(&source));
        }
    }

    println!(
        "\n{} capsule(s) installed",
        entries.len().to_string().bold()
    );
    Ok(())
}

#[cfg(test)]
fn installed_capsules_for(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<Vec<super::meta::InstalledCapsule>> {
    scan_installed_capsules_in_home_for_with_layout(
        home,
        principal,
        crate::workspace_layout::current(),
    )
}

/// Compact: one line per capsule.
#[cfg(test)]
fn print_compact(capsules: &[super::meta::InstalledCapsule]) {
    let max_name_len = capsules.iter().map(|c| c.name.len()).max().unwrap_or(30);
    let max_version_len = capsules
        .iter()
        .map(|c| c.meta.as_ref().map_or(7, |m| m.version.len()))
        .max()
        .unwrap_or(7); // "unknown".len()

    for cap in capsules {
        let (version, exports_count, imports_count) = match &cap.meta {
            Some(meta) => (
                meta.version.as_str(),
                meta.exports.values().map(HashMap::len).sum::<usize>(),
                meta.imports.values().map(HashMap::len).sum::<usize>(),
            ),
            None => ("unknown", 0, 0),
        };

        let location_tag = format!("[{}]", cap.location);
        let caps_summary = format!("exports: {exports_count}, imports: {imports_count}");

        // Pad the name before applying bold to avoid ANSI escape codes
        // distorting the column width calculation.
        let padded_name = format!("{:<width$}", cap.name, width = max_name_len);
        println!(
            "  {} {:<width$} {:<13} {}",
            padded_name.bold(),
            version,
            Theme::dimmed(&location_tag),
            Theme::dimmed(&caps_summary),
            width = max_version_len,
        );
    }
}

/// Verbose: full details per capsule.
#[cfg(test)]
fn print_verbose(home: &AstridHome, capsules: &[super::meta::InstalledCapsule]) {
    for (i, cap) in capsules.iter().enumerate() {
        if i > 0 {
            println!();
        }

        let Some(meta) = &cap.meta else {
            let version = "unknown";
            println!(
                "{}  {}  {}",
                cap.name.bold(),
                version,
                Theme::dimmed(&format!("[{}]", cap.location)),
            );
            println!("  {}", Theme::dimmed("(no metadata)"));
            continue;
        };
        let (version, source) = (meta.version.as_str(), meta.source.as_deref());

        println!(
            "{}  {}  {}",
            cap.name.bold(),
            version,
            Theme::dimmed(&format!("[{}]", cap.location)),
        );

        if let Some(src) = source {
            println!("  {}", Theme::kv("Source", src));
        }

        // Per-capsule contracts pin + skew marker. Rendered by the same
        // helper `capsule show` uses; `None` when no contracts vendored.
        let skew = astrid_capsule_install::contracts_skew(home, &meta.wit_files);
        if let Some(line) = super::show::contracts_line(&skew) {
            println!("  {}: {line}", "Contracts".bold());
        }

        print_interface_map("Exports", &meta.exports);
        print_interface_map("Imports", &meta.imports);
    }
}

/// Print a labelled interface map (imports or exports), or "(none)" if empty.
#[cfg(test)]
fn print_interface_map(
    label: &str,
    map: &std::collections::HashMap<String, std::collections::HashMap<String, String>>,
) {
    if map.is_empty() {
        println!("  {}: {}", label.bold(), Theme::dimmed("(none)"));
    } else {
        println!("  {}:", label.bold());
        for (ns, ifaces) in map {
            for (name, version) in ifaces {
                println!("    {ns}/{name} {version}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use astrid_core::PrincipalId;
    use astrid_core::dirs::AstridHome;

    use super::installed_capsules_for;

    #[test]
    fn list_scans_the_requested_principal_home() {
        let root = tempfile::tempdir().expect("temporary Astrid home");
        let home = AstridHome::from_path(root.path());
        let default = PrincipalId::default();
        let alice = PrincipalId::new("alice").expect("principal");

        std::fs::create_dir_all(
            home.principal_home(&default)
                .capsules_dir()
                .join("default-only"),
        )
        .expect("default capsule");
        std::fs::create_dir_all(
            home.principal_home(&alice)
                .capsules_dir()
                .join("alice-only"),
        )
        .expect("alice capsule");

        let capsules = installed_capsules_for(&home, &alice).expect("scan Alice capsules");
        let names = capsules
            .iter()
            .map(|capsule| capsule.name.as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"alice-only"));
        assert!(!names.contains(&"default-only"));
    }
}
