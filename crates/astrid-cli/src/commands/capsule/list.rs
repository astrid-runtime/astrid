//! `astrid capsule list` - display all installed capsules with interface metadata.

use std::collections::HashMap;

use astrid_capsule_install::mismatching_contracts;
use astrid_core::dirs::AstridHome;
use colored::Colorize;

use super::meta::scan_installed_capsules_in_home;
use crate::theme::Theme;

/// List all installed capsules with their provides/requires metadata.
///
/// In default mode, shows a compact one-line-per-capsule view with capability
/// counts. With `--verbose`, expands each capsule to show the full capability
/// list and install source.
pub(crate) fn list_capsules(verbose: bool) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    let capsules = scan_installed_capsules_in_home(&home)?;

    if capsules.is_empty() {
        println!("{}", Theme::info("No capsules installed."));
        return Ok(());
    }

    println!(
        "{} ({})",
        Theme::header("Installed Capsules"),
        capsules.len()
    );
    println!("{}", Theme::separator());

    if verbose {
        print_verbose(&home, &capsules);
    } else {
        print_compact(&capsules);
    }

    println!(
        "\n{} capsule(s) installed",
        capsules.len().to_string().bold()
    );

    // Contracts skew — one summary line naming any capsule whose
    // `astrid-contracts.wit` pin differs from the daemon canonical.
    // Warn-only, and silent when there is no canonical to compare
    // against. Detailed pins live in `--verbose` / `capsule show`.
    let mismatched = mismatching_contracts(&home, &capsules);
    if !mismatched.is_empty() {
        println!();
        println!(
            "{}",
            Theme::warning(&format!(
                "Contracts skew: astrid-contracts.wit pin differs from the daemon canonical for {}: {}.",
                if mismatched.len() == 1 {
                    "capsule"
                } else {
                    "capsules"
                },
                mismatched.join(", ")
            ))
        );
        println!(
            "{}",
            Theme::dimmed(
                "  Run `astrid capsule show <name>` (or `list --verbose`) for pins. Warning only."
            )
        );
    }
    Ok(())
}

/// Compact: one line per capsule.
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
