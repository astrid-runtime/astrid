use anyhow::{Context, Result, bail};
use cargo_metadata::cargo_platform::{Cfg, Platform};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

pub(super) fn cargo_config_target_and_rustflags(
    dir: &Path,
) -> Result<(Option<String>, Vec<String>)> {
    let cargo_home = cargo_home_from_env(dir);
    cargo_config_target_and_rustflags_with_home(dir, cargo_home.as_deref())
}

#[cfg(test)]
pub(super) fn cargo_config_has_matching_target_rustflags_with_home(
    dir: &Path,
    cargo_home: Option<&Path>,
    selected_target: &str,
) -> Result<bool> {
    Ok(cargo_config_rustflags_for_target_with_home(dir, cargo_home, selected_target)?.1)
}

#[derive(Debug, Default)]
pub(super) struct EffectiveCargoRustflags {
    pub(super) flags: Vec<String>,
    pub(super) has_matching_target: bool,
    pub(super) flags_are_array: bool,
}

#[cfg(test)]
pub(super) fn cargo_config_rustflags_for_target_with_home(
    dir: &Path,
    cargo_home: Option<&Path>,
    selected_target: &str,
) -> Result<(Vec<String>, bool)> {
    let config = load_cargo_config(dir, cargo_home, Some(selected_target))?;
    Ok((config.rustflags, config.has_matching_target_rustflags))
}

pub(super) fn cargo_config_effective_rustflags_for_target(
    dir: &Path,
    selected_target: &str,
) -> Result<EffectiveCargoRustflags> {
    let cargo_home = cargo_home_from_env(dir);
    let config = load_cargo_config(dir, cargo_home.as_deref(), Some(selected_target))?;
    Ok(EffectiveCargoRustflags {
        flags: config.rustflags,
        has_matching_target: config.has_matching_target_rustflags,
        flags_are_array: config.rustflags_is_array,
    })
}

pub(super) fn cargo_config_target_and_rustflags_with_home(
    dir: &Path,
    cargo_home: Option<&Path>,
) -> Result<(Option<String>, Vec<String>)> {
    cargo_config_target_and_rustflags_for_target_with_home(dir, cargo_home, None)
}

pub(super) fn cargo_config_target_and_rustflags_for_target_with_home(
    dir: &Path,
    cargo_home: Option<&Path>,
    selected_target: Option<&str>,
) -> Result<(Option<String>, Vec<String>)> {
    let config = load_cargo_config(dir, cargo_home, selected_target)?;
    Ok((config.target, config.rustflags))
}

struct CargoConfig {
    target: Option<String>,
    rustflags: Vec<String>,
    rustflags_is_array: bool,
    has_matching_target_rustflags: bool,
}

fn load_cargo_config(
    dir: &Path,
    cargo_home: Option<&Path>,
    selected_target: Option<&str>,
) -> Result<CargoConfig> {
    let mut state = CargoConfigState::default();
    let mut loader = CargoConfigLoader::default();
    let mut config_paths = Vec::new();
    let cargo_home = cargo_home.map(|home| resolve_cargo_home(dir, home.to_path_buf()));
    if let Some(cargo_home) = cargo_home.as_deref() {
        push_config_path(&mut config_paths, cargo_home);
    }

    let resolved_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let mut ancestors = resolved_dir
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        push_config_path(&mut config_paths, &ancestor.join(".cargo"));
    }
    for path in config_paths {
        loader.load(&path, &mut state)?;
    }

    let flags_target = selected_target.or(state.target.as_deref());
    let (target_flags, has_matching_target_rustflags) =
        matching_target_rustflags(flags_target, state.target_entries)?;
    let effective_rustflags = match target_flags {
        // An empty matching entry is still a matching entry, but it supplies no
        // effective flags. Keep the caller's build-level flags and form.
        Some(flags) if !flags.flags.is_empty() => Some(flags),
        _ => state.build_flags,
    };
    let (rustflags, rustflags_is_array) = effective_rustflags
        .map(|flags| (flags.flags, flags.is_array))
        .unwrap_or_default();
    Ok(CargoConfig {
        target: state.target,
        rustflags,
        rustflags_is_array,
        has_matching_target_rustflags,
    })
}

#[derive(Default)]
struct CargoConfigState {
    target: Option<String>,
    build_flags: Option<ParsedRustflags>,
    target_entries: Vec<(String, ParsedRustflags)>,
}

#[derive(Default)]
struct CargoConfigLoader {
    active: HashSet<PathBuf>,
}

impl CargoConfigLoader {
    fn load(&mut self, path: &Path, state: &mut CargoConfigState) -> Result<()> {
        let Some(content) = read_optional_config(path)? else {
            return Ok(());
        };
        let canonical = path
            .canonicalize()
            .with_context(|| format!("Failed to resolve Cargo configuration {}", path.display()))?;
        if !self.active.insert(canonical.clone()) {
            bail!(
                "Cargo configuration include cycle detected at {}",
                canonical.display()
            );
        }

        let result = self.load_content(&content, &canonical, state);
        self.active.remove(&canonical);
        result
    }

    fn load_content(
        &mut self,
        content: &str,
        path: &Path,
        state: &mut CargoConfigState,
    ) -> Result<()> {
        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("Failed to parse Cargo configuration {}", path.display()))?;

        for include in cargo_config_includes(&doc, path)?.into_iter().flatten() {
            self.load(&include, state)?;
        }
        state.absorb_document(&doc, path)
    }
}

impl CargoConfigState {
    fn absorb_document(&mut self, doc: &toml_edit::DocumentMut, path: &Path) -> Result<()> {
        if let Some(item) = doc.get("build").and_then(|build| build.get("target")) {
            if let Some(value) = item.as_str() {
                self.target = Some(value.to_owned());
            } else if item.as_array().is_some() {
                // Cargo supports a target array for multi-target builds. This
                // packager has one executable slot, so it must not guess.
                self.target = None;
            } else {
                bail!(
                    "Cargo build.target must be a string or array in {}",
                    path.display()
                );
            }
        }

        if let Some(item) = doc.get("build").and_then(|build| build.get("rustflags")) {
            merge_rustflags(&mut self.build_flags, parse_rustflags(item, path)?);
        }
        if let Some(targets) = doc.get("target").and_then(toml_edit::Item::as_table_like) {
            for (platform, item) in targets.iter() {
                let Some(rustflags) = item
                    .as_table_like()
                    .and_then(|target| target.get("rustflags"))
                else {
                    continue;
                };
                self.target_entries
                    .push((platform.to_owned(), parse_rustflags(rustflags, path)?));
            }
        }
        Ok(())
    }
}

fn cargo_config_includes(
    doc: &toml_edit::DocumentMut,
    path: &Path,
) -> Result<Vec<Option<PathBuf>>> {
    let Some(item) = doc.get("include") else {
        return Ok(Vec::new());
    };

    if let Some(value) = item.as_str() {
        return Ok(vec![resolve_cargo_config_include(path, value, false)?]);
    }
    if let Some(array) = item.as_array() {
        return array
            .iter()
            .map(|value| {
                if let Some(include) = value.as_str() {
                    Ok(resolve_cargo_config_include(path, include, false)?)
                } else if let Some(table) = value.as_inline_table() {
                    let include = table
                        .get("path")
                        .and_then(toml_edit::Value::as_str)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Cargo include table must contain a string path in {}",
                                path.display()
                            )
                        })?;
                    let optional = match table.get("optional") {
                        None => false,
                        Some(value) => value.as_bool().ok_or_else(|| {
                            anyhow::anyhow!(
                                "Cargo include optional must be a boolean in {}",
                                path.display()
                            )
                        })?,
                    };
                    Ok(resolve_cargo_config_include(path, include, optional)?)
                } else {
                    bail!(
                        "Cargo include array contains a non-string or non-table value in {}",
                        path.display()
                    )
                }
            })
            .collect();
    }
    if let Some(table) = item.as_table_like() {
        let include = table
            .get("path")
            .and_then(toml_edit::Item::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cargo include table must contain a string path in {}",
                    path.display()
                )
            })?;
        let optional = match table.get("optional") {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| {
                anyhow::anyhow!(
                    "Cargo include optional must be a boolean in {}",
                    path.display()
                )
            })?,
        };
        return Ok(vec![resolve_cargo_config_include(path, include, optional)?]);
    }
    bail!(
        "Cargo include must be a string, array, or table in {}",
        path.display()
    )
}

fn resolve_cargo_config_include(
    including_file: &Path,
    include: &str,
    optional: bool,
) -> Result<Option<PathBuf>> {
    if include.is_empty() {
        bail!("Cargo include path cannot be empty");
    }
    let parent = including_file
        .parent()
        .context("Cargo configuration file has no parent directory")?;
    let candidate = parent.join(include);
    let resolved = match candidate.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && optional => {
            return Ok(None);
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "Required Cargo configuration include {} does not exist",
                candidate.display()
            );
        },
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to resolve Cargo configuration include {}",
                    candidate.display()
                )
            });
        },
    };
    Ok(Some(resolved))
}

fn matching_target_rustflags(
    selected_target: Option<&str>,
    target_entries: Vec<(String, ParsedRustflags)>,
) -> Result<(Option<ParsedRustflags>, bool)> {
    let Some(selected_target) = selected_target else {
        return Ok((None, false));
    };

    let mut target_cfgs = None;
    let mut matching = None;
    let mut found = false;
    for (platform, flags) in target_entries {
        if target_platform_matches(&platform, selected_target, &mut target_cfgs)? {
            found = true;
            merge_rustflags(&mut matching, flags);
        }
    }
    Ok((matching, found))
}

fn target_platform_matches(
    platform: &str,
    selected_target: &str,
    target_cfgs: &mut Option<Vec<Cfg>>,
) -> Result<bool> {
    let platform = Platform::from_str(platform)
        .with_context(|| format!("Invalid Cargo target platform `{platform}`"))?;
    if !matches!(platform, Platform::Cfg(_)) {
        return Ok(platform.matches(selected_target, &[]));
    }

    if target_cfgs.is_none() {
        *target_cfgs = Some(target_cfgs_for(selected_target)?);
    }
    Ok(platform.matches(selected_target, target_cfgs.as_deref().unwrap_or_default()))
}

fn target_cfgs_for(target: &str) -> Result<Vec<Cfg>> {
    let output = Command::new("rustc")
        .args(["--print", "cfg", "--target", target])
        .output()
        .with_context(|| format!("Failed to inspect Cargo target cfg for `{target}`"))?;
    if !output.status.success() {
        bail!(
            "rustc could not report cfg values for Cargo target `{target}` (status {})",
            output.status
        );
    }
    std::str::from_utf8(&output.stdout)
        .with_context(|| format!("rustc emitted invalid cfg output for `{target}`"))?
        .lines()
        .map(|line| {
            Cfg::from_str(line)
                .with_context(|| format!("rustc emitted invalid cfg `{line}` for `{target}`"))
        })
        .collect()
}

fn push_config_path(paths: &mut Vec<PathBuf>, cargo_dir: &Path) {
    let toml = cargo_dir.join("config.toml");
    let legacy = cargo_dir.join("config");
    // Cargo prefers the extensionless file when both names exist.
    if legacy.is_file() {
        paths.push(legacy);
    } else if toml.is_file() {
        paths.push(toml);
    }
}

fn read_optional_config(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Failed to read Cargo configuration {}", path.display())),
    }
}

struct ParsedRustflags {
    flags: Vec<String>,
    is_array: bool,
}

fn parse_rustflags(item: &toml_edit::Item, path: &Path) -> Result<ParsedRustflags> {
    if let Some(array) = item.as_array() {
        let flags = array
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cargo rustflags array contains a non-string value in {}",
                        path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(ParsedRustflags {
            flags,
            is_array: true,
        });
    }
    if let Some(value) = item.as_str() {
        return Ok(ParsedRustflags {
            flags: value.split_whitespace().map(str::to_owned).collect(),
            is_array: false,
        });
    }
    bail!(
        "Cargo rustflags must be a string or array in {}",
        path.display()
    )
}

fn merge_rustflags(slot: &mut Option<ParsedRustflags>, incoming: ParsedRustflags) {
    if let Some(existing) = slot
        && existing.is_array
        && incoming.is_array
    {
        existing.flags.extend(incoming.flags);
    } else {
        *slot = Some(incoming);
    }
}

pub(super) fn cargo_home_from_env(dir: &Path) -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("CARGO_HOME")
        && !home.is_empty()
    {
        return Some(resolve_cargo_home(dir, PathBuf::from(home)));
    }
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(|home| resolve_cargo_home(dir, PathBuf::from(home).join(".cargo")))
}

pub(super) fn resolve_cargo_home(dir: &Path, home: PathBuf) -> PathBuf {
    if home.is_absolute() {
        home
    } else {
        // `cargo_home_from_env` may receive a relative working directory.
        // Anchor the result here so Cargo's loader cannot resolve it again.
        let dir = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            std::env::current_dir().map_or_else(|_| dir.to_path_buf(), |current| current.join(dir))
        };
        dir.join(home)
    }
}
