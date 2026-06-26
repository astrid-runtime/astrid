//! Source-annotated display for `config show`.
//!
//! Prints the resolved configuration with annotations showing which layer
//! (defaults, system, user, workspace, environment) set each value.

use std::fmt::{self, Write as _};

use crate::merge::FieldSources;
use crate::types::Config;

/// A resolved configuration together with source annotations.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// The final merged configuration.
    pub config: Config,
    /// Dotted field path → which layer set the value.
    pub field_sources: FieldSources,
    /// Config file paths that were loaded (in precedence order).
    pub loaded_files: Vec<String>,
}

/// Output format for `config show`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowFormat {
    /// TOML with inline comments showing source.
    Toml,
    /// JSON (for programmatic consumption).
    Json,
}

impl ResolvedConfig {
    /// Format the resolved config as TOML with source annotations.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn show(&self, format: ShowFormat, section: Option<&str>) -> Result<String, fmt::Error> {
        match format {
            ShowFormat::Toml => self.show_toml(section),
            ShowFormat::Json => self.show_json(section),
        }
    }

    fn show_toml(&self, section: Option<&str>) -> Result<String, fmt::Error> {
        let toml_str = if let Some(section_name) = section {
            // Serialize just one section.
            let val = toml::Value::try_from(&self.config).map_err(|_| fmt::Error)?;
            let table = val.as_table().ok_or(fmt::Error)?;
            let section_val = table.get(section_name).ok_or(fmt::Error)?;
            toml::to_string_pretty(section_val).map_err(|_| fmt::Error)?
        } else {
            toml::to_string_pretty(&self.config).map_err(|_| fmt::Error)?
        };

        let mut output = String::new();

        // Header.
        output.push_str("# Resolved Astrid Configuration\n");
        output.push_str("# Source annotations: [defaults] [system] [user] [workspace] [env]\n");

        if !self.loaded_files.is_empty() {
            output.push_str("#\n# Loaded files (in precedence order):\n");
            for (i, path) in self.loaded_files.iter().enumerate() {
                let _ = writeln!(output, "#   {}. {path}", i.saturating_add(1));
            }
        }

        output.push('\n');

        // Annotate each line.
        let prefix = section.unwrap_or("");
        for line in toml_str.lines() {
            // Try to identify the field from the line.
            if let Some(annotation) = self.annotate_line(line, prefix) {
                let _ = writeln!(output, "{line}  # {annotation}");
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }

        Ok(output)
    }

    fn show_json(&self, section: Option<&str>) -> Result<String, fmt::Error> {
        if let Some(section_name) = section {
            let val = toml::Value::try_from(&self.config).map_err(|_| fmt::Error)?;
            let table = val.as_table().ok_or(fmt::Error)?;
            let section_val = table.get(section_name).ok_or(fmt::Error)?;
            serde_json::to_string_pretty(section_val).map_err(|_| fmt::Error)
        } else {
            serde_json::to_string_pretty(&self.config).map_err(|_| fmt::Error)
        }
    }

    /// Try to extract a source annotation for a TOML line.
    fn annotate_line(&self, line: &str, prefix: &str) -> Option<String> {
        let trimmed = line.trim();

        // Skip empty lines, comments, and section headers.
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            return None;
        }

        // Extract key from "key = value" lines.
        let key = trimmed.split('=').next()?.trim();

        // Build the dotted path.
        let field_path = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };

        self.field_sources
            .get(&field_path)
            .map(|layer| format!("[{layer}]"))
    }

    /// List all config file paths that are checked during loading.
    #[must_use]
    pub fn config_paths(home_dir: Option<&str>, workspace_root: Option<&str>) -> Vec<String> {
        Self::config_paths_with_astrid_home(home_dir, None, workspace_root)
    }

    /// List config file paths, preserving an explicit `ASTRID_HOME` user layer.
    #[must_use]
    pub fn config_paths_with_astrid_home(
        home_dir: Option<&str>,
        astrid_home: Option<&str>,
        workspace_root: Option<&str>,
    ) -> Vec<String> {
        let mut paths = Vec::new();

        paths.push("/etc/astrid/config.toml".to_owned());

        if let Some(home) = astrid_home {
            paths.push(format!("{home}/config.toml"));
        } else if let Some(home) = home_dir {
            paths.push(format!("{home}/.astrid/config.toml"));
        } else {
            paths.push("~/.astrid/config.toml".to_owned());
        }

        if let Some(ws) = workspace_root {
            paths.push(format!("{ws}/.astrid/config.toml"));
        } else {
            paths.push("{workspace}/.astrid/config.toml".to_owned());
        }

        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Config;

    #[test]
    fn test_show_toml_default() {
        let resolved = ResolvedConfig {
            config: Config::default(),
            field_sources: FieldSources::new(),
            loaded_files: Vec::new(),
        };

        let output = resolved.show(ShowFormat::Toml, None).unwrap();
        assert!(output.contains("Resolved Astrid Configuration"));
        assert!(output.contains("provider"));
    }

    #[test]
    fn test_show_json_default() {
        let resolved = ResolvedConfig {
            config: Config::default(),
            field_sources: FieldSources::new(),
            loaded_files: Vec::new(),
        };

        let output = resolved.show(ShowFormat::Json, None).unwrap();
        // Should be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&output).unwrap();
    }

    #[test]
    fn test_show_section() {
        let resolved = ResolvedConfig {
            config: Config::default(),
            field_sources: FieldSources::new(),
            loaded_files: Vec::new(),
        };

        let output = resolved.show(ShowFormat::Toml, Some("model")).unwrap();
        assert!(output.contains("unknown"));
        // Should NOT contain budget or other sections.
        assert!(!output.contains("session_max_usd"));
    }

    #[test]
    fn test_show_http_section() {
        // The [http] host-limits section surfaces in `config show` (it is part
        // of the serialized Config, so generic serialization carries it).
        let resolved = ResolvedConfig {
            config: Config::default(),
            field_sources: FieldSources::new(),
            loaded_files: Vec::new(),
        };

        let output = resolved.show(ShowFormat::Toml, Some("http")).unwrap();
        assert!(output.contains("default_timeout_secs"));
        assert!(output.contains("max_concurrent_streams"));
        assert!(output.contains("max_response_bytes"));
        // Section-scoped: no unrelated sections leak in.
        assert!(!output.contains("session_max_usd"));
    }

    #[test]
    fn test_config_paths() {
        let paths = ResolvedConfig::config_paths(Some("/home/user"), Some("/home/user/project"));
        assert_eq!(paths.len(), 3);
        assert!(paths[0].contains("/etc/astrid"));
        assert!(paths[1].contains("/home/user/.astrid"));
        assert!(paths[2].contains("/home/user/project/.astrid"));
    }

    #[test]
    fn config_paths_prefer_explicit_astrid_home() {
        let paths = ResolvedConfig::config_paths_with_astrid_home(
            Some("/home/user"),
            Some("/tmp/astrid-home"),
            Some("/home/user/project"),
        );
        assert_eq!(paths[1], "/tmp/astrid-home/config.toml");
        assert!(!paths[1].contains("/home/user/.astrid"));
    }
}
