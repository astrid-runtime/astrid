//! Operator-controlled presentation for native filesystem mounts.

use serde::{Deserialize, Serialize};

/// Presentation only: changing the label does not change mount authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesystemSection {
    /// Display label used by native mounts; distributions can supply their brand.
    pub volume_name: String,
}

impl Default for FilesystemSection {
    fn default() -> Self {
        Self {
            volume_name: "Astrid".to_owned(),
        }
    }
}

impl FilesystemSection {
    pub(crate) fn validate(&self) -> crate::ConfigResult<()> {
        if self.volume_name.trim().is_empty()
            || self.volume_name.len() > 255
            || self.volume_name.contains('/')
            || self.volume_name.chars().any(char::is_control)
        {
            return Err(crate::ConfigError::ValidationError {
                field: "filesystem.volume_name".to_owned(),
                message: "must be a nonempty label of at most 255 UTF-8 bytes without slashes or controls".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branded_label_and_default_are_valid() {
        assert_eq!(FilesystemSection::default().volume_name, "Astrid");
        let section: FilesystemSection = toml::from_str("volume_name = 'AOS'").unwrap();
        assert!(section.validate().is_ok());
        for name in ["", "  ", "a/b", "a\n", "\0"] {
            assert!(
                FilesystemSection {
                    volume_name: name.to_owned()
                }
                .validate()
                .is_err()
            );
        }
    }
}
