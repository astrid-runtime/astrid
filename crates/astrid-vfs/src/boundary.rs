use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

/// High-performance, memory-mapped boundary for enforcing `.astridignore` rules.
///
/// This acts as the absolute security boundary for the VFS. Any path that matches
/// a rule in the boundary will be universally denied by the OS Kernel, protecting
/// host secrets (e.g. `.env`) from being read or corrupted by the agent.
#[derive(Debug, Clone)]
pub(crate) struct IgnoreBoundary {
    matcher: Gitignore,
}

impl IgnoreBoundary {
    /// Creates a new empty boundary that allows everything.
    pub(crate) fn empty(base_dir: impl AsRef<Path>) -> Self {
        Self {
            matcher: GitignoreBuilder::new(base_dir)
                .build()
                .unwrap_or_else(|_| Gitignore::empty()),
        }
    }

    /// Creates a boundary directly from a string (useful for hot-reloading from memory).
    ///
    /// # Errors
    ///
    /// Returns an error if the string contains invalid rules or parsing fails.
    pub(crate) fn from_content(
        base_dir: impl AsRef<Path>,
        content: &str,
    ) -> Result<Self, ignore::Error> {
        let mut builder = GitignoreBuilder::new(base_dir);
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                builder.add_line(None, trimmed)?;
            }
        }
        Ok(Self {
            matcher: builder.build()?,
        })
    }

    /// Loads and parses an `.astridignore` file directly from the physical disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub(crate) fn from_file(file_path: impl AsRef<Path>) -> Result<Self, ignore::Error> {
        let path = file_path.as_ref();
        let base_dir = path.parent().unwrap_or_else(|| Path::new(""));
        let mut builder = GitignoreBuilder::new(base_dir);

        // `add` returns an Option<ignore::Error>, not a Result
        if let Some(err) = builder.add(path) {
            tracing::error!("Failed to add path to ignore builder: {}", err);
            return Err(err);
        }

        Ok(Self {
            matcher: builder.build()?,
        })
    }

    /// Checks if a given path is denied by the boundary rules.
    ///
    /// # Arguments
    /// * `path` - The absolute or relative path to check.
    /// * `is_dir` - Whether the target path is a directory (important for glob rules like `target/`).
    pub(crate) fn is_ignored(&self, path: impl AsRef<Path>, is_dir: bool) -> bool {
        self.matcher.matched(path, is_dir).is_ignore()
    }
}

#[cfg(test)]
mod tests {
    use super::IgnoreBoundary;

    #[test]
    fn content_rules_preserve_deny_and_negation_semantics() {
        let root = tempfile::tempdir().unwrap();
        let boundary = IgnoreBoundary::from_content(
            root.path(),
            ".env\nsecrets/**\n!secrets/public.txt\ncache/\n",
        )
        .unwrap();

        assert!(boundary.is_ignored(root.path().join(".env"), false));
        assert!(boundary.is_ignored(root.path().join("secrets/private.key"), false));
        assert!(!boundary.is_ignored(root.path().join("secrets/public.txt"), false));
        assert!(boundary.is_ignored(root.path().join("cache"), true));
        assert!(!boundary.is_ignored(root.path().join("cache"), false));
        assert!(!boundary.is_ignored(root.path().join("src/lib.rs"), false));
    }

    #[test]
    fn file_rules_are_relative_to_the_ignore_file_directory() {
        let root = tempfile::tempdir().unwrap();
        let ignore_path = root.path().join(".astridignore");
        std::fs::write(&ignore_path, "private/**\n").unwrap();
        let boundary = IgnoreBoundary::from_file(&ignore_path).unwrap();

        assert!(boundary.is_ignored(root.path().join("private/token"), false));
        assert!(!boundary.is_ignored(root.path().join("public/token"), false));
    }
}
