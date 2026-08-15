//! Resource patterns for capability matching.
//!
//! Resource patterns use a URI-like format with glob support:
//! - `mcp://filesystem:read_file` - Exact match
//! - `mcp://filesystem:*` - Any tool in filesystem server
//! - `mcp://*:read_*` - Any read tool in any server
//! - `file:///home/user/**` - Any file under /home/user

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::error::{CapabilityError, CapabilityResult};

/// A pattern that matches resources.
///
/// Supports exact matches and glob patterns (*, **, ?).
#[derive(Debug, Clone)]
pub struct ResourcePattern {
    /// The original pattern string.
    pattern: String,
    /// Compiled glob matcher (None for exact matches).
    matcher: Option<GlobMatcher>,
}

impl ResourcePattern {
    /// Create a new resource pattern.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidPattern`] if the glob pattern is invalid
    /// or contains path traversal sequences (`..`).
    pub fn new(pattern: impl Into<String>) -> CapabilityResult<Self> {
        let pattern = pattern.into();

        // Reject path traversal attempts
        if Self::contains_path_traversal(&pattern) {
            return Err(CapabilityError::InvalidPattern {
                pattern,
                reason: "path traversal detected: pattern contains '..' segment".to_string(),
            });
        }

        // Check if it contains glob characters
        let is_glob = pattern.contains('*') || pattern.contains('?') || pattern.contains('[');

        let matcher = if is_glob {
            let glob = Glob::new(&pattern).map_err(|e| CapabilityError::InvalidPattern {
                pattern: pattern.clone(),
                reason: e.to_string(),
            })?;
            Some(glob.compile_matcher())
        } else {
            None
        };

        Ok(Self { pattern, matcher })
    }

    /// Create an exact match pattern.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidPattern`] if the pattern contains
    /// path traversal sequences (`..`).
    pub fn exact(pattern: impl Into<String>) -> CapabilityResult<Self> {
        let pattern = pattern.into();

        if Self::contains_path_traversal(&pattern) {
            return Err(CapabilityError::InvalidPattern {
                pattern,
                reason: "path traversal detected: pattern contains '..' segment".to_string(),
            });
        }

        Ok(Self {
            pattern,
            matcher: None,
        })
    }

    /// Create a pattern matching a file directory and all contents beneath it.
    ///
    /// Example: `file_dir("/home/user")` matches `file:///home/user/any/nested/file`.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidPattern`] if the path contains path traversal.
    pub fn file_dir(path: impl Into<String>) -> CapabilityResult<Self> {
        let path = path.into();
        let pattern = format!("file://{path}/**");
        Self::new(pattern)
    }

    /// Create a pattern matching an exact file path.
    ///
    /// Example: `file_exact("/home/user/file.txt")` matches only `file:///home/user/file.txt`.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidPattern`] if the path contains path traversal.
    pub fn file_exact(path: impl Into<String>) -> CapabilityResult<Self> {
        let path = path.into();
        Self::exact(format!("file://{path}"))
    }

    /// Create a pattern matching a specific MCP tool on a specific server.
    ///
    /// Example: `mcp_tool("filesystem", "read_file")` matches `mcp://filesystem:read_file`.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidPattern`] if server or tool names
    /// contain path traversal sequences.
    pub fn mcp_tool(server: impl Into<String>, tool: impl Into<String>) -> CapabilityResult<Self> {
        Self::exact(format!("mcp://{}:{}", server.into(), tool.into()))
    }

    /// Create a pattern matching all tools on an MCP server.
    ///
    /// Example: `mcp_server("filesystem")` matches `mcp://filesystem:read_file`,
    /// `mcp://filesystem:write_file`, etc.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidPattern`] if the glob compilation fails.
    pub fn mcp_server(server: impl Into<String>) -> CapabilityResult<Self> {
        Self::new(format!("mcp://{}:*", server.into()))
    }

    /// Check if this pattern matches a resource.
    ///
    /// Resources containing path traversal sequences (`..`) are always rejected.
    #[must_use]
    pub fn matches(&self, resource: &str) -> bool {
        // Reject path traversal in the resource being matched
        if Self::contains_path_traversal(resource) {
            return false;
        }

        match &self.matcher {
            Some(matcher) => matcher.is_match(resource),
            None => self.pattern == resource,
        }
    }

    /// Check if a string contains path traversal sequences.
    ///
    /// Detects `..` as a path segment: `/../`, `/..` at end, `../` at start, or bare `..`.
    fn contains_path_traversal(s: &str) -> bool {
        // Strip the scheme to check the path portion
        let path = s.split_once("://").map_or(s, |(_, rest)| rest);

        path.split('/').any(|segment| segment == "..")
    }

    /// Get the pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Check if this is a glob pattern.
    #[must_use]
    pub fn is_glob(&self) -> bool {
        self.matcher.is_some()
    }

    /// Parse a resource URI into components.
    ///
    /// Format: `scheme://server:tool` or `scheme://path`
    #[cfg(test)]
    #[must_use]
    pub(crate) fn parse_uri(resource: &str) -> Option<ResourceUri> {
        let (scheme, rest) = resource.split_once("://")?;

        // For file:// URIs, the rest is the path
        if scheme == "file" {
            return Some(ResourceUri {
                scheme: scheme.to_string(),
                server: None,
                tool: None,
                path: Some(rest.to_string()),
            });
        }

        // For mcp:// URIs, parse server:tool
        if let Some((server, tool)) = rest.split_once(':') {
            Some(ResourceUri {
                scheme: scheme.to_string(),
                server: Some(server.to_string()),
                tool: Some(tool.to_string()),
                path: None,
            })
        } else {
            Some(ResourceUri {
                scheme: scheme.to_string(),
                server: Some(rest.to_string()),
                tool: None,
                path: None,
            })
        }
    }
}

impl std::fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pattern)
    }
}

impl Serialize for ResourcePattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.pattern.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourcePattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let pattern = String::deserialize(deserializer)?;
        Self::new(pattern).map_err(serde::de::Error::custom)
    }
}

impl PartialEq for ResourcePattern {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for ResourcePattern {}

impl std::hash::Hash for ResourcePattern {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

/// Parsed components of a resource URI.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceUri {
    /// URI scheme (mcp, file, http, etc.)
    pub(crate) scheme: String,
    /// Server name (for MCP resources)
    pub(crate) server: Option<String>,
    /// Tool name (for MCP resources)
    pub(crate) tool: Option<String>,
    /// Path (for file resources)
    pub(crate) path: Option<String>,
}

#[cfg(test)]
impl ResourceUri {
    /// Create an MCP resource URI.
    #[must_use]
    pub(crate) fn mcp(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            scheme: "mcp".to_string(),
            server: Some(server.into()),
            tool: Some(tool.into()),
            path: None,
        }
    }

    /// Create a file resource URI.
    #[must_use]
    pub(crate) fn file(path: impl Into<String>) -> Self {
        Self {
            scheme: "file".to_string(),
            server: None,
            tool: None,
            path: Some(path.into()),
        }
    }

    /// Convert back to a URI string.
    #[must_use]
    pub(crate) fn to_uri(&self) -> String {
        match (&self.server, &self.tool, &self.path) {
            (Some(server), Some(tool), _) => format!("{}://{}:{}", self.scheme, server, tool),
            (Some(server), None, _) => format!("{}://{}", self.scheme, server),
            (_, _, Some(path)) => format!("{}://{}", self.scheme, path),
            _ => format!("{}://", self.scheme),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = ResourcePattern::exact("mcp://filesystem:read_file").unwrap();
        assert!(pattern.matches("mcp://filesystem:read_file"));
        assert!(!pattern.matches("mcp://filesystem:write_file"));
    }

    #[test]
    fn test_glob_single_wildcard() {
        let pattern = ResourcePattern::new("mcp://filesystem:*").unwrap();
        assert!(pattern.matches("mcp://filesystem:read_file"));
        assert!(pattern.matches("mcp://filesystem:write_file"));
        assert!(!pattern.matches("mcp://memory:read"));
    }

    #[test]
    fn test_glob_double_wildcard() {
        let pattern = ResourcePattern::new("file:///home/user/**").unwrap();
        assert!(pattern.matches("file:///home/user/file.txt"));
        assert!(pattern.matches("file:///home/user/deep/nested/file.txt"));
        assert!(!pattern.matches("file:///etc/passwd"));
    }

    #[test]
    fn test_glob_server_wildcard() {
        let pattern = ResourcePattern::new("mcp://*:read_*").unwrap();
        assert!(pattern.matches("mcp://filesystem:read_file"));
        assert!(pattern.matches("mcp://memory:read_graph"));
        assert!(!pattern.matches("mcp://filesystem:write_file"));
    }

    #[test]
    fn test_parse_mcp_uri() {
        let uri = ResourcePattern::parse_uri("mcp://filesystem:read_file").unwrap();
        assert_eq!(uri.scheme, "mcp");
        assert_eq!(uri.server, Some("filesystem".to_string()));
        assert_eq!(uri.tool, Some("read_file".to_string()));
    }

    #[test]
    fn test_parse_file_uri() {
        let uri = ResourcePattern::parse_uri("file:///home/user/file.txt").unwrap();
        assert_eq!(uri.scheme, "file");
        assert_eq!(uri.path, Some("/home/user/file.txt".to_string()));
    }

    #[test]
    fn test_resource_uri_round_trip() {
        let uri = ResourceUri::mcp("filesystem", "read_file");
        assert_eq!(uri.to_uri(), "mcp://filesystem:read_file");

        let uri = ResourceUri::file("/home/user/file.txt");
        assert_eq!(uri.to_uri(), "file:///home/user/file.txt");
    }

    #[test]
    fn test_invalid_pattern() {
        let result = ResourcePattern::new("mcp://[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_serialization() {
        let pattern = ResourcePattern::new("mcp://filesystem:*").unwrap();
        let json = serde_json::to_string(&pattern).unwrap();
        let decoded: ResourcePattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern, decoded);
    }

    #[test]
    fn pattern_public_api_contract_is_stable() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let exact = ResourcePattern::exact("mcp://filesystem:read_file").unwrap();
        let glob = ResourcePattern::mcp_server("filesystem").unwrap();
        let other = ResourcePattern::exact("mcp://filesystem:write_file").unwrap();

        assert_eq!(exact.as_str(), "mcp://filesystem:read_file");
        assert_eq!(glob.as_str(), "mcp://filesystem:*");
        assert_eq!(exact.to_string(), "mcp://filesystem:read_file");
        assert_eq!(glob.to_string(), "mcp://filesystem:*");

        assert!(!exact.is_glob());
        assert!(glob.is_glob());
        assert_eq!(exact, exact.clone());
        assert_ne!(exact, other);

        let mut exact_hasher = DefaultHasher::new();
        exact.hash(&mut exact_hasher);
        let mut other_hasher = DefaultHasher::new();
        other.hash(&mut other_hasher);
        assert_ne!(exact_hasher.finish(), other_hasher.finish());
    }

    // --- Helper constructor tests ---

    #[test]
    fn test_file_dir() {
        let pattern = ResourcePattern::file_dir("/home/user").unwrap();
        assert!(pattern.matches("file:///home/user/file.txt"));
        assert!(pattern.matches("file:///home/user/deep/nested/file.txt"));
        assert!(!pattern.matches("file:///etc/passwd"));
    }

    #[test]
    fn test_file_exact() {
        let pattern = ResourcePattern::file_exact("/home/user/file.txt").unwrap();
        assert!(pattern.matches("file:///home/user/file.txt"));
        assert!(!pattern.matches("file:///home/user/other.txt"));
    }

    #[test]
    fn test_mcp_tool() {
        let pattern = ResourcePattern::mcp_tool("filesystem", "read_file").unwrap();
        assert!(pattern.matches("mcp://filesystem:read_file"));
        assert!(!pattern.matches("mcp://filesystem:write_file"));
        assert!(!pattern.matches("mcp://other:read_file"));
    }

    #[test]
    fn test_mcp_server() {
        let pattern = ResourcePattern::mcp_server("filesystem").unwrap();
        assert!(pattern.matches("mcp://filesystem:read_file"));
        assert!(pattern.matches("mcp://filesystem:write_file"));
        assert!(!pattern.matches("mcp://memory:read"));
    }

    // --- Path traversal security tests ---

    #[test]
    fn test_reject_path_traversal_in_pattern() {
        // Direct traversal
        assert!(ResourcePattern::new("file:///home/user/../../../etc/passwd").is_err());
        // Traversal at end
        assert!(ResourcePattern::new("file:///home/user/..").is_err());
        // Traversal at start of path
        assert!(ResourcePattern::new("file://../etc/passwd").is_err());
        // Traversal with glob
        assert!(ResourcePattern::new("file:///home/user/../../**").is_err());
    }

    #[test]
    fn test_reject_path_traversal_in_exact() {
        assert!(ResourcePattern::exact("file:///home/user/../../../etc/passwd").is_err());
        assert!(ResourcePattern::exact("file:///home/user/..").is_err());
        assert!(ResourcePattern::exact("file://../etc/passwd").is_err());
    }

    #[test]
    fn test_reject_path_traversal_in_resource_match() {
        let pattern = ResourcePattern::new("file:///home/user/**").unwrap();

        // Traversal in the resource should be rejected even if glob would match
        assert!(!pattern.matches("file:///home/user/../../../etc/passwd"));
        assert!(!pattern.matches("file:///home/user/subdir/../../etc/shadow"));
        assert!(!pattern.matches("file:///home/user/.."));
    }

    #[test]
    fn test_reject_path_traversal_exact_match() {
        let pattern = ResourcePattern::exact("mcp://filesystem:read_file").unwrap();

        // Even exact patterns reject traversal in the matched resource
        assert!(!pattern.matches("mcp://filesystem:read_file/../../../etc/passwd"));
    }

    #[test]
    fn test_allow_double_dots_in_non_segment() {
        // Double dots inside a filename (not a path segment) should be fine
        let pattern = ResourcePattern::new("file:///home/user/**").unwrap();
        assert!(pattern.matches("file:///home/user/file..txt"));
        assert!(pattern.matches("file:///home/user/a...b"));

        // Pattern with dots in filename is valid
        let pattern = ResourcePattern::exact("file:///home/user/file..bak").unwrap();
        assert!(pattern.matches("file:///home/user/file..bak"));
    }

    #[test]
    fn test_reject_path_traversal_in_file_dir() {
        assert!(ResourcePattern::file_dir("/home/user/../../etc").is_err());
    }

    #[test]
    fn test_reject_path_traversal_in_file_exact() {
        assert!(ResourcePattern::file_exact("/home/../etc/passwd").is_err());
        assert!(ResourcePattern::file_exact("/../etc/shadow").is_err());
    }
}
