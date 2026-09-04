//! Environment variable security policy for spawned child processes.
//!
//! Provides a single, shared blocklist of environment variables that must never
//! be set by untrusted configuration (hook configs, MCP server manifests, plugin
//! manifests) on spawned child processes. These variables can inject code,
//! libraries, or redirect trust anchors.
//!
//! All enforcement points (hooks, MCP servers, plugins) MUST use this module
//! rather than maintaining their own inline blocklists.

/// Env vars that must never be set by untrusted configuration on spawned
/// child processes.
const BLOCKED_SPAWN_ENV: &[&str] = &[
    // Core execution environment
    "HOME",
    "PATH",
    "ASTRID_HOME",
    "ASTRID_RUN_DIR",
    // Library injection (Linux)
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    // Library injection (macOS)
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Node.js execution control
    "NODE_OPTIONS",
    "NODE_PATH",
    // Python code injection
    "PYTHONPATH",
    "PYTHONSTARTUP",
    // Perl/Ruby code injection
    "PERL5LIB",
    "RUBYLIB",
    // Shell startup injection
    "BASH_ENV",
    "ENV",
    // Java agent injection
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    // TLS/CA trust injection (MITM)
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    // OpenSSL engine loading
    "OPENSSL_CONF",
    // Temp directory redirection
    "TMPDIR",
    "TEMP",
    "TMP",
    // Traffic interception via proxy
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    // Socket access (prevents child processes from connecting to the daemon)
    "ASTRID_SOCKET_PATH",
    "ASTRID_SESSION_TOKEN",
];

/// Prefixes that are blocked entirely (case-insensitive).
///
/// Any env var whose lowercase name starts with one of these prefixes is
/// blocked, even if it is not in the explicit list above.
const BLOCKED_PREFIXES: &[&str] = &[
    "ld_",         // Linux dynamic linker
    "dyld_",       // macOS dynamic linker
    "npm_config_", // npm configuration override
];

/// Returns `true` if `key` is a blocked env var that must not be set by
/// untrusted configuration on spawned child processes.
///
/// Checks both exact matches (case-insensitive) and blocked prefixes.
#[must_use]
pub fn is_blocked_spawn_env(key: &str) -> bool {
    // Exact match (case-insensitive)
    if BLOCKED_SPAWN_ENV
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key))
    {
        return true;
    }
    // Prefix match (case-insensitive)
    let lower = key.to_ascii_lowercase();
    BLOCKED_PREFIXES.iter().any(|p| lower.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_matches_are_blocked() {
        assert!(is_blocked_spawn_env("LD_PRELOAD"));
        assert!(is_blocked_spawn_env("DYLD_INSERT_LIBRARIES"));
        assert!(is_blocked_spawn_env("NODE_OPTIONS"));
        assert!(is_blocked_spawn_env("PYTHONPATH"));
        assert!(is_blocked_spawn_env("PYTHONSTARTUP"));
        assert!(is_blocked_spawn_env("BASH_ENV"));
        assert!(is_blocked_spawn_env("ENV"));
        assert!(is_blocked_spawn_env("PERL5LIB"));
        assert!(is_blocked_spawn_env("RUBYLIB"));
        assert!(is_blocked_spawn_env("HOME"));
        assert!(is_blocked_spawn_env("PATH"));
        assert!(is_blocked_spawn_env("ASTRID_HOME"));
        assert!(is_blocked_spawn_env("ASTRID_RUN_DIR"));
        assert!(is_blocked_spawn_env("OPENSSL_CONF"));
        assert!(is_blocked_spawn_env("HTTP_PROXY"));
        assert!(is_blocked_spawn_env("HTTPS_PROXY"));
        assert!(is_blocked_spawn_env("ALL_PROXY"));
        assert!(is_blocked_spawn_env("NO_PROXY"));
        assert!(is_blocked_spawn_env("NODE_EXTRA_CA_CERTS"));
        assert!(is_blocked_spawn_env("SSL_CERT_FILE"));
        assert!(is_blocked_spawn_env("SSL_CERT_DIR"));
        assert!(is_blocked_spawn_env("TMPDIR"));
        assert!(is_blocked_spawn_env("JAVA_TOOL_OPTIONS"));
        assert!(is_blocked_spawn_env("_JAVA_OPTIONS"));
        assert!(is_blocked_spawn_env("JDK_JAVA_OPTIONS"));
        assert!(is_blocked_spawn_env("DYLD_FRAMEWORK_PATH"));
        assert!(is_blocked_spawn_env("ASTRID_SOCKET_PATH"));
        assert!(is_blocked_spawn_env("ASTRID_SESSION_TOKEN"));
    }

    #[test]
    fn case_insensitive_matching() {
        assert!(is_blocked_spawn_env("ld_preload"));
        assert!(is_blocked_spawn_env("Ld_Preload"));
        assert!(is_blocked_spawn_env("node_options"));
        assert!(is_blocked_spawn_env("pythonpath"));
        assert!(is_blocked_spawn_env("home"));
    }

    #[test]
    fn prefix_blocking() {
        // ld_ prefix catches novel LD_* vars
        assert!(is_blocked_spawn_env("LD_DEBUG"));
        assert!(is_blocked_spawn_env("LD_SOMETHING_NEW"));
        // dyld_ prefix
        assert!(is_blocked_spawn_env("DYLD_PRINT_LIBRARIES"));
        assert!(is_blocked_spawn_env("DYLD_FORCE_FLAT_NAMESPACE"));
        // npm_config_ prefix
        assert!(is_blocked_spawn_env("npm_config_registry"));
        assert!(is_blocked_spawn_env("npm_config_cache"));
        assert!(is_blocked_spawn_env("NPM_CONFIG_PREFIX"));
    }

    #[test]
    fn safe_vars_are_allowed() {
        assert!(!is_blocked_spawn_env("CUSTOM_VAR"));
        assert!(!is_blocked_spawn_env("MY_APP_ENV"));
        assert!(!is_blocked_spawn_env("LDFLAGS")); // not ld_ prefix (l-d, not ld_)
        assert!(!is_blocked_spawn_env("LANG"));
        assert!(!is_blocked_spawn_env("USER"));
        assert!(!is_blocked_spawn_env("SHELL"));
        assert!(!is_blocked_spawn_env("TERM"));
        assert!(!is_blocked_spawn_env("EDITOR"));
    }
}
