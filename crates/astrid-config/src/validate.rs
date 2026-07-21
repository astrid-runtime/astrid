//! Post-merge configuration validation.
//!
//! Validates that deserialized [`Config`](crate::Config) values are within
//! acceptable ranges and that cross-field invariants hold.

use crate::error::{ConfigError, ConfigResult};
use crate::types::Config;

/// Validate a fully-merged and deserialized configuration.
///
/// Returns `Ok(())` if the configuration is valid, or a list of all
/// validation errors encountered.
///
/// # Errors
///
/// Returns the first validation error found.
pub fn validate(config: &Config) -> ConfigResult<()> {
    validate_model(config)?;
    validate_budget(config)?;
    validate_workspace(config)?;
    validate_git(config)?;
    validate_servers(config)?;
    validate_timeouts(config)?;
    validate_logging(config)?;
    validate_subagents(config)?;
    validate_capsule(config)?;
    validate_retry(config)?;
    Ok(())
}

/// Maximum allowed `max_tokens` value (16 million).
const MAX_TOKENS_UPPER_BOUND: usize = 16_000_000;

fn validate_model(config: &Config) -> ConfigResult<()> {
    let m = &config.model;

    if !matches!(
        m.provider.as_str(),
        "claude" | "openai" | "openai-compat" | "zai" | "unknown"
    ) {
        return Err(ConfigError::ValidationError {
            field: "model.provider".to_owned(),
            message: format!(
                "unsupported provider '{}'; expected one of: claude, openai, openai-compat, zai, unknown",
                m.provider
            ),
        });
    }

    if !(0.0..=1.0).contains(&m.temperature) {
        return Err(ConfigError::ValidationError {
            field: "model.temperature".to_owned(),
            message: format!(
                "temperature {} is out of range; must be between 0.0 and 1.0",
                m.temperature
            ),
        });
    }

    if m.max_tokens == 0 || m.max_tokens > MAX_TOKENS_UPPER_BOUND {
        return Err(ConfigError::ValidationError {
            field: "model.max_tokens".to_owned(),
            message: format!("max_tokens must be between 1 and {MAX_TOKENS_UPPER_BOUND}"),
        });
    }

    if !m.pricing.input_per_million.is_finite() || m.pricing.input_per_million <= 0.0 {
        return Err(ConfigError::ValidationError {
            field: "model.pricing.input_per_million".to_owned(),
            message: "input_per_million must be a finite positive number".to_owned(),
        });
    }

    if !m.pricing.output_per_million.is_finite() || m.pricing.output_per_million <= 0.0 {
        return Err(ConfigError::ValidationError {
            field: "model.pricing.output_per_million".to_owned(),
            message: "output_per_million must be a finite positive number".to_owned(),
        });
    }

    Ok(())
}

/// Maximum allowed budget value in USD.
const BUDGET_UPPER_BOUND_USD: f64 = 10_000.0;

fn validate_budget(config: &Config) -> ConfigResult<()> {
    let b = &config.budget;

    if !b.session_max_usd.is_finite() || b.session_max_usd <= 0.0 {
        return Err(ConfigError::ValidationError {
            field: "budget.session_max_usd".to_owned(),
            message: "session_max_usd must be a finite positive number".to_owned(),
        });
    }

    if b.session_max_usd > BUDGET_UPPER_BOUND_USD {
        return Err(ConfigError::ValidationError {
            field: "budget.session_max_usd".to_owned(),
            message: format!(
                "session_max_usd ({}) exceeds maximum allowed value ({BUDGET_UPPER_BOUND_USD})",
                b.session_max_usd
            ),
        });
    }

    if !b.per_action_max_usd.is_finite() || b.per_action_max_usd <= 0.0 {
        return Err(ConfigError::ValidationError {
            field: "budget.per_action_max_usd".to_owned(),
            message: "per_action_max_usd must be a finite positive number".to_owned(),
        });
    }

    if b.per_action_max_usd > b.session_max_usd {
        return Err(ConfigError::ValidationError {
            field: "budget.per_action_max_usd".to_owned(),
            message: format!(
                "per_action_max_usd ({}) must not exceed session_max_usd ({})",
                b.per_action_max_usd, b.session_max_usd
            ),
        });
    }

    if b.warn_at_percent > 100 {
        return Err(ConfigError::ValidationError {
            field: "budget.warn_at_percent".to_owned(),
            message: format!(
                "warn_at_percent {} is out of range; must be 0-100",
                b.warn_at_percent
            ),
        });
    }

    Ok(())
}

fn validate_workspace(config: &Config) -> ConfigResult<()> {
    let w = &config.workspace;

    if !matches!(w.mode.as_str(), "safe" | "guided" | "autonomous" | "yolo") {
        return Err(ConfigError::ValidationError {
            field: "workspace.mode".to_owned(),
            message: format!(
                "unsupported mode '{}'; expected one of: safe, guided, autonomous, yolo",
                w.mode
            ),
        });
    }

    if !matches!(w.escape_policy.as_str(), "ask" | "deny" | "allow") {
        return Err(ConfigError::ValidationError {
            field: "workspace.escape_policy".to_owned(),
            message: format!(
                "unsupported escape_policy '{}'; expected one of: ask, deny, allow",
                w.escape_policy
            ),
        });
    }

    Ok(())
}

fn validate_git(config: &Config) -> ConfigResult<()> {
    if !matches!(
        config.git.completion.as_str(),
        "merge" | "pr" | "branch-only"
    ) {
        return Err(ConfigError::ValidationError {
            field: "git.completion".to_owned(),
            message: format!(
                "unsupported completion strategy '{}'; expected one of: merge, pr, branch-only",
                config.git.completion
            ),
        });
    }

    Ok(())
}

fn validate_servers(config: &Config) -> ConfigResult<()> {
    for (name, server) in &config.servers {
        if !matches!(
            server.transport.as_str(),
            "stdio" | "sse" | "streamable-http"
        ) {
            return Err(ConfigError::ValidationError {
                field: format!("servers.{name}.transport"),
                message: format!(
                    "unsupported transport '{}'; expected one of: stdio, sse, streamable-http",
                    server.transport
                ),
            });
        }

        if server.transport == "stdio" && server.command.is_none() {
            return Err(ConfigError::ValidationError {
                field: format!("servers.{name}.command"),
                message: "stdio transport requires a command".to_owned(),
            });
        }

        if (server.transport == "sse" || server.transport == "streamable-http")
            && server.url.is_none()
        {
            return Err(ConfigError::ValidationError {
                field: format!("servers.{name}.url"),
                message: format!("{} transport requires a url", server.transport),
            });
        }
    }

    Ok(())
}

fn validate_timeouts(config: &Config) -> ConfigResult<()> {
    let t = &config.timeouts;

    if t.request_secs == 0 {
        return Err(ConfigError::ValidationError {
            field: "timeouts.request_secs".to_owned(),
            message: "request_secs must be greater than 0".to_owned(),
        });
    }

    if t.tool_secs == 0 {
        return Err(ConfigError::ValidationError {
            field: "timeouts.tool_secs".to_owned(),
            message: "tool_secs must be greater than 0".to_owned(),
        });
    }

    if t.subagent_secs == 0 {
        return Err(ConfigError::ValidationError {
            field: "timeouts.subagent_secs".to_owned(),
            message: "subagent_secs must be greater than 0".to_owned(),
        });
    }

    if t.mcp_connect_secs == 0 {
        return Err(ConfigError::ValidationError {
            field: "timeouts.mcp_connect_secs".to_owned(),
            message: "mcp_connect_secs must be greater than 0".to_owned(),
        });
    }

    if t.approval_secs == 0 {
        return Err(ConfigError::ValidationError {
            field: "timeouts.approval_secs".to_owned(),
            message: "approval_secs must be greater than 0".to_owned(),
        });
    }

    Ok(())
}

fn validate_subagents(config: &Config) -> ConfigResult<()> {
    let s = &config.subagents;

    if s.max_concurrent == 0 {
        return Err(ConfigError::ValidationError {
            field: "subagents.max_concurrent".to_owned(),
            message: "max_concurrent must be greater than 0".to_owned(),
        });
    }

    if s.max_depth == 0 {
        return Err(ConfigError::ValidationError {
            field: "subagents.max_depth".to_owned(),
            message: "max_depth must be greater than 0".to_owned(),
        });
    }

    if s.timeout_secs == 0 {
        return Err(ConfigError::ValidationError {
            field: "subagents.timeout_secs".to_owned(),
            message: "timeout_secs must be greater than 0".to_owned(),
        });
    }

    Ok(())
}

fn validate_capsule(config: &Config) -> ConfigResult<()> {
    let c = &config.capsule;

    // `None` means host-derived; only an explicit override can be invalid. A
    // zero ceiling would wedge every host call of that class, so reject it here
    // rather than silently clamp.
    if c.host_blocking_concurrency == Some(0) {
        return Err(ConfigError::ValidationError {
            field: "capsule.host_blocking_concurrency".to_owned(),
            message: "host_blocking_concurrency must be greater than 0".to_owned(),
        });
    }

    if c.host_io_concurrency == Some(0) {
        return Err(ConfigError::ValidationError {
            field: "capsule.host_io_concurrency".to_owned(),
            message: "host_io_concurrency must be greater than 0".to_owned(),
        });
    }

    if c.host_net_streams == Some(0) {
        return Err(ConfigError::ValidationError {
            field: "capsule.host_net_streams".to_owned(),
            message: "host_net_streams must be greater than 0".to_owned(),
        });
    }

    if c.instance_pool_size == Some(0) {
        return Err(ConfigError::ValidationError {
            field: "capsule.instance_pool_size".to_owned(),
            message: "instance_pool_size must be greater than 0".to_owned(),
        });
    }

    Ok(())
}

fn validate_retry(config: &Config) -> ConfigResult<()> {
    let r = &config.retry;

    if r.llm_max_attempts == 0 {
        return Err(ConfigError::ValidationError {
            field: "retry.llm_max_attempts".to_owned(),
            message: "llm_max_attempts must be greater than 0".to_owned(),
        });
    }

    if r.mcp_max_attempts == 0 {
        return Err(ConfigError::ValidationError {
            field: "retry.mcp_max_attempts".to_owned(),
            message: "mcp_max_attempts must be greater than 0".to_owned(),
        });
    }

    Ok(())
}

fn validate_logging(config: &Config) -> ConfigResult<()> {
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.logging.level.as_str()) {
        return Err(ConfigError::ValidationError {
            field: "logging.level".to_owned(),
            message: format!(
                "unsupported log level '{}'; expected one of: {}",
                config.logging.level,
                valid_levels.join(", ")
            ),
        });
    }

    let valid_formats = ["pretty", "compact", "json", "full"];
    if !valid_formats.contains(&config.logging.format.as_str()) {
        return Err(ConfigError::ValidationError {
            field: "logging.format".to_owned(),
            message: format!(
                "unsupported log format '{}'; expected one of: {}",
                config.logging.format,
                valid_formats.join(", ")
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_provider() {
        let mut config = Config::default();
        config.model.provider = "grok".to_owned();
        let err = validate(&config).unwrap_err();
        assert!(matches!(err, ConfigError::ValidationError { .. }));
    }

    #[test]
    fn test_invalid_temperature() {
        let mut config = Config::default();
        config.model.temperature = 1.5;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_budget() {
        let mut config = Config::default();
        config.budget.per_action_max_usd = 200.0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_capsule_none_is_valid() {
        // Default (all `None` → host-derived) must pass validation.
        let config = Config::default();
        assert!(config.capsule.host_blocking_concurrency.is_none());
        assert!(config.capsule.host_io_concurrency.is_none());
        assert!(config.capsule.host_net_streams.is_none());
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_capsule_positive_override_is_valid() {
        let mut config = Config::default();
        config.capsule.host_blocking_concurrency = Some(4);
        config.capsule.host_io_concurrency = Some(256);
        config.capsule.host_net_streams = Some(128);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_capsule_zero_blocking_rejected() {
        let mut config = Config::default();
        config.capsule.host_blocking_concurrency = Some(0);
        let err = validate(&config).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ValidationError { field, .. }
                if field == "capsule.host_blocking_concurrency"
        ));
    }

    #[test]
    fn test_capsule_zero_io_rejected() {
        let mut config = Config::default();
        config.capsule.host_io_concurrency = Some(0);
        let err = validate(&config).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ValidationError { field, .. }
                if field == "capsule.host_io_concurrency"
        ));
    }

    #[test]
    fn test_capsule_zero_pool_size_rejected() {
        let mut config = Config::default();
        config.capsule.instance_pool_size = Some(0);
        let err = validate(&config).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ValidationError { field, .. }
                if field == "capsule.instance_pool_size"
        ));
    }

    #[test]
    fn test_capsule_zero_net_streams_rejected() {
        let mut config = Config::default();
        config.capsule.host_net_streams = Some(0);
        let err = validate(&config).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ValidationError { field, .. }
                if field == "capsule.host_net_streams"
        ));
    }

    #[test]
    fn test_yolo_workspace_mode() {
        let mut config = Config::default();
        config.workspace.mode = "yolo".to_owned();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_workspace_mode() {
        let mut config = Config::default();
        config.workspace.mode = "turbo".to_owned();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_git_completion() {
        let mut config = Config::default();
        config.git.completion = "fast-forward".to_owned();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_server_stdio_no_command() {
        let mut config = Config::default();
        config.servers.insert(
            "bad".to_owned(),
            crate::types::ServerSection {
                transport: "stdio".to_owned(),
                command: None,
                ..Default::default()
            },
        );
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_server_sse_no_url() {
        let mut config = Config::default();
        config.servers.insert(
            "bad".to_owned(),
            crate::types::ServerSection {
                transport: "sse".to_owned(),
                url: None,
                ..Default::default()
            },
        );
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_timeout_zero() {
        let mut config = Config::default();
        config.timeouts.request_secs = 0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_log_level() {
        let mut config = Config::default();
        config.logging.level = "verbose".to_owned();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_invalid_log_format() {
        let mut config = Config::default();
        config.logging.format = "yaml".to_owned();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_zero_max_tokens() {
        let mut config = Config::default();
        config.model.max_tokens = 0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_negative_pricing() {
        let mut config = Config::default();
        config.model.pricing.input_per_million = -1.0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_zero_pricing_rejected() {
        let mut config = Config::default();
        config.model.pricing.input_per_million = 0.0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_nan_budget_rejected() {
        let mut config = Config::default();
        config.budget.session_max_usd = f64::NAN;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_infinity_budget_rejected() {
        let mut config = Config::default();
        config.budget.session_max_usd = f64::INFINITY;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_nan_per_action_rejected() {
        let mut config = Config::default();
        config.budget.per_action_max_usd = f64::NAN;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_nan_pricing_rejected() {
        let mut config = Config::default();
        config.model.pricing.output_per_million = f64::NAN;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_budget_upper_bound() {
        let mut config = Config::default();
        config.budget.session_max_usd = 20_000.0;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn test_max_tokens_upper_bound() {
        let mut config = Config::default();
        config.model.max_tokens = 100_000_000;
        assert!(validate(&config).is_err());
    }
}
