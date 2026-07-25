use super::enforce::{
    block_workspace_expansion, block_workspace_override, clamp_max, clamp_max_int,
    enforce_bool_only_false, enforce_bool_only_true, enforce_mode_tighten, union_string_arrays,
};
use super::servers::sanitize_workspace_servers;

/// Enforce that the workspace layer can only **tighten** security, not loosen
/// it. Call this after merging the workspace layer but before final
/// deserialization.
///
/// `baseline` is the merged config *before* the workspace layer was applied.
/// This ensures enforcement works even when no user config file exists —
/// the defaults serve as the baseline.
#[expect(clippy::too_many_lines)]
pub fn enforce_restrictions(
    merged: &mut toml::Value,
    baseline: &toml::Value,
    workspace_layer: &toml::Value,
) {
    // Budget: can only decrease.
    clamp_max(
        merged,
        baseline,
        workspace_layer,
        &["budget", "session_max_usd"],
        "budget.session_max_usd",
    );
    clamp_max(
        merged,
        baseline,
        workspace_layer,
        &["budget", "per_action_max_usd"],
        "budget.per_action_max_usd",
    );

    // --- Step 3: Additional restriction enforcement ---

    // Workspace mode: can only tighten (safe < guided < autonomous).
    enforce_mode_tighten(
        merged,
        baseline,
        workspace_layer,
        &["workspace", "mode"],
        "workspace.mode",
        &["safe", "guided", "autonomous", "yolo"],
    );

    // Escape policy: can only tighten (deny < ask < allow).
    enforce_mode_tighten(
        merged,
        baseline,
        workspace_layer,
        &["workspace", "escape_policy"],
        "workspace.escape_policy",
        &["deny", "ask", "allow"],
    );

    // workspace.never_allow: union (can only add).
    union_string_arrays(
        merged,
        baseline,
        workspace_layer,
        &["workspace", "never_allow"],
        "workspace.never_allow",
    );

    // security.require_signatures: can only become true.
    enforce_bool_only_true(
        merged,
        workspace_layer,
        &["security", "require_signatures"],
        "security.require_signatures",
    );

    // security.approval_timeout_secs: can only decrease.
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["security", "approval_timeout_secs"],
        "security.approval_timeout_secs",
    );

    // security.capsule_local_egress: operator-only SSRF-airlock exemption.
    // A widening control, so a workspace/project layer must not be able to
    // set or expand it — only the operator's global config can.
    block_workspace_override(
        merged,
        baseline,
        workspace_layer,
        &["security", "capsule_local_egress"],
        "security.capsule_local_egress",
    );

    // http: operator-only host HTTP ceilings (timeouts, redirect/stream caps,
    // buffered-body limit). These are widening controls — a workspace/project
    // layer raising any of them would let untrusted project config relax the
    // host's outbound HTTP limits. Revert the WHOLE section to the operator
    // baseline if a workspace layer touches it (the table is reverted as a unit,
    // so a workspace cannot override even a single key). Only the operator's
    // global config can set `[http]`.
    block_workspace_override(merged, baseline, workspace_layer, &["http"], "http");

    // workspace.auto_allow_read: cannot expand beyond baseline.
    block_workspace_expansion(
        merged,
        baseline,
        workspace_layer,
        &["workspace", "auto_allow_read"],
        "workspace.auto_allow_read",
    );

    // workspace.auto_allow_write: cannot expand beyond baseline.
    block_workspace_expansion(
        merged,
        baseline,
        workspace_layer,
        &["workspace", "auto_allow_write"],
        "workspace.auto_allow_write",
    );

    // model.api_key: workspace cannot override.
    block_workspace_override(
        merged,
        baseline,
        workspace_layer,
        &["model", "api_key"],
        "model.api_key",
    );

    // model.api_url: workspace cannot override.
    block_workspace_override(
        merged,
        baseline,
        workspace_layer,
        &["model", "api_url"],
        "model.api_url",
    );

    // hooks.allow_wasm_hooks: cannot enable (only disable).
    enforce_bool_only_false(
        merged,
        workspace_layer,
        &["hooks", "allow_wasm_hooks"],
        "hooks.allow_wasm_hooks",
    );

    // hooks.allow_agent_hooks: cannot enable (only disable).
    enforce_bool_only_false(
        merged,
        workspace_layer,
        &["hooks", "allow_agent_hooks"],
        "hooks.allow_agent_hooks",
    );

    // rate_limits: can only decrease.
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["rate_limits", "elicitation_per_server_per_min"],
        "rate_limits.elicitation_per_server_per_min",
    );
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["rate_limits", "max_pending_requests"],
        "rate_limits.max_pending_requests",
    );

    // budget.warn_at_percent: can only decrease.
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["budget", "warn_at_percent"],
        "budget.warn_at_percent",
    );

    // subagents: limits can only decrease from workspace.
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["subagents", "max_concurrent"],
        "subagents.max_concurrent",
    );
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["subagents", "max_depth"],
        "subagents.max_depth",
    );
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["subagents", "timeout_secs"],
        "subagents.timeout_secs",
    );

    // retry: limits can only decrease from workspace.
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["retry", "llm_max_attempts"],
        "retry.llm_max_attempts",
    );
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["retry", "mcp_max_attempts"],
        "retry.mcp_max_attempts",
    );

    // timeouts.approval_secs: can only decrease.
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["timeouts", "approval_secs"],
        "timeouts.approval_secs",
    );

    // timeouts.idle_secs: can only decrease (prevent workspace keeping
    // sessions alive indefinitely).
    clamp_max_int(
        merged,
        baseline,
        workspace_layer,
        &["timeouts", "idle_secs"],
        "timeouts.idle_secs",
    );

    // hooks.allow_http_hooks: cannot enable (only disable).
    enforce_bool_only_false(
        merged,
        workspace_layer,
        &["hooks", "allow_http_hooks"],
        "hooks.allow_http_hooks",
    );

    // hooks.allow_command_hooks: cannot enable (only disable).
    enforce_bool_only_false(
        merged,
        workspace_layer,
        &["hooks", "allow_command_hooks"],
        "hooks.allow_command_hooks",
    );

    // --- Step 4: Prevent workspace server injection ---
    sanitize_workspace_servers(merged, baseline, workspace_layer);
}
