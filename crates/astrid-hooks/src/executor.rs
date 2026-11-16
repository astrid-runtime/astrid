//! Hook executor - runs hooks with their handlers.

use chrono::Utc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::handler::{CommandHandler, HttpHandler, WasmHandler};
use crate::hook::{FailAction, Hook, HookHandler, HookMatcher};
use crate::result::{HookContext, HookExecution, HookExecutionResult, HookResult};

/// Executes hooks using the appropriate handler.
#[derive(Debug)]
#[expect(clippy::struct_field_names)]
pub(crate) struct HookExecutor {
    command_handler: CommandHandler,
    http_handler: HttpHandler,
    wasm_handler: WasmHandler,
}

impl Default for HookExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl HookExecutor {
    /// Create a new hook executor with default workspace root (current directory).
    #[must_use]
    pub(crate) fn new() -> Self {
        let workspace_root = std::env::current_dir().unwrap_or_default();
        Self {
            command_handler: CommandHandler::new(),
            http_handler: HttpHandler::new(),
            wasm_handler: WasmHandler::new(workspace_root),
        }
    }

    /// Create a new hook executor with a specific workspace root for WASM handlers.
    #[must_use]
    pub(crate) fn with_workspace_root(workspace_root: std::path::PathBuf) -> Self {
        Self {
            command_handler: CommandHandler::new(),
            http_handler: HttpHandler::new(),
            wasm_handler: WasmHandler::new(workspace_root),
        }
    }

    /// Execute a single hook.
    pub(crate) async fn execute(&self, hook: &Hook, context: &HookContext) -> HookExecution {
        let started_at = Utc::now();
        let timeout = Duration::from_secs(hook.timeout_secs);

        debug!(
            hook_id = %hook.id,
            hook_name = ?hook.name,
            event = %hook.event,
            "Executing hook"
        );

        // Check if hook should be skipped
        if !hook.enabled {
            return HookExecution {
                hook_id: hook.id,
                invocation_id: context.invocation_id,
                started_at,
                completed_at: Utc::now(),
                duration_ms: 0,
                result: HookExecutionResult::Skipped {
                    reason: "hook is disabled".to_string(),
                },
            };
        }

        // Check matcher
        if let Some(ref matcher) = hook.matcher
            && !matches_context(matcher, context)
        {
            return HookExecution {
                hook_id: hook.id,
                invocation_id: context.invocation_id,
                started_at,
                completed_at: Utc::now(),
                duration_ms: 0,
                result: HookExecutionResult::Skipped {
                    reason: "matcher did not match".to_string(),
                },
            };
        }

        // Execute the appropriate handler
        let result = match &hook.handler {
            HookHandler::Command { .. } => {
                self.command_handler
                    .execute(&hook.handler, context, timeout)
                    .await
            },
            HookHandler::Http { .. } => {
                self.http_handler
                    .execute(&hook.handler, context, timeout)
                    .await
            },
            HookHandler::Wasm { .. } => {
                self.wasm_handler
                    .execute(&hook.handler, context, timeout)
                    .await
            },
        };

        let completed_at = Utc::now();
        #[expect(clippy::cast_sign_loss)]
        // Safety: chrono DateTime subtraction cannot overflow for reasonable time values
        #[expect(clippy::arithmetic_side_effects)]
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0) as u64;

        let execution_result = match result {
            Ok(result) => {
                info!(
                    hook_id = %hook.id,
                    duration_ms = duration_ms,
                    "Hook executed successfully"
                );
                result
            },
            Err(e) => {
                error!(
                    hook_id = %hook.id,
                    error = %e,
                    "Hook execution failed"
                );
                HookExecutionResult::Failure {
                    error: e.to_string(),
                    stderr: None,
                }
            },
        };

        HookExecution {
            hook_id: hook.id,
            invocation_id: context.invocation_id,
            started_at,
            completed_at,
            duration_ms,
            result: execution_result,
        }
    }

    /// Execute multiple hooks in sequence.
    pub(crate) async fn execute_all(
        &self,
        hooks: &[Hook],
        mut context: HookContext,
    ) -> Vec<HookExecution> {
        let mut executions = Vec::with_capacity(hooks.len());

        for hook in hooks {
            let execution = self.execute(hook, &context).await;

            // Add result to context for next hook
            if let Some(result) = execution.result.hook_result() {
                context.add_previous_result(result.clone());
            }

            // Handle fail action
            if !execution.result.is_success() {
                match hook.fail_action {
                    FailAction::Block => {
                        warn!(
                            hook_id = %hook.id,
                            "Hook failed with Block action, stopping chain"
                        );
                        executions.push(execution);
                        break;
                    },
                    FailAction::Warn => {
                        warn!(
                            hook_id = %hook.id,
                            "Hook failed with Warn action, continuing"
                        );
                    },
                    FailAction::Ignore => {
                        debug!(
                            hook_id = %hook.id,
                            "Hook failed with Ignore action, continuing silently"
                        );
                    },
                }
            }

            // Check if any hook blocked
            if let Some(HookResult::Block { .. }) = execution.result.hook_result() {
                info!(
                    hook_id = %hook.id,
                    "Hook returned Block result, stopping chain"
                );
                executions.push(execution);
                break;
            }

            executions.push(execution);
        }

        executions
    }

    /// Combine multiple hook results into a single result.
    ///
    /// Rules:
    /// - Any Block result → Block
    /// - Any Ask result → Ask (if no Block)
    /// - `ContinueWith` modifications are merged
    /// - Otherwise → Continue
    #[must_use]
    pub(crate) fn combine_results(executions: &[HookExecution]) -> HookResult {
        let mut modifications = std::collections::HashMap::new();
        let mut ask_question = None;

        for execution in executions {
            match execution.result.hook_result() {
                Some(HookResult::Block { reason }) => {
                    return HookResult::Block {
                        reason: reason.clone(),
                    };
                },
                Some(HookResult::Ask { question, default }) => {
                    if ask_question.is_none() {
                        ask_question = Some((question.clone(), default.clone()));
                    }
                },
                Some(HookResult::ContinueWith {
                    modifications: mods,
                }) => {
                    modifications.extend(mods.clone());
                },
                Some(HookResult::Continue) | None => {},
            }
        }

        if let Some((question, default)) = ask_question {
            return HookResult::Ask { question, default };
        }

        if !modifications.is_empty() {
            return HookResult::ContinueWith { modifications };
        }

        HookResult::Continue
    }
}

/// Check if a matcher matches the context.
fn matches_context(matcher: &HookMatcher, context: &HookContext) -> bool {
    match matcher {
        HookMatcher::Glob { pattern } => {
            // Try to match against tool_name or other relevant data
            if let Some(tool_name) = context.get_data_as::<String>("tool_name")
                && let Ok(glob) = globset::Glob::new(pattern)
            {
                let matcher = glob.compile_matcher();
                return matcher.is_match(&tool_name);
            }
            false
        },
        HookMatcher::Regex { pattern } => {
            if let Some(tool_name) = context.get_data_as::<String>("tool_name")
                && let Ok(re) = regex::Regex::new(pattern)
            {
                return re.is_match(&tool_name);
            }
            false
        },
        HookMatcher::ToolNames { names } => {
            if let Some(tool_name) = context.get_data_as::<String>("tool_name") {
                return names.contains(&tool_name);
            }
            false
        },
        HookMatcher::ServerNames { names } => {
            if let Some(server_name) = context.get_data_as::<String>("server_name") {
                return names.contains(&server_name);
            }
            false
        },
    }
}

/// Builder for `HookExecution` for testing.
#[derive(Debug)]
pub(crate) struct HookExecutionBuilder {
    hook_id: Uuid,
    invocation_id: Uuid,
    result: HookExecutionResult,
}

impl HookExecutionBuilder {
    /// Create a new builder.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            hook_id: Uuid::new_v4(),
            invocation_id: Uuid::new_v4(),
            result: HookExecutionResult::Success {
                result: HookResult::Continue,
                stdout: None,
            },
        }
    }

    /// Set the result.
    #[must_use]
    pub(crate) fn with_result(mut self, result: HookExecutionResult) -> Self {
        self.result = result;
        self
    }

    /// Build the execution.
    #[must_use]
    pub(crate) fn build(self) -> HookExecution {
        let now = Utc::now();
        HookExecution {
            hook_id: self.hook_id,
            invocation_id: self.invocation_id,
            started_at: now,
            completed_at: now,
            duration_ms: 0,
            result: self.result,
        }
    }
}

impl Default for HookExecutionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::HookEvent;

    #[tokio::test]
    async fn test_executor_disabled_hook() {
        let executor = HookExecutor::new();
        let hook = Hook::new(HookEvent::PreToolCall).disabled();
        let context = HookContext::new(HookEvent::PreToolCall);

        let execution = executor.execute(&hook, &context).await;

        assert!(matches!(
            execution.result,
            HookExecutionResult::Skipped { .. }
        ));
    }

    #[tokio::test]
    async fn test_executor_command_hook() {
        let executor = HookExecutor::new();
        let hook = Hook::new(HookEvent::PreToolCall)
            .with_handler(HookHandler::Command {
                command: "echo".to_string(),
                args: vec!["continue".to_string()],
                env: std::collections::HashMap::default(),
                working_dir: None,
            })
            .with_timeout(5);

        let context = HookContext::new(HookEvent::PreToolCall);

        let execution = executor.execute(&hook, &context).await;

        assert!(execution.result.is_success());
    }

    #[test]
    fn test_combine_results_continue() {
        let executions = vec![
            HookExecutionBuilder::new()
                .with_result(HookExecutionResult::Success {
                    result: HookResult::Continue,
                    stdout: None,
                })
                .build(),
            HookExecutionBuilder::new()
                .with_result(HookExecutionResult::Success {
                    result: HookResult::Continue,
                    stdout: None,
                })
                .build(),
        ];

        let combined = HookExecutor::combine_results(&executions);
        assert!(matches!(combined, HookResult::Continue));
    }

    #[test]
    fn test_combine_results_block_takes_precedence() {
        let executions = vec![
            HookExecutionBuilder::new()
                .with_result(HookExecutionResult::Success {
                    result: HookResult::Continue,
                    stdout: None,
                })
                .build(),
            HookExecutionBuilder::new()
                .with_result(HookExecutionResult::Success {
                    result: HookResult::Block {
                        reason: "blocked".to_string(),
                    },
                    stdout: None,
                })
                .build(),
        ];

        let combined = HookExecutor::combine_results(&executions);
        assert!(matches!(combined, HookResult::Block { .. }));
    }
}
