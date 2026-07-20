//! `astrid capsule check` — a static, CI-friendly capsule linter.
//!
//! Cross-checks a capsule project's `#[astrid::tool]` annotations (the tools it
//! *advertises*) against its `Capsule.toml` `[subscribe]`/`[publish]` tables (how
//! the kernel actually *routes*), catching wiring mistakes that otherwise fail
//! silently at runtime — a tool that advertises but never executes, results that
//! can never return, a subscription with no matching tool, a mistyped handler.
//!
//! It is deliberately **static**: it derives the advertised-tool set from source
//! (`#[astrid::tool("…")]`), not by instantiating the WASM component, so it needs
//! no daemon, no WASM runtime, and no `ASTRID_HOME`. That makes it a fast,
//! deterministic, side-effect-free CI gate (non-zero exit on any finding) —
//! `cargo check` for capsules. An authoritative `--deep` mode (ephemeral-load +
//! the real `tool_describe`, reusing the load-time check) is a later addition.
//!
//! Check #1 (advertised-but-unrouted) reuses the exact
//! [`astrid_capsule::tools_missing_execute_route`] predicate the kernel's
//! load-time warning uses, so the CI check and the runtime can never disagree.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_capsule::ToolDescriptor;
use astrid_capsule::manifest::{CapsuleManifest, InterceptorDef};
use syn::visit::Visit;
use syn::{Attribute, Expr, Lit, Token, punctuated::Punctuated};

use crate::theme::Theme;

/// Topic prefix for a tool invocation (`tool.v1.execute.<name>`). Kept in step
/// with the same constant in `astrid-capsule` — the topic scheme is stable, and
/// this is the CLI's own parse of an author's manifest.
const TOOL_EXECUTE_PREFIX: &str = "tool.v1.execute.";

/// The `[publish]` entries every tool capsule must declare: without the result
/// pattern tool results never return, and without the describe pattern the
/// describe fan-out can't answer. Paired with the `wit` reference to suggest.
const MANDATORY_PUBLISH: &[(&str, &str, &str)] = &[
    (
        "tool.v1.execute.*.result",
        "@unicity-astrid/wit/types/tool-call-result",
        "tool results can never return to the caller",
    ),
    (
        "tool.v1.response.describe.*",
        "@unicity-astrid/wit/tool/describe-response",
        "the tool describe fan-out cannot answer",
    ),
];

/// A single problem found by the linter. Every finding is an error (it maps to a
/// runtime failure), so any finding fails the check.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    /// Short machine-readable rule id (shown in the report).
    rule: &'static str,
    /// Human-readable description, ending with the concrete fix.
    message: String,
}

/// Entry point for `astrid capsule check [PATH]`. Returns a non-zero
/// [`ExitCode`] when any problem is found, so it gates a CI job or pre-commit
/// hook without extra glue.
pub(crate) fn run(path: Option<&str>) -> Result<ExitCode> {
    let dir = match path {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir().context("resolving the current directory")?,
    };

    let manifest_path = dir.join("Capsule.toml");
    if !manifest_path.exists() {
        anyhow::bail!(
            "no Capsule.toml in {} — run `astrid capsule check` from a capsule project directory \
             (or pass its path)",
            dir.display()
        );
    }
    let raw = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: CapsuleManifest =
        toml::from_str(&raw).with_context(|| format!("parsing {}", manifest_path.display()))?;

    let tool_names = scan_tool_annotations(&dir.join("src"))?;
    let interceptors = manifest.effective_interceptors();
    let publishes = manifest.effective_ipc_publish_patterns();

    let findings = check_capsule(&tool_names, &interceptors, &publishes);

    print_report(tool_names.len(), &findings);
    Ok(if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Run every rule over the extracted project facts. Pure over its inputs — the
/// advertised tool names (from source), the manifest's interceptor routes
/// (`[subscribe]` handlers), and its publish patterns — so the whole ruleset is
/// unit-testable without a filesystem or a live capsule.
fn check_capsule(
    tool_names: &[String],
    interceptors: &[InterceptorDef],
    publish_patterns: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Rule 1: a tool is advertised (`#[astrid::tool]`) but no `[subscribe]`
    // routes its execute topic — it will appear in tools/list yet never run.
    // Reuse the exact predicate the kernel's load-time warning uses.
    let descriptors: Vec<ToolDescriptor> = tool_names
        .iter()
        .map(|name| ToolDescriptor {
            name: name.clone(),
            description: String::new(),
            input_schema: serde_json::Value::Null,
        })
        .collect();
    for name in astrid_capsule::tools_missing_execute_route(&descriptors, interceptors) {
        findings.push(Finding {
            rule: "unrouted-tool",
            message: format!(
                "tool `{name}` is declared with #[astrid::tool] but has no \
                 `tool.v1.execute.{name}` subscription — it will advertise in tools/list but \
                 never execute. Add to Capsule.toml:\n      [subscribe]\n      \
                 \"tool.v1.execute.{name}\" = {{ wit = \"@unicity-astrid/wit/types/tool-call\", \
                 handler = \"tool_execute_{name}\" }}"
            ),
        });
    }

    // Rule 2: a tool capsule missing the mandatory `[publish]` boilerplate.
    if !tool_names.is_empty() {
        for (pattern, wit, consequence) in MANDATORY_PUBLISH {
            if !publish_patterns.iter().any(|p| p == pattern) {
                findings.push(Finding {
                    rule: "missing-publish",
                    message: format!(
                        "missing mandatory `[publish]` entry `{pattern}` — without it \
                         {consequence}. Add to Capsule.toml:\n      [publish]\n      \
                         \"{pattern}\" = {{ wit = \"{wit}\" }}"
                    ),
                });
            }
        }
    }

    // Rules 3 & 4: inspect each exact `tool.v1.execute.<name>` subscription.
    for def in interceptors {
        let Some(segment) = def.event.strip_prefix(TOOL_EXECUTE_PREFIX) else {
            continue;
        };
        // Only bare single-segment tool topics. Skip wildcards, multi-segment
        // per-tool result topics (`<name>.result`), and the reserved bare
        // `result` delivery topic — none of those name a tool.
        if segment.is_empty()
            || segment.contains('.')
            || segment.contains('*')
            || segment == "result"
        {
            continue;
        }

        if tool_names.iter().any(|n| n == segment) {
            // Rule 4: the subscription routes and the tool exists, but the
            // handler must be the macro-generated `tool_execute_<name>` or the
            // guest denies the unknown action after routing.
            let expected = format!("tool_execute_{segment}");
            if def.action != expected {
                findings.push(Finding {
                    rule: "handler-mismatch",
                    message: format!(
                        "`[subscribe] \"tool.v1.execute.{segment}\"` handler is `{}` but must be \
                         `{expected}` — the macro-generated handler name. The call routes but the \
                         guest denies the unknown action, so the tool never runs.",
                        def.action
                    ),
                });
            }
        } else {
            // Rule 3: a tool-execute subscription with no matching tool — a typo
            // or a tool that was removed without its route.
            findings.push(Finding {
                rule: "dangling-subscription",
                message: format!(
                    "`[subscribe] \"tool.v1.execute.{segment}\"` has no matching \
                     #[astrid::tool(\"{segment}\")] — a typo or a removed tool. Fix the name or \
                     drop the subscription."
                ),
            });
        }
    }

    // Deterministic output: interceptor/publish tables are HashMap-backed and
    // the source scan follows filesystem order, so sort by (rule, message)
    // before returning — a CI gate must not emit findings in a flaky order.
    findings.sort_by(|a, b| a.rule.cmp(b.rule).then_with(|| a.message.cmp(&b.message)));
    findings
}

/// Print the check report and a one-line summary.
fn print_report(tool_count: usize, findings: &[Finding]) {
    if findings.is_empty() {
        // `Theme::success`/`error` already prepend the ✓/✗ marker.
        println!(
            "{}",
            Theme::success(&format!(
                "capsule check passed — {tool_count} tool(s), all wired"
            ))
        );
        return;
    }
    for finding in findings {
        println!(
            "{}",
            Theme::error(&format!("{}: {}", finding.rule, finding.message))
        );
    }
    println!(
        "{}",
        Theme::error(&format!(
            "{} problem(s) found — fix the above and re-run `astrid capsule check`",
            findings.len()
        ))
    );
}

/// Collect the tool names declared by `#[astrid::tool("…")]` under `src_dir`.
///
/// Static source scan (no build): recurses `src/`, reads each `.rs` file, and
/// extracts the first string argument of each `astrid::tool(` attribute. A
/// source read or parse failure aborts the check: silently returning a partial
/// tool inventory would let wiring errors pass CI.
fn scan_tool_annotations(src_dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for path in rs_files(src_dir)? {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading Rust source {}", path.display()))?;
        for name in tool_names_in_source(&content)
            .with_context(|| format!("parsing Rust source {}", path.display()))?
        {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Recursively collect `.rs` file paths under `dir` (iterative, so a deep tree
/// can't blow the stack). A missing source directory yields no files, while an
/// unreadable directory or entry fails the scan rather than returning a
/// partial inventory.
///
/// Uses `entry.file_type()` rather than `path.is_dir()`: `file_type` does NOT
/// follow symlinks, so a symlinked directory is never recursed into — which also
/// makes a symlink loop (a link pointing at an ancestor) impossible to follow, so
/// the scan can't spin forever / OOM on a hostile or accidental link cycle.
fn rs_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .with_context(|| format!("reading Rust source directory {}", d.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!("reading an entry in Rust source directory {}", d.display())
            })?;
            let file_type = entry
                .file_type()
                .with_context(|| format!("reading file type for {}", entry.path().display()))?;
            let p = entry.path();
            if file_type.is_dir() {
                stack.push(p);
            } else if file_type.is_file() && p.extension().is_some_and(|ext| ext == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Parse Rust syntax and collect literal names from live
/// `#[astrid::tool("name")]` attributes.
///
/// Parsing the syntax tree is important here: Forge and other authoring tools
/// embed example Rust source in string literals. A text scan mistakes those
/// examples for executable attributes and reports phantom unrouted tools.
fn tool_names_in_source(source: &str) -> syn::Result<Vec<String>> {
    let file = syn::parse_file(source)?;
    let mut visitor = ToolAttributeVisitor::default();
    visitor.visit_file(&file);
    Ok(visitor.names)
}

#[derive(Default)]
struct ToolAttributeVisitor {
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for ToolAttributeVisitor {
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        let mut segments = attribute.path().segments.iter();
        let is_tool = segments
            .next()
            .is_some_and(|segment| segment.ident == "astrid")
            && segments
                .next()
                .is_some_and(|segment| segment.ident == "tool")
            && segments.next().is_none();
        if !is_tool {
            return;
        }

        let Ok(arguments) =
            attribute.parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        else {
            return;
        };
        let Some(Expr::Lit(literal)) = arguments.first() else {
            return;
        };
        let Lit::Str(name) = &literal.lit else {
            return;
        };
        let name = name.value();
        if !name.is_empty() {
            self.names.push(name);
        }
    }
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
