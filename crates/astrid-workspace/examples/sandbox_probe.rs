//! Verification probe for the #655 sandbox-policy fix.
//!
//! Builds a `ProcessSandboxConfig` and calls `sandbox_prefix()`,
//! reporting which arm of the policy enum fired so the verification
//! shell script can grep the output.
//!
//! Run via:
//!     cargo run --example `sandbox_probe` -- [`WRITABLE_ROOT`]
//!
//! Reads `ASTRID_SANDBOX_POLICY` from the env to exercise both the
//! default (`Required`) path and the explicit `off` override.

use astrid_workspace::ProcessSandboxConfig;

#[allow(clippy::unnecessary_debug_formatting)]
fn main() {
    let writable = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/astrid-probe".to_string());
    let _ = std::fs::create_dir_all(&writable);

    let env_policy =
        std::env::var("ASTRID_SANDBOX_POLICY").unwrap_or_else(|_| "<unset>".to_string());
    println!("== ASTRID_SANDBOX_POLICY = {env_policy} ==");
    println!("== writable_root = {writable} ==");

    let cfg = ProcessSandboxConfig::new(&writable);
    match cfg.sandbox_prefix() {
        Ok(Some(prefix)) => {
            println!("RESULT: Ok(Some) — sandboxed");
            println!("  program: {:?}", prefix.program);
            println!("  arg_count: {}", prefix.args.len());
            println!("  first_args:");
            for arg in prefix.args.iter().take(4) {
                println!("    {arg:?}");
            }
        },
        Ok(None) => {
            println!("RESULT: Ok(None) — no sandbox applied");
            println!("  cause: policy=off, platform unsupported, or macOS Seatbelt unreachable");
        },
        Err(e) => {
            println!("RESULT: Err — refused to launch");
            println!("  message: {e}");
        },
    }
}
