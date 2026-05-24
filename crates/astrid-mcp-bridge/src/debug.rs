//! File-based debug logging.
//!
//! Claude Code swallows MCP subprocess stderr, and we haven't set up
//! a `tracing_subscriber` in `run_stdio` (no good default for a
//! stdio-talking process — anything we write to stderr risks
//! interleaving with rmcp's framing). So during the v1 debug phase
//! we append to a file the user can `tail -f` from a separate
//! terminal.
//!
//! Set `ASTRID_BRIDGE_DEBUG=0` (or any non-"1" value) to disable.
//! Default path: `/tmp/astrid-bridge.log`. Override with
//! `ASTRID_BRIDGE_LOG_PATH=/some/other/path`.

use std::fmt::Arguments;
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static ENABLED: OnceLock<bool> = OnceLock::new();
static PATH: OnceLock<String> = OnceLock::new();

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var("ASTRID_BRIDGE_DEBUG")
            .map(|v| v != "0" && !v.is_empty())
            .unwrap_or(true) // default ON during v1 debug phase
    })
}

fn path() -> &'static str {
    PATH.get_or_init(|| {
        std::env::var("ASTRID_BRIDGE_LOG_PATH")
            .unwrap_or_else(|_| "/tmp/astrid-bridge.log".into())
    })
}

/// Append one timestamped line to the bridge debug log.
pub fn log(args: Arguments<'_>) {
    if !enabled() {
        return;
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path())
    else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let ms = now.subsec_millis();
    let _ = writeln!(f, "[{secs}.{ms:03}] {args}");
}
