//! Commands for managing Astrid sessions.

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;
use colored::Colorize;
use std::fs;

use crate::theme::Theme;

/// List all session directories under `run/`.
pub(crate) fn list_sessions() -> Result<()> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    let sessions_dir = home.run_dir();

    if !sessions_dir.exists() {
        println!("{}", Theme::info("No active sessions found."));
        return Ok(());
    }

    let mut sessions = Vec::new();
    for entry in fs::read_dir(sessions_dir)? {
        let entry = entry?;
        if entry.metadata()?.is_dir()
            && let Some(name) = entry.file_name().to_str()
        {
            // If it looks like a UUID, count it as a session
            if uuid::Uuid::parse_str(name).is_ok() {
                let modified = entry.metadata()?.modified()?;
                sessions.push((name.to_string(), modified));
            }
        }
    }

    if sessions.is_empty() {
        println!("{}", Theme::info("No active sessions found."));
        return Ok(());
    }

    sessions.sort_by(|a, b| b.1.cmp(&a.1));

    println!("{}", "Active Sessions:".bold());
    for (id, modified) in sessions {
        let time = chrono::DateTime::<chrono::Local>::from(modified)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        println!("  {} ({})", Theme::session_id(&id), Theme::dimmed(&time));
    }

    Ok(())
}

/// Delete a session by UUID.
pub(crate) fn delete_session(id: &str) -> Result<()> {
    // Validate as UUID to prevent path traversal (e.g. "../../config")
    uuid::Uuid::parse_str(id)
        .map_err(|_| anyhow::anyhow!("Invalid session ID (must be a UUID): {id}"))?;
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    let session_dir = home.run_dir().join(id);

    if !session_dir.exists() {
        anyhow::bail!("Session not found: {id}");
    }

    fs::remove_dir_all(&session_dir)?;
    println!("{}", Theme::success(&format!("Deleted session {id}")));
    Ok(())
}

/// Show information about a session by UUID.
pub(crate) fn session_info(id: &str) -> Result<()> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| anyhow::anyhow!("Invalid session ID (must be a UUID): {id}"))?;
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    let session_dir = home.run_dir().join(id);

    if !session_dir.exists() {
        anyhow::bail!("Session not found: {id}");
    }

    println!("{}", "Session Information".bold());
    println!("  ID: {}", Theme::session_id(id));

    // The global daemon socket path — shows daemon health, not session-specific status.
    let sock_path = home.socket_path();
    if sock_path.exists() {
        println!("  Daemon: {}", "Running".green());
    } else {
        println!("  Daemon: {}", "Not Running".yellow());
    }

    Ok(())
}
