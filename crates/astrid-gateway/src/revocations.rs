//! Bearer revocation persistence + audit-event watcher.
//!
//! When an admin successfully deletes a principal, every outstanding
//! bearer for that principal must stop authenticating. The gateway's
//! bearers are stateless ed25519-signed tokens, so revocation lives
//! in this side-channel:
//!
//! 1. The bearer wire format carries an `iat` (issued-at) claim —
//!    see [`crate::auth`] for the format definition.
//! 2. This module maintains `principal → revoked_at_epoch` (the
//!    moment the principal was deleted).
//! 3. [`crate::auth::verify_bearer`] rejects any bearer whose `iat`
//!    is at-or-before the recorded epoch.
//!
//! Persistence: the map is written atomically to
//! `$ASTRID_HOME/etc/gateway-revocations.json` after every update.
//! On boot the gateway reads it back; a missing or empty file means
//! "no revocations yet". The audit log on disk is the kernel-owned
//! source of truth for *what happened*; this file is the
//! gateway-local index that turns those facts into a cheap O(1)
//! lookup on the verify hot path.
//!
//! Concurrency: writes are rare (admin deletes), reads are frequent
//! (every authenticated request). Backed by `std::sync::RwLock`; the
//! critical sections are non-`await`-blocking by construction.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use astrid_core::PrincipalId;

/// JSON file under `etc/` that mirrors the in-memory revocation map.
fn revocations_path() -> anyhow::Result<PathBuf> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .map_err(|e| anyhow::anyhow!("resolve $ASTRID_HOME for revocation file: {e}"))?;
    Ok(home.etc_dir().join("gateway-revocations.json"))
}

/// Hard cap on the on-disk revocation file. Each entry is ~50 bytes
/// of JSON; `10 MiB` lets us hold ~200k revocations which is well
/// past any realistic operator's lifetime. Acts as a `DoS` / `OOM`
/// guard against a malicious or corrupted file — without the cap, a
/// gigabyte-sized file would block the daemon's boot path inside
/// `read_to_string` while it allocates.
const MAX_REVOCATIONS_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Load the persisted revocation map. Returns an empty map if the
/// file doesn't exist yet (single-tenant default, fresh install).
///
/// # Errors
/// Returns an error if the file exists but is corrupt — refusing to
/// boot on a corrupt file is intentional, so an operator notices and
/// either restores from backup or deletes the file to start fresh.
pub fn load_from_disk() -> anyhow::Result<HashMap<PrincipalId, u64>> {
    let path = revocations_path()?;
    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(anyhow::anyhow!("stat {}: {e}", path.display())),
    };
    if metadata.len() > MAX_REVOCATIONS_FILE_BYTES {
        anyhow::bail!(
            "revocation file {} is {} bytes; refusing to load (cap is {} bytes — investigate disk pressure or a corrupted file)",
            path.display(),
            metadata.len(),
            MAX_REVOCATIONS_FILE_BYTES
        );
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", path.display())),
    };
    if text.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let raw: HashMap<String, u64> =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let mut out = HashMap::with_capacity(raw.len());
    for (k, v) in raw {
        let principal = PrincipalId::new(&k)
            .map_err(|e| anyhow::anyhow!("invalid principal {k:?} in revocation file: {e}"))?;
        out.insert(principal, v);
    }
    Ok(out)
}

/// Persist the revocation map atomically. Writes to `<path>.tmp.<uuid>`,
/// fsyncs, then renames into place — matches the durability pattern
/// in `state::SigningMaterial::load_or_generate`. A crash between
/// `write` and `rename` leaves the temp file behind (cleaned up by
/// the next operator-initiated daemon restart) but never produces
/// a half-written `gateway-revocations.json`.
///
/// Blocking I/O: callers from async contexts should wrap this in
/// `tokio::task::spawn_blocking` — the watcher in this module does.
#[allow(clippy::implicit_hasher)] // map shape is internal to this module; no generic hasher
pub fn persist(map: &HashMap<PrincipalId, u64>) -> anyhow::Result<()> {
    let path = revocations_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }
    let raw: HashMap<String, u64> = map.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let text = serde_json::to_string_pretty(&raw).context("serialise revocation map")?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4().simple()));
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(text.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        // fsync so a power loss between write+rename can't produce a
        // 0-byte revocation file on next boot.
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Spawn the audit-event watcher. Subscribes to the kernel's audit
/// topic and updates the revocation map whenever a successful
/// `AgentDelete` admin op lands. Detached: terminates when the bus
/// is dropped (i.e. daemon shutdown), so no explicit join is needed.
///
/// `bus` is the kernel's shared event bus; `revoked_at` is the same
/// `Arc<RwLock<…>>` held by [`crate::state::GatewayState`] so writes
/// here become visible to every in-flight verify call.
///
/// # Panics
/// The spawned task panics if the revocation map's `RwLock` is
/// poisoned. Same fail-stop posture as the verify path — a poisoned
/// lock means an earlier writer crashed mid-update, and continuing
/// against an undefined snapshot is worse than dropping the task.
#[allow(clippy::implicit_hasher)] // map shape is internal to this module
pub fn spawn_watcher(
    bus: Arc<astrid_events::EventBus>,
    revoked_at: Arc<RwLock<HashMap<PrincipalId, u64>>>,
) {
    tokio::spawn(async move {
        let mut receiver =
            bus.subscribe_topic_as(crate::routes::events::AUDIT_TOPIC, "revocation_watcher");
        while let Some(event) = receiver.recv().await {
            let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            let astrid_events::ipc::IpcPayload::RawJson(val) = &message.payload else {
                continue;
            };
            // The kernel publishes the dotted wire-name from `admin_request_method`
            // (`admin.agent.delete`), NOT the PascalCase enum variant — matching
            // the variant name here meant the watcher never fired in production.
            if val.get("method").and_then(serde_json::Value::as_str) != Some("admin.agent.delete") {
                continue;
            }
            if val.get("outcome").and_then(serde_json::Value::as_str) != Some("success") {
                continue;
            }
            let Some(target) = val
                .get("target_principal")
                .and_then(serde_json::Value::as_str)
            else {
                tracing::warn!(
                    audit = ?val,
                    "AgentDelete audit event missing target_principal — cannot revoke"
                );
                continue;
            };
            let Ok(principal) = PrincipalId::new(target) else {
                tracing::warn!(
                    target = %target,
                    "AgentDelete audit event carries invalid principal id"
                );
                continue;
            };
            // `ts_epoch` from the audit envelope is authoritative —
            // using wall-clock `now()` here would race the audit
            // publish if the gateway clock drifted from the kernel's.
            let ts_epoch = val
                .get("ts_epoch")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs())
                });

            let snapshot = {
                let mut guard = revoked_at
                    .write()
                    .expect("revocation map poisoned — fail-stop");
                // Idempotent: a duplicate AgentDelete event (or a
                // retry from a flaky subscriber) won't move the
                // epoch backward.
                let prev = guard.get(&principal).copied().unwrap_or(0);
                if ts_epoch <= prev {
                    continue;
                }
                guard.insert(principal.clone(), ts_epoch);
                guard.clone()
            };

            // `persist` does sync I/O (fsync + rename); offload it to
            // the blocking-IO threadpool so a slow disk doesn't stall
            // the tokio worker that owns this watcher task.
            let principal_for_log = principal.clone();
            let persist_result = tokio::task::spawn_blocking(move || persist(&snapshot)).await;
            match persist_result {
                Ok(Ok(())) => {
                    tracing::info!(
                        principal = %principal_for_log,
                        revoked_at_epoch = ts_epoch,
                        "bearer revocation recorded"
                    );
                },
                Ok(Err(e)) => {
                    // Persistence failures degrade to in-memory only — the
                    // revocation still applies for this daemon's lifetime.
                    // Logging is the operator's signal that the file write
                    // path needs attention.
                    tracing::error!(
                        error = %e,
                        principal = %principal_for_log,
                        "failed to persist gateway revocation — keeping in-memory; investigate disk health"
                    );
                },
                Err(join_err) => {
                    tracing::error!(
                        error = %join_err,
                        principal = %principal_for_log,
                        "revocation persistence task panicked"
                    );
                },
            }
        }
    });
}

/// Spawn the per-device bearer-revocation watcher. Subscribes to the kernel's
/// audit topic and adds a device's `key_id` to `revoked_key_ids` whenever a
/// successful `admin.auth.pair.revoke` admin op lands, so a live device-scoped
/// bearer is rejected at the HTTP edge immediately (the kernel cap-gate already
/// fails it closed — this is defense in depth on the bearer).
///
/// Detached: terminates when the bus is dropped (daemon shutdown). In-memory
/// only — a revoked key never needs to survive a restart because the profile
/// it was removed from is the source of truth and the bearer's TTL bounds the
/// window regardless.
///
/// # Panics
/// Panics if the `revoked_key_ids` `RwLock` is poisoned — same fail-stop
/// posture as the verify path.
#[allow(clippy::implicit_hasher)] // map shape is internal to this module
pub fn spawn_key_revocation_watcher(
    bus: Arc<astrid_events::EventBus>,
    revoked_key_ids: Arc<RwLock<std::collections::HashMap<String, u64>>>,
) {
    tokio::spawn(async move {
        let mut receiver =
            bus.subscribe_topic_as(crate::routes::events::AUDIT_TOPIC, "key_revocation_watcher");
        while let Some(event) = receiver.recv().await {
            let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            let astrid_events::ipc::IpcPayload::RawJson(val) = &message.payload else {
                continue;
            };
            // The top-level `method` is the kernel's wire-name for the op (see
            // `admin_request_method`). Only successful device revocations evict.
            if val.get("method").and_then(serde_json::Value::as_str)
                != Some("admin.auth.pair.revoke")
            {
                continue;
            }
            if val.get("outcome").and_then(serde_json::Value::as_str) != Some("success") {
                continue;
            }
            // `key_id` lives in the sanitized request params (a non-secret
            // fingerprint, recorded verbatim): `params.params.key_id`.
            let Some(key_id) = val
                .get("params")
                .and_then(|p| p.get("params"))
                .and_then(|p| p.get("key_id"))
                .and_then(serde_json::Value::as_str)
            else {
                tracing::warn!(
                    audit = ?val,
                    "pair-device revoke audit event missing key_id — cannot evict bearer"
                );
                continue;
            };
            // `ts_epoch` from the audit envelope is the revocation moment; a
            // bearer minted at-or-before it is dead, one minted after a re-pair
            // survives. Mirrors the principal-level `AgentDelete` watcher.
            let ts_epoch = val
                .get("ts_epoch")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs())
                });
            {
                let mut guard = revoked_key_ids
                    .write()
                    .expect("revoked-key-id map poisoned — fail-stop");
                // Idempotent: a duplicate / replayed revoke event must not move
                // the epoch backward (which could resurrect a dead bearer).
                let prev = guard.get(key_id).copied().unwrap_or(0);
                if ts_epoch > prev {
                    guard.insert(key_id.to_string(), ts_epoch);
                }
            }
            tracing::info!(key_id = %key_id, revoked_at_epoch = ts_epoch, "device bearer revocation recorded");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn empty_map_round_trips() {
        let map: HashMap<PrincipalId, u64> = HashMap::new();
        // Round-trip the serialisation only (not the disk path — that
        // depends on $ASTRID_HOME and is exercised in integration).
        let text = serde_json::to_string(
            &map.iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect::<HashMap<String, u64>>(),
        )
        .unwrap();
        assert_eq!(text, "{}");
    }

    #[test]
    fn map_serialises_with_string_keys() {
        let mut map = HashMap::new();
        map.insert(PrincipalId::new("alice").unwrap(), 1_700_000_000_u64);
        let raw: HashMap<String, u64> = map.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let text = serde_json::to_string(&raw).unwrap();
        assert!(text.contains("\"alice\""));
        assert!(text.contains("1700000000"));
    }

    #[tokio::test]
    async fn watcher_records_agent_delete_event() {
        let bus = Arc::new(astrid_events::EventBus::new());
        let revoked_at: Arc<RwLock<HashMap<PrincipalId, u64>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Spawn the watcher BEFORE publishing — broadcast channels
        // don't replay history to late subscribers.
        let bus_clone = Arc::clone(&bus);
        let revoked_clone = Arc::clone(&revoked_at);
        spawn_watcher_no_persist(bus_clone, revoked_clone);

        // Give the watcher a tick to subscribe.
        tokio::task::yield_now().await;

        let event = serde_json::json!({
            "ts_epoch": 1_700_000_500_u64,
            "method": "admin.agent.delete",
            "required_capability": "self:agent:delete",
            "principal": "admin",
            "target_principal": "alice",
            "params": {},
            "outcome": "success",
        });
        let msg = astrid_events::ipc::IpcMessage::new(
            crate::routes::events::AUDIT_TOPIC,
            astrid_events::ipc::IpcPayload::RawJson(event),
            uuid::Uuid::nil(),
        )
        .with_principal("admin".to_string());
        let _ = bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("test"),
            message: msg,
        });

        // Wait for the watcher to process — a short yield loop is
        // enough here; if the event never lands, the assertion fails.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if revoked_at
                .read()
                .expect("read")
                .contains_key(&PrincipalId::new("alice").unwrap())
            {
                break;
            }
        }

        let guard = revoked_at.read().expect("read");
        assert_eq!(
            guard.get(&PrincipalId::new("alice").unwrap()).copied(),
            Some(1_700_000_500),
            "AgentDelete should record alice's epoch"
        );
    }

    /// Test-only watcher that skips disk persistence — unit tests
    /// don't bind a real `$ASTRID_HOME` and we want the assertion
    /// to be about the in-memory map shape, not the file system.
    fn spawn_watcher_no_persist(
        bus: Arc<astrid_events::EventBus>,
        revoked_at: Arc<RwLock<HashMap<PrincipalId, u64>>>,
    ) {
        tokio::spawn(async move {
            let mut receiver =
                bus.subscribe_topic_as(crate::routes::events::AUDIT_TOPIC, "revocation_watcher");
            while let Some(event) = receiver.recv().await {
                let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                    continue;
                };
                let astrid_events::ipc::IpcPayload::RawJson(val) = &message.payload else {
                    continue;
                };
                if val.get("method").and_then(serde_json::Value::as_str)
                    != Some("admin.agent.delete")
                    || val.get("outcome").and_then(serde_json::Value::as_str) != Some("success")
                {
                    continue;
                }
                let Some(target) = val
                    .get("target_principal")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Ok(principal) = PrincipalId::new(target) else {
                    continue;
                };
                let ts_epoch = val
                    .get("ts_epoch")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let mut guard = revoked_at.write().expect("write");
                guard.insert(principal, ts_epoch);
            }
        });
    }
}
