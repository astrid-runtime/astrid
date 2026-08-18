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
//! Persistence: principal and device epochs live in the fixed system control
//! KV namespace [`REVOCATION_NAMESPACE`]. Updates use compare-and-swap/max
//! semantics so concurrent gateway instances cannot move an epoch backwards.
//! The old `etc/gateway-revocations.json` is accepted only as an explicit,
//! one-time migration source and is removed after durable KV read-back.
//!
//! Concurrency: writes are rare (admin deletes), reads are frequent
//! (every authenticated request). Backed by `std::sync::RwLock`; the
//! critical sections are non-`await`-blocking by construction.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use astrid_core::PrincipalId;
use astrid_storage::KvStore;

/// Fixed host-only control namespace. Capsules never receive this scope.
pub const REVOCATION_NAMESPACE: &str = "system:gateway:revocations";
const PRINCIPAL_PREFIX: &str = "principal/";
const DEVICE_PREFIX: &str = "device/";
const MIGRATION_RECEIPT_KEY: &str = "migration/legacy-json-v1";
const MAX_REVOCATION_ENTRIES: usize = 1_000_000;

/// Released JSON file under `etc/`, retained only as a one-time migration
/// source. Runtime authority is the system control KV namespace above.
fn revocations_path() -> anyhow::Result<PathBuf> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .map_err(|e| anyhow::anyhow!("resolve $ASTRID_HOME for revocation file: {e}"))?;
    Ok(home.etc_dir().join("gateway-revocations.json"))
}

/// Whether the released JSON index exists. Used only to fail closed when a
/// standalone gateway has no authoritative KV wiring during startup.
pub fn legacy_file_exists() -> anyhow::Result<bool> {
    let path = revocations_path()?;
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                anyhow::bail!(
                    "legacy gateway revocation path is not a regular file: {}",
                    path.display()
                );
            }
            Ok(true)
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow::anyhow!("inspect legacy revocation file: {error}")),
    }
}

/// Hard cap on the legacy migration file. Each entry is ~50 bytes of JSON;
/// `10 MiB` gives migration ample room without permitting an unbounded boot
/// allocation from a corrupted or hostile operator file.
const MAX_REVOCATIONS_FILE_BYTES: u64 = 10 * 1024 * 1024;

fn read_legacy_bytes(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open legacy revocation file {}", path.display()))?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)
        .with_context(|| format!("open legacy revocation file {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_REVOCATIONS_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read legacy revocation file {}", path.display()))?;
    if bytes.len() as u64 > MAX_REVOCATIONS_FILE_BYTES {
        anyhow::bail!("legacy revocation file exceeds migration cap");
    }
    Ok(bytes)
}

fn decode_epoch(bytes: &[u8], key: &str) -> anyhow::Result<u64> {
    let raw: [u8; 8] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "revocation KV value for {key:?} has {} bytes; expected 8",
            bytes.len()
        )
    })?;
    Ok(u64::from_le_bytes(raw))
}

fn encode_epoch(epoch: u64) -> Vec<u8> {
    epoch.to_le_bytes().to_vec()
}

/// Record the maximum principal revocation epoch durably. The returned value
/// is the epoch now authoritative in storage (which may be newer than the
/// requested event when another writer won the CAS race).
pub async fn record_principal_max(
    store: &dyn KvStore,
    principal: &PrincipalId,
    epoch: u64,
) -> anyhow::Result<u64> {
    let key = format!("{PRINCIPAL_PREFIX}{principal}");
    loop {
        let current = store
            .get(REVOCATION_NAMESPACE, &key)
            .await
            .map_err(|error| anyhow::anyhow!("read principal revocation {principal}: {error}"))?;
        let current_epoch = current
            .as_deref()
            .map(|bytes| decode_epoch(bytes, &key))
            .transpose()?;
        let wanted = current_epoch.map_or(epoch, |current| current.max(epoch));
        if current_epoch == Some(wanted) {
            return Ok(wanted);
        }
        match store
            .compare_and_swap(
                REVOCATION_NAMESPACE,
                &key,
                current.as_deref(),
                encode_epoch(wanted),
            )
            .await
        {
            Ok(true) => return Ok(wanted),
            Ok(false) => {},
            Err(cas_error) => {
                // A successful delete must never become reversible merely
                // because the monotonic CAS path is unavailable. Persist an
                // unconditional maximum-epoch tombstone: this intentionally
                // sacrifices alias reuse until operator repair, but it is
                // monotonic under every concurrent writer and survives a
                // restart. If the fallback write also fails, propagate the
                // durability loss to the watcher as before.
                store
                    .set(REVOCATION_NAMESPACE, &key, encode_epoch(u64::MAX))
                    .await
                    .map_err(|fallback_error| {
                        anyhow::anyhow!(
                            "write principal revocation {principal}: CAS failed: {cas_error}; fail-closed tombstone failed: {fallback_error}"
                        )
                    })?;
                return Ok(u64::MAX);
            },
        }
    }
}

/// Record the maximum device revocation epoch durably using the same CAS/max
/// rule as principal revocations.
pub async fn record_device_max(
    store: &dyn KvStore,
    key_id: &str,
    epoch: u64,
) -> anyhow::Result<u64> {
    if key_id.is_empty() || key_id.contains('/') {
        anyhow::bail!("invalid device revocation key id");
    }
    let key = format!("{DEVICE_PREFIX}{key_id}");
    loop {
        let current = store
            .get(REVOCATION_NAMESPACE, &key)
            .await
            .map_err(|error| anyhow::anyhow!("read device revocation {key_id}: {error}"))?;
        let current_epoch = current
            .as_deref()
            .map(|bytes| decode_epoch(bytes, &key))
            .transpose()?;
        let wanted = current_epoch.map_or(epoch, |current| current.max(epoch));
        if current_epoch == Some(wanted) {
            return Ok(wanted);
        }
        match store
            .compare_and_swap(
                REVOCATION_NAMESPACE,
                &key,
                current.as_deref(),
                encode_epoch(wanted),
            )
            .await
        {
            Ok(true) => return Ok(wanted),
            Ok(false) => {},
            Err(cas_error) => {
                // Same fail-closed durability rule as principal deletion.
                // MAX cannot be moved backward by a later CAS writer, so a
                // persistence-path fault cannot resurrect this device bearer
                // after restart.
                store
                    .set(REVOCATION_NAMESPACE, &key, encode_epoch(u64::MAX))
                    .await
                    .map_err(|fallback_error| {
                        anyhow::anyhow!(
                            "write device revocation {key_id}: CAS failed: {cas_error}; fail-closed tombstone failed: {fallback_error}"
                        )
                    })?;
                return Ok(u64::MAX);
            },
        }
    }
}

/// Load all durable principal and device epochs from the fixed control
/// namespace. Every key/value is bounded and validated before publication.
pub async fn load_from_store(
    store: &dyn KvStore,
) -> anyhow::Result<(HashMap<PrincipalId, u64>, HashMap<String, u64>)> {
    let principal_keys = store
        .list_keys_with_prefix(REVOCATION_NAMESPACE, PRINCIPAL_PREFIX)
        .await
        .map_err(|error| anyhow::anyhow!("list principal revocations: {error}"))?;
    let device_keys = store
        .list_keys_with_prefix(REVOCATION_NAMESPACE, DEVICE_PREFIX)
        .await
        .map_err(|error| anyhow::anyhow!("list device revocations: {error}"))?;
    if principal_keys.len().saturating_add(device_keys.len()) > MAX_REVOCATION_ENTRIES {
        anyhow::bail!("gateway revocation namespace exceeds entry cap");
    }
    let mut principals = HashMap::with_capacity(principal_keys.len());
    for key in principal_keys {
        let alias = key
            .strip_prefix(PRINCIPAL_PREFIX)
            .filter(|alias| !alias.is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid principal revocation key {key:?}"))?;
        let principal = PrincipalId::new(alias).map_err(|error| {
            anyhow::anyhow!("invalid principal revocation key {key:?}: {error}")
        })?;
        let value = store
            .get(REVOCATION_NAMESPACE, &key)
            .await
            .map_err(|error| anyhow::anyhow!("read principal revocation {key:?}: {error}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("principal revocation {key:?} disappeared during load")
            })?;
        principals.insert(principal, decode_epoch(&value, &key)?);
    }
    let mut devices = HashMap::with_capacity(device_keys.len());
    for key in device_keys {
        let key_id = key
            .strip_prefix(DEVICE_PREFIX)
            .filter(|key_id| !key_id.is_empty() && !key_id.contains('/'))
            .ok_or_else(|| anyhow::anyhow!("invalid device revocation key {key:?}"))?;
        let value = store
            .get(REVOCATION_NAMESPACE, &key)
            .await
            .map_err(|error| anyhow::anyhow!("read device revocation {key:?}: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("device revocation {key:?} disappeared during load"))?;
        devices.insert(key_id.to_owned(), decode_epoch(&value, &key)?);
    }
    Ok((principals, devices))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyMigrationReceipt {
    schema: u8,
    digest: String,
    principal_count: usize,
}

/// Import the released JSON index into durable KV, verify read-back, write a
/// receipt, and retire the legacy file. This is called only during explicit
/// gateway startup migration; runtime updates never touch `etc/`.
pub async fn migrate_legacy_file(store: &dyn KvStore) -> anyhow::Result<bool> {
    let path = revocations_path()?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(anyhow::anyhow!("stat {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "legacy gateway revocation path is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_REVOCATIONS_FILE_BYTES {
        anyhow::bail!("legacy revocation file exceeds migration cap");
    }
    let bytes = read_legacy_bytes(&path)?;
    let text = std::str::from_utf8(&bytes).context("legacy revocation file is not UTF-8")?;
    let raw: HashMap<String, u64> = if text.trim().is_empty() {
        HashMap::new()
    } else {
        serde_json::from_str(text).with_context(|| format!("parse {}", path.display()))?
    };
    if raw.len() > MAX_REVOCATION_ENTRIES {
        anyhow::bail!("legacy revocation file exceeds entry cap");
    }
    let digest = blake3::hash(&bytes).to_hex().to_string();
    let entries = raw
        .into_iter()
        .map(|(alias, epoch)| {
            PrincipalId::new(&alias)
                .map(|principal| (principal, epoch))
                .map_err(|error| anyhow::anyhow!("invalid principal {alias:?}: {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    for (principal, epoch) in &entries {
        record_principal_max(store, principal, *epoch).await?;
    }
    let (principals, _) = load_from_store(store).await?;
    for (principal, epoch) in &entries {
        let durable = principals.get(principal).copied().ok_or_else(|| {
            anyhow::anyhow!("principal revocation {principal} missing after migration")
        })?;
        if durable < *epoch {
            anyhow::bail!(
                "principal revocation {principal} read back epoch {durable}, expected at least {epoch}"
            );
        }
    }
    let receipt = LegacyMigrationReceipt {
        schema: 1,
        digest,
        principal_count: entries.len(),
    };
    let encoded = serde_json::to_vec(&receipt).context("encode revocation migration receipt")?;
    let existing = store
        .get(REVOCATION_NAMESPACE, MIGRATION_RECEIPT_KEY)
        .await
        .map_err(|error| anyhow::anyhow!("read revocation migration receipt: {error}"))?;
    if let Some(existing) = existing {
        if existing != encoded {
            anyhow::bail!("gateway revocation migration receipt conflicts");
        }
    } else if !store
        .compare_and_swap(REVOCATION_NAMESPACE, MIGRATION_RECEIPT_KEY, None, encoded)
        .await
        .map_err(|error| anyhow::anyhow!("write revocation migration receipt: {error}"))?
    {
        anyhow::bail!("gateway revocation migration receipt raced; retry startup");
    }
    let _ = load_from_store(store).await?;
    match std::fs::remove_file(&path) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(anyhow::anyhow!("retire {}: {error}", path.display())),
    }
    Ok(true)
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
    storage: Option<Arc<dyn KvStore>>,
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

            let durable_epoch = if let Some(storage) = storage.as_deref() {
                match record_principal_max(storage, &principal, ts_epoch).await {
                    Ok(epoch) => epoch,
                    Err(error) => {
                        // Preserve a fail-closed in-memory fence even when
                        // both CAS and tombstone writes fail. A restart with
                        // the same unavailable backend fails hydration rather
                        // than exposing the listener without the fence.
                        tracing::error!(
                            error = %error,
                            principal = %principal,
                            "gateway revocation KV write failed; running in degraded in-memory mode"
                        );
                        u64::MAX
                    },
                }
            } else {
                tracing::error!(
                    principal = %principal,
                    "gateway revocation storage is unavailable; running in degraded in-memory mode"
                );
                u64::MAX
            };

            {
                let mut guard = revoked_at
                    .write()
                    .expect("revocation map poisoned — fail-stop");
                // Idempotent: a duplicate AgentDelete event (or a
                // retry from a flaky subscriber) won't move the
                // epoch backward.
                let prev = guard.get(&principal).copied().unwrap_or(0);
                if durable_epoch <= prev {
                    continue;
                }
                guard.insert(principal.clone(), durable_epoch);
            }
            tracing::info!(
                principal = %principal,
                revoked_at_epoch = durable_epoch,
                "bearer revocation recorded"
            );
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
    storage: Option<Arc<dyn KvStore>>,
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
            let durable_epoch = if let Some(storage) = storage.as_deref() {
                match record_device_max(storage, key_id, ts_epoch).await {
                    Ok(epoch) => epoch,
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            key_id = %key_id,
                            "device revocation KV write failed; running in degraded in-memory mode"
                        );
                        u64::MAX
                    },
                }
            } else {
                tracing::error!(
                    key_id = %key_id,
                    "device revocation storage is unavailable; running in degraded in-memory mode"
                );
                u64::MAX
            };
            {
                let mut guard = revoked_key_ids
                    .write()
                    .expect("revoked-key-id map poisoned — fail-stop");
                // Idempotent: a duplicate / replayed revoke event must not move
                // the epoch backward (which could resurrect a dead bearer).
                let prev = guard.get(key_id).copied().unwrap_or(0);
                if durable_epoch > prev {
                    guard.insert(key_id.to_string(), durable_epoch);
                }
            }
            tracing::info!(key_id = %key_id, revoked_at_epoch = durable_epoch, "device bearer revocation recorded");
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
    async fn durable_epochs_are_monotonic_and_reloadable() {
        let store = astrid_storage::MemoryKvStore::new();
        let alice = PrincipalId::new("alice").unwrap();
        assert_eq!(record_principal_max(&store, &alice, 50).await.unwrap(), 50);
        assert_eq!(record_principal_max(&store, &alice, 20).await.unwrap(), 50);
        assert_eq!(record_device_max(&store, "device-a", 9).await.unwrap(), 9);
        assert_eq!(record_device_max(&store, "device-a", 12).await.unwrap(), 12);

        let (principals, devices) = load_from_store(&store).await.unwrap();
        assert_eq!(principals.get(&alice), Some(&50));
        assert_eq!(devices.get("device-a"), Some(&12));
    }

    #[tokio::test]
    async fn invalid_device_keys_never_enter_control_namespace() {
        let store = astrid_storage::MemoryKvStore::new();
        assert!(record_device_max(&store, "", 1).await.is_err());
        assert!(record_device_max(&store, "device/a", 1).await.is_err());
        assert!(load_from_store(&store).await.unwrap().1.is_empty());
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
            astrid_events::ipc::Topic::from_raw(crate::routes::events::AUDIT_TOPIC),
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
