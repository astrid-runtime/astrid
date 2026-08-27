use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static BACKEND_LOCK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
static LOCKS: Mutex<Option<HashMap<String, StationLock>>> = Mutex::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static SET_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static DELETE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FAIL_SET_ON_CALL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static QUEUED_DELETE_FAILURE: AtomicBool = AtomicBool::new(false);

pub(super) struct Guard {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        *LOCKS.lock().unwrap() = None;
        SET_CALLS.store(0, Ordering::Release);
        DELETE_CALLS.store(0, Ordering::Release);
        FAIL_SET_ON_CALL.store(0, Ordering::Release);
        QUEUED_DELETE_FAILURE.store(false, Ordering::Release);
        ACTIVE.store(false, Ordering::Release);
    }
}

pub(super) async fn install() -> Guard {
    let permit = BACKEND_LOCK.acquire().await.unwrap();
    *LOCKS.lock().unwrap() = Some(HashMap::new());
    SET_CALLS.store(0, Ordering::Release);
    DELETE_CALLS.store(0, Ordering::Release);
    FAIL_SET_ON_CALL.store(0, Ordering::Release);
    QUEUED_DELETE_FAILURE.store(false, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);
    Guard { _permit: permit }
}

pub(super) fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

fn key(principal: &PrincipalId, capsule: &str) -> String {
    format!("{principal}:{capsule}")
}

pub(super) fn get(principal: &PrincipalId, capsule: &str) -> Option<StationLock> {
    LOCKS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|locks| locks.get(&key(principal, capsule)).cloned())
}

fn canonical_bytes(lock: &StationLock) -> Result<Vec<u8>, String> {
    serde_json::to_vec(lock).map_err(|error| format!("encode Station lock: {error}"))
}

fn lock_hash(lock: &StationLock) -> Result<String, String> {
    canonical_bytes(lock).map(|bytes| format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

pub(super) fn set(
    principal: &PrincipalId,
    capsule: &str,
    lock: StationLock,
    expected_hash: Option<&str>,
) -> Result<(), String> {
    let call = SET_CALLS
        .fetch_add(1, Ordering::AcqRel)
        .checked_add(1)
        .expect("Station lock test call counter overflow");
    if FAIL_SET_ON_CALL
        .compare_exchange(call, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        return Err("injected Station lock backend write failure".to_owned());
    }
    let mut locks = LOCKS.lock().unwrap();
    let locks = locks.as_mut().expect("test Station lock backend");
    let current_hash = locks
        .get(&key(principal, capsule))
        .map(lock_hash)
        .transpose()?;
    if current_hash.as_deref() != expected_hash {
        return Err("Station lock changed; test backend expected_hash rejected".to_owned());
    }
    locks.insert(key(principal, capsule), lock);
    Ok(())
}

pub(super) fn set_calls() -> usize {
    SET_CALLS.load(Ordering::Acquire)
}

pub(super) fn delete_calls() -> usize {
    DELETE_CALLS.load(Ordering::Acquire)
}

pub(super) fn queue_next_set_failure() {
    let next = set_calls()
        .checked_add(1)
        .expect("Station lock test call counter overflow");
    FAIL_SET_ON_CALL.store(next, Ordering::Release);
}

pub(super) fn queue_set_failure_on_call(call: usize) {
    FAIL_SET_ON_CALL.store(call, Ordering::Release);
}

pub(super) fn queue_next_delete_failure() {
    QUEUED_DELETE_FAILURE.store(true, Ordering::Release);
}

pub(super) fn delete(
    principal: &PrincipalId,
    capsule: &str,
    expected_hash: Option<String>,
) -> Result<(), String> {
    DELETE_CALLS.fetch_add(1, Ordering::AcqRel);
    if QUEUED_DELETE_FAILURE.swap(false, Ordering::AcqRel) {
        return Err("injected Station lock backend delete failure".to_owned());
    }
    let mut locks_guard = LOCKS.lock().unwrap();
    let locks = locks_guard.as_mut().expect("test Station lock backend");
    if let Some(expected_hash) = expected_hash {
        let current_hash = locks
            .get(&key(principal, capsule))
            .map(lock_hash)
            .transpose()?;
        if current_hash.as_deref() != Some(expected_hash.as_str()) {
            return Err("Station lock changed; test backend expected_hash rejected".to_owned());
        }
    }
    locks.remove(&key(principal, capsule));
    Ok(())
}
