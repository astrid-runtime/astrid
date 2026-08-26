use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static BACKEND_LOCK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
static LOCKS: Mutex<Option<HashMap<String, StationLock>>> = Mutex::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static SET_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) struct Guard {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        *LOCKS.lock().unwrap() = None;
        SET_CALLS.store(0, Ordering::Release);
        ACTIVE.store(false, Ordering::Release);
    }
}

pub(super) async fn install() -> Guard {
    let permit = BACKEND_LOCK.acquire().await.unwrap();
    *LOCKS.lock().unwrap() = Some(HashMap::new());
    SET_CALLS.store(0, Ordering::Release);
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

pub(super) fn set(principal: &PrincipalId, capsule: &str, lock: StationLock) {
    SET_CALLS.fetch_add(1, Ordering::AcqRel);
    LOCKS
        .lock()
        .unwrap()
        .as_mut()
        .expect("test Station lock backend")
        .insert(key(principal, capsule), lock);
}

pub(super) fn set_calls() -> usize {
    SET_CALLS.load(Ordering::Acquire)
}

pub(super) fn delete(principal: &PrincipalId, capsule: &str) {
    if let Some(locks) = LOCKS.lock().unwrap().as_mut() {
        locks.remove(&key(principal, capsule));
    }
}
