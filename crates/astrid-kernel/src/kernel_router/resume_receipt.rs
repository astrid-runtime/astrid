//! Principal-scoped durable capsule-install resume receipts.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    CapsuleInstallResumeReceipt, InstalledCapsuleGeneration, KernelResponse,
};
use astrid_storage::ScopedKvStore;

use crate::Kernel;

const NAMESPACE: &str = "capsule-install-resume";
// Receipts contain only three digests and an identifier. Keep the wire value
// bounded at the protocol layer rather than making this a user configuration
// knob; oversized bytes are never completion proof and fail closed on get.
const MAX_BYTES: usize = 16 * 1024;

/// Read one authenticated caller's resume receipt.
pub(super) async fn get(kernel: &Arc<Kernel>, caller: &PrincipalId, id: &str) -> KernelResponse {
    let key = match capsule_id(id) {
        Ok(key) => key,
        Err(error) => return KernelResponse::Error(error),
    };
    let store = match principal_store(kernel, caller) {
        Ok(store) => store,
        Err(error) => return KernelResponse::Error(error),
    };
    let value = match store.get(key).await {
        Ok(value) => value,
        Err(error) => {
            return KernelResponse::Error(format!("read capsule resume receipt: {error}"));
        },
    };
    let Some(value) = value else {
        return KernelResponse::CapsuleInstallResumeReceipt(None);
    };
    if value.len() > MAX_BYTES {
        return KernelResponse::CapsuleInstallResumeReceipt(None);
    }
    let Ok(receipt) = serde_json::from_slice::<CapsuleInstallResumeReceipt>(&value) else {
        return KernelResponse::CapsuleInstallResumeReceipt(None);
    };
    if !valid_receipt(&receipt, key) {
        return KernelResponse::CapsuleInstallResumeReceipt(None);
    }
    KernelResponse::CapsuleInstallResumeReceipt(Some(receipt))
}

/// Atomically replace one authenticated caller's resume receipt and verify the
/// exact bytes persisted before reporting success.
pub(super) async fn put(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    receipt: CapsuleInstallResumeReceipt,
) -> KernelResponse {
    let key = match capsule_id(&receipt.id) {
        Ok(key) => key,
        Err(error) => return KernelResponse::Error(error),
    };
    if !valid_receipt(&receipt, key) {
        return KernelResponse::Error("invalid capsule install resume receipt".to_owned());
    }
    let encoded = match serde_json::to_vec(&receipt) {
        Ok(encoded) if encoded.len() <= MAX_BYTES => encoded,
        Ok(_) => {
            return KernelResponse::Error(
                "capsule install resume receipt exceeds size limit".to_owned(),
            );
        },
        Err(error) => {
            return KernelResponse::Error(format!(
                "encode capsule install resume receipt: {error}"
            ));
        },
    };
    let store = match principal_store(kernel, caller) {
        Ok(store) => store,
        Err(error) => return KernelResponse::Error(error),
    };
    let previous = match store.get(key).await {
        Ok(previous) => previous,
        Err(error) => {
            return KernelResponse::Error(format!("read capsule resume receipt: {error}"));
        },
    };
    let swapped = match store
        .compare_and_swap(key, previous.as_deref(), encoded.clone())
        .await
    {
        Ok(swapped) => swapped,
        Err(error) => {
            return KernelResponse::Error(format!("write capsule resume receipt: {error}"));
        },
    };
    if !swapped {
        return KernelResponse::Error(
            "capsule install resume receipt changed concurrently; retry".to_owned(),
        );
    }
    let read_back = match store.get(key).await {
        Ok(read_back) => read_back,
        Err(error) => {
            return KernelResponse::Error(format!("verify capsule resume receipt write: {error}"));
        },
    };
    if read_back.as_deref() != Some(encoded.as_slice()) {
        return KernelResponse::Error("capsule resume receipt write did not read back".to_owned());
    }
    KernelResponse::Success(serde_json::json!({ "stored": true }))
}

fn capsule_id(id: &str) -> Result<&str, String> {
    astrid_capsule_types::CapsuleId::new(id.to_owned())
        .map(|_| id)
        .map_err(|error| format!("invalid capsule id '{id}': {error}"))
}

fn principal_store(kernel: &Arc<Kernel>, caller: &PrincipalId) -> Result<ScopedKvStore, String> {
    let store = kernel
        .principal_store
        .as_ref()
        .ok_or_else(|| "authoritative principal store is unavailable".to_owned())?;
    let uid = kernel
        .principal_directory
        .uid_for(caller)
        .map_err(|error| format!("resolve caller principal UID: {error}"))?;
    store
        .principal_control_kv(uid, NAMESPACE)
        .map_err(|error| format!("open capsule resume control namespace: {error}"))
}

fn valid_receipt(receipt: &CapsuleInstallResumeReceipt, key: &str) -> bool {
    receipt.id == key && is_digest(&receipt.archive_digest) && valid_generation(&receipt.generation)
}

fn valid_generation(generation: &InstalledCapsuleGeneration) -> bool {
    is_digest(&generation.archive)
        && is_digest(&generation.metadata)
        && is_digest(&generation.authority)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::dirs::AstridHome;
    use astrid_core::kernel_api::InstalledCapsuleGeneration;

    fn generation(seed: char) -> InstalledCapsuleGeneration {
        let value = seed.to_string().repeat(64);
        InstalledCapsuleGeneration {
            archive: value.clone(),
            metadata: value.clone(),
            authority: value,
        }
    }

    fn receipt(id: &str, seed: char) -> CapsuleInstallResumeReceipt {
        CapsuleInstallResumeReceipt {
            id: id.to_owned(),
            archive_digest: "b".repeat(64),
            generation: generation(seed),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_receipt_is_explicit_absence() {
        let directory = tempfile::tempdir().expect("test home");
        let kernel = crate::test_kernel_with_home(AstridHome::from_path(directory.path())).await;
        let response = get(&kernel, &PrincipalId::default(), "missing-capsule").await;
        assert!(matches!(
            response,
            KernelResponse::CapsuleInstallResumeReceipt(None)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receipt_roundtrip_is_uid_scoped() {
        let directory = tempfile::tempdir().expect("test home");
        let home = AstridHome::from_path(directory.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let caller = PrincipalId::default();
        let value = receipt("scoped-capsule", 'a');
        let response = put(&kernel, &caller, value.clone()).await;
        assert!(
            matches!(response, KernelResponse::Success(_)),
            "{response:?}"
        );
        assert!(matches!(
            get(&kernel, &caller, "scoped-capsule").await,
            KernelResponse::CapsuleInstallResumeReceipt(Some(found)) if found == value
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_and_oversized_receipts_fail_closed_on_get() {
        let directory = tempfile::tempdir().expect("test home");
        let home = AstridHome::from_path(directory.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let caller = PrincipalId::default();
        let store = principal_store(&kernel, &caller).expect("receipt store");
        store
            .set("bad-capsule", b"not-json".to_vec())
            .await
            .expect("write malformed receipt");
        assert!(matches!(
            get(&kernel, &caller, "bad-capsule").await,
            KernelResponse::CapsuleInstallResumeReceipt(None)
        ));
        store
            .set("large-capsule", vec![b'x'; MAX_BYTES + 1])
            .await
            .expect("write oversized receipt");
        assert!(matches!(
            get(&kernel, &caller, "large-capsule").await,
            KernelResponse::CapsuleInstallResumeReceipt(None)
        ));
    }
}
