#[path = "../domains/types.rs"]
pub mod types;

pub(crate) use types::DomainHandle;

pub(crate) fn mark_ipc_cancelled(domain: crate::ipc::DomainToken) -> bool {
    wait::mark_ipc_cancelled(domain)
}

pub(crate) fn copy_current_user(address: u64, buffer: &mut [u8], to_user: bool) -> bool {
    let _ = (address, buffer, to_user);
    false
}

pub(crate) fn domain_handle_for(domain: crate::ipc::DomainToken) -> Option<DomainHandle> {
    wait::domain_handle_token(domain)
}

pub(crate) fn mark_ipc_peer_failed(handle: DomainHandle) {
    wait::mark_ipc_peer_failed(handle);
}

#[path = "../domains/wait.rs"]
pub mod wait;
