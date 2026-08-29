//! Native protection domains: admission, paging, lifecycle, and harness.

use x86_64::registers::control::Cr3;

mod harness;
mod manager;
mod paging;
mod types;
mod wait;

pub(crate) fn bind_kernel_cr3() {
    manager::init_kernel_cr3();
    let (root, flags) = Cr3::read();
    crate::serial::ev_kernel_cr3(root.start_address().as_u64(), flags.bits());
}

pub(crate) fn start_harness(raw: &[u8], expected: astrid_system_generation::ContentId) -> ! {
    manager::init_resume_stack();
    harness::start(raw, expected)
}

pub(crate) fn handle_domain_trap(frame: &mut crate::trap::TrapFrame, fault_address: u64) -> bool {
    manager::handle_domain_trap(frame, fault_address)
}

pub(crate) fn copy_current_user(address: u64, buffer: &mut [u8], to_user: bool) -> bool {
    wait::copy_current_user(address, buffer, to_user)
}

pub(crate) fn bind_ipc_peer(
    creator_slot: u64,
    creator_generation: u64,
    peer_slot: u64,
    peer_generation: u64,
) -> bool {
    wait::bind_ipc_peer(creator_slot, creator_generation, peer_slot, peer_generation)
}

pub(crate) fn mark_ipc_cancelled(domain: crate::ipc::DomainToken) -> bool {
    wait::mark_ipc_cancelled(domain)
}

pub(crate) fn mark_ipc_peer_failed(domain: crate::ipc::DomainToken) -> bool {
    wait::mark_ipc_peer_failed_domain(domain)
}

#[cfg(test)]
pub(crate) fn ipc_peer_status_for_test(domain: crate::ipc::DomainToken) -> Option<&'static str> {
    let Some(handle) = wait::domain_handle_token(domain) else {
        return None;
    };
    wait::test_support::status_name(handle)
}

#[cfg(test)]
pub(crate) fn park_ipc_peer_for_test(domain: crate::ipc::DomainToken, status: &str) -> bool {
    let Some(handle) = wait::domain_handle_token(domain) else {
        return false;
    };
    let status = match status {
        "sent" => wait::BlockStatus::Sent,
        "received" => wait::BlockStatus::Received,
        _ => return false,
    };
    wait::test_support::park(handle, status, 0, 0, crate::ipc::MAX_BUFFER_BYTES as u64);
    true
}

#[cfg(test)]
pub(crate) fn reset_wait_state_for_test() {
    wait::test_support::reset();
}
