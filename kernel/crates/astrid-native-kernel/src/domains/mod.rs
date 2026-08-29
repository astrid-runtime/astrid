//! Native protection domains: admission, paging, lifecycle, and harness.

#[cfg(not(test))]
use x86_64::registers::control::Cr3;

#[cfg(not(test))]
mod harness;
mod manager;
#[cfg(not(test))]
mod paging;
#[cfg(test)]
mod test_support;
mod types;
mod wait;

#[cfg(not(test))]
pub fn bind_kernel_cr3() {
    manager::init_kernel_cr3();
    let (root, flags) = Cr3::read();
    crate::serial::ev_kernel_cr3(root.start_address().as_u64(), flags.bits());
}

#[cfg(not(test))]
pub fn start_harness(raw: &[u8], expected: astrid_system_generation::ContentId) -> ! {
    manager::init_resume_stack();
    harness::start(raw, expected)
}

#[cfg(not(test))]
pub fn handle_domain_trap(frame: &mut crate::trap::TrapFrame, fault_address: u64) -> bool {
    manager::handle_domain_trap(frame, fault_address)
}

#[cfg(not(test))]
pub fn copy_current_user(address: u64, buffer: &mut [u8], to_user: bool) -> bool {
    wait::copy_current_user(address, buffer, to_user)
}

pub fn bind_ipc_peer(
    creator_slot: u64,
    creator_generation: u64,
    peer_slot: u64,
    peer_generation: u64,
) -> bool {
    wait::bind_ipc_peer(creator_slot, creator_generation, peer_slot, peer_generation)
}

pub fn mark_ipc_cancelled(domain: crate::ipc::DomainToken) -> bool {
    wait::mark_ipc_cancelled(domain)
}

pub fn mark_ipc_peers_failed(domains: [Option<crate::ipc::DomainToken>; 2]) -> usize {
    wait::mark_ipc_peers_failed(domains)
}

#[cfg(test)]
pub fn ipc_peer_status_for_test(domain: crate::ipc::DomainToken) -> Option<&'static str> {
    let Some(handle) = wait::domain_handle_token(domain) else {
        return None;
    };
    wait::test_support::status_name(handle)
}

#[cfg(test)]
pub fn ipc_peer_parked_for_test(domain: crate::ipc::DomainToken) -> bool {
    let Some(handle) = wait::domain_handle_token(domain) else {
        return false;
    };
    wait::test_support::parked(handle)
}

#[cfg(test)]
pub fn park_ipc_peer_for_test(domain: crate::ipc::DomainToken, status: &str) -> bool {
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
pub fn install_blocked_ipc_for_test(domain: crate::ipc::DomainToken) -> bool {
    let Some(handle) = wait::domain_handle_token(domain) else {
        return false;
    };
    test_support::install_blocked(handle)
}

#[cfg(test)]
pub fn ipc_blocked_for_test(domain: crate::ipc::DomainToken) -> bool {
    let Some(handle) = wait::domain_handle_token(domain) else {
        return false;
    };
    test_support::is_blocked(handle)
}

#[cfg(test)]
pub fn reset_wait_state_for_test() {
    test_support::reset();
    wait::test_support::reset();
}
