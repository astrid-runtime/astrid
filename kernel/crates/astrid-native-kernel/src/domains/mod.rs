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
