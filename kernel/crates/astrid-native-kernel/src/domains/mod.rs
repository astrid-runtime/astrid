//! Native protection domains: admission, paging, lifecycle, and harness.

mod harness;
mod manager;
mod paging;
mod types;

pub(crate) fn start_harness(raw: &[u8], expected: astrid_system_generation::ContentId) -> ! {
    manager::init_resume_stack();
    harness::start(raw, expected)
}

pub(crate) fn handle_domain_trap(frame: &mut crate::trap::TrapFrame, fault_address: u64) -> bool {
    manager::handle_domain_trap(frame, fault_address)
}
