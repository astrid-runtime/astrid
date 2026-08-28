//! Native protection domains: admission, paging, lifecycle, and harness.

use x86_64::registers::control::Cr3;

mod harness;
mod manager;
mod paging;
mod types;

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
