//! Ring-0 dual-closure acceptance. The bootloader ramdisk is a memory-resident
//! table, not a guest filesystem.
//!
//! `BootInfo::ramdisk_addr` is the virtual address where the loader mapped the
//! table. It is not a physical address. The table is copied into kernel-owned
//! memory only after a [`ClosureTableRegion`] proves every covering page is
//! present and readable. Verification uses the compiled emulator
//! [`TrustedPolicy`], not table-chosen keys or floors.
//!
//! Authenticated loader handoff is not available. This is not firmware root of
//! trust and not self-measurement.

use astrid_native_closure::{
    BoundIdentities, ClosureError, ClosureTableRegion, TABLE_LEN, TrustedPolicy,
    prove_pages_readable, verify_table,
};
use bootloader_api::BootInfo;

pub fn accept(boot_info: &BootInfo) -> Result<BoundIdentities, ClosureError> {
    let mut buf = [0u8; TABLE_LEN];
    copy_ramdisk(boot_info, &mut buf)?;
    verify_table(&buf, &TrustedPolicy::emulator_fixture())
}

fn copy_ramdisk(boot_info: &BootInfo, buf: &mut [u8; TABLE_LEN]) -> Result<(), ClosureError> {
    let Some(addr) = boot_info.ramdisk_addr.into_option() else {
        return Err(ClosureError::Missing);
    };
    let region = ClosureTableRegion::try_new(addr, boot_info.ramdisk_len)?;
    prove_pages_readable(region, crate::memory::page_present_readable)?;
    // SAFETY: every covering page is present and readable in the active boot
    // page tables. GDT/IDT are already loaded, so a residual fault would hit
    // the installed handler rather than an undefined pre-IDT dereference.
    unsafe { region.copy_to(buf) };
    Ok(())
}
