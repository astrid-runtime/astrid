//! Ring-0 dual-closure acceptance. The bootloader ramdisk is a memory-resident
//! table, not a guest filesystem.
//!
//! `BootInfo::ramdisk_addr` is the virtual address where the loader mapped the
//! table. It is not a physical address.

use astrid_native_closure::{BoundIdentities, ClosureError, TABLE_LEN, verify_table};
use bootloader_api::BootInfo;

pub fn accept(boot_info: &BootInfo) -> Result<BoundIdentities, ClosureError> {
    let mut buf = [0u8; TABLE_LEN];
    copy_ramdisk(boot_info, &mut buf)?;
    verify_table(&buf)
}

fn copy_ramdisk(boot_info: &BootInfo, buf: &mut [u8; TABLE_LEN]) -> Result<(), ClosureError> {
    let Some(addr) = boot_info.ramdisk_addr.into_option() else {
        return Err(ClosureError::Missing);
    };
    let Ok(len) = usize::try_from(boot_info.ramdisk_len) else {
        return Err(ClosureError::Truncated);
    };
    if len == 0 {
        return Err(ClosureError::Missing);
    }
    if len != TABLE_LEN {
        return Err(ClosureError::Truncated);
    }
    // Safety: the bootloader mapped `ramdisk_addr` for `ramdisk_len` bytes.
    let src = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
    buf.copy_from_slice(src);
    Ok(())
}
