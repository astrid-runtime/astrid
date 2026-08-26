//! Astrid native-kernel M1: boot to Rust ring 0 on the experimental QEMU
//! machine contract, emit structured serial evidence, run negative-first
//! self-tests, and halt with a machine-checkable outcome.
//!
//! The boot loader (`bootloader` crate) is replaceable scaffolding outside the
//! covenant: paging-audit and self-test evidence check its output. This crate
//! carries the charter §9 reserved name `astrid-native-kernel` and is distinct
//! from the user-space `astrid-kernel` supervisor.
//!
//! M1 claims: UEFI q35 TCG boot, W^X of the kernel image, APIC timer delivery,
//! fallible heap/frame pools, and a fixture-only root-signed policy handoff
//! whose original raw ELF/table/context bindings are verified by the loader
//! before writable PT_LOAD mappings and rechecked by ring 0 before closures.
//! The relocated image, bootloader, firmware, and physical ownership are not
//! measured or authenticated. This crate does not claim KVM, virtio, IOMMU,
//! DMA, A/B, first-owner, services, filesystem, Linux, or host-absence.

#![no_std]
#![no_main]

mod apic;
mod closure;
mod entropy;
mod gdt;
mod interrupts;
mod memory;
mod serial;
mod tests;
mod trap;

use astrid_system_generation::{MANIFEST_LEN, verify_manifest};
use bootloader_api::config::Mapping;
use bootloader_api::{BootInfo, BootloaderConfig, entry_point};

/// Fixed physical-memory mapping + 128 KiB kernel stack.
static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::FixedAddress(0xffff_8000_0000_0000));
    config.kernel_stack_size = 128 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial::init();
    serial::ev_boot_entry();

    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("bootloader did not provide a physical-memory offset");
    memory::set_phys_offset(phys_offset);

    // Safe handlers before any ramdisk touch. Invalid ranges reject in
    // software; a residual fault uses this IDT rather than an undefined
    // pre-IDT dereference.
    gdt::init();
    interrupts::init_idt();
    serial::ev_idt_ready(interrupts::EXCEPTION_VECTORS);

    match closure::accept(boot_info) {
        Ok(accepted) => {
            // Keep descriptor bytes independent of the loader-owned mapping;
            // only this kernel-owned copy may enter manifest verification.
            let mut descriptor = [0u8; MANIFEST_LEN];
            closure::copy_system_generation(&accepted, &mut descriptor);
            if accepted.bound().sysgen_identity()
                != astrid_native_closure::MeasuredIdentity::from_payload(&descriptor)
            {
                serial::ev_closure_reject(
                    astrid_native_closure::ClosureError::BindingMismatch.as_reason(),
                );
                serial::ev_halt(false);
                serial::exit_qemu(false);
            }
            let trusted = match closure::trusted_system_generation_input(&accepted) {
                Ok(input) => input,
                Err(err) => {
                    serial::ev_closure_reject(err.as_reason());
                    serial::ev_halt(false);
                    serial::exit_qemu(false);
                },
            };
            if let Err(err) = verify_manifest(&descriptor, &trusted) {
                serial::ev_closure_reject(err.as_reason());
                serial::ev_halt(false);
                serial::exit_qemu(false);
            }
            // Emit success-bound evidence only after the descriptor has been
            // copied into kernel-owned memory, identity-bound, and admitted by
            // the canonical manifest verifier.
            emit_bound(&accepted);
        },
        Err(err) => {
            serial::ev_closure_reject(err.as_reason());
            serial::ev_halt(false);
            serial::exit_qemu(false);
        },
    }

    let (regions, bytes) = memory::summarize(&boot_info.memory_regions);
    serial::ev_mem_map(regions, bytes);
    memory::init_frames(&boot_info.memory_regions);

    let (rodata_nx_w, text_w, data_exec) = memory::audit_wx();
    serial::ev_paging_wx(rodata_nx_w, text_w);

    memory::init_heap();
    serial::ev_heap_ready(memory::HEAP_SIZE);

    apic::init(phys_offset);
    serial::ev_apic_timer_start();

    x86_64::instructions::interrupts::enable();
    while interrupts::tick_count() < 8 {
        x86_64::instructions::hlt();
    }
    x86_64::instructions::interrupts::disable();
    apic::mask_timer();

    serial::ev_entropy(entropy::seed());

    let wx_ok = !rodata_nx_w && !text_w && !data_exec;
    let tests_ok = tests::run_all(data_exec);
    serial::ev_halt(wx_ok && tests_ok);
    serial::exit_qemu(wx_ok && tests_ok);
}

fn emit_bound(accepted: &closure::AcceptedClosure) {
    let bound = accepted.bound();
    let mut kernel_hex = [0u8; 64];
    let mut sysgen_hex = [0u8; 64];
    bound.kernel_identity().write_hex(&mut kernel_hex);
    bound.sysgen_identity().write_hex(&mut sysgen_hex);
    let kernel_hex = core::str::from_utf8(&kernel_hex).expect("hex digits are ascii");
    let sysgen_hex = core::str::from_utf8(&sysgen_hex).expect("hex digits are ascii");
    let mut kernel_image_hex = [0u8; 64];
    let mut closure_table_hex = [0u8; 64];
    accepted.kernel_image().write_hex(&mut kernel_image_hex);
    accepted.closure_table().write_hex(&mut closure_table_hex);
    let kernel_image_hex = core::str::from_utf8(&kernel_image_hex).expect("hex digits are ascii");
    let closure_table_hex = core::str::from_utf8(&closure_table_hex).expect("hex digits are ascii");
    serial::ev_handoff_bound(
        accepted.handoff().policy().policy_generation().get(),
        kernel_image_hex,
        closure_table_hex,
    );
    serial::ev_closure_kernel(bound.kernel_floor().get(), kernel_hex);
    serial::ev_closure_sysgen(bound.sysgen_floor().get(), sysgen_hex, false);
    serial::ev_closure_bound(
        bound.kernel_floor().get(),
        bound.sysgen_floor().get(),
        kernel_hex,
        sysgen_hex,
    );
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = info.location() {
        serial::ev_panic(format_args!("{}:{}", location.file(), location.line()));
    } else {
        serial::ev_panic(format_args!("unknown"));
    }
    serial::exit_qemu(false);
}
