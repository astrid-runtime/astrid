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
//! fallible heap/frame pools. Dual-closure stub: ring 0 binds kernel/bootstrap and empty
//! System Generation identities against a compiled fixture public-key policy. This crate does
//! not claim KVM, virtio, IOMMU, DMA, A/B, first-owner, services, filesystem,
//! Linux, host-absence, or physical ownership.

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
        Ok(bound) => emit_bound(bound),
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

fn emit_bound(bound: astrid_native_closure::BoundIdentities) {
    let mut kernel_hex = [0u8; 64];
    let mut sysgen_hex = [0u8; 64];
    bound.kernel_bootstrap.write_hex(&mut kernel_hex);
    bound.system_generation.write_hex(&mut sysgen_hex);
    let kernel_hex = core::str::from_utf8(&kernel_hex).expect("hex digits are ascii");
    let sysgen_hex = core::str::from_utf8(&sysgen_hex).expect("hex digits are ascii");
    serial::ev_closure_kernel(bound.kernel_floor.get(), kernel_hex);
    serial::ev_closure_sysgen(bound.sysgen_floor.get(), sysgen_hex);
    serial::ev_closure_bound(
        bound.kernel_floor.get(),
        bound.sysgen_floor.get(),
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
