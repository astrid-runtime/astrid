//! Astrid native-kernel M1 skeleton: boot to Rust ring 0 on the frozen machine
//! contract, emit structured serial evidence, run negative-first self-tests,
//! and halt with a machine-checkable outcome.
//!
//! The boot loader (`bootloader` crate) is ring-3-era scaffolding outside the
//! covenant surface: it is replaceable, and its output is checked by the
//! paging-audit and self-test evidence below, never trusted by design.
//!
//! Note (charter §9): the covenant reserves the name `astrid-native-kernel`
//! for the ring-0 artifact. This crate is named `astrid-kernel` per its build
//! spec; the naming is a deliberate, reported deviation, not a conflation with
//! the user-space semantic supervisor.

#![no_std]
#![no_main]

mod apic;
mod entropy;
mod gdt;
mod interrupts;
mod memory;
mod serial;
mod tests;
mod trap;

use bootloader_api::config::Mapping;
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};

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

    let (regions, bytes) = memory::summarize(&boot_info.memory_regions);
    serial::ev_mem_map(regions, bytes);
    memory::init_frames(&boot_info.memory_regions);

    let (rodata_nx_w, text_w, data_exec) = memory::audit_wx();
    serial::ev_paging_wx(rodata_nx_w, text_w);

    memory::init_heap();
    serial::ev_heap_ready(memory::HEAP_SIZE);

    gdt::init();
    interrupts::init_idt();
    serial::ev_idt_ready(interrupts::EXCEPTION_VECTORS);

    apic::init(phys_offset);
    serial::ev_apic_timer_start();

    // Enable interrupts and wait for the timer to deliver 8 ticks; the handler
    // masks the timer at tick 8.
    x86_64::instructions::interrupts::enable();
    while interrupts::tick_count() < 8 {
        x86_64::instructions::hlt();
    }
    x86_64::instructions::interrupts::disable();

    serial::ev_entropy(entropy::seed());

    // A W^X or NX violation observed by the audit must not silently pass.
    let wx_ok = !rodata_nx_w && !text_w && !data_exec;
    let tests_ok = tests::run_all(data_exec);
    let ok = wx_ok && tests_ok;

    serial::ev_halt(ok);
    serial::exit_qemu(ok);
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
