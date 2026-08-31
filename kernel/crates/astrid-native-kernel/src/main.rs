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

use astrid_native_kernel::platform::{self, Platform};
use astrid_native_kernel::tests;
use astrid_native_kernel::{apic, closure, domains, entropy, gdt, interrupts, memory, serial};

struct KernelPlatform;

impl Platform for KernelPlatform {
    fn copy_current_user(&self, address: u64, buffer: &mut [u8], to_user: bool) -> bool {
        domains::copy_current_user(address, buffer, to_user)
    }

    fn ev_ipc_op(&self, id: u64, generation: u64, operation: &str, status: &str) {
        serial::ev_ipc_op(id, generation, operation, status);
    }
}

fn install_ipc_platform() {
    platform::install(&KernelPlatform);
}

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
    install_ipc_platform();
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

    let admitted;
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
            let verified = match verify_manifest(&descriptor, &trusted) {
                Ok(verified) => verified,
                Err(err) => {
                    serial::ev_closure_reject(err.as_reason());
                    serial::ev_halt(false);
                    serial::exit_qemu(false)
                },
            };
            // Admission consumes the verifier-owned generation, not fixture
            // constants. Keep this gate ahead of every success-bound event.
            admitted = match closure::admit_component(verified, accepted.component()) {
                Ok(admitted) => admitted,
                Err(err) => {
                    serial::ev_closure_reject(err.as_reason());
                    serial::ev_halt(false);
                    serial::exit_qemu(false)
                },
            };
            if admitted.verified_generation().signer()
                != accepted.handoff().policy().sysgen_verify()
            {
                serial::ev_closure_reject(
                    astrid_native_closure::ClosureError::BindingMismatch.as_reason(),
                );
                serial::ev_halt(false);
                serial::exit_qemu(false);
            }
            serial::ev_component_bound();
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

    let Some(seed) = entropy::provision() else {
        serial::ev_entropy(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    };
    let audit_identity = match entropy::install(seed) {
        Ok(identity) => identity,
        Err(_) => {
            serial::ev_entropy(true);
            serial::ev_audit_install_failed();
            serial::ev_halt(false);
            serial::exit_qemu(false);
        },
    };
    serial::ev_entropy(true);
    serial::ev_audit_boot(
        &audit_identity.boot().bytes(),
        audit_identity.authority_id(),
    );

    let wx_ok = !rodata_nx_w && !text_w && !data_exec;
    let tests_ok = tests::run_all(data_exec);
    if wx_ok && tests_ok {
        memory::reserve_live_page_tables();
        domains::bind_kernel_cr3();
        let component = *admitted.component();
        domains::start_harness(&component, &admitted);
    }
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
