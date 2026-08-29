//! COM1 serial writer and the machine-readable event bus.
//!
//! Every kernel event is exactly one JSON line over COM1 by polled TX. A single
//! spinlock guards both the monotonic `seq` counter and the UART. Emission runs
//! with interrupts disabled so an ISR can emit without deadlocking.

use core::fmt::{self, Write};

use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::instructions::port::Port;

const COM1_BASE: u16 = 0x3F8;
const DEBUG_EXIT_PORT: u16 = 0xF4;

struct SerialPort {
    base: u16,
}

impl SerialPort {
    const fn new(base: u16) -> Self {
        Self { base }
    }

    /// Program the UART for 115200 8N1, FIFOs on, interrupts off.
    ///
    /// # Safety
    /// Touches COM1 I/O ports directly; must run once during early boot.
    unsafe fn init(&self) {
        let mut ier: Port<u8> = Port::new(self.base + 1);
        let mut lcr: Port<u8> = Port::new(self.base + 3);
        let mut dll: Port<u8> = Port::new(self.base);
        let mut dlm: Port<u8> = Port::new(self.base + 1);
        let mut fcr: Port<u8> = Port::new(self.base + 2);
        let mut mcr: Port<u8> = Port::new(self.base + 4);
        unsafe {
            ier.write(0x00);
            lcr.write(0x80);
            dll.write(0x01);
            dlm.write(0x00);
            lcr.write(0x03);
            fcr.write(0xC7);
            mcr.write(0x0B);
        }
    }

    #[inline]
    fn write_byte(&self, byte: u8) {
        let mut lsr: Port<u8> = Port::new(self.base + 5);
        let mut thr: Port<u8> = Port::new(self.base);
        unsafe {
            while lsr.read() & 0x20 == 0 {}
            thr.write(byte);
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            self.write_byte(b);
        }
        Ok(())
    }
}

struct Emitter {
    seq: u64,
    port: SerialPort,
}

static EMITTER: Mutex<Emitter> = Mutex::new(Emitter {
    seq: 0,
    port: SerialPort::new(COM1_BASE),
});

pub fn init() {
    without_interrupts(|| {
        unsafe { EMITTER.lock().port.init() };
    });
}

fn emit(args: fmt::Arguments) {
    without_interrupts(|| {
        let mut e = EMITTER.lock();
        let seq = e.seq;
        e.seq = seq.wrapping_add(1);
        let _ = writeln!(e.port, "{{\"seq\":{seq},{args}}}");
    });
}

pub fn ev_boot_entry() {
    emit(format_args!("\"ev\":\"boot.entry\""));
}

pub fn ev_mem_map(usable_regions: usize, usable_bytes: u64) {
    emit(format_args!(
        "\"ev\":\"mem.map\",\"usable_regions\":{usable_regions},\"usable_bytes\":{usable_bytes}"
    ));
}

pub fn ev_mem_truncated(ignored_frames: u64) {
    emit(format_args!(
        "\"ev\":\"mem.truncated\",\"ignored_frames\":{ignored_frames}"
    ));
}

pub fn ev_paging_wx(rodata_nx_w: bool, text_w: bool) {
    emit(format_args!(
        "\"ev\":\"paging.wx\",\"rodata_nx_w\":{rodata_nx_w},\"text_w\":{text_w}"
    ));
}

pub fn ev_heap_ready(bytes: usize) {
    emit(format_args!("\"ev\":\"heap.ready\",\"bytes\":{bytes}"));
}

pub fn ev_idt_ready(vectors: u32) {
    emit(format_args!("\"ev\":\"idt.ready\",\"vectors\":{vectors}"));
}

pub fn ev_handoff_bound(policy_generation: u64, kernel_image: &str, closure_table: &str) {
    emit(format_args!(
        "\"ev\":\"handoff.bound\",\"policy_generation\":{policy_generation},\"kernel_image\":\"{kernel_image}\",\"closure_table\":\"{closure_table}\""
    ));
}

pub fn ev_apic_timer_start() {
    emit(format_args!("\"ev\":\"apic.timer.start\""));
}

pub fn ev_apic_timer_tick(n: u32) {
    emit(format_args!("\"ev\":\"apic.timer.tick\",\"n\":{n}"));
}

pub fn ev_entropy(seeded: bool) {
    if seeded {
        emit(format_args!(
            "\"ev\":\"entropy.seeded\",\"source\":\"rdrand\""
        ));
    } else {
        emit(format_args!("\"ev\":\"entropy.unavailable\""));
    }
}

pub fn ev_fault(vector: u8, code: u64, rip: u64) {
    emit(format_args!(
        "\"ev\":\"fault\",\"vector\":{vector},\"code\":{code},\"rip\":\"{rip:#x}\""
    ));
}

pub fn ev_test(name: &'static str, pass: bool) {
    let ev = if pass { "test.pass" } else { "test.fail" };
    emit(format_args!("\"ev\":\"{ev}\",\"name\":\"{name}\""));
}

pub fn ev_closure_kernel(floor: u64, id: &str) {
    emit(format_args!(
        "\"ev\":\"closure.kernel\",\"kind\":\"kernel-bootstrap\",\"floor\":{floor},\"id\":\"{id}\""
    ));
}

pub fn ev_closure_sysgen(floor: u64, id: &str, empty: bool) {
    emit(format_args!(
        "\"ev\":\"closure.sysgen\",\"kind\":\"system-generation\",\"floor\":{floor},\"id\":\"{id}\",\"empty\":{empty}"
    ));
}

pub fn ev_closure_bound(kernel_floor: u64, sysgen_floor: u64, kernel_id: &str, sysgen_id: &str) {
    emit(format_args!(
        "\"ev\":\"closure.bound\",\"kernel_floor\":{kernel_floor},\"sysgen_floor\":{sysgen_floor},\"kernel_id\":\"{kernel_id}\",\"sysgen_id\":\"{sysgen_id}\""
    ));
}

pub fn ev_closure_reject(reason: &str) {
    emit(format_args!(
        "\"ev\":\"closure.reject\",\"reason\":\"{reason}\""
    ));
}

pub fn ev_component_bound() {
    emit(format_args!("\"ev\":\"component.bound\",\"empty\":false"));
}

pub fn ev_kernel_cr3(root: u64, flags: u64) {
    emit(format_args!(
        "\"ev\":\"kernel.cr3\",\"root\":\"{root:#x}\",\"flags\":{flags}"
    ));
}

pub fn ev_domain_started(id: u64, generation: u64, scenario: u64) {
    emit(format_args!(
        "\"ev\":\"domain.start\",\"id\":{id},\"generation\":{generation},\"scenario\":{scenario}"
    ));
}

pub fn ev_domain_entered(id: u64, generation: u64, cpl: u64) {
    emit(format_args!(
        "\"ev\":\"domain.entered\",\"id\":{id},\"generation\":{generation},\"cpl\":{cpl}"
    ));
}

pub fn ev_domain_context(
    id: u64,
    generation: u64,
    root: u64,
    flags: u64,
    cpl: u64,
    fs: u64,
    gs: u64,
) {
    emit(format_args!(
        "\"ev\":\"domain.context\",\"id\":{id},\"generation\":{generation},\
        \"root\":\"{root:#x}\",\"flags\":{flags},\"cpl\":{cpl},\"fs\":{fs},\"gs\":{gs}"
    ));
}

pub fn ev_domain_cancel_request(id: u64, generation: u64) {
    emit(format_args!(
        "\"ev\":\"domain.cancel.request\",\"id\":{id},\"generation\":{generation}"
    ));
}

pub fn ev_domain_trap_reject(reason: &str) {
    emit(format_args!(
        "\"ev\":\"domain.trap.reject\",\"reason\":\"{reason}\""
    ));
}

pub fn ev_domain_cancelled(id: u64, generation: u64) {
    emit(format_args!(
        "\"ev\":\"domain.cancelled\",\"id\":{id},\"generation\":{generation}"
    ));
}

pub fn ev_domain_cancel_rejected(id: u64, generation: u64, reason: &str) {
    emit(format_args!(
        "\"ev\":\"domain.cancel.reject\",\"id\":{id},\"generation\":{generation},\"reason\":\"{reason}\""
    ));
}

pub fn ev_domain_quota(id: u64, ticks: u32) {
    emit(format_args!(
        "\"ev\":\"domain.quota\",\"id\":{id},\"ticks\":{ticks}"
    ));
}

#[allow(clippy::too_many_arguments)]
pub fn ev_domain_registers(
    id: u64,
    generation: u64,
    cpl: u64,
    rdi: u64,
    rsp: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
) {
    emit(format_args!(
        "\"ev\":\"domain.registers\",\"id\":{id},\"generation\":{generation},\"cpl\":{cpl},\
        \"rax\":{rax},\"rbx\":{rbx},\"rcx\":{rcx},\"rdx\":{rdx},\"rsi\":{rsi},\"rdi\":{rdi},\
        \"rbp\":{rbp},\"r8\":{r8},\"r9\":{r9},\"r10\":{r10},\"r11\":{r11},\"r12\":{r12},\
        \"r13\":{r13},\"r14\":{r14},\"r15\":{r15},\"rsp\":\"{rsp:#x}\""
    ));
}

pub fn ev_domain_restore(id: u64, generation: u64, ok: bool, root: u64, flags: u64) {
    emit(format_args!(
        "\"ev\":\"domain.restore\",\"id\":{id},\"generation\":{generation},\"ok\":{ok},\
        \"root\":\"{root:#x}\",\"flags\":{flags}"
    ));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainEventIdentity {
    pub event_id: u64,
    pub generation: u64,
}

impl DomainEventIdentity {
    pub const fn new(event_id: u64, generation: u64) -> Self {
        Self {
            event_id,
            generation,
        }
    }
}

pub fn ev_domain_outcome(
    identity: DomainEventIdentity,
    kind: &str,
    vector: u8,
    error_code: u64,
    fault_address: u64,
    rip: u64,
    cpl: u64,
) {
    emit(format_args!(
        "\"ev\":\"domain.outcome\",\"id\":{},\"generation\":{},\"kind\":\"{kind}\",\
        \"vector\":{vector},\"error_code\":{error_code},\
        \"fault_address\":\"{fault_address:#x}\",\"rip\":\"{rip:#x}\",\"cpl\":{cpl}",
        identity.event_id, identity.generation,
    ));
}

pub fn ev_domain_reclaimed(
    id: u64,
    generation: u64,
    expected: u64,
    freed: u64,
    swept: u64,
    blocked: u64,
) {
    emit(format_args!(
        "\"ev\":\"domain.reclaim\",\"id\":{id},\"generation\":{generation},\"expected\":{expected},\"freed\":{freed},\"swept\":{swept},\"blocked\":{blocked}"
    ));
}

pub fn ev_domain_audit(frames: u64, wx_ok: bool, kernel_excluded: bool, peer_excluded: bool) {
    emit(format_args!(
        "\"ev\":\"domain.audit\",\"frames\":{frames},\"wx_ok\":{wx_ok},\"kernel_excluded\":{kernel_excluded},\"peer_excluded\":{peer_excluded}"
    ));
}

pub fn ev_domain_accounting(expected: u64, observed: u64) {
    emit(format_args!(
        "\"ev\":\"domain.accounting\",\"expected\":{expected},\"observed\":{observed}"
    ));
}

pub fn ev_domain_policy(audit_ok: bool, stack_zeroed: bool, probe_zeroed: bool) {
    emit(format_args!(
        "\"ev\":\"domain.policy\",\"audit_ok\":{audit_ok},\"stack_zeroed\":{stack_zeroed},\"probe_zeroed\":{probe_zeroed}"
    ));
}

pub fn ev_domain_exclusion(alias_excluded: bool, kernel_excluded: bool, peer_excluded: bool) {
    emit(format_args!(
        "\"ev\":\"domain.exclusion\",\"alias_excluded\":{alias_excluded},\"kernel_excluded\":{kernel_excluded},\"peer_excluded\":{peer_excluded}"
    ));
}

pub fn ev_domain_auth_reject(reason: &str) {
    emit(format_args!(
        "\"ev\":\"domain.auth.reject\",\"reason\":\"{reason}\""
    ));
}

pub fn ev_domain_harness(pass: bool) {
    emit(format_args!("\"ev\":\"domain.harness\",\"outcome\":{pass}"));
}

pub fn ev_ipc_op(id: u64, generation: u64, operation: &str, status: &str) {
    emit(format_args!(
        "\"ev\":\"ipc.op\",\"id\":{id},\"generation\":{generation},\"op\":\"{operation}\",\"status\":\"{status}\""
    ));
}

pub fn ev_ipc_park(id: u64, generation: u64) {
    emit(format_args!(
        "\"ev\":\"ipc.park\",\"id\":{id},\"generation\":{generation}"
    ));
}

pub fn ev_ipc_resume(id: u64, generation: u64) {
    emit(format_args!(
        "\"ev\":\"ipc.resume\",\"id\":{id},\"generation\":{generation}"
    ));
}

pub fn ev_ipc_wake(id: u64, generation: u64, status: &str) {
    emit(format_args!(
        "\"ev\":\"ipc.wake\",\"id\":{id},\"generation\":{generation},\"status\":\"{status}\""
    ));
}

pub fn ev_ipc_reclaim(id: u64, generation: u64, endpoints: u64, capabilities: u64, queued: u64) {
    emit(format_args!(
        "\"ev\":\"ipc.reclaim\",\"id\":{id},\"generation\":{generation},\"endpoints\":{endpoints},\"capabilities\":{capabilities},\"queued\":{queued}"
    ));
}

pub fn ev_halt(ok: bool) {
    let outcome = if ok { "ok" } else { "fault" };
    emit(format_args!("\"ev\":\"halt\",\"outcome\":\"{outcome}\""));
}

pub fn ev_panic(args: fmt::Arguments) {
    emit(format_args!("\"ev\":\"panic\",\"where\":\"{args}\""));
}

/// Write the isa-debug-exit port and hlt forever. QEMU maps written value `v`
/// to process exit code `(v << 1) | 1`: 0x10 -> 33 (success), 0x11 -> 35.
pub fn exit_qemu(success: bool) -> ! {
    let value: u32 = if success { 0x10 } else { 0x11 };
    let mut port: Port<u32> = Port::new(DEBUG_EXIT_PORT);
    unsafe { port.write(value) };
    loop {
        x86_64::instructions::hlt();
    }
}
