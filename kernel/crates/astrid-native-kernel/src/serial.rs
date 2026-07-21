//! COM1 serial writer and the machine-readable event bus.
//!
//! Every kernel event is exactly one line of JSON emitted over COM1 by polled
//! TX. A single spinlock guards both the monotonic `seq` counter and the UART,
//! and every emission runs with interrupts disabled for the duration of the
//! lock, so an interrupt handler can emit without deadlocking against the main
//! thread (charter: serialization-clean, strings are compile-time literals
//! only — this is the seed of the legibility ABI).

use core::fmt::{self, Write};

use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::instructions::port::Port;

const COM1_BASE: u16 = 0x3F8;
/// isa-debug-exit iobase (frozen machine contract).
const DEBUG_EXIT_PORT: u16 = 0xF4;

/// A minimal 16550 UART driver: polled transmit only.
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
    /// Touches COM1 I/O ports directly; must run once during early boot before
    /// any emission.
    unsafe fn init(&self) {
        let mut ier: Port<u8> = Port::new(self.base + 1);
        let mut lcr: Port<u8> = Port::new(self.base + 3);
        let mut dll: Port<u8> = Port::new(self.base);
        let mut dlm: Port<u8> = Port::new(self.base + 1);
        let mut fcr: Port<u8> = Port::new(self.base + 2);
        let mut mcr: Port<u8> = Port::new(self.base + 4);
        // SAFETY: standard 16550 init sequence on the fixed COM1 ports.
        unsafe {
            ier.write(0x00); // disable UART interrupts
            lcr.write(0x80); // enable DLAB
            dll.write(0x01); // divisor low  -> 115200
            dlm.write(0x00); // divisor high
            lcr.write(0x03); // 8 bits, no parity, one stop; DLAB off
            fcr.write(0xC7); // enable + clear FIFOs, 14-byte threshold
            mcr.write(0x0B); // DTR, RTS, OUT2
        }
    }

    #[inline]
    fn write_byte(&self, byte: u8) {
        let mut lsr: Port<u8> = Port::new(self.base + 5);
        let mut thr: Port<u8> = Port::new(self.base);
        // SAFETY: poll the line-status register until the transmit-holding
        // register is empty, then write one byte. COM1 ports only.
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

/// Program the UART. Call once, first thing in boot.
pub fn init() {
    without_interrupts(|| {
        // SAFETY: single early-boot caller, exclusive under the lock.
        unsafe { EMITTER.lock().port.init() };
    });
}

/// Emit one event line: `{"seq":N,<args>}\n`. `args` must render the `"ev"`
/// field and any structured, alloc-free payload from compile-time literals.
fn emit(args: fmt::Arguments) {
    without_interrupts(|| {
        let mut e = EMITTER.lock();
        let seq = e.seq;
        e.seq = seq.wrapping_add(1);
        // Writes to a polled UART are infallible in practice; ignore fmt error.
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

pub fn ev_domain_create(domain: usize, frames: usize) {
    emit(format_args!(
        "\"ev\":\"domain.create\",\"domain\":{domain},\"frames\":{frames}"
    ));
}

pub fn ev_domain_enter(domain: usize) {
    emit(format_args!("\"ev\":\"domain.enter\",\"domain\":{domain}"));
}

pub fn ev_domain_note(domain: usize, value: u64) {
    emit(format_args!(
        "\"ev\":\"domain.note\",\"domain\":{domain},\"value\":{value}"
    ));
}

pub fn ev_domain_fault(domain: usize, vector: u64, code: u64, rip: u64) {
    emit(format_args!(
        "\"ev\":\"domain.fault\",\"domain\":{domain},\"vector\":{vector},\"code\":{code},\"rip\":\"{rip:#x}\",\"cpl\":3"
    ));
}

pub fn ev_domain_exit(domain: usize, code: u64) {
    emit(format_args!(
        "\"ev\":\"domain.exit\",\"domain\":{domain},\"code\":{code}"
    ));
}

pub fn ev_domain_killed(domain: usize, cause: &'static str) {
    emit(format_args!(
        "\"ev\":\"domain.killed\",\"domain\":{domain},\"cause\":\"{cause}\""
    ));
}

pub fn ev_domain_reclaimed(domain: usize, frames_freed: usize, balance_ok: bool) {
    emit(format_args!(
        "\"ev\":\"domain.reclaimed\",\"domain\":{domain},\"frames_freed\":{frames_freed},\"balance_ok\":{balance_ok}"
    ));
}

pub fn ev_cap_revoked(object: u32, generation: u32) {
    emit(format_args!(
        "\"ev\":\"cap.revoked\",\"object\":{object},\"generation\":{generation}"
    ));
}

// ---- M3: bounded IPC endpoints + capability transfer by derivation ---------

pub fn ev_ep_create(object: u32, ep: u8, domain: usize) {
    emit(format_args!(
        "\"ev\":\"ep.create\",\"object\":{object},\"ep\":{ep},\"domain\":{domain}"
    ));
}

pub fn ev_ipc_send(ep: u8, from: usize, data: u64, cap: bool) {
    emit(format_args!(
        "\"ev\":\"ipc.send\",\"ep\":{ep},\"from\":{from},\"data\":{data},\"cap\":{cap}"
    ));
}

pub fn ev_ipc_recv(ep: u8, to: usize, data: u64, cap: bool) {
    emit(format_args!(
        "\"ev\":\"ipc.recv\",\"ep\":{ep},\"to\":{to},\"data\":{data},\"cap\":{cap}"
    ));
}

pub fn ev_ipc_blocked(domain: usize, ep: u8) {
    emit(format_args!(
        "\"ev\":\"ipc.blocked\",\"domain\":{domain},\"ep\":{ep}"
    ));
}

pub fn ev_ipc_wakeup(domain: usize, ep: u8) {
    emit(format_args!(
        "\"ev\":\"ipc.wakeup\",\"domain\":{domain},\"ep\":{ep}"
    ));
}

pub fn ev_ipc_cap_dropped(ep: u8) {
    emit(format_args!("\"ev\":\"ipc.cap_dropped\",\"ep\":{ep}"));
}

pub fn ev_cap_transfer(object: u32, from: usize, to: usize, rights: u32, node: u32) {
    emit(format_args!(
        "\"ev\":\"cap.transfer\",\"object\":{object},\"from\":{from},\"to\":{to},\"rights\":{rights},\"node\":{node}"
    ));
}

pub fn ev_cap_revoke_tree(node: u32, killed: usize) {
    emit(format_args!(
        "\"ev\":\"cap.revoke_tree\",\"node\":{node},\"killed\":{killed}"
    ));
}

pub fn ev_ipc_deadlock(domains: usize) {
    emit(format_args!(
        "\"ev\":\"ipc.deadlock\",\"domains\":{domains}"
    ));
}

pub fn ev_pools_census(objects_free: usize, endpoints_free: usize, deriv_free: usize) {
    emit(format_args!(
        "\"ev\":\"pools.census\",\"objects_free\":{objects_free},\"endpoints_free\":{endpoints_free},\"deriv_free\":{deriv_free}"
    ));
}

pub fn ev_test(name: &'static str, pass: bool) {
    let ev = if pass { "test.pass" } else { "test.fail" };
    emit(format_args!("\"ev\":\"{ev}\",\"name\":\"{name}\""));
}

pub fn ev_halt(ok: bool) {
    let outcome = if ok { "ok" } else { "fault" };
    emit(format_args!("\"ev\":\"halt\",\"outcome\":\"{outcome}\""));
}

pub fn ev_panic(args: fmt::Arguments) {
    emit(format_args!("\"ev\":\"panic\",\"where\":\"{args}\""));
}

/// Write the isa-debug-exit port and hlt forever. QEMU maps the written value
/// `v` to process exit code `(v << 1) | 1`: 0x10 -> 33 (success), 0x11 -> 35.
pub fn exit_qemu(success: bool) -> ! {
    let value: u32 = if success { 0x10 } else { 0x11 };
    let mut port: Port<u32> = Port::new(DEBUG_EXIT_PORT);
    // SAFETY: the frozen machine contract wires isa-debug-exit at 0xF4.
    unsafe { port.write(value) };
    loop {
        x86_64::instructions::hlt();
    }
}
