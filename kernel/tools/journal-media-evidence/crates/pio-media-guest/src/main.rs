#![no_std]
#![no_main]

#[path = "../../../shared/media.rs"]
mod media;

use core::arch::asm;
use core::hint::black_box;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};

use crate::media::{
    auth::Authenticator, build_slot_record, canonical_payload, parse_media, CommitMetadata,
    Recovery, FRAME_COUNT, KEY_ID, MEDIA_LEN, RECORD_LEN, RECORD_SECTORS, SECTOR_LEN,
    STATE_COMMITTED,
};

const COMMAND_BASE: u16 = 0x1f0;
const CONTROL_BASE: u16 = 0x3f6;
const REG_ERROR_FEATURES: u16 = COMMAND_BASE + 1;
const REG_SECTOR_COUNT: u16 = COMMAND_BASE + 2;
const REG_LBA_LOW: u16 = COMMAND_BASE + 3;
const REG_LBA_MID: u16 = COMMAND_BASE + 4;
const REG_LBA_HIGH: u16 = COMMAND_BASE + 5;
const REG_DEVICE: u16 = COMMAND_BASE + 6;
const REG_STATUS_COMMAND: u16 = COMMAND_BASE + 7;
const REG_ALT_STATUS_CONTROL: u16 = CONTROL_BASE;
const FW_CFG_SELECTOR: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;
const FW_CFG_FILE_DIR: u16 = 0x0019;
const UART_DATA: u16 = 0x3f8;
const DEBUG_EXIT_PORT: u16 = 0xf4;

const CMD_IDENTIFY_DEVICE: u8 = 0xec;
const CMD_READ_SECTORS_EXT: u8 = 0x24;
const CMD_WRITE_SECTORS_EXT: u8 = 0x34;
const CMD_FLUSH_CACHE_EXT: u8 = 0xea;
const STATUS_ERR: u8 = 0x01;
const STATUS_DRQ: u8 = 0x08;
const STATUS_DF: u8 = 0x20;
const STATUS_BSY: u8 = 0x80;

static mut MEDIA_MAP: [u8; MEDIA_LEN] = [0; MEDIA_LEN];
static mut STAGED_RECORD: [u8; RECORD_LEN] = [0; RECORD_LEN];
static mut TRANSFER_SECTOR: [u8; SECTOR_LEN] = [0; SECTOR_LEN];
static mut AUTHENTICATOR_KEY: [u8; 32] = [0; 32];
static mut FRESHNESS_FLOOR_TEXT: [u8; 32] = [0; 32];
static mut FRESHNESS_FLOOR_LEN: usize = 0;
static mut MODE_TEXT: [u8; 32] = [0; 32];
static mut CRASH_TEXT: [u8; 48] = [0; 48];

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    uart_print(b"PIO-GUEST-PANIC ");
    let _ = info;
    uart_print(b"freestanding");
    uart_print(b"\n");
    debug_exit(0x21)
}

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: u64, _system_table: u64) -> u64 {
    run()
}

fn run() -> ! {
    uart_print(b"PIO1691 BOOT\n");
    load_fw_cfg();
    print_config();
    identify_device();
    read_initial_media();
    let authenticator =
        Authenticator::new(*authenticator_key()).expect("external verifier key is nonzero");
    let fresh_floor = parse_floor();
    let observed = match parse_media(media_map(), fresh_floor, &authenticator) {
        Ok(result) => result,
        Err(_) => guest_panic("media-size"),
    };
    print_recovery(&observed);
    if starts_with_bytes(mode_text(), b"recover") {
        match observed {
            Recovery::Candidate { epoch, payload, .. } => {
                if payload != canonical_payload() {
                    guest_panic("authenticated-payload-mismatch");
                }
                print_exact(&[b"GUEST-AUTH-CANDIDATE ", b"EPOCH="]);
                uart_hex(epoch);
                uart_print(b"\n");
                finish();
            },
            Recovery::Torn { .. } => finish(),
            _ => guest_panic("RECOVERY-FAIL-CLOSED"),
        }
    }
    let blank_media = media_map().iter().all(|byte| *byte == 0);
    let (epoch, observed_slot, payload) = match observed {
        Recovery::Candidate {
            epoch,
            slot,
            payload,
        } => (epoch, slot, payload),
        Recovery::Torn {
            reason: "missing-commit",
        } if blank_media => (1000, media::Slot::A, canonical_payload()),
        _ => guest_panic("RECOVERY-FAIL-CLOSED"),
    };
    if payload != canonical_payload() {
        guest_panic("authenticated-payload-mismatch");
    }

    let target_slot = observed_slot.other();
    let next_epoch = epoch.max(fresh_floor).max(1000).saturating_add(1);
    *staged_record() = build_slot_record(
        &payload,
        CommitMetadata {
            state: STATE_COMMITTED,
            epoch: next_epoch,
        },
        target_slot,
        &authenticator,
    );

    invalidate_commit_if_present(target_slot);
    for frame_index in 0..FRAME_COUNT {
        crash_arm(frame_index);
        copy_frame_sector(target_slot.index(), frame_index);
        let lba = target_slot.index() as u64 * RECORD_SECTORS as u64 + frame_index as u64;
        pio_write_sector(lba, transfer_sector());
        print_hex_u64(b"GUEST-ATA WRITE.SECTORS.EXT=0x34 LBA=", lba);
    }

    pio_flush_cache_ext(b"data");
    read_back_frames_guest(target_slot);
    print_exact(&[b"PHASE ", b"DATA-F ", b"LUSHED-READBACK-OK\n"]);
    crash_before_commit_write();
    write_commit_sector(target_slot);
    crash_before_commit_flush();
    pio_flush_cache_ext(b"commit");
    verify_record_guest(&authenticator);
    print_exact(&[b"PIO1691 ", b"ROUNDTRIP PASS\n"]);
    finish()
}

fn starts_with_bytes(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()] == prefix[..]
}

fn patch_invalidated_commit(slot: media::Slot) {
    let start = slot.index() * RECORD_LEN + FRAME_COUNT * SECTOR_LEN;
    let invalidated = {
        let mut sector = [0u8; SECTOR_LEN];
        sector[..8].copy_from_slice(media::INVALID_MAGIC);
        sector[8..10].copy_from_slice(&2u16.to_le_bytes());
        sector[10..12].copy_from_slice(&1u16.to_le_bytes());
        sector[12] = slot.index() as u8;
        sector[15] = media::STATE_INVALIDATED;
        sector
    };
    let media = media_map();
    media[start..start + SECTOR_LEN].copy_from_slice(&invalidated);
}

fn invalidate_commit_if_present(slot: media::Slot) {
    let base = slot.index() * RECORD_LEN;
    let commit_start = base + FRAME_COUNT * SECTOR_LEN;
    let header = &media_map()[commit_start..commit_start + 8];
    let inactive =
        header.iter().all(|byte| *byte == 0) || starts_with_bytes(header, media::INVALID_MAGIC);
    if inactive {
        print_exact(&[b"INACTIVE ", b"-HAD-NO-COMMIT\n"]);
        return;
    }

    let mut invalidation = [0u8; SECTOR_LEN];
    invalidation[..8].copy_from_slice(media::INVALID_MAGIC);
    invalidation[8..10].copy_from_slice(&2u16.to_le_bytes());
    invalidation[10..12].copy_from_slice(&1u16.to_le_bytes());
    invalidation[12] = slot.index() as u8;
    invalidation[15] = media::STATE_INVALIDATED;
    let lba = slot.index() as u64 * RECORD_SECTORS as u64 + FRAME_COUNT as u64;
    pio_write_sector(lba, &invalidation);
    patch_invalidated_commit(slot);
    pio_flush_cache_ext(b"invalidation");
}

fn copy_frame_sector(slot_index: usize, frame_index: usize) {
    let source = frame_index * SECTOR_LEN;
    transfer_sector().copy_from_slice(&staged_record()[source..source + SECTOR_LEN]);
    black_box((slot_index, frame_index));
}

fn write_commit_sector(slot: media::Slot) {
    let start = FRAME_COUNT * SECTOR_LEN;
    transfer_sector().copy_from_slice(&staged_record()[start..start + SECTOR_LEN]);
    let lba = slot.index() as u64 * RECORD_SECTORS as u64 + FRAME_COUNT as u64;
    pio_write_sector(lba, transfer_sector());
    print_hex_u64(b"GUEST-ATA COMMIT-WRITE LBA=", lba);
}

fn read_initial_media() {
    print_exact(&[b"GUEST-ATA ", b"INITIAL-READ-BACK BEGIN COUNT=34\n"]);
    let mut sector = [0u8; SECTOR_LEN];
    for lba in 0..(MEDIA_LEN / SECTOR_LEN) as u64 {
        pio_read_sector(lba, &mut sector);
        let start = lba as usize * SECTOR_LEN;
        media_map()[start..start + SECTOR_LEN].copy_from_slice(&sector);
    }
    print_exact(&[b"GUEST-ATA ", b"INITIAL-READ-BACK STATUS=OK\n"]);
}

fn read_back_frames_guest(slot: media::Slot) {
    let base_lba = slot.index() as u64 * RECORD_SECTORS as u64;
    let mut observed = [0u8; SECTOR_LEN];
    for index in 0..FRAME_COUNT {
        pio_read_sector(base_lba + index as u64, &mut observed);
        let start = index * SECTOR_LEN;
        if observed != staged_record()[start..start + SECTOR_LEN] {
            guest_panic("DATA-READBACK-MISMATCH");
        }
    }
}

fn verify_record_guest(authenticator: &Authenticator) {
    let mut observed = [0u8; MEDIA_LEN];
    let mut sector = [0u8; SECTOR_LEN];
    for slot in media::Slot::ALL {
        let base_lba = slot.index() as u64 * RECORD_SECTORS as u64;
        for index in 0..RECORD_SECTORS {
            pio_read_sector(base_lba + index as u64, &mut sector);
            let destination = slot.index() * RECORD_LEN + index * SECTOR_LEN;
            observed[destination..destination + SECTOR_LEN].copy_from_slice(&sector);
        }
    }
    match parse_media(&observed, parse_floor(), authenticator) {
        Ok(Recovery::Candidate { epoch, payload, .. }) if payload == canonical_payload() => {
            print_exact(&[b"GUEST-AUTH-CANDIDATE ", b"EPOCH="]);
            uart_hex(epoch);
            uart_print(b"\n");
        },
        _ => guest_panic("guest-final-authentication-failed"),
    }
}

fn identify_device() {
    print_exact(&[b"GUEST-ATA ", b"IDENTIFY-BEGIN\n"]);
    let initial_status = wait_device_ready();
    print_hex_u64(b"GUEST-ATA INITIAL-STATUS=", u64::from(initial_status));
    write_u8(REG_DEVICE, 0xa0);
    io_delay_400ns();
    wait_not_busy_or_die();
    write_u8(REG_ERROR_FEATURES, 0);
    write_u8(REG_SECTOR_COUNT, 0);
    write_u8(REG_LBA_LOW, 0);
    write_u8(REG_LBA_MID, 0);
    write_u8(REG_LBA_HIGH, 0);
    write_u8(REG_STATUS_COMMAND, CMD_IDENTIFY_DEVICE);
    print_exact(&[b"GUEST-ATA ", b"IDENTIFY-COMMAND-ISSUED\n"]);
    wait_data_or_die();
    print_exact(&[b"GUEST-ATA ", b"IDENTIFY-DATA-READY\n"]);
    let mut words = [0u16; 256];
    for word in words.iter_mut() {
        *word = read_u16(COMMAND_BASE);
    }
    wait_transfer_complete();
    print_hex_u64(b"GUEST-ATA IDENTIFY-WORD83=", u64::from(words[83]));
    print_hex_u64(b"GUEST-ATA IDENTIFY-WORD106=", u64::from(words[106]));
    if words[83] & (1 << 10) == 0 || words[83] & (1 << 13) == 0 {
        guest_panic("IDENTIFY-LBA48-OR-FLUSHEXT-MISSING");
    }
    print_exact(&[
        b"GUEST-ATA IDENTIFY.DEVICE=0xEC ",
        b"SECTORS=512 LBA48=YES FLUSH=YES\n",
    ]);
}

fn wait_device_ready() -> u8 {
    for _attempt in 0..20_000_000usize {
        let status = read_u8(REG_ALT_STATUS_CONTROL);
        if status & STATUS_BSY == 0 && status != 0xff {
            return status;
        }
    }
    guest_panic("ATA-DEVICE-READY-TIMEOUT");
}

fn select_lba48(lba: u64) {
    write_u8(REG_DEVICE, 0xe0);
    io_delay_400ns();
    write_u8(REG_ERROR_FEATURES, 0);
    write_u8(REG_SECTOR_COUNT, 0);
    write_u8(REG_LBA_LOW, (lba >> 24) as u8);
    write_u8(REG_LBA_MID, (lba >> 32) as u8);
    write_u8(REG_LBA_HIGH, (lba >> 40) as u8);
    write_u8(REG_ERROR_FEATURES, 0);
    write_u8(REG_SECTOR_COUNT, 1);
    write_u8(REG_LBA_LOW, lba as u8);
    write_u8(REG_LBA_MID, (lba >> 8) as u8);
    write_u8(REG_LBA_HIGH, (lba >> 16) as u8);
    io_delay_400ns();
}

fn wait_not_busy() -> u8 {
    loop {
        let status = read_u8(REG_ALT_STATUS_CONTROL);
        if status & STATUS_BSY == 0 {
            return status;
        }
    }
}

fn wait_status(required: u8) -> u8 {
    for _attempt in 0..20_000_000usize {
        let status = read_u8(REG_ALT_STATUS_CONTROL);
        if status & (STATUS_ERR | STATUS_DF) != 0 {
            guest_panic("ATA-WAIT-STATUS-ERROR");
        }
        if status & STATUS_BSY == 0 && status & required != 0 {
            return status;
        }
    }
    guest_panic("ATA-WAIT-TIMEOUT");
}

fn check_ata_status(status: u8) {
    if status & (STATUS_ERR | STATUS_DF) != 0 {
        print_hex_u64(b"GUEST-ATA STATUS=", u64::from(status));
        print_hex_u64(b"GUEST-ATA ERROR=", u64::from(read_u8(REG_ERROR_FEATURES)));
        guest_panic("ATA-STATUS-ERROR");
    }
}

fn wait_transfer_complete() {
    let status = wait_not_busy();
    if status & STATUS_DRQ != 0 {
        print_hex_u64(b"GUEST-ATA STATUS=", u64::from(status));
        print_hex_u64(b"GUEST-ATA ERROR=", u64::from(read_u8(REG_ERROR_FEATURES)));
        guest_panic("ATA-DRQ-STILL-ASSERTED");
    }
    check_ata_status(status);
}

fn wait_not_busy_or_die() {
    check_ata_status(wait_not_busy());
}

fn wait_data_or_die() {
    wait_status(STATUS_DRQ);
}

fn pio_read_sector(lba: u64, sector: &mut [u8; SECTOR_LEN]) {
    wait_not_busy_or_die();
    select_lba48(lba);
    write_u8(REG_STATUS_COMMAND, CMD_READ_SECTORS_EXT);
    wait_data_or_die();
    for pair in sector.chunks_exact_mut(2) {
        let bytes = read_u16(COMMAND_BASE).to_le_bytes();
        (*pair).copy_from_slice(&bytes);
    }
    wait_transfer_complete();
    print_hex_u64(b"GUEST-ATA READ.SECTORS.EXT=0x24 LBA=", lba);
}

fn pio_write_sector(lba: u64, sector: &[u8; SECTOR_LEN]) {
    wait_not_busy_or_die();
    select_lba48(lba);
    write_u8(REG_STATUS_COMMAND, CMD_WRITE_SECTORS_EXT);
    wait_data_or_die();
    for pair in sector.chunks_exact(2) {
        write_u16(COMMAND_BASE, u16::from_le_bytes([pair[0], pair[1]]));
    }
    wait_transfer_complete();
}

fn pio_flush_cache_ext(phase: &[u8]) {
    uart_print(b"GUEST-ATA FLUSH.CACHE.EXT=0xEA FLUSH.BEGIN PHASE=");
    uart_print(phase);
    uart_print(b"\n");
    wait_not_busy_or_die();
    write_u8(REG_DEVICE, 0xe0);
    io_delay_400ns();
    write_u8(REG_STATUS_COMMAND, CMD_FLUSH_CACHE_EXT);
    check_ata_status(wait_not_busy());
    print_exact(&[b"GUEST-ATA ", b"FLUSH.STATUS=OK\n"]);
}

fn io_delay_400ns() {
    for _ in 0..4 {
        black_box(read_u8(REG_ALT_STATUS_CONTROL));
    }
}

fn write_u8(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack)
        );
    }
}

fn write_u16(port: u16, value: u16) {
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack)
        );
    }
}

fn read_u8(port: u16) -> u8 {
    let value;
    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack)
        );
    }
    value
}

fn read_u16(port: u16) -> u16 {
    let value;
    unsafe {
        asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack)
        );
    }
    value
}

fn media_map() -> &'static mut [u8; MEDIA_LEN] {
    unsafe { &mut *addr_of_mut!(MEDIA_MAP) }
}

fn staged_record() -> &'static mut [u8; RECORD_LEN] {
    unsafe { &mut *addr_of_mut!(STAGED_RECORD) }
}

fn transfer_sector() -> &'static mut [u8; SECTOR_LEN] {
    unsafe { &mut *addr_of_mut!(TRANSFER_SECTOR) }
}

fn authenticator_key() -> &'static mut [u8; 32] {
    unsafe { &mut *addr_of_mut!(AUTHENTICATOR_KEY) }
}

fn set_freshness_floor(bytes: &[u8]) {
    let text = unsafe { &mut *addr_of_mut!(FRESHNESS_FLOOR_TEXT) };
    let stored = bytes.len().min(text.len());
    text[..stored].copy_from_slice(&bytes[..stored]);
    unsafe { *addr_of_mut!(FRESHNESS_FLOOR_LEN) = stored };
}

fn freshness_floor_text() -> &'static [u8; 32] {
    unsafe { &*addr_of!(FRESHNESS_FLOOR_TEXT) }
}

fn freshness_floor_len() -> usize {
    unsafe { *addr_of!(FRESHNESS_FLOOR_LEN) }
}

fn mode_text() -> &'static [u8; 32] {
    unsafe { &*addr_of!(MODE_TEXT) }
}

fn crash_text() -> [u8; 48] {
    unsafe { *addr_of!(CRASH_TEXT) }
}

fn load_fw_cfg() {
    write_u16(FW_CFG_SELECTOR, FW_CFG_FILE_DIR);
    read_fw_cfg_file(b"opt/astrid.pio.key", authenticator_key());
    let mut floor = [0u8; 32];
    let floor_len = read_fw_cfg_file(b"opt/astrid.pio.floor", &mut floor);
    set_freshness_floor(&floor[..floor_len]);
    read_fw_cfg_file(b"opt/astrid.pio.mode", unsafe {
        &mut *addr_of_mut!(MODE_TEXT)
    });
    read_fw_cfg_file(b"opt/astrid.pio.crash", unsafe {
        &mut *addr_of_mut!(CRASH_TEXT)
    });
}

fn read_fw_cfg_file(name: &[u8], output: &mut [u8]) -> usize {
    write_u16(FW_CFG_SELECTOR, FW_CFG_FILE_DIR);
    let count = read_fw_cfg_u16_from_u32();
    for _ in 0..count {
        let mut size_be = [0u8; 4];
        for byte in size_be.iter_mut() {
            *byte = read_u8(FW_CFG_DATA);
        }
        let entry_size = u32::from_be_bytes(size_be) as usize;
        let selector_be = [read_u8(FW_CFG_DATA), read_u8(FW_CFG_DATA)];
        let _reserved = [read_u8(FW_CFG_DATA), read_u8(FW_CFG_DATA)];
        let mut entry_name = [0u8; 56];
        for byte in entry_name.iter_mut() {
            *byte = read_u8(FW_CFG_DATA);
        }
        if name.len() < entry_name.len()
            && entry_name.starts_with(name)
            && entry_name[name.len()] == 0
        {
            write_u16(FW_CFG_SELECTOR, u16::from_be_bytes(selector_be));
            let stored = entry_size.min(output.len());
            for destination in output[..stored].iter_mut() {
                *destination = read_u8(FW_CFG_DATA);
            }
            return stored;
        }
    }
    0
}

fn print_config() {
    print("EXTERNAL-KEY-FWCFG=PRESENT KEY-ID=");
    uart_print(KEY_ID);
    print("\nEXTERNAL-FLOOR=");
    let length = freshness_floor_len();
    uart_print(&freshness_floor_text()[..length]);
    print("\nMODE=");
    print_zero_terminated(mode_text());
    print("\nCRASH-POINT=");
    print_zero_terminated(&crash_text());
    print("\n");
}

fn parse_floor() -> u64 {
    let length = freshness_floor_len();
    parse_ascii_u64(&freshness_floor_text()[..length])
}

fn parse_ascii_u64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|next| next.checked_add(u64::from(byte.wrapping_sub(b'0'))))
            .expect("numeric fw_cfg floor")
    })
}

fn crash_arm(frame_index: usize) {
    let text = crash_text();
    if !starts_with_bytes(&text, b"frame:") {
        return;
    }
    let digits_end = text[6..]
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(text.len());
    if digits_end == 6 {
        return;
    }
    if parse_ascii_u64(&text[6..digits_end]) as usize == frame_index {
        print_hex_u64(b"CRASH-BARRIER FRAME=", frame_index as u64);
        spin_for_kill();
    }
}

fn crash_before_commit_write() {
    let text = crash_text();
    if starts_with_bytes(&text, b"before-commit") {
        print_exact(&[b"CRASH-BARRIER ", b"BEFORE-COMMIT\n"]);
        spin_for_kill();
    }
}

fn crash_before_commit_flush() {
    let text = crash_text();
    if starts_with_bytes(&text, b"commit-flush-begin") {
        print_exact(&[b"CRASH-BARRIER ", b"COMMIT-FLUSH-BEGIN\n"]);
        spin_for_kill();
    }
}

fn spin_for_kill() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn print(text: &'static str) {
    uart_print(text.as_bytes());
}

fn print_exact(parts: &[&[u8]]) {
    for part in parts {
        uart_print(part);
    }
}

fn print_zero_terminated(bytes: &[u8]) {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    uart_print(&bytes[..end]);
}

fn print_recovery(recovery: &Recovery) {
    match *recovery {
        Recovery::Candidate { epoch, .. } => print_hex_u64(b"RECOVERY=CANDIDATE EPOCH=", epoch),
        Recovery::Torn { reason } => {
            print("RECOVERY=TORN REASON=");
            uart_print(reason.as_bytes());
            uart_print(b"\n");
        },
        Recovery::ConflictingSameEpoch { epoch } => {
            print_hex_u64(b"RECOVERY=SAME-EPOCH-CONFLICT EPOCH=", epoch)
        },
        Recovery::Uncommitted { epoch } => print_hex_u64(b"RECOVERY=UNCOMMITTED EPOCH=", epoch),
        Recovery::StaleEpoch { found, floor } => {
            print_hex_u64(b"RECOVERY=STALE FOUND=", found);
            print_hex_u64(b"FLOOR=", floor);
        },
    }
}

fn print_hex_u64(label: &[u8], value: u64) {
    uart_print(label);
    uart_hex(value);
    uart_print(b"\n");
}

fn uart_hex(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digits = [0u8; 16];
    for index in 0..digits.len() {
        digits[15 - index] = HEX[((value >> (index * 4)) & 0xf) as usize];
    }
    uart_print(&digits);
}

fn uart_print(mut bytes: &[u8]) {
    while let Some((first, rest)) = bytes.split_first() {
        uart_send_byte(*first);
        bytes = rest;
    }
}

fn uart_send_byte(value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") UART_DATA,
            in("al") value,
            options(nomem, nostack)
        );
    }
}

fn read_fw_cfg_u16_from_u32() -> u16 {
    let mut bytes = [0u8; 4];
    for byte in bytes.iter_mut() {
        *byte = read_u8(FW_CFG_DATA);
    }
    // QEMU's directory count is a full 32-bit big-endian value. Preserve its
    // low half after consuming all four stream bytes.
    u16::from_be_bytes([bytes[2], bytes[3]])
}

fn finish() -> ! {
    print_exact(&[b"PIO1691 ", b"SUCCESS\n"]);
    debug_exit(0x10)
}

fn guest_panic(message: &'static str) -> ! {
    print("PIO-GUEST-PANIC ");
    print(message);
    print("\n");
    debug_exit(0x21)
}

fn debug_exit(value: u8) -> ! {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") DEBUG_EXIT_PORT,
            in("al") value,
            options(nomem, nostack)
        );
    }
    halt()
}

fn halt() -> ! {
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) }
    }
}
