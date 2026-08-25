use super::{
    DEFAULT_INSTRUCTION_FUEL, DRAM_BASE, MAX_INSTRUCTION_FUEL, MachineError, PortableMachine,
    RAM_BYTES,
};
use crate::fixtures::{alice_principal, bob_principal};
use crate::image::{
    GuestImage, MAX_IMAGE_BYTES, SYNTHETIC_EXIT_SEVEN, SYNTHETIC_EXIT_ZERO, encode_jal,
    encode_load, encode_store,
};

fn words_to_bytes(words: &[u32]) -> ([u8; MAX_IMAGE_BYTES], usize) {
    let mut bytes = [0_u8; MAX_IMAGE_BYTES];
    for (index, word) in words.iter().enumerate() {
        let encoded = word.to_le_bytes();
        let offset = index * 4;
        bytes[offset..offset + 4].copy_from_slice(&encoded);
    }
    (bytes, words.len() * 4)
}

fn run_words(words: &[u32], fuel: u64) -> Result<(u8, u64), MachineError> {
    let (buffer, len) = words_to_bytes(words);
    let image = GuestImage::admit(&buffer[..len])?;
    let mut machine = PortableMachine::for_owner(alice_principal(), &image, fuel)?;
    let status = machine.run(alice_principal())?;
    Ok((status, machine.instructions_retired()))
}

const ECALL: u32 = 0x0000_0073;

const fn encode_i(opcode: u32, rd: u32, rs1: u32, funct3: u32, immediate: i32) -> u32 {
    ((immediate as u32 & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

const fn encode_r(opcode: u32, rd: u32, rs1: u32, rs2: u32, funct3: u32, funct7: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

const fn encode_shift_i(rd: u32, rs1: u32, funct3: u32, funct6: u32, shamt: u32) -> u32 {
    (funct6 << 26) | ((shamt & 0x3f) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x13
}

const fn encode_shift_i32(rd: u32, rs1: u32, funct3: u32, funct7: u32, shamt: u32) -> u32 {
    (funct7 << 25) | ((shamt & 0x1f) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x1b
}

const fn encode_u(opcode: u32, rd: u32, immediate: u32) -> u32 {
    (immediate << 12) | (rd << 7) | opcode
}

const fn encode_b(rs1: u32, rs2: u32, immediate: u32, funct3: u32) -> u32 {
    (((immediate >> 12) & 1) << 31)
        | (((immediate >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((immediate >> 1) & 0x0f) << 8)
        | (((immediate >> 11) & 1) << 7)
        | 0x63
}

const fn encode_jalr(rd: u32, rs1: u32, immediate: i32) -> u32 {
    encode_i(0x67, rd, rs1, 0, immediate)
}

fn machine_words(words: &[u32], fuel: u64) -> Result<PortableMachine, MachineError> {
    let (buffer, len) = words_to_bytes(words);
    let image = GuestImage::admit(&buffer[..len])?;
    PortableMachine::for_owner(alice_principal(), &image, fuel)
}

fn assert_register(machine: &PortableMachine, register: usize, expected: u64) {
    assert_eq!(machine.regs[register], expected, "x{register} mismatch");
}

#[test]
fn synthetic_exit_images_retire_guest_instructions() {
    let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).unwrap();
    let mut machine =
        PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_eq!(machine.instructions_retired(), 2);

    let image = GuestImage::admit(&SYNTHETIC_EXIT_SEVEN).unwrap();
    let mut machine =
        PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(7));
    assert_eq!(machine.instructions_retired(), 2);
}

#[test]
fn illegal_and_unsupported_instructions_trap() {
    assert!(matches!(
        run_words(&[0x0000_0000], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::IllegalInstruction { instruction: 0, .. })
    ));
    assert!(matches!(
        run_words(&[0xC000_2073], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::UnsupportedInstruction {
            instruction: 0xC000_2073,
            ..
        })
    ));
    assert!(matches!(
        run_words(&[0x0010_0073], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::UnsupportedInstruction { .. })
    ));
    assert!(matches!(
        run_words(&[0x0000_100f], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::UnsupportedInstruction {
            instruction: 0x0000_100f,
            ..
        })
    ));
    assert_eq!(
        run_words(&[0x0000_000f, 0x0000_0073], DEFAULT_INSTRUCTION_FUEL),
        Ok((0, 2))
    );
}

#[test]
fn store_beyond_ram_and_fuel_exhaustion_fail_closed() {
    let oob = [encode_store(0, 0, 0, 2)];
    assert!(matches!(
        run_words(&oob, DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::StoreAccessFault { address: 0 })
    ));
    let load_oob = [encode_load(6, 0, 0, 3)];
    assert!(matches!(
        run_words(&load_oob, DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::LoadAccessFault { .. })
    ));
    assert_eq!(
        run_words(&[encode_jal(0, 0)], 4),
        Err(MachineError::FuelExhausted)
    );
}

#[test]
fn alice_ram_cannot_be_selected_or_mutated_as_bob() {
    let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).unwrap();
    let mut alice =
        PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL).unwrap();
    alice.store_u8(DRAM_BASE, 0xAA, alice_principal()).unwrap();
    assert_eq!(
        alice.require_owner(bob_principal()),
        Err(MachineError::PrincipalMismatch)
    );
    assert_eq!(
        alice.load_u8(DRAM_BASE, bob_principal()),
        Err(MachineError::PrincipalMismatch)
    );
    assert_eq!(
        alice.store_u8(DRAM_BASE, 0xBB, bob_principal()),
        Err(MachineError::PrincipalMismatch)
    );
    assert_eq!(alice.load_u8(DRAM_BASE, alice_principal()), Ok(0xAA));
    assert_eq!(
        alice.run(bob_principal()),
        Err(MachineError::PrincipalMismatch)
    );
    let bob =
        PortableMachine::for_owner(bob_principal(), &image, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_ne!(alice.owner(), bob.owner());
    assert_eq!(
        bob.load_u8(DRAM_BASE, bob_principal()).unwrap(),
        SYNTHETIC_EXIT_ZERO[0]
    );
}

// This is intentionally a crate-private architectural oracle. It compares
// the admitted load/store encodings with the RV64I sign-extension and
// little-endian results, without claiming an external ISA certification.
#[test]
fn rv64i_load_store_classes_match_architectural_oracle() {
    let words = [
        encode_u(0x17, 1, 0),                          // auipc x1, 0
        encode_i(0x13, 1, 1, 0, 128),                  // addi x1, x1, 128
        encode_i(0x13, 2, 0, 0, -1),                   // addi x2, x0, -1
        super::super::image::encode_store(1, 2, 0, 0), // sb x2, 0(x1)
        super::super::image::encode_store(1, 2, 2, 1), // sh x2, 2(x1)
        super::super::image::encode_store(1, 2, 4, 2), // sw x2, 4(x1)
        super::super::image::encode_store(1, 2, 8, 3), // sd x2, 8(x1)
        super::super::image::encode_load(3, 1, 0, 0),  // lb x3, 0(x1)
        super::super::image::encode_load(4, 1, 0, 4),  // lbu x4, 0(x1)
        super::super::image::encode_load(5, 1, 2, 1),  // lh x5, 2(x1)
        super::super::image::encode_load(6, 1, 2, 5),  // lhu x6, 2(x1)
        super::super::image::encode_load(7, 1, 4, 2),  // lw x7, 4(x1)
        super::super::image::encode_load(8, 1, 4, 6),  // lwu x8, 4(x1)
        super::super::image::encode_load(9, 1, 8, 3),  // ld x9, 8(x1)
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 1, DRAM_BASE + 128);
    assert_register(&machine, 2, u64::MAX);
    assert_register(&machine, 3, u64::MAX);
    assert_register(&machine, 4, 0xff);
    assert_register(&machine, 5, u64::MAX);
    assert_register(&machine, 6, 0xffff);
    assert_register(&machine, 7, u64::MAX);
    assert_register(&machine, 8, 0xffff_ffff);
    assert_register(&machine, 9, u64::MAX);
    assert_eq!(
        &machine.ram[128..136],
        &[0xff, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn rv64i_op_imm_class_matches_architectural_oracle() {
    let words = [
        encode_i(0x13, 1, 0, 0, -8),
        encode_i(0x13, 2, 0, 0, 3),
        encode_i(0x13, 3, 1, 2, 0),        // slti x3, x1, 0
        encode_i(0x13, 4, 1, 3, 0),        // sltiu x4, x1, 0
        encode_i(0x13, 5, 1, 4, 0x0ff),    // xori x5, x1, 0xff
        encode_i(0x13, 6, 2, 6, 0x100),    // ori x6, x2, 0x100
        encode_i(0x13, 7, 1, 7, -1),       // andi x7, x1, -1
        encode_shift_i(8, 2, 1, 0, 4),     // slli x8, x2, 4
        encode_shift_i(9, 1, 5, 0, 2),     // srli x9, x1, 2
        encode_shift_i(11, 1, 5, 0x10, 2), // srai x11, x1, 2
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 1, u64::MAX - 7);
    assert_register(&machine, 2, 3);
    assert_register(&machine, 3, 1);
    assert_register(&machine, 4, 0);
    assert_register(&machine, 5, u64::MAX - 248);
    assert_register(&machine, 6, 0x103);
    assert_register(&machine, 7, u64::MAX - 7);
    assert_register(&machine, 8, 48);
    assert_register(&machine, 9, 0x3fff_ffff_ffff_fffe);
    assert_register(&machine, 11, u64::MAX - 1);
}

#[test]
fn rv64i_op_class_matches_architectural_oracle() {
    let words = [
        encode_i(0x13, 1, 0, 0, -8),
        encode_i(0x13, 2, 0, 0, 3),
        encode_r(0x33, 3, 1, 2, 0, 0),     // add x3, x1, x2
        encode_r(0x33, 4, 1, 2, 0, 0x20),  // sub x4, x1, x2
        encode_r(0x33, 5, 1, 2, 1, 0),     // sll x5, x1, x2
        encode_r(0x33, 6, 1, 2, 2, 0),     // slt x6, x1, x2
        encode_r(0x33, 7, 1, 2, 3, 0),     // sltu x7, x1, x2
        encode_r(0x33, 8, 1, 2, 4, 0),     // xor x8, x1, x2
        encode_r(0x33, 9, 1, 2, 5, 0),     // srl x9, x1, x2
        encode_r(0x33, 11, 1, 2, 5, 0x20), // sra x11, x1, x2
        encode_r(0x33, 12, 1, 2, 6, 0),    // or x12, x1, x2
        encode_r(0x33, 13, 1, 2, 7, 0),    // and x13, x1, x2
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 3, u64::MAX - 4);
    assert_register(&machine, 4, u64::MAX - 10);
    assert_register(&machine, 5, u64::MAX - 63);
    assert_register(&machine, 6, 1);
    assert_register(&machine, 7, 0);
    assert_register(&machine, 8, u64::MAX - 4);
    assert_register(&machine, 9, 0x1fff_ffff_ffff_ffff);
    assert_register(&machine, 11, u64::MAX);
    assert_register(&machine, 12, u64::MAX - 4);
    assert_register(&machine, 13, 0);
}

#[test]
fn rv64i_word_classes_match_architectural_oracle() {
    let op_imm_words = [
        encode_u(0x37, 1, 0x80000), // lui x1, 0x80000 -> sign-extended i32
        encode_i(0x13, 2, 0, 0, 1),
        encode_i(0x1b, 3, 1, 0, 1),         // addiw x3, x1, 1
        encode_shift_i32(4, 2, 1, 0, 1),    // slliw x4, x2, 1
        encode_shift_i32(5, 1, 5, 0, 1),    // srliw x5, x1, 1
        encode_shift_i32(6, 1, 5, 0x20, 1), // sraiw x6, x1, 1
        ECALL,
    ];
    let mut machine = machine_words(&op_imm_words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 1, 0xffff_ffff_8000_0000);
    assert_register(&machine, 3, 0xffff_ffff_8000_0001);
    assert_register(&machine, 4, 2);
    assert_register(&machine, 5, 0x0000_0000_4000_0000);
    assert_register(&machine, 6, 0xffff_ffff_c000_0000);

    let op_words = [
        encode_i(0x13, 1, 0, 0, -8),
        encode_i(0x13, 2, 0, 0, 3),
        encode_r(0x3b, 3, 1, 2, 0, 0),    // addw
        encode_r(0x3b, 4, 1, 2, 0, 0x20), // subw
        encode_r(0x3b, 5, 1, 2, 1, 0),    // sllw
        encode_r(0x3b, 6, 1, 2, 5, 0),    // srlw
        encode_r(0x3b, 7, 1, 2, 5, 0x20), // sraw
        ECALL,
    ];
    let mut machine = machine_words(&op_words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 3, u64::MAX - 4);
    assert_register(&machine, 4, u64::MAX - 10);
    assert_register(&machine, 5, u64::MAX - 63);
    assert_register(&machine, 6, 0x0000_0000_1fff_ffff);
    assert_register(&machine, 7, u64::MAX);
}

#[test]
fn rv64i_lui_auipc_and_jumps_match_architectural_oracle() {
    let words = [
        encode_u(0x37, 1, 0x12345), // lui x1, 0x12345
        encode_u(0x17, 2, 0),       // auipc x2, 0 at pc + 4
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 1, 0x1234_5000);
    assert_register(&machine, 2, DRAM_BASE + 4);

    let words = [
        super::super::image::encode_jal(1, 12),
        encode_i(0x13, 10, 0, 0, 1),
        ECALL,
        encode_i(0x13, 10, 0, 0, 7),
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(7));
    assert_register(&machine, 1, DRAM_BASE + 4);
    assert_register(&machine, 10, 7);

    let words = [
        encode_u(0x17, 1, 0),
        encode_i(0x13, 1, 1, 0, 12),
        encode_jalr(5, 1, 0),
        encode_i(0x13, 10, 0, 0, 7),
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(7));
    assert_register(&machine, 1, DRAM_BASE + 12);
    assert_register(&machine, 5, DRAM_BASE + 12);
    assert_register(&machine, 10, 7);
}

fn run_branch(funct3: u32, lhs: i32, rhs: i32) -> u8 {
    let words = [
        encode_i(0x13, 1, 0, 0, lhs),
        encode_i(0x13, 2, 0, 0, rhs),
        encode_b(1, 2, 12, funct3),
        encode_i(0x13, 10, 0, 0, 1),
        ECALL,
        encode_i(0x13, 10, 0, 0, 2),
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    machine.run(alice_principal()).unwrap()
}

#[test]
fn rv64i_branch_classes_match_architectural_oracle() {
    let cases = [
        (0, 1, 1, 2),  // beq taken
        (0, 1, 2, 1),  // beq not taken
        (1, 1, 2, 2),  // bne taken
        (1, 1, 1, 1),  // bne not taken
        (4, -1, 0, 2), // blt taken
        (4, 1, 0, 1),  // blt not taken
        (5, 1, 0, 2),  // bge taken
        (5, -1, 0, 1), // bge not taken
        (6, 0, 1, 2),  // bltu taken
        (6, 1, 0, 1),  // bltu not taken
        (7, 1, 0, 2),  // bgeu taken
        (7, 0, 1, 1),  // bgeu not taken
    ];
    for (funct3, lhs, rhs, expected) in cases {
        assert_eq!(run_branch(funct3, lhs, rhs), expected);
    }
}

#[test]
fn rv64i_x0_and_wraparound_rules_match_architectural_oracle() {
    let words = [
        encode_i(0x13, 0, 0, 0, 5), // writes to x0 are discarded
        encode_i(0x13, 1, 0, 0, -1),
        encode_i(0x13, 2, 1, 0, 1),       // -1 + 1 wraps to zero
        encode_r(0x33, 3, 0, 1, 0, 0),    // 0 + -1 wraps to max
        encode_r(0x33, 4, 0, 1, 0, 0x20), // 0 - -1 = 1
        ECALL,
    ];
    let mut machine = machine_words(&words, DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(machine.run(alice_principal()), Ok(0));
    assert_register(&machine, 0, 0);
    assert_register(&machine, 1, u64::MAX);
    assert_register(&machine, 2, 0);
    assert_register(&machine, 3, u64::MAX);
    assert_register(&machine, 4, 1);
}

#[test]
fn rv64i_hostile_encodings_and_boundaries_remain_fail_closed() {
    let illegal = [
        0x0000_0000,
        0x0000_007f,
        encode_i(0x03, 1, 0, 7, 0),
        super::super::image::encode_store(0, 0, 0, 4),
        encode_b(0, 0, 12, 2),
        encode_r(0x33, 1, 0, 0, 0, 1),
        encode_shift_i(1, 0, 1, 1, 1),
        encode_i(0x0f, 0, 0, 2, 0),
    ];
    for instruction in illegal {
        assert!(matches!(
            run_words(&[instruction], DEFAULT_INSTRUCTION_FUEL),
            Err(MachineError::IllegalInstruction { instruction: actual, .. }) if actual == instruction
        ));
    }

    assert!(matches!(
        run_words(&[0x0000_100f], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::UnsupportedInstruction {
            instruction: 0x0000_100f,
            ..
        })
    ));
    assert!(matches!(
        run_words(&[0x0000_1073], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::UnsupportedInstruction {
            instruction: 0x0000_1073,
            ..
        })
    ));
    assert!(matches!(
        run_words(&[0x0010_0073], DEFAULT_INSTRUCTION_FUEL),
        Err(MachineError::UnsupportedInstruction {
            instruction: 0x0010_0073,
            ..
        })
    ));

    let mut misaligned = machine_words(&[ECALL], DEFAULT_INSTRUCTION_FUEL).unwrap();
    misaligned.pc = DRAM_BASE + 2;
    assert_eq!(
        misaligned.run(alice_principal()),
        Err(MachineError::Misaligned {
            address: DRAM_BASE + 2
        })
    );

    let mut fetch_oob = machine_words(&[ECALL], DEFAULT_INSTRUCTION_FUEL).unwrap();
    fetch_oob.pc = DRAM_BASE + RAM_BYTES as u64;
    assert_eq!(
        fetch_oob.run(alice_principal()),
        Err(MachineError::InstructionAccessFault {
            address: DRAM_BASE + RAM_BYTES as u64
        })
    );

    let mut memory_oob = machine_words(&[ECALL], DEFAULT_INSTRUCTION_FUEL).unwrap();
    assert_eq!(
        memory_oob.store_u8(DRAM_BASE + RAM_BYTES as u64, 1, alice_principal()),
        Err(MachineError::StoreAccessFault {
            address: DRAM_BASE + RAM_BYTES as u64
        })
    );
    assert_eq!(
        memory_oob.load_u8(DRAM_BASE + RAM_BYTES as u64, alice_principal()),
        Err(MachineError::LoadAccessFault {
            address: DRAM_BASE + RAM_BYTES as u64
        })
    );
    assert!(matches!(
        PortableMachine::for_owner(
            alice_principal(),
            &GuestImage::admit(&SYNTHETIC_EXIT_ZERO).unwrap(),
            0
        ),
        Err(MachineError::InvalidFuel)
    ));
    let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).unwrap();
    assert!(PortableMachine::for_owner(alice_principal(), &image, MAX_INSTRUCTION_FUEL).is_ok());
    for fuel in [MAX_INSTRUCTION_FUEL + 1, u64::MAX] {
        assert!(matches!(
            PortableMachine::for_owner(alice_principal(), &image, fuel),
            Err(MachineError::InvalidFuel)
        ));
    }
}
