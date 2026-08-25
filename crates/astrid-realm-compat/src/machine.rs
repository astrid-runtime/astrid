//! Bounded RV64I portable machine recovered from the Realm machine core.
//!
//! This is a workload-neutral instruction fixture. It is not Linux, `BusyBox`,
//! `Hermes`, `NVIDIA`, a POSIX ABI, or a public WIT surface. Guest UIDs, paths,
//! and PIDs are never Astrid authority.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use astrid_provider::{HostPrincipal, ProviderError};

use crate::image::GuestImage;

/// Guest DRAM base used by the recovered RV64 virt profile.
pub const DRAM_BASE: u64 = 0x8000_0000;
/// Fixed ephemeral guest RAM. Not a volume and not host-backed.
pub const RAM_BYTES: usize = 4096;
/// Default retired-instruction budget for one execution.
pub const DEFAULT_INSTRUCTION_FUEL: u64 = 64;
/// Hard cap on instruction fuel. Larger requests fail closed.
pub const MAX_INSTRUCTION_FUEL: u64 = 1024;

/// Construction or execution failure of the portable machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineError {
    /// Image is empty, unaligned, or larger than the admission cap.
    InvalidImage,
    /// Requested fuel is zero or exceeds [`MAX_INSTRUCTION_FUEL`].
    InvalidFuel,
    /// Instruction budget was consumed without a halt.
    FuelExhausted,
    /// Opcode or funct field is not in the recovered RV64I subset.
    IllegalInstruction {
        /// Guest PC of the trapped fetch.
        pc: u64,
        /// Encoded instruction word.
        instruction: u32,
    },
    /// Instruction is decoded but not implemented by this fixture.
    UnsupportedInstruction {
        /// Guest PC of the trapped fetch.
        pc: u64,
        /// Encoded instruction word.
        instruction: u32,
    },
    /// Instruction fetch was outside admitted RAM.
    InstructionAccessFault {
        /// Faulting guest address.
        address: u64,
    },
    /// Load was outside admitted RAM.
    LoadAccessFault {
        /// Faulting guest address.
        address: u64,
    },
    /// Store was outside admitted RAM.
    StoreAccessFault {
        /// Faulting guest address.
        address: u64,
    },
    /// PC or memory operand was not naturally aligned.
    Misaligned {
        /// Faulting guest address.
        address: u64,
    },
    /// Caller is not the immutable RAM owner.
    PrincipalMismatch,
}

impl MachineError {
    /// Map a machine failure onto the accepted provider error vocabulary.
    #[must_use]
    pub const fn as_provider_error(self) -> ProviderError {
        match self {
            Self::InvalidImage | Self::Misaligned { .. } => ProviderError::InvalidLength,
            Self::PrincipalMismatch => ProviderError::PrincipalMismatch,
            Self::InvalidFuel
            | Self::FuelExhausted
            | Self::IllegalInstruction { .. }
            | Self::UnsupportedInstruction { .. }
            | Self::InstructionAccessFault { .. }
            | Self::LoadAccessFault { .. }
            | Self::StoreAccessFault { .. } => ProviderError::NotSupported,
        }
    }
}

/// Owner-bound RV64I machine. Fresh RAM per execution; no global table.
pub struct PortableMachine {
    owner: HostPrincipal,
    ram: [u8; RAM_BYTES],
    pc: u64,
    regs: [u64; 32],
    fuel_left: u64,
    instructions_retired: u64,
    halted: Option<u8>,
}

impl PortableMachine {
    /// Bind a fresh RAM image to `owner` and copy the admitted instruction bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MachineError::InvalidFuel`] when `fuel` is outside the cap.
    pub fn for_owner(
        owner: HostPrincipal,
        image: &GuestImage,
        fuel: u64,
    ) -> Result<Self, MachineError> {
        if fuel == 0 || fuel > MAX_INSTRUCTION_FUEL {
            return Err(MachineError::InvalidFuel);
        }
        let mut ram = [0_u8; RAM_BYTES];
        let bytes = image.as_bytes();
        ram.get_mut(..bytes.len())
            .ok_or(MachineError::InvalidImage)?
            .copy_from_slice(bytes);
        Ok(Self {
            owner,
            ram,
            pc: DRAM_BASE,
            regs: [0; 32],
            fuel_left: fuel,
            instructions_retired: 0,
            halted: None,
        })
    }

    /// Immutable owner encoded in this machine. Not a guest UID.
    #[must_use]
    pub const fn owner(&self) -> HostPrincipal {
        self.owner
    }

    /// Instructions retired by a completed or partial run.
    #[must_use]
    pub const fn instructions_retired(&self) -> u64 {
        self.instructions_retired
    }

    /// Reject a caller that does not own this RAM.
    ///
    /// # Errors
    ///
    /// Returns [`MachineError::PrincipalMismatch`] when `caller` is not the owner.
    pub fn require_owner(&self, caller: HostPrincipal) -> Result<(), MachineError> {
        if caller.as_bytes() == self.owner.as_bytes() {
            Ok(())
        } else {
            Err(MachineError::PrincipalMismatch)
        }
    }

    /// Load one byte. Requires the matching owner.
    ///
    /// # Errors
    ///
    /// Principal mismatch or an out-of-range address.
    pub fn load_u8(&self, address: u64, caller: HostPrincipal) -> Result<u8, MachineError> {
        self.require_owner(caller)?;
        let offset = self.offset(address, 1, Access::Load)?;
        self.ram
            .get(offset)
            .copied()
            .ok_or(MachineError::LoadAccessFault { address })
    }

    /// Store one byte. Requires the matching owner.
    ///
    /// # Errors
    ///
    /// Principal mismatch or an out-of-range address.
    pub fn store_u8(
        &mut self,
        address: u64,
        value: u8,
        caller: HostPrincipal,
    ) -> Result<(), MachineError> {
        self.require_owner(caller)?;
        let offset = self.offset(address, 1, Access::Store)?;
        let slot = self
            .ram
            .get_mut(offset)
            .ok_or(MachineError::StoreAccessFault { address })?;
        *slot = value;
        Ok(())
    }

    /// Execute until halt or a fail-closed trap.
    ///
    /// `ecall` is a private exit portal: status is `a0` truncated to a byte.
    /// It is not SBI, Linux, or public WIT.
    ///
    /// # Errors
    ///
    /// Traps, fuel exhaustion, and owner mismatch fail closed.
    pub fn run(&mut self, caller: HostPrincipal) -> Result<u8, MachineError> {
        self.require_owner(caller)?;
        loop {
            if let Some(status) = self.halted {
                return Ok(status);
            }
            if self.fuel_left == 0 {
                return Err(MachineError::FuelExhausted);
            }
            self.fuel_left = self.fuel_left.saturating_sub(1);
            self.step()?;
        }
    }

    fn step(&mut self) -> Result<(), MachineError> {
        if !self.pc.is_multiple_of(4) {
            return Err(MachineError::Misaligned { address: self.pc });
        }
        let instruction = self.fetch(self.pc)?;
        let opcode = instruction & 0x7f;
        let rd = ((instruction >> 7) & 0x1f) as usize;
        let funct3 = (instruction >> 12) & 0x7;
        let rs1 = ((instruction >> 15) & 0x1f) as usize;
        let rs2 = ((instruction >> 20) & 0x1f) as usize;
        let funct7 = instruction >> 25;
        let mut next_pc = self.pc.wrapping_add(4);

        match opcode {
            0x03 => self.execute_load(instruction, rd, rs1, funct3)?,
            0x0f => {
                match funct3 {
                    // FENCE is part of the claimed base RV64I subset. The
                    // fixture has no shared memory, so it retires as a no-op.
                    0 => {},
                    // FENCE.I belongs to Zifencei and is deliberately not
                    // admitted by this base-subset machine.
                    1 => return Err(unsupported(self.pc, instruction)),
                    _ => return Err(illegal(self.pc, instruction)),
                }
            },
            0x13 => self.execute_op_imm(instruction, rd, rs1, funct3)?,
            0x17 => self.write(rd, self.pc.wrapping_add(immediate_u(instruction))),
            0x1b => self.execute_op_imm_32(instruction, rd, rs1, funct3)?,
            0x23 => self.execute_store(instruction, rs1, rs2, funct3)?,
            0x33 => self.execute_op(instruction, rd, rs1, rs2, funct3, funct7)?,
            0x37 => self.write(rd, immediate_u(instruction)),
            0x3b => self.execute_op_32(instruction, rd, rs1, rs2, funct3, funct7)?,
            0x63 => {
                if self.branch_taken(funct3, rs1, rs2, instruction)? {
                    let target = self.pc.wrapping_add(immediate_b(instruction));
                    ensure_instruction_aligned(target)?;
                    next_pc = target;
                }
            },
            0x67 => {
                if funct3 != 0 {
                    return Err(illegal(self.pc, instruction));
                }
                let target = self.read(rs1).wrapping_add(immediate_i(instruction)) & !1;
                ensure_instruction_aligned(target)?;
                self.write(rd, next_pc);
                next_pc = target;
            },
            0x6f => {
                let target = self.pc.wrapping_add(immediate_j(instruction));
                ensure_instruction_aligned(target)?;
                self.write(rd, next_pc);
                next_pc = target;
            },
            0x73 => {
                if funct3 != 0 {
                    return Err(unsupported(self.pc, instruction));
                }
                match instruction {
                    0x0000_0073 => {
                        let status = self.read(10) as u8;
                        self.halted = Some(status);
                        self.instructions_retired = self.instructions_retired.saturating_add(1);
                        self.pc = next_pc;
                        self.regs[0] = 0;
                        return Ok(());
                    },
                    _ => return Err(unsupported(self.pc, instruction)),
                }
            },
            _ => return Err(illegal(self.pc, instruction)),
        }

        self.pc = next_pc;
        self.regs[0] = 0;
        self.instructions_retired = self.instructions_retired.saturating_add(1);
        Ok(())
    }

    fn execute_load(
        &mut self,
        instruction: u32,
        rd: usize,
        rs1: usize,
        funct3: u32,
    ) -> Result<(), MachineError> {
        let (bytes, signed) = match funct3 {
            0 => (1, true),
            1 => (2, true),
            2 => (4, true),
            3 => (8, true),
            4 => (1, false),
            5 => (2, false),
            6 => (4, false),
            _ => return Err(illegal(self.pc, instruction)),
        };
        let address = self.read(rs1).wrapping_add(immediate_i(instruction));
        ensure_aligned(address, bytes)?;
        let value = self.read_mem(address, bytes, Access::Load)?;
        let value = if signed {
            sign_extend(value, u32::from(bytes) * 8)
        } else {
            value
        };
        self.write(rd, value);
        Ok(())
    }

    fn execute_store(
        &mut self,
        instruction: u32,
        rs1: usize,
        rs2: usize,
        funct3: u32,
    ) -> Result<(), MachineError> {
        let bytes = match funct3 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(illegal(self.pc, instruction)),
        };
        let address = self.read(rs1).wrapping_add(immediate_s(instruction));
        ensure_aligned(address, bytes)?;
        self.write_mem(address, self.read(rs2), bytes)
    }

    fn execute_op_imm(
        &mut self,
        instruction: u32,
        rd: usize,
        rs1: usize,
        funct3: u32,
    ) -> Result<(), MachineError> {
        let lhs = self.read(rs1);
        let immediate = immediate_i(instruction);
        let value = match funct3 {
            0 => lhs.wrapping_add(immediate),
            2 => u64::from((lhs as i64) < (immediate as i64)),
            3 => u64::from(lhs < immediate),
            4 => lhs ^ immediate,
            6 => lhs | immediate,
            7 => lhs & immediate,
            1 if instruction >> 26 == 0 => lhs.wrapping_shl((instruction >> 20) & 0x3f),
            5 if instruction >> 26 == 0 => lhs.wrapping_shr((instruction >> 20) & 0x3f),
            5 if instruction >> 26 == 0x10 => ((lhs as i64) >> ((instruction >> 20) & 0x3f)) as u64,
            _ => return Err(illegal(self.pc, instruction)),
        };
        self.write(rd, value);
        Ok(())
    }

    fn execute_op_imm_32(
        &mut self,
        instruction: u32,
        rd: usize,
        rs1: usize,
        funct3: u32,
    ) -> Result<(), MachineError> {
        let lhs = self.read(rs1) as u32;
        let value = match funct3 {
            0 => lhs.wrapping_add(immediate_i(instruction) as u32),
            1 if instruction >> 25 == 0 => lhs.wrapping_shl((instruction >> 20) & 0x1f),
            5 if instruction >> 25 == 0 => lhs.wrapping_shr((instruction >> 20) & 0x1f),
            5 if instruction >> 25 == 0x20 => ((lhs as i32) >> ((instruction >> 20) & 0x1f)) as u32,
            _ => return Err(illegal(self.pc, instruction)),
        };
        self.write(rd, sign_extend(u64::from(value), 32));
        Ok(())
    }

    fn execute_op(
        &mut self,
        instruction: u32,
        rd: usize,
        rs1: usize,
        rs2: usize,
        funct3: u32,
        funct7: u32,
    ) -> Result<(), MachineError> {
        let lhs = self.read(rs1);
        let rhs = self.read(rs2);
        let value = match (funct7, funct3) {
            (0x00, 0) => lhs.wrapping_add(rhs),
            (0x20, 0) => lhs.wrapping_sub(rhs),
            (0x00, 1) => lhs.wrapping_shl((rhs & 0x3f) as u32),
            (0x00, 2) => u64::from((lhs as i64) < (rhs as i64)),
            (0x00, 3) => u64::from(lhs < rhs),
            (0x00, 4) => lhs ^ rhs,
            (0x00, 5) => lhs.wrapping_shr((rhs & 0x3f) as u32),
            (0x20, 5) => ((lhs as i64) >> (rhs & 0x3f)) as u64,
            (0x00, 6) => lhs | rhs,
            (0x00, 7) => lhs & rhs,
            _ => return Err(illegal(self.pc, instruction)),
        };
        self.write(rd, value);
        Ok(())
    }

    fn execute_op_32(
        &mut self,
        instruction: u32,
        rd: usize,
        rs1: usize,
        rs2: usize,
        funct3: u32,
        funct7: u32,
    ) -> Result<(), MachineError> {
        let lhs = self.read(rs1) as u32;
        let rhs = self.read(rs2) as u32;
        let value = match (funct7, funct3) {
            (0x00, 0) => lhs.wrapping_add(rhs),
            (0x20, 0) => lhs.wrapping_sub(rhs),
            (0x00, 1) => lhs.wrapping_shl(rhs & 0x1f),
            (0x00, 5) => lhs.wrapping_shr(rhs & 0x1f),
            (0x20, 5) => ((lhs as i32) >> (rhs & 0x1f)) as u32,
            _ => return Err(illegal(self.pc, instruction)),
        };
        self.write(rd, sign_extend(u64::from(value), 32));
        Ok(())
    }

    fn branch_taken(
        &self,
        funct3: u32,
        rs1: usize,
        rs2: usize,
        instruction: u32,
    ) -> Result<bool, MachineError> {
        let lhs = self.read(rs1);
        let rhs = self.read(rs2);
        match funct3 {
            0 => Ok(lhs == rhs),
            1 => Ok(lhs != rhs),
            4 => Ok((lhs as i64) < (rhs as i64)),
            5 => Ok((lhs as i64) >= (rhs as i64)),
            6 => Ok(lhs < rhs),
            7 => Ok(lhs >= rhs),
            _ => Err(illegal(self.pc, instruction)),
        }
    }

    fn fetch(&self, pc: u64) -> Result<u32, MachineError> {
        Ok(self.read_mem(pc, 4, Access::Instruction)? as u32)
    }

    fn read_mem(&self, address: u64, bytes: u8, access: Access) -> Result<u64, MachineError> {
        let offset = self.offset(address, bytes, access)?;
        let mut value = 0_u64;
        for index in 0..usize::from(bytes) {
            let byte = self
                .ram
                .get(offset + index)
                .copied()
                .ok_or_else(|| access.fault(address))?;
            value |= u64::from(byte) << (8 * index);
        }
        Ok(value)
    }

    fn write_mem(&mut self, address: u64, value: u64, bytes: u8) -> Result<(), MachineError> {
        let offset = self.offset(address, bytes, Access::Store)?;
        for index in 0..usize::from(bytes) {
            let slot = self
                .ram
                .get_mut(offset + index)
                .ok_or(MachineError::StoreAccessFault { address })?;
            *slot = (value >> (8 * index)) as u8;
        }
        Ok(())
    }

    fn offset(&self, address: u64, bytes: u8, access: Access) -> Result<usize, MachineError> {
        let _ = self;
        if address < DRAM_BASE {
            return Err(access.fault(address));
        }
        let start = address - DRAM_BASE;
        let end = start
            .checked_add(u64::from(bytes))
            .ok_or_else(|| access.fault(address))?;
        if end > RAM_BYTES as u64 {
            return Err(access.fault(address));
        }
        usize::try_from(start).map_err(|_| access.fault(address))
    }

    fn read(&self, register: usize) -> u64 {
        self.regs.get(register).copied().unwrap_or(0)
    }

    fn write(&mut self, register: usize, value: u64) {
        if register != 0
            && let Some(slot) = self.regs.get_mut(register)
        {
            *slot = value;
        }
    }
}

#[derive(Clone, Copy)]
enum Access {
    Instruction,
    Load,
    Store,
}

impl Access {
    const fn fault(self, address: u64) -> MachineError {
        match self {
            Self::Instruction => MachineError::InstructionAccessFault { address },
            Self::Load => MachineError::LoadAccessFault { address },
            Self::Store => MachineError::StoreAccessFault { address },
        }
    }
}

fn ensure_aligned(address: u64, bytes: u8) -> Result<(), MachineError> {
    if address.is_multiple_of(u64::from(bytes)) {
        Ok(())
    } else {
        Err(MachineError::Misaligned { address })
    }
}

fn ensure_instruction_aligned(address: u64) -> Result<(), MachineError> {
    if address.is_multiple_of(4) {
        Ok(())
    } else {
        Err(MachineError::Misaligned { address })
    }
}

const fn illegal(pc: u64, instruction: u32) -> MachineError {
    MachineError::IllegalInstruction { pc, instruction }
}

const fn unsupported(pc: u64, instruction: u32) -> MachineError {
    MachineError::UnsupportedInstruction { pc, instruction }
}

fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    ((value << shift) as i64 >> shift) as u64
}

fn immediate_i(instruction: u32) -> u64 {
    sign_extend(u64::from(instruction >> 20), 12)
}

fn immediate_s(instruction: u32) -> u64 {
    let value = ((instruction >> 7) & 0x1f) | (((instruction >> 25) & 0x7f) << 5);
    sign_extend(u64::from(value), 12)
}

fn immediate_b(instruction: u32) -> u64 {
    let value = (((instruction >> 8) & 0x0f) << 1)
        | (((instruction >> 25) & 0x3f) << 5)
        | (((instruction >> 7) & 1) << 11)
        | (((instruction >> 31) & 1) << 12);
    sign_extend(u64::from(value), 13)
}

fn immediate_u(instruction: u32) -> u64 {
    sign_extend(u64::from(instruction & 0xffff_f000), 32)
}

fn immediate_j(instruction: u32) -> u64 {
    let value = (((instruction >> 21) & 0x03ff) << 1)
        | (((instruction >> 20) & 1) << 11)
        | (((instruction >> 12) & 0xff) << 12)
        | (((instruction >> 31) & 1) << 20);
    sign_extend(u64::from(value), 21)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_INSTRUCTION_FUEL, DRAM_BASE, MachineError, PortableMachine, RAM_BYTES};
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
            PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
                .unwrap();
        assert_eq!(machine.run(alice_principal()), Ok(0));
        assert_eq!(machine.instructions_retired(), 2);

        let image = GuestImage::admit(&SYNTHETIC_EXIT_SEVEN).unwrap();
        let mut machine =
            PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
                .unwrap();
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
            PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
                .unwrap();
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
    }
}
