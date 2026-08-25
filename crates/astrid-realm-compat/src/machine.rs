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
mod tests;
