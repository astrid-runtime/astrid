#!/usr/bin/env python3

from __future__ import annotations

import unittest

import check_static_elf


class StaticElfTests(unittest.TestCase):
    def validate(
        self,
        *,
        architecture: str = "x86_64",
        machine: str = "Advanced Micro Devices X86-64",
        programs: str = "LOAD 0x000000",
        dynamic: str = "There is no dynamic section in this file.",
        versions: str = "No version information found in this file.",
    ) -> None:
        check_static_elf.validate_readelf(
            architecture,
            f"ELF Header:\n  Machine: {machine}\n",
            programs,
            dynamic,
            versions,
        )

    def test_accepts_static_x86_64_and_aarch64(self) -> None:
        self.validate()
        self.validate(architecture="aarch64", machine="AArch64")

    def test_rejects_wrong_machine(self) -> None:
        with self.assertRaisesRegex(ValueError, "ELF machine"):
            self.validate(machine="AArch64")

    def test_rejects_program_interpreter(self) -> None:
        with self.assertRaisesRegex(ValueError, "program interpreter"):
            self.validate(programs=" INTERP 0x000000\n LOAD 0x001000")

    def test_rejects_dynamic_dependency(self) -> None:
        with self.assertRaisesRegex(ValueError, "shared-library"):
            self.validate(dynamic="0x0000000000000001 (NEEDED) Shared library: [libc.so]")

    def test_rejects_glibc_symbol_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "glibc"):
            self.validate(versions="Name: GLIBC_2.34")

    def test_rejects_unknown_architecture(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported ELF architecture"):
            self.validate(architecture="riscv64")


if __name__ == "__main__":
    unittest.main()
