#!/usr/bin/env python3

from __future__ import annotations

import unittest

import check_glibc


class GlibcCompatibilityTests(unittest.TestCase):
    def test_extracts_unique_required_versions(self) -> None:
        versions = check_glibc.required_versions(
            """
            0x0010: Name: GLIBC_2.17  Flags: none
            0x0020: Name: GLIBC_2.34  Flags: none
            0x0030: Name: GLIBC_2.17  Flags: none
            """
        )
        self.assertEqual(versions, {(2, 17), (2, 34)})

    def test_ignores_similar_non_glibc_symbols(self) -> None:
        self.assertEqual(
            check_glibc.required_versions("GLIBCXX_3.4 CXXABI_1.3"),
            set(),
        )

    def test_rejects_malformed_ceiling(self) -> None:
        for value in ("2", "2.x", "v2.34"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                check_glibc.parse_version(value)


if __name__ == "__main__":
    unittest.main()
