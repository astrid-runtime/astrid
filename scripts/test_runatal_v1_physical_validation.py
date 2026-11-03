#!/usr/bin/env python3
"""Regression tests for independent physical-store validation."""

import unittest
from pathlib import Path
from unittest.mock import patch

import runatal_v1_reader as reader
from runatal_v1_specs import LEGACY_FORMAT_SPECIFICATIONS

from runatal_v1_physical import (
    FormatError,
    canonical_prefix,
    identity_bytes,
    prefix_bits,
    search_key,
    validate_map,
)
from runatal_v1_physical_store import validate_direct_coverage, validate_direct_lengths


def tagged(byte):
    return (1, 2, bytes([byte]) * 32)


class PhysicalValidationTests(unittest.TestCase):
    def test_volume_rejects_pre_catalogue_profile_before_evidence_lookup(self):
        unsupported = (1, 1, bytes.fromhex(
            "82e46f53ba9bb2f52d6b942088d5965eaa17c2720e61ce842ed9d5e3c0d1219d"
        ))
        self.assertIn(unsupported, LEGACY_FORMAT_SPECIFICATIONS)
        # Isolate profile admission from physical checksum/coverage validation.
        # Missing Evidence must not determine whether a profile is supported.
        physical = {"frozen_specification": reader.identity_text(unsupported)}
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(reader, "recover_volume", return_value={
                "objects.arena": b"", "roots.journal": b"",
            }),
            patch.object(reader, "decode_physical_store", return_value=physical),
            self.assertRaisesRegex(reader.FormatError,
                                   "volume direct profile selects an unsupported format"),
        ):
            reader.recover(Path("isolated-volume"), False)

    def test_map_rejects_noncanonical_prefix_bytes(self):
        zero_key = tagged(0x00)
        one_key = tagged(0x80)
        zero_search = search_key(zero_key)
        one_search = search_key(one_key)
        bits = prefix_bits(zero_search, one_search)
        prefix = bytearray(canonical_prefix(zero_search, bits))
        prefix[0] ^= 0x80
        zero_id = tagged(0x11)
        one_id = tagged(0x22)
        root_id = tagged(0x33)
        nodes = {
            identity_bytes(zero_id): {
                "domain": 0,
                "tag": 0,
                "key": zero_key,
                "value": b"zero",
            },
            identity_bytes(one_id): {
                "domain": 0,
                "tag": 0,
                "key": one_key,
                "value": b"one",
            },
            identity_bytes(root_id): {
                "domain": 0,
                "tag": 1,
                "prefix_bits": bits,
                "prefix": bytes(prefix),
                "zero": zero_id,
                "one": one_id,
                "subtree_entries": 2,
            },
        }
        with self.assertRaisesRegex(FormatError, "prefix bytes are not canonical"):
            validate_map(root_id, 0, 2, nodes, lambda _key, _value: None)

    def test_direct_lengths_bind_record_placement_and_bytes(self):
        record = {"coverage": (0, tagged(0x44), 64)}
        placement = {"encoded_length": 64}
        validate_direct_lengths(record, placement, 64)
        with self.assertRaisesRegex(FormatError, "coverage length"):
            validate_direct_lengths(record, placement, 63)
        placement["encoded_length"] = 63
        with self.assertRaisesRegex(FormatError, "placement length"):
            validate_direct_lengths(record, placement, 64)

    def test_radix_map_rejects_a_child_under_the_wrong_selector(self):
        zero_entries = [(tagged(1), b"zero")]
        eight_entries = [(tagged(0x81), b"eight")]
        zero_id = tagged(0x11)
        eight_id = tagged(0x22)
        root_id = tagged(0x33)
        nodes = {
            identity_bytes(zero_id): {
                "version": 2,
                "domain": 0,
                "tag": 0,
                "entries": zero_entries,
            },
            identity_bytes(eight_id): {
                "version": 2,
                "domain": 0,
                "tag": 0,
                "entries": eight_entries,
            },
            identity_bytes(root_id): {
                "version": 2,
                "domain": 0,
                "tag": 1,
                "prefix_nibbles": 0,
                "prefix": b"",
                "child_bitmap": (1 << 1) | (1 << 8),
                "children": [zero_id, eight_id],
                "subtree_entries": 2,
            },
        }
        with self.assertRaisesRegex(FormatError, "child crosses its selector"):
            validate_map(root_id, 0, 2, nodes, lambda _key, _value: None)

    def test_radix_map_rejects_legacy_children(self):
        zero_id = tagged(0x11)
        eight_id = tagged(0x22)
        root_id = tagged(0x33)
        nodes = {
            identity_bytes(zero_id): {
                "version": 1,
                "domain": 0,
                "tag": 0,
                "key": tagged(0x01),
                "value": b"zero",
            },
            identity_bytes(eight_id): {
                "version": 1,
                "domain": 0,
                "tag": 0,
                "key": tagged(0x81),
                "value": b"eight",
            },
            identity_bytes(root_id): {
                "version": 2,
                "domain": 0,
                "tag": 1,
                "prefix_nibbles": 0,
                "prefix": b"",
                "child_bitmap": (1 << 0) | (1 << 8),
                "children": [zero_id, eight_id],
                "subtree_entries": 2,
            },
        }
        with self.assertRaisesRegex(FormatError, "mixes node constructions"):
            validate_map(root_id, 0, 2, nodes, lambda _key, _value: None)

    def test_direct_coverage_exempts_only_declared_bootstrap_objects(self):
        bootstrap = b"bootstrap"
        represented = b"represented"
        validate_direct_coverage({bootstrap, represented}, {represented}, {bootstrap})
        with self.assertRaisesRegex(FormatError, "does not cover every"):
            validate_direct_coverage({bootstrap, represented}, set(), {bootstrap})


if __name__ == "__main__":
    unittest.main()
