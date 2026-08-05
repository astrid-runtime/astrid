#!/usr/bin/env python3
"""Regression tests for independent physical-store validation."""

import unittest

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

    def test_direct_coverage_exempts_only_declared_bootstrap_objects(self):
        bootstrap = b"bootstrap"
        represented = b"represented"
        validate_direct_coverage({bootstrap, represented}, {represented}, {bootstrap})
        with self.assertRaisesRegex(FormatError, "does not cover every"):
            validate_direct_coverage({bootstrap, represented}, set(), {bootstrap})


if __name__ == "__main__":
    unittest.main()
