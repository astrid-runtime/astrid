#!/usr/bin/env python3
"""Regression tests for independent physical-store validation."""

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import runatal_v1_reader as reader
from runatal_v1_specs import LEGACY_FORMAT_SPECIFICATIONS

from runatal_v1_physical import (
    ARENA_MAGIC, BLOB_CONTEXT, PROFILE_CONTEXT, RECORD_CONTEXT, FormatError,
    decode_placement_entry, decode_profile, decode_representation, derived_dependencies,
    encode_placement_entry, encode_profile, encode_representation, frame_checksum,
    physical_identity,
    canonical_prefix,
    identity_bytes,
    prefix_bits,
    search_key,
    validate_map,
)
from runatal_v1_physical_store import (
    validate_direct_arena, validate_direct_coverage, validate_direct_lengths,
)


def tagged(byte):
    return (1, 2, bytes([byte]) * 32)


def canonical_profile(kind):
    specification = (1, 1, bytes([0x41]) * 32)
    pinned = specification if kind == 3 else None
    encoded = encode_profile({
        "version": 1, "kind": kind, "decoder": pinned, "contract": pinned,
        "runtime": pinned, "parameters": b"", "dependencies": [(0, specification)],
        "bounds_version": 1, "bounds": (8, 8, 4096, 4096, 4096, 4096, 4096),
        "specification": specification,
    })
    return physical_identity(PROFILE_CONTEXT, encoded), decode_profile(encoded)


def canonical_record(profile, coverage, recipe, evidence=None):
    encoded = encode_representation({
        "version": 1, "profile": profile, "coverage": coverage, "recipe": recipe,
        "dependencies": derived_dependencies(profile, recipe, evidence),
        "canonical_output_bytes": coverage[2], "maximum_reconstruction_bytes": 4096,
        "evidence": evidence,
    })
    return physical_identity(RECORD_CONTEXT, encoded), decode_representation(encoded)


def alternate_coverage_fixture(store, recipe_tag, covers_bootstrap):
    """Real frames and canonical records; direct coverage remains complete."""
    bootstrap = (1, 1, bytes([0x51]) * 32)
    ordinary = (1, 1, bytes([0x52]) * 32)
    evidence = (1, 1, bytes([0x53]) * 32)
    direct_profile, direct = canonical_profile(0)
    other_profile, other = canonical_profile(1 if recipe_tag == 1 else 3)
    arena = bytearray()
    for object_id, canonical in [(bootstrap, b"bootstrap canonical"),
                                 (ordinary, b"ordinary canonical")]:
        payload = identity_bytes(object_id) + canonical
        checksum = frame_checksum(ARENA_MAGIC, payload)
        offset = len(arena)
        arena += (ARENA_MAGIC + struct.pack("<HHQ", 1, 0, len(payload))
                  + checksum + payload)
    (store / "objects.arena").write_bytes(arena)
    blob = physical_identity(BLOB_CONTEXT, identity_bytes(direct_profile)
                             + struct.pack("<Q", len(canonical)) + canonical)
    direct_id, direct_record = canonical_record(
        direct_profile, (0, ordinary, len(canonical)), (0, blob)
    )
    placement = decode_placement_entry(encode_placement_entry({
        "blob": blob, "profile": direct_profile, "encoded_length": len(canonical),
        "replicas": [(0, (0, 0, offset, len(payload), checksum))],
    }))
    covered = bootstrap if covers_bootstrap else ordinary
    length = len(b"bootstrap canonical") if covers_bootstrap else len(canonical)
    recipe = {
        1: (1, tagged(0x61), 0, length),
        3: (3, tagged(0x61), None),
        4: (4, tagged(0x61), ordinary),
        5: (5, ordinary, 0, evidence),
    }[recipe_tag]
    alternate_id, alternate = canonical_record(
        other_profile, (0, covered, length), recipe, evidence
    )
    return (direct_profile,
            {identity_bytes(direct_profile): direct, identity_bytes(other_profile): other},
            {direct_id: direct_record, alternate_id: alternate},
            {identity_bytes(blob): placement}, {identity_bytes(bootstrap)})


class PhysicalValidationTests(unittest.TestCase):
    def test_every_alternate_recipe_rejects_bootstrap_exact_coverage(self):
        for recipe_tag in (1, 3, 4, 5):
            with self.subTest(recipe=recipe_tag), tempfile.TemporaryDirectory(
                prefix="astrid-bootstrap-coverage-"
            ) as directory:
                store = Path(directory)
                arguments = alternate_coverage_fixture(store, recipe_tag, True)
                with self.assertRaisesRegex(FormatError, "bootstrap object"):
                    validate_direct_arena(store, *arguments)

    def test_every_alternate_recipe_preserves_valid_nonbootstrap_coverage(self):
        for recipe_tag in (1, 3, 4, 5):
            with self.subTest(recipe=recipe_tag), tempfile.TemporaryDirectory(
                prefix="astrid-ordinary-coverage-"
            ) as directory:
                store = Path(directory)
                arguments = alternate_coverage_fixture(store, recipe_tag, False)
                validate_direct_arena(store, *arguments)

    def test_alternate_recipes_do_not_replace_required_direct_coverage(self):
        for recipe_tag in (1, 3, 4, 5):
            with self.subTest(recipe=recipe_tag), tempfile.TemporaryDirectory(
                prefix="astrid-missing-direct-coverage-"
            ) as directory:
                store = Path(directory)
                direct, profiles, records, placements, bootstrap = alternate_coverage_fixture(
                    store, recipe_tag, False
                )
                records = {key: record for key, record in records.items()
                           if record["recipe"][0] != 0}
                with self.assertRaisesRegex(FormatError, "does not cover every"):
                    validate_direct_arena(store, direct, profiles, records, placements, bootstrap)

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
