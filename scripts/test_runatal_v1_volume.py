#!/usr/bin/env python3
"""Independent hosted-volume page grammar and recovery regressions."""
import struct
import tempfile
import unittest
from pathlib import Path

from runatal_v1_volume import VolumeFormatError, recover_volume
from runatal_v1_blake3 import derive_key

COMMIT = "system/volume-commit"
MAX_COMMIT_SNAPSHOT_BYTES = 16 * 1024 * 1024


def append_record(data, sequence, operation, name, logical, payload):
    sequence += 1
    name = name.encode()
    offset = len(data)
    material = struct.pack("<QBHQQ", sequence, operation, len(name), logical, len(payload)) + name + payload
    checksum = derive_key("astrid volume record v1", material)
    header = (
        b"ASTREG1\0"
        + struct.pack("<QQBHQQ", 75 + len(name) + len(payload), sequence, operation, len(name), logical, len(payload))
        + checksum
    )
    assert len(header) == 75
    data.extend(header + name + payload)
    return sequence, offset, offset + 75 + len(name), checksum


def encode_legacy_snapshot(entries):
    payload = bytearray(b"ASTMAP1\0")
    payload.extend(struct.pack("<I", len(entries)))
    for name, length, extents in entries:
        raw = name.encode()
        payload.extend(struct.pack("<H", len(raw)))
        payload.extend(raw)
        payload.extend(struct.pack("<Q", length))
        payload.extend(struct.pack("<I", len(extents)))
        for start, end, physical in extents:
            payload.extend(struct.pack("<QQQ", start, end, physical))
    return bytes(payload)


def public_write(names=None):
    names = names or (("data/test", b"acknowledged"),)
    data = bytearray(b"ASTVOL1\0")
    sequence = 0
    expected = {}
    physical = {}
    for name, value in names:
        sequence, _, _, _ = append_record(data, sequence, 1, name, 0, b"")
        sequence, _, payload_offset, _ = append_record(data, sequence, 2, name, 0, value)
        expected[name] = value
        physical[name] = payload_offset
    return data, sequence, expected, physical


def fixture(page_mutation=None, reference_mutation=None):
    data = bytearray(b"ASTVOL1\0")
    sequence = 0

    def append(operation, name, logical, payload):
        nonlocal sequence
        sequence, offset, physical, checksum = append_record(data, sequence, operation, name, logical, payload)
        return offset, physical, sequence, checksum

    name = "data/test"
    value = b"acknowledged"
    append(1, name, 0, b"")
    _, physical, _, _ = append(2, name, 0, value)
    append(8, COMMIT, 0, b"")
    page = b"ASTXPG1\0" + struct.pack("<B3xH2x", 0, 1) + struct.pack("<QQQ", 0, len(value), physical)
    page = page.ljust(4096, b"\0")
    if page_mutation is not None:
        page = page_mutation(page)
    offset, _, seq, checksum = append(9, "system/volume-extent-index", 0, page)
    reference = struct.pack("<QQ", offset, seq) + checksum + struct.pack("<QQQB7x", 0, len(value), 1, 0)
    if reference_mutation is not None:
        reference = reference_mutation(reference)
    assert len(reference) == 80
    catalogue = (
        b"ASTMAP2\0"
        + struct.pack("<IH", 1, len(name))
        + name.encode()
        + struct.pack("<QB", len(value), 1)
        + reference
    )
    append(8, COMMIT, 0, catalogue)
    return data, {name: value}


def replace_bytes(data, offset, value):
    return data[:offset] + value + data[offset + len(value):]


class IndependentVolumeRecovery(unittest.TestCase):
    def recover(self, data):
        with tempfile.TemporaryDirectory(prefix="astrid-independent-volume-") as directory:
            path = Path(directory) / "astrid.volume"
            path.write_bytes(data)
            before = path.read_bytes()
            try:
                return recover_volume(path)
            finally:
                self.assertEqual(path.read_bytes(), before, "offline reader mutated source")


class IndependentReaderPagedRegression(IndependentVolumeRecovery):
    def test_valid_paged_checkpoint_recovers_public_region(self):
        data, expected = fixture()
        self.assertEqual(self.recover(data), expected)

    def test_checksum_valid_malformed_page_is_rejected(self):
        for offset, replacement in [(0, b"!"), (9, b"!"), (14, b"!"), (4095, b"!"), (12, bytes(2))]:
            with self.subTest(offset=offset):
                data, _ = fixture(page_mutation=lambda page, offset=offset, replacement=replacement: replace_bytes(page, offset, replacement))
                with self.assertRaises(VolumeFormatError):
                    self.recover(data)

    def test_checksum_valid_forged_root_is_rejected(self):
        for offset, replacement in [(16, bytes(32)), (64, struct.pack("<Q", 2)), (73, b"!")]:
            with self.subTest(offset=offset):
                data, _ = fixture(reference_mutation=lambda ref, offset=offset, replacement=replacement: replace_bytes(ref, offset, replacement))
                with self.assertRaises(VolumeFormatError):
                    self.recover(data)

    def test_forward_payload_reference_is_rejected(self):
        data, _ = fixture(page_mutation=lambda page: replace_bytes(page, 32, struct.pack("<Q", (1 << 64) - 1)))
        with self.assertRaisesRegex(VolumeFormatError, "payload bounds"):
            self.recover(data)

    def test_root_record_must_complete_before_commit(self):
        data, _ = fixture(reference_mutation=lambda ref: replace_bytes(ref, 0, struct.pack("<Q", int.from_bytes(ref[:8], "little") + 1)))
        with self.assertRaisesRegex(VolumeFormatError, "precede parent"):
            self.recover(data)

    def test_unpublished_complete_page_preserves_prior_acknowledged_namespace(self):
        data, expected = fixture()
        # Remove only the final commit; complete index pages are unpublished.
        final = data.rfind(b"ASTREG1\0")
        self.assertEqual(self.recover(data[:final]), expected)


class IndependentReaderLegacyCommitRegression(IndependentVolumeRecovery):
    def commit(self, data, sequence, payload):
        append_record(data, sequence, 8, COMMIT, 0, payload)
        return data

    def matching_snapshot(self, expected, physical):
        return encode_legacy_snapshot(
            [
                (name, len(value), [(0, len(value), physical[name])])
                for name, value in expected.items()
            ]
        )

    def test_valid_empty_commit_recovers_public_region(self):
        data, sequence, expected, _ = public_write()
        self.assertEqual(self.recover(self.commit(data, sequence, b"")), expected)

    def test_valid_legacy_snapshot_recovers_public_region(self):
        data, sequence, expected, physical = public_write()
        snapshot = self.matching_snapshot(expected, physical)
        self.assertEqual(self.recover(self.commit(data, sequence, snapshot)), expected)

    def test_valid_unsorted_legacy_names_recover(self):
        names = (("z/item", b"zeta-value"), ("a/item", b"alpha-value"))
        data, sequence, expected, physical = public_write(names)
        snapshot = encode_legacy_snapshot(
            [
                ("z/item", len(expected["z/item"]), [(0, len(expected["z/item"]), physical["z/item"])]),
                ("a/item", len(expected["a/item"]), [(0, len(expected["a/item"]), physical["a/item"])]),
            ]
        )
        self.assertEqual(self.recover(self.commit(data, sequence, snapshot)), expected)

    def test_checksum_valid_garbage_commit_payload_is_rejected(self):
        data, sequence, _, _ = public_write()
        with self.assertRaises(VolumeFormatError):
            self.recover(self.commit(data, sequence, b"not ASTMAP1 or ASTMAP2 payload"))

    def test_valid_legacy_sparse_hole_and_tail_recover(self):
        data = bytearray(b"ASTVOL1\0")
        sequence, _, _, _ = append_record(data, 0, 1, "data/sparse", 0, b"")
        sequence, _, physical, _ = append_record(data, sequence, 2, "data/sparse", 3, b"x")
        sequence, _, _, _ = append_record(data, sequence, 3, "data/sparse", 7, b"")
        snapshot = encode_legacy_snapshot([("data/sparse", 7, [(3, 4, physical)])])
        self.assertEqual(self.recover(self.commit(data, sequence, snapshot)),
                         {"data/sparse": b"\0\0\0x\0\0\0"})

    def test_checksum_valid_malformed_legacy_snapshot_is_rejected(self):
        data, sequence, expected, physical = public_write()
        matching = self.matching_snapshot(expected, physical)
        name = "data/test"
        value = expected[name]
        commit_offset = len(data)
        cases = {
            "bad_magic": b"NOTMAP1\0" + struct.pack("<I", 0),
            "short": b"ASTMAP1\0" + b"\x00" * 3,
            "truncated_body": b"ASTMAP1\0" + struct.pack("<I", 1),
            "trailing": matching + b"\x00",
            "duplicate_name": encode_legacy_snapshot(
                [
                    (name, len(value), [(0, len(value), physical[name])]),
                    (name, len(value), [(0, len(value), physical[name])]),
                ]
            ),
            "start_not_before_end": encode_legacy_snapshot(
                [(name, len(value), [(4, 4, physical[name])])]
            ),
            "extent_past_length": encode_legacy_snapshot(
                [(name, len(value), [(0, len(value) + 1, physical[name])])]
            ),
            "physical_past_commit": encode_legacy_snapshot(
                [(name, len(value), [(0, len(value), commit_offset)])]
            ),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                volume = bytearray(data)
                with self.assertRaises(VolumeFormatError):
                    self.recover(self.commit(volume, sequence, payload))

    def test_checksum_valid_oversize_commit_payload_is_rejected(self):
        data, sequence, _, _ = public_write()
        payload = b"\x00" * (MAX_COMMIT_SNAPSHOT_BYTES + 1)
        with self.assertRaises(VolumeFormatError):
            self.recover(self.commit(data, sequence, payload))

    def test_legacy_snapshot_contradicting_replay_is_rejected(self):
        data, sequence, expected, physical = public_write()
        name = "data/test"
        value = expected[name]
        cases = {
            "wrong_length": encode_legacy_snapshot(
                [(name, len(value) + 7, [(0, len(value), physical[name])])]
            ),
            "extra_region": encode_legacy_snapshot(
                [
                    (name, len(value), [(0, len(value), physical[name])]),
                    ("extra/region", 0, []),
                ]
            ),
            "omitted_region": encode_legacy_snapshot([]),
            "extent_bytes": encode_legacy_snapshot(
                [(name, len(value), [(0, len(value), 0)])]
            ),
            "nonzero_hole": encode_legacy_snapshot(
                [(name, len(value), [(4, len(value), physical[name] + 4)])]
            ),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                volume = bytearray(data)
                with self.assertRaises(VolumeFormatError):
                    self.recover(self.commit(volume, sequence, payload))


if __name__ == "__main__":
    unittest.main()
