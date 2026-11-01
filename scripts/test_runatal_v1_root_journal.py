#!/usr/bin/env python3
"""Root-journal grammar remains strict after separating the independent decoder."""

import struct
import unittest

import runatal_v1_reader as reader
from runatal_v1_codec import FormatError
from runatal_v1_root_journal import decode_root, principal_text

OWNER = b"\1" + b"u" * 32
IDENTITY = (1, 1, b"i" * 32)
STATE = (3, IDENTITY)
STATE_BYTES = struct.pack("<QHHI", 3, 1, 1, 32) + IDENTITY[2]
EXTENSION = struct.pack("<Q", (1 << 64) - 1)
REMOVAL = EXTENSION + b"\2" + struct.pack("<Q", len(OWNER)) + OWNER + STATE_BYTES


class RootJournalTests(unittest.TestCase):
    def test_reader_reexports_one_authoritative_decoder_and_error_type(self):
        self.assertIs(reader.decode_root, decode_root)
        self.assertIs(reader.FormatError, FormatError)
        self.assertEqual(decode_root(REMOVAL), ("remove", OWNER, STATE))

    def test_every_truncated_removal_fails(self):
        for length in range(len(REMOVAL)):
            with self.subTest(length=length), self.assertRaises(FormatError):
                decode_root(REMOVAL[:length])

    def test_removal_rejects_padding(self):
        for suffix in (b"\0", b"extra"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(FormatError, "trailing payload"):
                decode_root(REMOVAL + suffix)

    def test_unknown_extension_fails(self):
        with self.assertRaisesRegex(FormatError, "unknown root-journal extension"):
            decode_root(EXTENSION + b"\3")

    def test_removal_rejects_zero_tagged_identity_fields(self):
        prefix = EXTENSION + b"\2" + struct.pack("<Q", len(OWNER)) + OWNER
        for algorithm, construction, length in ((0, 1, 32), (1, 0, 32), (1, 1, 0)):
            with self.subTest(tags=(algorithm, construction, length)), self.assertRaisesRegex(FormatError, "zero identity"):
                decode_root(prefix + struct.pack("<QHHI", 3, algorithm, construction, length) + IDENTITY[2])

    def test_transition_expected_option_remains_strict(self):
        prefix = struct.pack("<Q", len(OWNER)) + OWNER
        self.assertEqual(decode_root(prefix + b"\0" + STATE_BYTES), ("transition", OWNER, None, STATE))
        self.assertEqual(decode_root(prefix + b"\1" + STATE_BYTES + STATE_BYTES), ("transition", OWNER, STATE, STATE))
        with self.assertRaisesRegex(FormatError, "invalid expected-root tag"):
            decode_root(prefix + b"\2" + STATE_BYTES)

    def test_snapshot_rejects_duplicate_and_reversed_principals(self):
        second = b"\1" + b"v" * 32
        prefix = EXTENSION + b"\1" + struct.pack("<Q", 2)
        def entry(owner):
            return struct.pack("<Q", len(owner)) + owner + STATE_BYTES
        self.assertEqual(decode_root(prefix + entry(OWNER) + entry(second)), ("snapshot", [(OWNER, STATE), (second, STATE)]))
        for owners in ((OWNER, OWNER), (second, OWNER)):
            with self.subTest(owners=owners), self.assertRaisesRegex(FormatError, "non-canonical root snapshot order"):
                decode_root(prefix + entry(owners[0]) + entry(owners[1]))

    def test_owner_names_preserve_scope_and_reject_malformed_encoding(self):
        self.assertEqual(principal_text(b"\0"), "system")
        self.assertEqual(principal_text(OWNER), (b"u" * 32).hex())
        self.assertEqual(principal_text(b"\2" + b"u" * 32), "fleet:" + (b"u" * 32).hex())
        for owner in (b"", b"\0extra", b"\1short", b"\3" + b"u" * 32):
            with self.subTest(owner=owner), self.assertRaisesRegex(FormatError, "invalid state-owner"):
                principal_text(owner)


if __name__ == "__main__":
    unittest.main()
