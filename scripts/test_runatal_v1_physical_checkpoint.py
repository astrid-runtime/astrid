#!/usr/bin/env python3
"""Independent checkpoint replay tests using byte-exact durable frames."""

import struct
import tempfile
import unittest
from pathlib import Path

from runatal_v1_physical import (
    CATALOGUE_CONTEXT, JOURNAL_CONTEXT, JOURNAL_MAGIC, PLACEMENT_CONTEXT,
    STATE_CONTEXT, FormatError, encode_catalogue_root, encode_optional,
    encode_placement_set, encode_representation_state, identity_bytes,
    physical_identity,
)
from runatal_v1_frames import frame_checksum
from runatal_v1_physical_store import replay_state_journal


def tagged(byte):
    return (1, 2, bytes([byte]) * 32)


def frame(payload):
    return (JOURNAL_MAGIC + struct.pack("<HHQ", 1, 0, len(payload))
            + frame_checksum(JOURNAL_MAGIC, payload) + payload)


class CheckpointReplayTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {"values": {}, "nodes": {}}

    def add(self, kind, context, data):
        identifier = physical_identity(context, data)
        self.metadata["values"][(kind, identity_bytes(identifier))] = data
        return identifier

    def state(self, generation=7, previous=None, root_generation=5, missing_map=False):
        catalogue = self.add(3, CATALOGUE_CONTEXT, encode_catalogue_root({
            "version": 1, "generation": root_generation,
            "profiles_root": tagged(8) if missing_map else None,
            "profile_count": int(missing_map),
            "representations_root": None, "representation_count": 0,
        }))
        placements = self.add(4, PLACEMENT_CONTEXT, encode_placement_set({
            "version": 1, "epoch": root_generation, "entries_root": None,
            "blob_count": 0, "replica_extent_count": 0,
        }))
        return self.add(5, STATE_CONTEXT, encode_representation_state({
            "version": 1, "generation": generation,
            "previous": previous if previous is not None else tagged(2),
            "catalogue": catalogue, "placements": placements,
        }))

    def checkpoint(self, active, generation=2, state_generation=7, prior=None):
        return frame(b"\x01" + struct.pack("<Q", generation)
                     + encode_optional(active) + struct.pack("<Q", state_generation)
                     + encode_optional(prior))

    def replay(self, checkpoint, tail=b"", generation=2, digest=None,
               max_tail_frames=100, max_tail_bytes=10000):
        with tempfile.TemporaryDirectory(prefix="astrid-reader-checkpoint-") as directory:
            path = Path(directory) / "state.journal"
            path.write_bytes(checkpoint + tail)
            return replay_state_journal(
                path, generation,
                digest or physical_identity(JOURNAL_CONTEXT, checkpoint),
                max_tail_frames, max_tail_bytes, self.metadata,
            )

    def test_compacted_checkpoint_seeds_active_state_without_old_history(self):
        active = self.state()
        checkpoint = self.checkpoint(active, prior=tagged(3))
        self.assertEqual(self.replay(checkpoint), active)

    def test_compacted_checkpoint_seeds_tail_cas_and_root_generations(self):
        active = self.state()
        replacement = self.state(generation=8, previous=active, root_generation=6)
        checkpoint = self.checkpoint(active, prior=tagged(3))
        tail = frame(b"\x00" + struct.pack("<Q", 2)
                     + encode_optional(active) + identity_bytes(replacement))
        self.assertEqual(self.replay(checkpoint, tail), replacement)

    def test_compacted_tail_can_reuse_authenticated_roots(self):
        active = self.state()
        replacement = self.state(generation=8, previous=active)
        checkpoint = self.checkpoint(active, prior=tagged(3))
        tail = frame(b"\x00" + struct.pack("<Q", 2)
                     + encode_optional(active) + identity_bytes(replacement))
        self.assertEqual(self.replay(checkpoint, tail), replacement)

    def test_compacted_checkpoint_rejects_missing_prior_or_active(self):
        active = self.state()
        for state, prior in [(active, None), (None, tagged(3))]:
            with self.subTest(active=state, prior=prior), self.assertRaises(FormatError):
                self.replay(self.checkpoint(state, prior=prior))

    def test_compacted_checkpoint_rejects_wrong_state_generation(self):
        active = self.state()
        with self.assertRaisesRegex(FormatError, "checkpoint state generation"):
            self.replay(self.checkpoint(active, state_generation=8, prior=tagged(3)))

    def test_compacted_checkpoint_rejects_missing_state_and_map_closure(self):
        for active in [tagged(9), self.state(missing_map=True)]:
            with self.subTest(active=active), self.assertRaises(FormatError):
                self.replay(self.checkpoint(active, prior=tagged(3)))

    def test_initial_checkpoint_still_requires_empty_generation_one(self):
        empty = self.checkpoint(None, generation=1, state_generation=0)
        # An initial checkpoint can be valid but cannot itself supply an active state.
        with self.assertRaisesRegex(FormatError, "no active state"):
            self.replay(empty, generation=1)
        active = self.state()
        with self.assertRaises(FormatError):
            self.replay(self.checkpoint(active, generation=1, prior=tagged(3)), generation=1)

    def test_compacted_checkpoint_preserves_digest_and_tail_budget_checks(self):
        active = self.state()
        checkpoint = self.checkpoint(active, prior=tagged(3))
        with self.assertRaisesRegex(FormatError, "checkpoint digest mismatch"):
            self.replay(checkpoint, digest=tagged(4))
        with self.assertRaisesRegex(FormatError, "tail budget"):
            self.replay(checkpoint, frame(b"x"), max_tail_frames=0)

    def test_compacted_tail_still_rejects_cas_and_root_generation_changes(self):
        active = self.state()
        checkpoint = self.checkpoint(active, prior=tagged(3))
        replacement = self.state(generation=8, previous=active, root_generation=9)
        for expected, message in [(tagged(4), "CAS conflict"), (active, "root generation")]:
            tail = frame(b"\x00" + struct.pack("<Q", 2)
                         + encode_optional(expected) + identity_bytes(replacement))
            with self.subTest(expected=expected), self.assertRaisesRegex(FormatError, message):
                self.replay(checkpoint, tail)

    def test_compacted_tail_rejects_wrong_predecessor_and_generation(self):
        active = self.state()
        checkpoint = self.checkpoint(active, prior=tagged(3))
        for generation, previous in [(8, tagged(4)), (9, active)]:
            replacement = self.state(generation=generation, previous=previous)
            tail = frame(b"\x00" + struct.pack("<Q", 2)
                         + encode_optional(active) + identity_bytes(replacement))
            with self.subTest(generation=generation), self.assertRaisesRegex(
                FormatError, "does not advance its predecessor"
            ):
                self.replay(checkpoint, tail)


if __name__ == "__main__":
    unittest.main()
