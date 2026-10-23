#!/usr/bin/env python3
"""Focused independent-reader grammar tests for root removal and workspaces."""

from __future__ import annotations

import struct
import unittest

from runatal_v1_reader import (
    ROOT_REMOVAL_RECORD,
    ROOT_SNAPSHOT_RECORD,
    ROOT_SNAPSHOT_SENTINEL,
    FormatError,
    decode_root,
)
from runatal_v1_workspace import (
    BRANCH_MAGIC,
    BRANCH_RECEIPT_MAGIC,
    NODE_QUOTA_BYTES,
    WorkspaceFormatError,
    decode_workspace_branch,
    leaf_summary,
    primary_key,
    validate_workspace_branch_schema,
)


def identity_bytes(digest: bytes):
    return struct.pack("<HHI", 1, 1, 32) + digest


def root_state_bytes(generation: int, digest: bytes):
    return generation.to_bytes(8, "little") + identity_bytes(digest)


def encode_removal(principal: bytes, generation: int, digest: bytes):
    return (
        ROOT_SNAPSHOT_SENTINEL.to_bytes(8, "little")
        + bytes([ROOT_REMOVAL_RECORD])
        + len(principal).to_bytes(8, "little")
        + principal
        + root_state_bytes(generation, digest)
    )


def encode_snapshot(entries):
    payload = (
        ROOT_SNAPSHOT_SENTINEL.to_bytes(8, "little")
        + bytes([ROOT_SNAPSHOT_RECORD])
        + len(entries).to_bytes(8, "little")
    )
    for principal, generation, digest in entries:
        payload += len(principal).to_bytes(8, "little")
        payload += principal
        payload += root_state_bytes(generation, digest)
    return payload


def encode_transition(principal, expected, replacement):
    payload = len(principal).to_bytes(8, "little") + principal
    if expected is None:
        payload += b"\0"
    else:
        payload += b"\1" + root_state_bytes(*expected)
    payload += root_state_bytes(*replacement)
    return payload


def apply_roots(frames):
    roots = {}
    for offset, payload in frames:
        record = decode_root(payload)
        if record[0] == "snapshot":
            if offset != 0 or roots:
                raise FormatError("root snapshot must be the first journal frame")
            for principal, current in record[1]:
                roots[principal] = current
        elif record[0] == "remove":
            _, principal, expected = record
            actual = roots.get(principal)
            if actual != expected:
                raise FormatError("root CAS mismatch")
            del roots[principal]
        else:
            _, principal, expected, replacement = record
            actual = roots.get(principal)
            if actual != expected:
                raise FormatError("root CAS mismatch")
            roots[principal] = replacement
    return roots


def workspace_bytes(
    *,
    magic=BRANCH_MAGIC,
    workspace_uid=b"\x11" * 16,
    binding=None,
    legacy=False,
    prefix=b"docs",
    base=None,
    working=None,
):
    payload = magic + workspace_uid
    if not legacy:
        if binding is None:
            payload += b"\0" + bytes(32)
        else:
            payload += b"\1" + binding
    payload += len(prefix).to_bytes(4, "little") + prefix
    for root in (base, working):
        if root is None:
            payload += b"\0" + bytes(32)
        else:
            payload += b"\1" + root
    return payload


class RootRemovalGrammarTests(unittest.TestCase):
    def test_decode_root_accepts_tag2_and_rejects_unknown_or_trailing(self):
        principal = b"\1" + bytes(range(32))
        digest = bytes([7]) * 32
        payload = encode_removal(principal, 3, digest)
        record = decode_root(payload)
        self.assertEqual(record[0], "remove")
        self.assertEqual(record[1], principal)
        self.assertEqual(record[2], (3, (1, 1, digest)))

        truncated = payload[:-1]
        with self.assertRaises(FormatError):
            decode_root(truncated)
        trailing = payload + b"\0"
        with self.assertRaisesRegex(FormatError, "trailing"):
            decode_root(trailing)
        unknown = bytearray(payload)
        unknown[8] = 3
        with self.assertRaisesRegex(FormatError, "unknown root-journal extension"):
            decode_root(bytes(unknown))

    def test_recover_removes_exact_expected_and_fails_closed_on_stale(self):
        alice = b"\1" + b"a" * 32
        bob = b"\1" + b"b" * 32
        alice_digest = b"\x0a" * 32
        bob_digest = b"\x0b" * 32
        snapshot = encode_snapshot(
            [
                (alice, 1, alice_digest),
                (bob, 0, bob_digest),
            ]
        )
        removal = encode_removal(alice, 1, alice_digest)
        roots = apply_roots([(0, snapshot), (100, removal)])
        self.assertNotIn(alice, roots)
        self.assertEqual(roots[bob], (0, (1, 1, bob_digest)))

        with self.assertRaisesRegex(FormatError, "root CAS mismatch"):
            apply_roots([(0, snapshot), (100, encode_removal(alice, 0, alice_digest))])
        with self.assertRaisesRegex(FormatError, "root CAS mismatch"):
            apply_roots([(0, snapshot), (100, removal), (200, removal)])

    def test_transition_and_snapshot_still_decode(self):
        principal = b"\1" + b"c" * 32
        digest = b"\x0c" * 32
        transition = encode_transition(principal, None, (0, digest))
        self.assertEqual(decode_root(transition)[0], "transition")
        snapshot = encode_snapshot([(principal, 0, digest)])
        self.assertEqual(decode_root(snapshot)[0], "snapshot")
        self.assertEqual(snapshot[8], ROOT_SNAPSHOT_RECORD)


class WorkspaceBranchGrammarTests(unittest.TestCase):
    def test_live_bound_and_promoted_records_decode(self):
        binding = b"\x22" * 32
        base = b"\x33" * 32
        working = b"\x44" * 32
        live = {
            "kind": 17,
            "version": 1,
            "class": 1,
            "logical_bytes": 0,
            "canonical": workspace_bytes(
                binding=binding, prefix=b"docs/src", base=base, working=working
            ),
            "references": [
                {"label": b"base", "target": (1, 1, base), "kind": 0},
                {"label": b"working", "target": (1, 1, working), "kind": 0},
            ],
        }
        decoded = decode_workspace_branch(live)
        self.assertFalse(decoded["promoted"])
        self.assertEqual(decoded["binding_uid_hex"], binding.hex())
        self.assertEqual(decoded["target_prefix"], "docs/src")
        self.assertEqual(primary_key(False, decoded["id_hex"]), f"b/{decoded['id_hex']}")

        receipt = {
            "kind": 17,
            "version": 1,
            "class": 1,
            "logical_bytes": 0,
            "canonical": workspace_bytes(
                magic=BRANCH_RECEIPT_MAGIC,
                binding=binding,
                prefix=b"docs/src",
                base=base,
                working=working,
            ),
            "references": [],
        }
        promoted = decode_workspace_branch(receipt)
        self.assertTrue(promoted["promoted"])

    def test_legacy_unbound_and_malformed_fail_closed(self):
        legacy = {
            "kind": 17,
            "version": 1,
            "class": 1,
            "logical_bytes": 0,
            "canonical": workspace_bytes(legacy=True, prefix=b"docs", base=None, working=None),
            "references": [],
        }
        decoded = decode_workspace_branch(legacy)
        self.assertIsNone(decoded["binding_uid"])
        self.assertTrue(decoded["legacy_encoding"])

        malformed = dict(legacy)
        malformed["canonical"] = workspace_bytes(binding=b"\x01" * 32, prefix=b"")
        with self.assertRaisesRegex(WorkspaceFormatError, "bound workspace has no prefix"):
            validate_workspace_branch_schema(malformed)

        bad_ref = dict(legacy)
        bad_ref["canonical"] = workspace_bytes(legacy=True, prefix=b"docs", base=b"\x55" * 32)
        bad_ref["references"] = []
        with self.assertRaisesRegex(WorkspaceFormatError, "not canonical"):
            validate_workspace_branch_schema(bad_ref)

    def test_workspace_leaf_quota_includes_fixed_reserve(self):
        summary = leaf_summary("b/" + "ab" * 16, 10, node_quota_bytes=NODE_QUOTA_BYTES)
        self.assertEqual(summary["entries"], 1)
        self.assertEqual(summary["logical_bytes"], 10)
        self.assertEqual(summary["quota_bytes"], 10 + len("b/" + "ab" * 16) + NODE_QUOTA_BYTES)



def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def make_record(kind, version, canonical, references, logical_bytes=0, object_class=1):
    return {
        "kind": kind,
        "version": version,
        "class": object_class,
        "logical_bytes": logical_bytes,
        "canonical": canonical,
        "references": references,
    }


class WorkspaceDirectoryGrammarTests(unittest.TestCase):
    def test_unbound_primary_leaf_directory_validates(self):
        from runatal_v1_workspace import (
            VALUE_LABEL,
            decode_workspace_branch,
            row_charge,
            validate_workspace_directory,
        )

        workspace_uid = b"\x11" * 16
        branch_digest = b"\x77" * 32
        directory_digest = b"\x88" * 32
        branch_record = make_record(
            17,
            1,
            workspace_bytes(legacy=True, workspace_uid=workspace_uid, prefix=b"docs"),
            [],
        )
        branch = decode_workspace_branch(branch_record)
        charge = row_charge(branch_record, branch, promoted=False, working_quota_bytes=0)
        name = f"b/{branch['id_hex']}".encode()
        leaf_canonical = (
            b"\0"
            + charge.to_bytes(8, "little")
            + len(name).to_bytes(8, "little")
            + name
        )
        leaf_record = make_record(
            4,
            3,
            leaf_canonical,
            [{"label": VALUE_LABEL, "target": (1, 1, branch_digest), "kind": 0}],
            logical_bytes=charge,
        )
        objects = {
            identity_text((1, 1, branch_digest)): branch_record,
            identity_text((1, 1, directory_digest)): leaf_record,
        }
        validated = validate_workspace_directory(objects, (1, 1, directory_digest))
        self.assertEqual(len(validated["leaves"]), 1)
        self.assertEqual(validated["leaves"][0]["name"], name.decode())

    def test_bound_primary_without_inventory_fails_closed(self):
        from runatal_v1_workspace import (
            VALUE_LABEL,
            decode_workspace_branch,
            row_charge,
            validate_workspace_directory,
        )

        workspace_uid = b"\x11" * 16
        binding = b"\x22" * 32
        branch_digest = b"\x77" * 32
        directory_digest = b"\x88" * 32
        branch_record = make_record(
            17,
            1,
            workspace_bytes(
                workspace_uid=workspace_uid,
                binding=binding,
                prefix=b"docs",
            ),
            [],
        )
        branch = decode_workspace_branch(branch_record)
        charge = row_charge(branch_record, branch, promoted=False, working_quota_bytes=0)
        name = f"b/{branch['id_hex']}".encode()
        leaf_canonical = (
            b"\0"
            + charge.to_bytes(8, "little")
            + len(name).to_bytes(8, "little")
            + name
        )
        leaf_record = make_record(
            4,
            3,
            leaf_canonical,
            [{"label": VALUE_LABEL, "target": (1, 1, branch_digest), "kind": 0}],
            logical_bytes=charge,
        )
        objects = {
            identity_text((1, 1, branch_digest)): branch_record,
            identity_text((1, 1, directory_digest)): leaf_record,
        }
        with self.assertRaisesRegex(WorkspaceFormatError, "binding inventory disagrees"):
            validate_workspace_directory(objects, (1, 1, directory_digest))


class FlatWorkspaceLabelGrammarTests(unittest.TestCase):
    def test_flat_live_and_receipt_labels_bind_to_record(self):
        from runatal_v1_workspace import (
            validate_flat_workspace_reference,
            validate_principal_workspace,
        )

        workspace_uid = b"\xab" * 16
        live_digest = b"\x01" * 32
        receipt_digest = b"\x02" * 32
        state_digest = b"\x03" * 32
        commit_digest = b"\x04" * 32
        live = make_record(
            17,
            1,
            workspace_bytes(workspace_uid=workspace_uid, legacy=True, prefix=b"docs"),
            [],
        )
        # Distinct receipt identity uses a different workspace uid.
        receipt_uid = b"\xcd" * 16
        receipt = make_record(
            17,
            1,
            workspace_bytes(
                magic=BRANCH_RECEIPT_MAGIC,
                workspace_uid=receipt_uid,
                legacy=True,
                prefix=b"docs",
            ),
            [],
        )
        live_label = b"workspace/" + workspace_uid.hex().encode()
        receipt_label = b"workspace-promoted/workspace/" + receipt_uid.hex().encode()
        live_ref = {"label": live_label, "target": (1, 1, live_digest), "kind": 0}
        receipt_ref = {
            "label": receipt_label,
            "target": (1, 1, receipt_digest),
            "kind": 0,
        }
        objects = {
            identity_text((1, 1, live_digest)): live,
            identity_text((1, 1, receipt_digest)): receipt,
        }
        self.assertEqual(
            validate_flat_workspace_reference(objects, live_ref)["id_hex"],
            workspace_uid.hex(),
        )
        self.assertTrue(validate_flat_workspace_reference(objects, receipt_ref)["promoted"])

        mismatched = dict(live_ref)
        mismatched["label"] = b"workspace/" + (b"\x11" * 16).hex().encode()
        with self.assertRaisesRegex(WorkspaceFormatError, "label disagrees with record uid"):
            validate_flat_workspace_reference(objects, mismatched)

        wrong_life = dict(live_ref)
        wrong_life["label"] = b"workspace-promoted/workspace/" + workspace_uid.hex().encode()
        with self.assertRaisesRegex(WorkspaceFormatError, "label disagrees with lifecycle"):
            validate_flat_workspace_reference(objects, wrong_life)

        state = make_record(
            8,
            4,
            b"",
            [
                live_ref,
                receipt_ref,
            ],
        )
        commit = make_record(
            9,
            4,
            b"\0" * 8 + b"\0" + bytes(40) + b"\1" + bytes(40),
            [{"label": b"state", "target": (1, 1, state_digest), "kind": 0}],
        )
        # Canonical commit bytes are not validated here; only references/workspace.
        commit["canonical"] = b"x" * 89
        objects[identity_text((1, 1, state_digest))] = state
        objects[identity_text((1, 1, commit_digest))] = commit
        validated = validate_principal_workspace(objects, (1, 1, commit_digest))
        self.assertEqual(validated["layout"], "flat")
        self.assertEqual(len(validated["branches"]), 2)

    def test_non_owning_flat_edge_fails_closed(self):
        from runatal_v1_workspace import validate_flat_workspace_reference

        workspace_uid = b"\xab" * 16
        digest = b"\x01" * 32
        record = make_record(
            17,
            1,
            workspace_bytes(workspace_uid=workspace_uid, legacy=True, prefix=b"docs"),
            [],
        )
        objects = {identity_text((1, 1, digest)): record}
        with self.assertRaisesRegex(WorkspaceFormatError, "not owning"):
            validate_flat_workspace_reference(
                objects,
                {
                    "label": b"workspace/" + workspace_uid.hex().encode(),
                    "target": (1, 1, digest),
                    "kind": 1,
                },
            )


class BoundDirectoryBijectionGrammarTests(unittest.TestCase):
    def _bound_records(self):
        workspace_uid = b"\x11" * 16
        binding = b"\x22" * 32
        branch_digest = b"\x77" * 32
        branch_record = make_record(
            17,
            1,
            workspace_bytes(
                workspace_uid=workspace_uid,
                binding=binding,
                prefix=b"docs",
            ),
            [],
        )
        from runatal_v1_workspace import decode_workspace_branch, row_charge

        branch = decode_workspace_branch(branch_record)
        charge = row_charge(branch_record, branch, promoted=False, working_quota_bytes=0)
        return branch_record, branch, branch_digest, charge, binding

    def _leaf(self, name, target, charge):
        from runatal_v1_workspace import VALUE_LABEL

        name_bytes = name.encode()
        leaf_canonical = (
            b"\0"
            + charge.to_bytes(8, "little")
            + len(name_bytes).to_bytes(8, "little")
            + name_bytes
        )
        return make_record(
            4,
            3,
            leaf_canonical,
            [{"label": VALUE_LABEL, "target": target, "kind": 0}],
            logical_bytes=charge,
        )

    def _branch_node(self, bit, left_id, left_summary, right_id, right_summary):
        from runatal_v1_workspace import LEFT_LABEL, RIGHT_LABEL

        def pack_summary(summary):
            return (
                summary["logical_bytes"].to_bytes(8, "little")
                + summary["quota_bytes"].to_bytes(8, "little")
                + summary["entries"].to_bytes(8, "little")
            )

        canonical = (
            b"\1"
            + bit.to_bytes(8, "little")
            + pack_summary(left_summary)
            + pack_summary(right_summary)
        )
        return make_record(
            4,
            3,
            canonical,
            [
                {"label": LEFT_LABEL, "target": left_id, "kind": 0},
                {"label": RIGHT_LABEL, "target": right_id, "kind": 0},
            ],
        )

    def _build_directory(self, objects, rows):
        """Build a canonical binary directory from sorted (name, charge, digest, target)."""
        from runatal_v1_workspace import NODE_QUOTA_BYTES, first_differing_bit, leaf_summary

        rows = sorted(rows, key=lambda item: item[0])
        nodes = []
        for name, leaf_charge, digest, target in rows:
            objects[identity_text((1, 1, digest))] = self._leaf(name, target, leaf_charge)
            nodes.append(
                {
                    "id": (1, 1, digest),
                    "summary": leaf_summary(
                        name, leaf_charge, node_quota_bytes=NODE_QUOTA_BYTES
                    ),
                    "min": name,
                    "max": name,
                }
            )

        counter = 0
        while len(nodes) > 1:
            # Always combine the adjacent pair whose first differing bit is largest
            # (deepest), matching the compressed-binary construction.
            best = None
            for index in range(len(nodes) - 1):
                bit = first_differing_bit(nodes[index]["max"], nodes[index + 1]["min"])
                if best is None or bit > best[0]:
                    best = (bit, index)
            bit, index = best
            left = nodes[index]
            right = nodes[index + 1]
            digest = bytes([0xD0 + counter]) + bytes(31)
            counter += 1
            summary = {
                "logical_bytes": left["summary"]["logical_bytes"]
                + right["summary"]["logical_bytes"],
                "quota_bytes": left["summary"]["quota_bytes"] + right["summary"]["quota_bytes"],
                "entries": left["summary"]["entries"] + right["summary"]["entries"],
            }
            objects[identity_text((1, 1, digest))] = self._branch_node(
                bit,
                left["id"],
                left["summary"],
                right["id"],
                right["summary"],
            )
            nodes[index : index + 2] = [
                {
                    "id": (1, 1, digest),
                    "summary": summary,
                    "min": left["min"],
                    "max": right["max"],
                }
            ]
        return nodes[0]["id"]

    def test_bound_primary_with_inventory_and_selector_validates(self):
        from runatal_v1_workspace import (
            inventory_key,
            primary_key,
            selector_key,
            validate_workspace_directory,
        )

        branch_record, branch, branch_digest, charge, binding = self._bound_records()
        primary = primary_key(False, branch["id_hex"])
        inventory = inventory_key(binding.hex(), branch["id_hex"])
        selector = selector_key(binding.hex(), branch["target_prefix"])
        target = (1, 1, branch_digest)
        objects = {identity_text(target): branch_record}
        root = self._build_directory(
            objects,
            [
                (inventory, 0, b"\xa1" * 32, target),
                (primary, charge, b"\xa2" * 32, target),
                (selector, 0, b"\xa3" * 32, target),
            ],
        )
        validated = validate_workspace_directory(objects, root)
        self.assertEqual(len(validated["leaves"]), 3)
        self.assertEqual(validated["summary"]["entries"], 3)

    def test_redundant_inventory_row_fails_closed(self):
        from runatal_v1_workspace import (
            inventory_key,
            primary_key,
            selector_key,
            validate_workspace_directory,
        )

        branch_record, branch, branch_digest, charge, binding = self._bound_records()
        other_uid = b"\x33" * 16
        orphan = make_record(
            17,
            1,
            workspace_bytes(
                workspace_uid=other_uid,
                binding=binding,
                prefix=b"docs",
            ),
            [],
        )
        orphan_digest = b"\x66" * 32
        primary = primary_key(False, branch["id_hex"])
        inventory = inventory_key(binding.hex(), branch["id_hex"])
        selector = selector_key(binding.hex(), branch["target_prefix"])
        redundant = inventory_key(binding.hex(), other_uid.hex())
        objects = {
            identity_text((1, 1, branch_digest)): branch_record,
            identity_text((1, 1, orphan_digest)): orphan,
        }
        root = self._build_directory(
            objects,
            [
                (inventory, 0, b"\xc1" * 32, (1, 1, branch_digest)),
                (redundant, 0, b"\xc2" * 32, (1, 1, orphan_digest)),
                (primary, charge, b"\xc3" * 32, (1, 1, branch_digest)),
                (selector, 0, b"\xc4" * 32, (1, 1, branch_digest)),
            ],
        )
        with self.assertRaisesRegex(WorkspaceFormatError, "binding inventory disagrees"):
            validate_workspace_directory(objects, root)



class ContentCatalogLeafLengthTests(unittest.TestCase):
    def _file_and_leaf(self, *, payload_logical, leaf_logical):
        import struct
        from runatal_v1_workspace import FILE_LABEL

        file_digest = b"\xf1" * 32
        leaf_digest = b"\xf2" * 32
        # File object header logical_bytes is always 0; payload length is canonical.
        file_canonical = struct.pack(
            "<BHBIIIQQQ",
            1,  # algorithm
            1,  # revision
            1,  # normalization
            1024,
            8192,
            262144,
            0,  # seed
            payload_logical,
            1 if payload_logical else 0,
        )
        file_record = make_record(2, 1, file_canonical, [], logical_bytes=0)
        name = b"main.rs"
        leaf_canonical = (
            b"\0"
            + leaf_logical.to_bytes(8, "little")
            + len(name).to_bytes(8, "little")
            + name
        )
        leaf_record = make_record(
            4,
            2,
            leaf_canonical,
            [{"label": FILE_LABEL, "target": (1, 1, file_digest), "kind": 0}],
            logical_bytes=leaf_logical,
        )
        objects = {
            identity_text((1, 1, file_digest)): file_record,
            identity_text((1, 1, leaf_digest)): leaf_record,
        }
        return objects, (1, 1, leaf_digest)

    def test_nonempty_leaf_matches_file_payload_length(self):
        from runatal_v1_workspace import validate_content_catalog

        objects, root = self._file_and_leaf(payload_logical=12, leaf_logical=12)
        validated = validate_content_catalog(objects, root)
        self.assertEqual(validated["summary"]["logical_bytes"], 12)
        self.assertEqual(validated["leaves"][0]["name"], "main.rs")

    def test_leaf_length_disagrees_with_file_payload_fails_closed(self):
        from runatal_v1_workspace import validate_content_catalog

        objects, root = self._file_and_leaf(payload_logical=12, leaf_logical=99)
        with self.assertRaisesRegex(
            WorkspaceFormatError, "content catalog leaf length disagrees with File"
        ):
            validate_content_catalog(objects, root)

    def test_zero_header_field_is_not_used_as_file_length(self):
        from runatal_v1_workspace import validate_content_catalog

        # Regression: comparing the File object-header field (always 0) would
        # reject every nonempty catalog leaf.
        objects, root = self._file_and_leaf(payload_logical=7, leaf_logical=7)
        self.assertEqual(
            validate_content_catalog(objects, root)["summary"]["logical_bytes"], 7
        )




if __name__ == "__main__":
    unittest.main()
