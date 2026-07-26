#!/usr/bin/env python3
"""Independent, deliberately primitive Astrid principal-store format-1 reader."""

import argparse
import json
import struct
import sys
from pathlib import Path

from principal_store_v1_blake3 import derive_key

FRAME_CONTEXT = "astrid durable physical frame checksum v1"
OBJECT_CONTEXT = "astrid principal store object identity v1"
ARENA_MAGIC = b"ASTOBJ1\0"
ROOT_MAGIC = b"ASTROOT\0"
HEADER_BYTES = 52
KIND_NAMES = (
    "Chunk",
    "ChunkTree",
    "File",
    "Symlink",
    "Directory",
    "KvLeaf",
    "KvBranch",
    "NamespaceMap",
    "PrincipalState",
    "Commit",
    "Evidence",
    "Derived",
)
REFERENCE_NAMES = ("Owns", "Evidence", "Lineage", "Derived")


class FormatError(Exception):
    pass


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise FormatError("truncated payload")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def done(self):
        if self.offset != len(self.data):
            raise FormatError("trailing payload bytes")


def frame_checksum(magic, payload):
    material = magic + struct.pack("<H", 1) + struct.pack("<Q", len(payload)) + payload
    return derive_key(FRAME_CONTEXT, material)


def physical_frame(data, magic, offset):
    if len(data) - offset < HEADER_BYTES:
        return None
    header = data[offset : offset + HEADER_BYTES]
    if header[:8] != magic:
        return False
    version, reserved, length = struct.unpack("<HHQ", header[8:20])
    if version != 1 or reserved != 0:
        raise FormatError(f"unsupported frame header at byte {offset}")
    end = offset + HEADER_BYTES + length
    if end > len(data):
        return None
    payload = data[offset + HEADER_BYTES : end]
    if frame_checksum(magic, payload) != header[20:52]:
        return False
    return (end, payload)


def valid_frame_follows(data, magic, offset):
    candidate = data.find(magic, offset + 1)
    while candidate >= 0:
        try:
            frame = physical_frame(data, magic, candidate)
        except FormatError:
            frame = False
        if frame:
            return True
        candidate = data.find(magic, candidate + 1)
    return False


def frames(path, magic):
    data = path.read_bytes()
    offset = 0
    while offset < len(data):
        frame = physical_frame(data, magic, offset)
        if frame is None:
            break
        if frame is False:
            if valid_frame_follows(data, magic, offset):
                raise FormatError(f"corrupt interior frame at byte {offset} in {path}")
            break
        end, payload = frame
        yield offset, payload
        offset = end


def identity(cursor):
    algorithm = cursor.integer(2)
    construction = cursor.integer(2)
    length = cursor.integer(4)
    if not algorithm or not construction or not length:
        raise FormatError("zero identity tag field")
    return (algorithm, construction, cursor.take(length))


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def encode_identity(value):
    algorithm, construction, digest = value
    return struct.pack("<HHI", algorithm, construction, len(digest)) + digest


def object_material(record):
    output = bytearray()
    output += struct.pack("<HH", record["kind"], record["version"])
    output += len(record["canonical"]).to_bytes(16, "little")
    output += record["canonical"]
    output += struct.pack("<QB", record["logical_bytes"], record["class"])
    output += len(record["references"]).to_bytes(16, "little")
    for reference in record["references"]:
        label = reference["label"]
        target = reference["target"]
        if target[:2] != (1, 1) or len(target[2]) != 32:
            raise FormatError("construction 1 reference uses another identity scheme")
        output += len(label).to_bytes(16, "little")
        output += label
        output += target[2]
        output += struct.pack("<B", reference["kind"])
    return bytes(output)


def decode_object(payload):
    cursor = Cursor(payload)
    object_id = identity(cursor)
    kind = cursor.integer(2)
    version = cursor.integer(2)
    object_class = cursor.integer(1)
    logical_bytes = cursor.integer(8)
    canonical_length = cursor.integer(8)
    reference_count = cursor.integer(8)
    if kind >= len(KIND_NAMES) or not version or object_class > 1:
        raise FormatError("unknown object tag")
    canonical = cursor.take(canonical_length)
    references = []
    previous = None
    for _ in range(reference_count):
        label = cursor.take(cursor.integer(8))
        target = identity(cursor)
        reference_kind = cursor.integer(1)
        if reference_kind >= len(REFERENCE_NAMES):
            raise FormatError("unknown reference kind")
        if previous is not None and label <= previous:
            raise FormatError("non-canonical reference order")
        previous = label
        references.append(
            {"label": label, "target": target, "kind": reference_kind}
        )
    cursor.done()
    record = {
        "kind": kind,
        "version": version,
        "class": object_class,
        "logical_bytes": logical_bytes,
        "canonical": canonical,
        "references": references,
    }
    if object_id[:2] != (1, 1) or len(object_id[2]) != 32:
        raise FormatError("reader does not implement this object identity")
    computed = derive_key(OBJECT_CONTEXT, object_material(record))
    if computed != object_id[2]:
        raise FormatError(f"object identity mismatch for {identity_text(object_id)}")
    return object_id, record


def root_state(cursor):
    return (cursor.integer(8), identity(cursor))


def decode_root(payload):
    cursor = Cursor(payload)
    principal = cursor.take(cursor.integer(8))
    expected_tag = cursor.integer(1)
    if expected_tag == 0:
        expected = None
    elif expected_tag == 1:
        expected = root_state(cursor)
    else:
        raise FormatError("invalid expected-root tag")
    replacement = root_state(cursor)
    cursor.done()
    return principal, expected, replacement


def principal_text(principal):
    if principal == b"\0":
        return "system"
    if principal[:1] == b"\1":
        value = principal[1:].decode("ascii")
        if not 1 <= len(value) <= 64 or any(
            not (character.isalnum() or character in "-_") for character in value
        ):
            raise FormatError("invalid principal identifier")
        return value
    raise FormatError("invalid state-owner encoding")


def parse_metadata(path):
    entries = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in entries:
            raise FormatError("invalid store.meta")
        entries[key] = value
    required = {
        "format": "astrid-principal-store-v1",
        "identity": "blake3-object-identity-v1",
        "identity-wire": "tagged-identity-v1",
        "principal-codec": "state-owner-v1",
        "projection": "kv-tree-v3",
    }
    for key, value in required.items():
        if entries.get(key) != value:
            raise FormatError(f"unsupported store.meta {key}")
    fields = entries["format-spec-object"].split(":")
    if len(fields) != 4:
        raise FormatError("invalid format-spec-object")
    tagged = (int(fields[0]), int(fields[1]), bytes.fromhex(fields[3]))
    if int(fields[2]) != len(tagged[2]):
        raise FormatError("format-spec-object length mismatch")
    return tagged


def validate_closure(objects, root):
    marks = {}

    def visit(object_id):
        key = identity_text(object_id)
        if marks.get(key) == 1:
            raise FormatError(f"ownership cycle at {key}")
        if marks.get(key) == 2:
            return
        record = objects.get(key)
        if record is None:
            raise FormatError(f"missing owned object {key}")
        marks[key] = 1
        for reference in record["references"]:
            if reference["kind"] == 0:
                visit(reference["target"])
        marks[key] = 2

    visit(root)


def recover(store, include_payloads):
    specification = parse_metadata(store / "store.meta")
    objects = {}
    offsets = {}
    for offset, payload in frames(store / "objects.arena", ARENA_MAGIC):
        object_id, record = decode_object(payload)
        key = identity_text(object_id)
        if key in objects and objects[key] != record:
            raise FormatError(f"object collision for {key}")
        objects[key] = record
        offsets.setdefault(key, offset)
    spec_key = identity_text(specification)
    spec = objects.get(spec_key)
    if (
        spec is None
        or spec["kind"] != 10
        or spec["version"] != 1
        or spec["class"] != 1
        or spec["logical_bytes"] != 0
        or spec["references"]
    ):
        raise FormatError("missing or invalid in-band format specification")

    roots = {}
    for offset, payload in frames(store / "roots.journal", ROOT_MAGIC):
        principal, expected, replacement = decode_root(payload)
        name = principal_text(principal)
        actual = roots.get(name)
        if actual != expected:
            raise FormatError(f"root CAS mismatch for {name} at byte {offset}")
        generation = 0 if actual is None else actual[0] + 1
        if replacement[0] != generation:
            raise FormatError(f"root generation mismatch for {name} at byte {offset}")
        roots[name] = replacement
    for name, root in roots.items():
        record = objects.get(identity_text(root[1]))
        if record is None or record["kind"] != 9:
            raise FormatError(f"principal {name} root is not a Commit")
        validate_closure(objects, root[1])

    dumped_objects = []
    for key in sorted(objects):
        record = objects[key]
        dumped = {
            "id": key,
            "arena_offset": offsets[key],
            "kind": KIND_NAMES[record["kind"]],
            "format_version": record["version"],
            "class": "Data" if record["class"] == 0 else "Metadata",
            "logical_bytes": record["logical_bytes"],
            "canonical_bytes": len(record["canonical"]),
            "references": [
                {
                    "label_hex": reference["label"].hex(),
                    "target": identity_text(reference["target"]),
                    "kind": REFERENCE_NAMES[reference["kind"]],
                }
                for reference in record["references"]
            ],
        }
        if include_payloads:
            dumped["canonical_hex"] = record["canonical"].hex()
        dumped_objects.append(dumped)
    return {
        "format_spec_object": spec_key,
        "objects": dumped_objects,
        "roots": {
            name: {"generation": root[0], "commit": identity_text(root[1])}
            for name, root in sorted(roots.items())
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("store", type=Path)
    parser.add_argument("--payloads", action="store_true")
    arguments = parser.parse_args()
    try:
        result = recover(arguments.store, arguments.payloads)
    except (FormatError, OSError, UnicodeError, ValueError) as error:
        print(f"principal-store-v1-reader: {error}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
