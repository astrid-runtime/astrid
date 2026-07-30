#!/usr/bin/env python3
"""Independent, deliberately primitive Astrid RÚNATAL format-1 reader."""

import argparse
import json
import struct
import sys
from pathlib import Path

from runatal_v1_blake3 import derive_key
from runatal_v1_fastcdc import (
    ASTRID_V1,
    is_canonical_boundary,
    validate_profile,
    verify_golden_vectors,
)

FRAME_CONTEXT = "astrid durable physical frame checksum v1"
OBJECT_CONTEXT = "astrid principal store object identity v1"
ARENA_MAGIC = b"ASTOBJ1\0"
ROOT_MAGIC = b"ASTROOT\0"
ROOT_SNAPSHOT_SENTINEL = (1 << 64) - 1
ROOT_SNAPSHOT_RECORD = 1
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
    "RuntimeSemanticProfile",
    "DerivationInvocation",
    "DerivationEvidence",
    "GcPlanEvidence",
    "GcCommitEvidence",
)
REFERENCE_NAMES = ("Owns", "Evidence", "Lineage", "Derived")
FORMAT_SPECIFICATION = (
    1,
    1,
    bytes.fromhex("0f9a06bce643fb90e6446c4c0dc42144ba1446826e5c7c624cebeb661a479143"),
)
CONTENT_CATALOG_SPECIFICATION = (
    1,
    1,
    bytes.fromhex("8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb"),
)
CHUNK_TREE_FANOUT = 128
CONTENT_LABEL = b"content"
U64_MAX = (1 << 64) - 1


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


def require_metadata_schema(record, kind, canonical_length):
    if (
        record["kind"] != kind
        or record["version"] != 1
        or record["class"] != 1
        or record["logical_bytes"] != 0
        or len(record["canonical"]) != canonical_length
    ):
        raise FormatError(f"invalid {KIND_NAMES[kind]} object header")


def indexed_suffix(label, prefix, expected, require_suffix):
    index_end = len(prefix) + 8
    suffix_start = index_end + 1
    if (
        len(label) < suffix_start
        or not label.startswith(prefix)
        or label[index_end] != 0
        or int.from_bytes(label[len(prefix) : index_end], "big") != expected
    ):
        raise FormatError("invalid indexed reference label")
    suffix = label[suffix_start:]
    if require_suffix and not suffix:
        raise FormatError("indexed semantic label is empty")
    if not require_suffix and suffix:
        raise FormatError("indexed set label has a suffix")
    return suffix


def require_reference_kind(reference, expected):
    if reference["kind"] != expected:
        raise FormatError("invalid canonical reference kind")


def decode_file(record):
    require_metadata_schema(record, 2, 40)
    (
        algorithm,
        revision,
        normalization,
        minimum,
        average,
        maximum,
        seed,
        logical_bytes,
        chunk_count,
    ) = struct.unpack("<BHBIIIQQQ", record["canonical"])
    profile = (
        algorithm,
        revision,
        normalization,
        minimum,
        average,
        maximum,
        seed,
    )
    try:
        validate_profile(profile)
    except ValueError as error:
        raise FormatError(str(error)) from error
    references = record["references"]
    if not logical_bytes:
        if chunk_count or references:
            raise FormatError("empty File has chunks or content")
        return profile, 0, 0, None
    if not chunk_count:
        raise FormatError("non-empty File has no chunks")
    if (chunk_count == 1) != (logical_bytes <= maximum):
        raise FormatError("File violates the whole-object threshold")
    if (
        len(references) != 1
        or references[0]["label"] != CONTENT_LABEL
        or references[0]["kind"] != 0
    ):
        raise FormatError("invalid File content reference")
    return profile, logical_bytes, chunk_count, references[0]["target"]


def canonical_tree_depth(chunk_count):
    depth = 0
    capacity = 1
    while capacity < chunk_count:
        capacity *= CHUNK_TREE_FANOUT
        depth += 1
    return depth


def tree_capacity(depth):
    return CHUNK_TREE_FANOUT**depth


def validate_profile_bounds(logical_bytes, chunk_count, profile, ends_file):
    minimum = profile[3] & ~1
    maximum = profile[5]
    maximum_total = chunk_count * maximum
    required_full_chunks = chunk_count - 1 if ends_file else chunk_count
    minimum_total = required_full_chunks * minimum + (1 if ends_file else 0)
    if (
        logical_bytes > U64_MAX
        or logical_bytes < minimum_total
        or logical_bytes > maximum_total
    ):
        raise FormatError("content shape violates the declared chunking profile")


def decode_tree(record, shape):
    logical_bytes, chunk_count, depth, profile, ends_file = shape
    require_metadata_schema(record, 1, len(record["canonical"]))
    canonical = record["canonical"]
    if len(canonical) < 18:
        raise FormatError("truncated ChunkTree header")
    child_count, stored_bytes, stored_chunks = struct.unpack("<HQQ", canonical[:18])
    references = record["references"]
    if (
        not 1 <= child_count <= CHUNK_TREE_FANOUT
        or len(references) != child_count
        or len(canonical) != 18 + child_count * 16
        or stored_bytes != logical_bytes
        or stored_chunks != chunk_count
    ):
        raise FormatError("inconsistent ChunkTree header")

    children = []
    total_bytes = 0
    total_chunks = 0
    child_capacity = tree_capacity(depth - 1)
    for index, reference in enumerate(references):
        if reference["label"] != index.to_bytes(2, "big") or reference["kind"] != 0:
            raise FormatError("non-canonical ChunkTree child reference")
        start = 18 + index * 16
        child_bytes, child_chunks = struct.unpack("<QQ", canonical[start : start + 16])
        if (
            not child_bytes
            or not child_chunks
            or child_chunks > child_capacity
            or (index + 1 < child_count and child_chunks != child_capacity)
        ):
            raise FormatError("non-canonical ChunkTree child shape")
        child_ends_file = ends_file and index + 1 == child_count
        validate_profile_bounds(
            child_bytes,
            child_chunks,
            profile,
            child_ends_file,
        )
        total_bytes += child_bytes
        total_chunks += child_chunks
        children.append(
            (
                reference["target"],
                (
                    child_bytes,
                    child_chunks,
                    depth - 1,
                    profile,
                    child_ends_file,
                ),
            )
        )
    if total_bytes != stored_bytes or total_chunks != stored_chunks:
        raise FormatError("ChunkTree child totals do not match its header")
    return children


def validate_content_boundary(left_object, left, right_prefix, profile, memo):
    key = (identity_text(left_object), right_prefix, profile)
    valid = memo.get(key)
    if valid is None:
        valid = is_canonical_boundary(left, right_prefix, profile)
        memo[key] = valid
    if not valid:
        raise FormatError("non-canonical FastCDC boundary")


def content_summary(objects, object_id, shape, summaries, boundaries):
    key = (identity_text(object_id), shape)
    cached = summaries.get(key)
    if cached is not None:
        return cached

    logical_bytes, chunk_count, depth, profile, ends_file = shape
    record = objects.get(identity_text(object_id))
    if record is None:
        raise FormatError("File content object is missing")
    if record["kind"] == 0:
        if (
            record["version"] != 1
            or record["class"] != 0
            or record["logical_bytes"] != 0
            or record["references"]
            or len(record["canonical"]) != logical_bytes
            or chunk_count != 1
            or depth != 0
        ):
            raise FormatError("invalid Chunk object")
        validate_profile_bounds(logical_bytes, 1, profile, ends_file)
        summary = (
            record["canonical"][:2],
            object_id,
            record["canonical"],
        )
        summaries[key] = summary
        return summary
    if record["kind"] != 1 or depth == 0:
        raise FormatError("File content points to a non-canonical object kind")

    first_prefix = None
    last_object = None
    last_bytes = None
    for child, child_shape in decode_tree(record, shape):
        child_prefix, child_last_object, child_last_bytes = content_summary(
            objects,
            child,
            child_shape,
            summaries,
            boundaries,
        )
        if last_bytes is None:
            first_prefix = child_prefix
        else:
            validate_content_boundary(
                last_object,
                last_bytes,
                child_prefix,
                profile,
                boundaries,
            )
        last_object = child_last_object
        last_bytes = child_last_bytes

    if first_prefix is None or last_object is None or last_bytes is None:
        raise FormatError("non-empty ChunkTree has no content summary")
    summary = (first_prefix, last_object, last_bytes)
    summaries[key] = summary
    return summary


def validate_file(objects, record):
    profile, logical_bytes, chunk_count, content = decode_file(record)
    if content is None:
        return
    shape = (
        logical_bytes,
        chunk_count,
        canonical_tree_depth(chunk_count),
        profile,
        True,
    )
    content_summary(objects, content, shape, {}, {})


def verify_content_summary_vectors():
    chunk_id = (1, 1, bytes((1,)) * 32)
    branch_id = (1, 1, bytes((2,)) * 32)
    root_id = (1, 1, bytes((3,)) * 32)
    chunk_bytes = bytes(ASTRID_V1[5])

    def tree_record(child, child_bytes, child_chunks):
        count = CHUNK_TREE_FANOUT
        logical_bytes = child_bytes * count
        chunk_count = child_chunks * count
        canonical = bytearray(struct.pack("<HQQ", count, logical_bytes, chunk_count))
        references = []
        for index in range(count):
            canonical += struct.pack("<QQ", child_bytes, child_chunks)
            references.append(
                {
                    "label": index.to_bytes(2, "big"),
                    "target": child,
                    "kind": 0,
                }
            )
        return {
            "kind": 1,
            "version": 1,
            "canonical": bytes(canonical),
            "logical_bytes": 0,
            "class": 1,
            "references": references,
        }

    class CountingObjects(dict):
        def __init__(self, *args):
            super().__init__(*args)
            self.lookups = {}

        def get(self, key, default=None):
            self.lookups[key] = self.lookups.get(key, 0) + 1
            return super().get(key, default)

    chunk_record = {
        "kind": 0,
        "version": 1,
        "canonical": chunk_bytes,
        "logical_bytes": 0,
        "class": 0,
        "references": [],
    }
    branch_record = tree_record(chunk_id, len(chunk_bytes), 1)
    root_record = tree_record(
        branch_id,
        len(chunk_bytes) * CHUNK_TREE_FANOUT,
        CHUNK_TREE_FANOUT,
    )
    objects = CountingObjects(
        {
            identity_text(chunk_id): chunk_record,
            identity_text(branch_id): branch_record,
            identity_text(root_id): root_record,
        }
    )
    chunk_count = CHUNK_TREE_FANOUT**2
    shape = (
        len(chunk_bytes) * chunk_count,
        chunk_count,
        2,
        ASTRID_V1,
        True,
    )
    content_summary(objects, root_id, shape, {}, {})
    if any(lookups > 2 for lookups in objects.lookups.values()):
        raise FormatError("shared content subtree was expanded instead of memoized")


def validate_runtime_profile(record):
    require_metadata_schema(record, 12, 1)
    component_present = record["canonical"][0]
    if component_present not in (0, 1):
        raise FormatError("invalid runtime-profile option byte")
    required = {
        b"00-wasm-core",
        b"02-float",
        b"03-threads",
        b"04-resource-failure",
    }
    seen = set()
    proposal_count = 0
    previous_proposal = None
    previous_host = None
    component_seen = False
    for reference in record["references"]:
        require_reference_kind(reference, 0)
        label = reference["label"]
        if label in required:
            seen.add(label)
        elif label == b"01-component-model":
            component_seen = True
        elif label.startswith(b"10-proposal/"):
            indexed_suffix(label, b"10-proposal/", proposal_count, False)
            target = reference["target"]
            if previous_proposal is not None and target <= previous_proposal:
                raise FormatError("runtime proposals are not a canonical set")
            previous_proposal = target
            proposal_count += 1
        elif label.startswith(b"20-host-function/"):
            name = label[len(b"20-host-function/") :]
            if not name or (previous_host is not None and name <= previous_host):
                raise FormatError("runtime host functions are not canonical")
            previous_host = name
        else:
            raise FormatError("unknown runtime-profile field")
    if seen != required or component_seen != bool(component_present):
        raise FormatError("incomplete runtime-profile fields")


def validate_derivation_invocation(record):
    require_metadata_schema(record, 13, 2)
    execution_class, option_mask = record["canonical"]
    if execution_class > 3 or option_mask & ~0b11:
        raise FormatError("invalid derivation invocation payload")
    expected = {
        b"00-transform": 0,
        b"01-transform-contract": 0,
        b"02-canonical-parameters": 0,
        b"03-runtime-semantic-profile": 0,
        b"04-output-contract": 0,
    }
    seen = set()
    snapshot_seen = False
    seed_seen = False
    input_count = 0
    for reference in record["references"]:
        label = reference["label"]
        if label in expected:
            require_reference_kind(reference, expected[label])
            seen.add(label)
        elif label == b"05-provenance-snapshot":
            require_reference_kind(reference, 1)
            snapshot_seen = True
        elif label == b"06-deterministic-seed":
            require_reference_kind(reference, 0)
            seed_seen = True
        elif label.startswith(b"10-input/"):
            require_reference_kind(reference, 1)
            indexed_suffix(label, b"10-input/", input_count, True)
            input_count += 1
        else:
            raise FormatError("unknown derivation invocation field")
    if seen != set(expected):
        raise FormatError("incomplete derivation invocation fields")
    if bool(option_mask & 1) != snapshot_seen or bool(option_mask & 2) != seed_seen:
        raise FormatError("derivation invocation option mask mismatch")
    if (execution_class == 0 and snapshot_seen) or (
        execution_class == 1 and not snapshot_seen
    ):
        raise FormatError("derivation execution class conflicts with snapshot")


def validate_derivation_evidence(record):
    require_metadata_schema(record, 14, 2)
    execution_class, verifier_present = record["canonical"]
    if execution_class > 3 or verifier_present not in (0, 1):
        raise FormatError("invalid derivation evidence payload")
    expected = {
        b"00-invocation": 0,
        b"01-transform": 1,
        b"02-transform-contract": 1,
        b"03-runtime-semantic-profile": 1,
        b"04-engine-build": 1,
        b"05-execution-measurements": 1,
        b"06-authority-epoch": 1,
        b"07-computation-sharing-domain": 1,
    }
    seen = set()
    verifier_seen = False
    input_count = 0
    output_count = 0
    for reference in record["references"]:
        label = reference["label"]
        if label in expected:
            require_reference_kind(reference, expected[label])
            seen.add(label)
        elif label == b"08-verifier-evidence":
            require_reference_kind(reference, 1)
            verifier_seen = True
        elif label.startswith(b"10-input/"):
            require_reference_kind(reference, 1)
            indexed_suffix(label, b"10-input/", input_count, True)
            input_count += 1
        elif label.startswith(b"20-output/"):
            require_reference_kind(reference, 3)
            indexed_suffix(label, b"20-output/", output_count, True)
            output_count += 1
        else:
            raise FormatError("unknown derivation evidence field")
    if seen != set(expected) or not output_count:
        raise FormatError("incomplete derivation evidence fields")
    if verifier_seen != bool(verifier_present):
        raise FormatError("derivation evidence verifier mask mismatch")


def validate_gc_plan(record):
    require_metadata_schema(record, 15, 0)
    expected = {
        b"00-fact-snapshot": 0,
        b"01-retention-policy": 0,
        b"02-tensor-logic-proof": 0,
    }
    seen = set()
    condemned_count = 0
    previous_target = None
    for reference in record["references"]:
        label = reference["label"]
        if label in expected:
            require_reference_kind(reference, expected[label])
            seen.add(label)
        elif label.startswith(b"10-condemned/"):
            require_reference_kind(reference, 1)
            indexed_suffix(label, b"10-condemned/", condemned_count, False)
            target = reference["target"]
            if previous_target is not None and target <= previous_target:
                raise FormatError("GC condemned identities are not a canonical set")
            previous_target = target
            condemned_count += 1
        else:
            raise FormatError("unknown GC plan field")
    if seen != set(expected) or not condemned_count:
        raise FormatError("incomplete GC plan fields")


def validate_gc_commit(record):
    require_metadata_schema(record, 16, 0)
    expected = {
        b"00-plan": 0,
        b"01-fact-snapshot": 1,
        b"02-placement-before": 1,
        b"03-placement-after": 1,
        b"04-execution-measurements": 1,
    }
    seen = {}
    for reference in record["references"]:
        label = reference["label"]
        if label not in expected:
            raise FormatError("unknown GC commit field")
        require_reference_kind(reference, expected[label])
        seen[label] = reference["target"]
    if set(seen) != set(expected):
        raise FormatError("incomplete GC commit fields")
    if seen[b"02-placement-before"] == seen[b"03-placement-after"]:
        raise FormatError("GC commit records an unchanged placement")


def validate_known_schema(record):
    validators = {
        12: validate_runtime_profile,
        13: validate_derivation_invocation,
        14: validate_derivation_evidence,
        15: validate_gc_plan,
        16: validate_gc_commit,
    }
    validator = validators.get(record["kind"])
    if validator is not None:
        validator(record)


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
    validate_known_schema(record)
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
    prefix = cursor.integer(8)
    if prefix == ROOT_SNAPSHOT_SENTINEL:
        if cursor.integer(1) != ROOT_SNAPSHOT_RECORD:
            raise FormatError("unknown root-journal extension record")
        entries = []
        previous = None
        for _ in range(cursor.integer(8)):
            principal = cursor.take(cursor.integer(8))
            if previous is not None and principal <= previous:
                raise FormatError("non-canonical root snapshot order")
            previous = principal
            entries.append((principal, root_state(cursor)))
        cursor.done()
        return ("snapshot", entries)

    principal = cursor.take(prefix)
    expected_tag = cursor.integer(1)
    if expected_tag == 0:
        expected = None
    elif expected_tag == 1:
        expected = root_state(cursor)
    else:
        raise FormatError("invalid expected-root tag")
    replacement = root_state(cursor)
    cursor.done()
    return ("transition", principal, expected, replacement)


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
    specification = parse_metadata_identity(entries["format-spec-object"])
    if specification != FORMAT_SPECIFICATION:
        raise FormatError("store.meta does not name the frozen format specification")
    try:
        catalog_specification = parse_metadata_identity(
            entries["content-catalog-spec-object"]
        )
    except KeyError as error:
        raise FormatError(
            "store.meta omits the frozen content catalog specification"
        ) from error
    if catalog_specification != CONTENT_CATALOG_SPECIFICATION:
        raise FormatError("store.meta names an unknown content catalog specification")
    return specification, catalog_specification


def parse_metadata_identity(value):
    fields = value.split(":")
    if len(fields) != 4:
        raise FormatError("invalid metadata identity")
    tagged = (int(fields[0]), int(fields[1]), bytes.fromhex(fields[3]))
    if int(fields[2]) != len(tagged[2]):
        raise FormatError("metadata identity length mismatch")
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
    return set(marks)


def recover(store, include_payloads):
    verify_golden_vectors()
    verify_content_summary_vectors()
    specification, catalog_specification = parse_metadata(store / "store.meta")
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
    if catalog_specification is not None:
        catalog_key = identity_text(catalog_specification)
        catalog_spec = objects.get(catalog_key)
        if (
            catalog_spec is None
            or catalog_spec["kind"] != 10
            or catalog_spec["version"] != 1
            or catalog_spec["class"] != 1
            or catalog_spec["logical_bytes"] != 0
            or catalog_spec["references"]
        ):
            raise FormatError("missing or invalid content catalog specification")

    roots = {}
    for offset, payload in frames(store / "roots.journal", ROOT_MAGIC):
        record = decode_root(payload)
        if record[0] == "snapshot":
            if offset != 0 or roots:
                raise FormatError("root snapshot must be the first journal frame")
            for principal, current in record[1]:
                name = principal_text(principal)
                if name in roots:
                    raise FormatError(f"duplicate snapshot principal {name}")
                roots[name] = current
        else:
            _, principal, expected, replacement = record
            name = principal_text(principal)
            actual = roots.get(name)
            if actual != expected:
                raise FormatError(f"root CAS mismatch for {name} at byte {offset}")
            generation = 0 if actual is None else actual[0] + 1
            if replacement[0] != generation:
                raise FormatError(f"root generation mismatch for {name} at byte {offset}")
            roots[name] = replacement
    validated_files = set()
    for name, root in roots.items():
        record = objects.get(identity_text(root[1]))
        if record is None or record["kind"] != 9:
            raise FormatError(f"principal {name} root is not a Commit")
        closure = validate_closure(objects, root[1])
        for key in closure:
            record = objects[key]
            if record["kind"] == 2 and key not in validated_files:
                validate_file(objects, record)
                validated_files.add(key)

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
        "content_catalog_spec_object": identity_text(catalog_specification),
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
