#!/usr/bin/env python3
"""Primitive independent decoder for Astrid principal KV projections."""

import struct

LEAF_MAGIC = b"astrid-kv-bplus-leaf-v1\0"
BRANCH_MAGIC = b"astrid-kv-bplus-branch-v1\0"
INLINE_MAX = 1024
PAGE_BYTES = 4096
PAGE_SLOTS = 64
MAX_LEVEL = 16


class KvFormatError(ValueError):
    pass


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise KvFormatError("truncated KV payload")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def done(self):
        if self.offset != len(self.data):
            raise KvFormatError("trailing KV payload bytes")


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def object_at(objects, object_id, kind, version):
    record = objects.get(identity_text(object_id))
    if record is None:
        raise KvFormatError("missing KV object")
    if record["kind"] != kind or record["version"] != version:
        raise KvFormatError("KV object has the wrong kind or version")
    return record


def exact_reference(record, label, kind, required=True):
    found = [reference for reference in record["references"] if reference["label"] == label]
    if len(found) > 1 or (required and not found):
        raise KvFormatError("missing or duplicate KV reference")
    if not found:
        return None
    if found[0]["kind"] != kind:
        raise KvFormatError("KV reference has the wrong reachability kind")
    return found[0]["target"]


def require_structural(record):
    if record["class"] != 1 or record["logical_bytes"] or record["canonical"]:
        raise KvFormatError("principal structural object carries payload")


def composite_key(key):
    if key.count(b"\0") != 1:
        raise KvFormatError("invalid KV composite key")
    namespace, name = key.split(b"\0")
    if not namespace or not name:
        raise KvFormatError("empty KV namespace or key")
    try:
        namespace.decode("utf-8")
        name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise KvFormatError("KV key is not UTF-8") from error
    return namespace, name


def totals(entries):
    logical = sum(len(value) for value in entries.values())
    quota = sum(len(key) + len(value) for key, value in entries.items())
    if logical >= 1 << 64 or quota >= 1 << 64 or len(entries) >= 1 << 64:
        raise KvFormatError("KV accounting overflows u64")
    return (len(entries), logical, quota)


def retained_bytes(record):
    return 29 + len(record["canonical"]) + sum(
        41 + len(reference["label"]) for reference in record["references"]
    )


def decode_value(objects, object_id, length, version):
    record = object_at(objects, object_id, 5, version)
    if (
        record["class"] != 0
        or record["logical_bytes"]
        or record["references"]
        or len(record["canonical"]) != length
        or (version == 4 and length <= INLINE_MAX)
    ):
        raise KvFormatError("invalid spilled KV value")
    return record["canonical"]


def page_totals(cursor):
    return (cursor.integer(8), cursor.integer(8), cursor.integer(8))


def decode_page(objects, object_id, marks):
    key = identity_text(object_id)
    if key in marks:
        raise KvFormatError("KV checkpoint reuses a page or contains a cycle")
    marks.add(key)
    record = objects.get(key)
    if record is None or record["version"] != 4 or record["class"] != 1:
        raise KvFormatError("invalid KV checkpoint page")
    if record["logical_bytes"]:
        raise KvFormatError("KV checkpoint page carries logical bytes")
    cursor = Cursor(record["canonical"])
    if record["kind"] == 5:
        result = decode_leaf(objects, record, cursor)
        unsplittable = 1
    elif record["kind"] == 6:
        result = decode_branch(objects, record, cursor, marks)
        unsplittable = 3
    else:
        raise KvFormatError("invalid KV checkpoint page kind")
    if retained_bytes(record) > PAGE_BYTES and result[4] > unsplittable:
        raise KvFormatError("splittable KV checkpoint page exceeds 4096 bytes")
    return result


def decode_leaf(objects, record, cursor):
    if cursor.take(len(LEAF_MAGIC)) != LEAF_MAGIC:
        raise KvFormatError("invalid KV leaf magic")
    count = cursor.integer(2)
    declared = page_totals(cursor)
    if not 1 <= count <= PAGE_SLOTS:
        raise KvFormatError("invalid KV leaf population")
    entries = {}
    reference_index = 0
    for entry_index in range(count):
        key = cursor.take(cursor.integer(4))
        composite_key(key)
        length = cursor.integer(8)
        storage = cursor.integer(1)
        if storage == 0:
            if length > INLINE_MAX:
                raise KvFormatError("oversized inline KV value")
            value = cursor.take(length)
        elif storage == 1:
            if length <= INLINE_MAX or reference_index >= len(record["references"]):
                raise KvFormatError("invalid spilled KV value slot")
            reference = record["references"][reference_index]
            expected = b"value/" + entry_index.to_bytes(2, "big")
            if reference["label"] != expected or reference["kind"] != 0:
                raise KvFormatError("invalid spilled KV value reference")
            value = decode_value(objects, reference["target"], length, 4)
            reference_index += 1
        else:
            raise KvFormatError("unknown KV value storage tag")
        if entries and key <= next(reversed(entries)):
            raise KvFormatError("unsorted or duplicate KV leaf key")
        entries[key] = value
    cursor.done()
    if reference_index != len(record["references"]) or totals(entries) != declared:
        raise KvFormatError("KV leaf totals or references disagree")
    keys = list(entries)
    return entries, keys[0], keys[-1], 0, count


def decode_branch(objects, record, cursor, marks):
    if cursor.take(len(BRANCH_MAGIC)) != BRANCH_MAGIC:
        raise KvFormatError("invalid KV branch magic")
    level = cursor.integer(2)
    count = cursor.integer(2)
    declared = page_totals(cursor)
    if (
        not 1 <= level <= MAX_LEVEL
        or not 2 <= count <= PAGE_SLOTS
        or len(record["references"]) != count
    ):
        raise KvFormatError("invalid KV branch header")
    pointers = []
    for index in range(count):
        lower = cursor.take(cursor.integer(4))
        composite_key(lower)
        child_totals = page_totals(cursor)
        reference = record["references"][index]
        if (
            reference["label"] != b"child/" + index.to_bytes(2, "big")
            or reference["kind"] != 0
            or not child_totals[0]
        ):
            raise KvFormatError("invalid KV branch pointer")
        pointers.append((lower, child_totals, reference["target"]))
    cursor.done()
    if any(left[0] >= right[0] for left, right in zip(pointers, pointers[1:])):
        raise KvFormatError("unsorted KV branch bounds")
    entries = {}
    minimum = None
    maximum = None
    for lower, child_totals, child_id in pointers:
        child, child_min, child_max, child_level, _ = decode_page(objects, child_id, marks)
        if lower != child_min or child_level + 1 != level or totals(child) != child_totals:
            raise KvFormatError("KV branch child summary disagrees")
        if maximum is not None and maximum >= child_min:
            raise KvFormatError("overlapping KV branch children")
        entries.update(child)
        minimum = child_min if minimum is None else minimum
        maximum = child_max
    if totals(entries) != declared:
        raise KvFormatError("KV branch totals disagree")
    return entries, minimum, maximum, level, count


def decode_checkpoint(objects, object_id):
    record = object_at(objects, object_id, 7, 4)
    cursor = Cursor(record["canonical"])
    if cursor.integer(1) != 0:
        raise KvFormatError("KV chain does not end in a checkpoint")
    declared = (cursor.integer(8), record["logical_bytes"], cursor.integer(8))
    cursor.done()
    root = exact_reference(record, b"root", 0, False)
    if len(record["references"]) != int(root is not None):
        raise KvFormatError("invalid KV checkpoint references")
    entries = {} if root is None else decode_page(objects, root, set())[0]
    if totals(entries) != declared:
        raise KvFormatError("KV checkpoint totals disagree")
    return entries


def decode_delta(objects, object_id):
    record = object_at(objects, object_id, 7, 4)
    cursor = Cursor(record["canonical"])
    if cursor.integer(1) != 1:
        raise KvFormatError("unknown KV projection record")
    depth = cursor.integer(8)
    delta_bytes = cursor.integer(8)
    declared = (cursor.integer(8), record["logical_bytes"], cursor.integer(8))
    count = cursor.integer(4)
    if not depth or not count:
        raise KvFormatError("empty KV delta")
    previous = exact_reference(record, b"previous", 0, False)
    mutations = []
    referenced = int(previous is not None)
    payload_bytes = 0
    for index in range(count):
        key = cursor.take(cursor.integer(4))
        composite_key(key)
        operation = cursor.integer(1)
        if operation == 0:
            value = None
        elif operation == 1:
            length = cursor.integer(8)
            if length > INLINE_MAX:
                raise KvFormatError("oversized inline KV delta")
            value = cursor.take(length)
        elif operation == 2:
            length = cursor.integer(8)
            reference = exact_reference(
                record, b"value/" + index.to_bytes(4, "big"), 0
            )
            if length <= INLINE_MAX:
                raise KvFormatError("small KV delta value was spilled")
            value = decode_value(objects, reference, length, 4)
            referenced += 1
        else:
            raise KvFormatError("unknown KV delta operation")
        if mutations and key <= mutations[-1][0]:
            raise KvFormatError("unsorted or duplicate KV delta key")
        payload_bytes += len(key) + (0 if value is None else len(value))
        mutations.append((key, value))
    cursor.done()
    if len(record["references"]) != referenced or payload_bytes > delta_bytes:
        raise KvFormatError("invalid KV delta references or byte count")
    return previous, depth, delta_bytes, mutations, declared, payload_bytes


def decode_v4(objects, head):
    chain = []
    visited = set()
    cursor = head
    while cursor is not None:
        key = identity_text(cursor)
        if key in visited:
            raise KvFormatError("KV delta chain contains a cycle")
        visited.add(key)
        record = object_at(objects, cursor, 7, 4)
        if record["canonical"][:1] == b"\0":
            entries = decode_checkpoint(objects, cursor)
            break
        previous, depth, delta_bytes, mutations, declared, payload = decode_delta(
            objects, cursor
        )
        chain.append((depth, delta_bytes, mutations, declared, payload))
        cursor = previous
    else:
        entries = {}
    prior_depth = 0
    prior_bytes = 0
    for depth, delta_bytes, mutations, declared, payload in reversed(chain):
        if depth != prior_depth + 1 or delta_bytes != prior_bytes + payload:
            raise KvFormatError("KV delta counters disagree")
        for key, value in mutations:
            if entries.get(key) == value and (key in entries or value is None):
                raise KvFormatError("KV delta contains a no-op")
            if value is None:
                entries.pop(key, None)
            else:
                entries[key] = value
        if totals(entries) != declared:
            raise KvFormatError("KV delta accounting disagrees")
        prior_depth = depth
        prior_bytes = delta_bytes
    return entries


def decode_legacy_node(objects, object_id, marks):
    key_id = identity_text(object_id)
    if key_id in marks:
        raise KvFormatError("legacy KV tree reuses a node or contains a cycle")
    marks.add(key_id)
    record = object_at(objects, object_id, 6, 3)
    if record["class"] != 1 or record["logical_bytes"] or len(record["canonical"]) < 28:
        raise KvFormatError("invalid legacy KV node")
    height, logical, quota, value_length = struct.unpack(
        "<IQQQ", record["canonical"][:28]
    )
    key = record["canonical"][28:]
    composite_key(key)
    value_id = exact_reference(record, b"value", 0)
    value = decode_value(objects, value_id, value_length, 3)
    left_id = exact_reference(record, b"left", 0, False)
    right_id = exact_reference(record, b"right", 0, False)
    if len(record["references"]) != 1 + int(left_id is not None) + int(right_id is not None):
        raise KvFormatError("unexpected legacy KV reference")
    left = None if left_id is None else decode_legacy_node(objects, left_id, marks)
    right = None if right_id is None else decode_legacy_node(objects, right_id, marks)
    if left and left[2] >= key or right and right[1] <= key:
        raise KvFormatError("legacy KV key order is invalid")
    expected_height = 1 + max(0 if left is None else left[3], 0 if right is None else right[3])
    if (
        not height
        or height != expected_height
        or abs((0 if left is None else left[3]) - (0 if right is None else right[3])) > 1
    ):
        raise KvFormatError("legacy KV tree is not canonical AVL")
    entries = {}
    if left:
        entries.update(left[0])
    entries[key] = value
    if right:
        entries.update(right[0])
    if totals(entries)[1:] != (logical, quota):
        raise KvFormatError("legacy KV totals disagree")
    return entries, (left[1] if left else key), (right[2] if right else key), height


def decode_v3(objects, wrapper_id):
    record = object_at(objects, wrapper_id, 7, 3)
    if record["class"] != 1 or len(record["canonical"]) != 8:
        raise KvFormatError("invalid legacy KV wrapper")
    root = exact_reference(record, b"root", 0, False)
    if len(record["references"]) != int(root is not None):
        raise KvFormatError("unexpected legacy KV wrapper reference")
    entries = {} if root is None else decode_legacy_node(objects, root, set())[0]
    declared = (
        len(entries),
        record["logical_bytes"],
        int.from_bytes(record["canonical"], "little"),
    )
    if totals(entries) != declared:
        raise KvFormatError("legacy KV wrapper totals disagree")
    return entries


def validate_principal_kv(objects, commit_id, include_payloads=False):
    commit = objects.get(identity_text(commit_id))
    if commit is None or commit["kind"] != 9 or commit["version"] not in (3, 4):
        raise KvFormatError("principal root is not a supported Commit")
    require_structural(commit)
    state_id = exact_reference(commit, b"state", 0)
    state = object_at(objects, state_id, 8, commit["version"])
    require_structural(state)
    kv = exact_reference(state, b"kv", 0, False)
    entries = {}
    if kv is not None:
        entries = decode_v3(objects, kv) if commit["version"] == 3 else decode_v4(objects, kv)
    result = {
        "entries": len(entries),
        "logical_bytes": totals(entries)[1],
        "quota_bytes": totals(entries)[2],
    }
    if include_payloads:
        result["values"] = [
            {
                "namespace": composite_key(key)[0].decode("utf-8"),
                "key": composite_key(key)[1].decode("utf-8"),
                "value_hex": value.hex(),
            }
            for key, value in sorted(entries.items())
        ]
    return result
