#!/usr/bin/env python3
"""Independent primitive decoder for Astrid format-one physical records."""

import argparse
import json
import struct
import sys
from pathlib import Path

from runatal_v1_blake3 import derive_key
from runatal_v1_frames import frame_checksum, frames, physical_frame

LOGICAL_SCHEME = (1, 1, 32)
PHYSICAL_SCHEME = (1, 2, 32)
PROFILE_CONTEXT = "astrid-representation-profile-v1\0"
BLOB_CONTEXT = "astrid-blob-identity-v1\0"
RECORD_CONTEXT = "astrid-representation-record-v1\0"
MAP_CONTEXT = "astrid-physical-map-node-v1\0"
CATALOGUE_CONTEXT = "astrid-representation-catalogue-root-v1\0"
PLACEMENT_CONTEXT = "astrid-placement-set-v1\0"
STATE_CONTEXT = "astrid-representation-state-v1\0"
JOURNAL_CONTEXT = "astrid-representation-journal-bytes-v1\0"
ARENA_MAGIC = b"ASTOBJ1\0"
METADATA_MAGIC = b"ASTRPM1\0"
JOURNAL_MAGIC = b"ASTREP1\0"
CURRENT_MAGIC = b"ASTCUR1\0"


class FormatError(Exception):
    pass


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise FormatError("truncated physical record")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def byte_string(self):
        return self.take(self.integer(8))

    def done(self):
        if self.offset != len(self.data):
            raise FormatError("trailing physical record bytes")


def identity(cursor, scheme):
    algorithm = cursor.integer(2)
    construction = cursor.integer(2)
    length = cursor.integer(4)
    if not algorithm or not construction or not length:
        raise FormatError("zero tagged-identity field")
    digest = cursor.take(length)
    if (algorithm, construction, length) != scheme:
        raise FormatError("unsupported tagged-identity scheme")
    return (algorithm, construction, digest)


def identity_bytes(value):
    return struct.pack("<HHI", value[0], value[1], len(value[2])) + value[2]


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def optional_identity(cursor, scheme):
    tag = cursor.integer(1)
    if tag == 0:
        return None
    if tag == 1:
        return identity(cursor, scheme)
    raise FormatError("invalid identity option tag")


def encode_optional(value):
    return b"\0" if value is None else b"\1" + identity_bytes(value)


def decode_profile_dependency(cursor):
    tag = cursor.integer(1)
    if tag == 0:
        value = identity(cursor, LOGICAL_SCHEME)
    elif tag == 1:
        value = identity(cursor, PHYSICAL_SCHEME)
    else:
        raise FormatError("unknown profile dependency tag")
    return (tag, value)


def encode_profile_dependency(value):
    return bytes([value[0]]) + identity_bytes(value[1])


def decode_profile(data):
    cursor = Cursor(data)
    version = cursor.integer(2)
    if version != 1:
        raise FormatError("unsupported representation profile version")
    kind = cursor.integer(1)
    if kind > 3:
        raise FormatError("unknown representation profile kind")
    decoder = optional_identity(cursor, LOGICAL_SCHEME)
    contract = optional_identity(cursor, LOGICAL_SCHEME)
    runtime = optional_identity(cursor, LOGICAL_SCHEME)
    parameters = cursor.byte_string()
    dependencies = [
        decode_profile_dependency(cursor) for _ in range(cursor.integer(8))
    ]
    bounds_version = cursor.integer(2)
    if bounds_version != 1:
        raise FormatError("unsupported reconstruction bounds version")
    bounds = (
        cursor.integer(4),
        cursor.integer(4),
        cursor.integer(8),
        cursor.integer(8),
        cursor.integer(8),
        cursor.integer(8),
        cursor.integer(8),
    )
    specification = identity(cursor, LOGICAL_SCHEME)
    cursor.done()
    if not all(bounds):
        raise FormatError("zero reconstruction bound")
    if len(dependencies) > bounds[1]:
        raise FormatError("profile exceeds its reconstruction fanout bound")
    encoded_dependencies = [encode_profile_dependency(value) for value in dependencies]
    if any(
        left >= right
        for left, right in zip(encoded_dependencies, encoded_dependencies[1:])
    ):
        raise FormatError("non-canonical profile dependencies")
    required = {(0, identity_bytes(specification))}
    if kind == 3:
        if None in (decoder, contract, runtime):
            raise FormatError("transform profile omits a pinned field")
        required.update(
            (0, identity_bytes(value)) for value in (decoder, contract, runtime)
        )
        actual = {(tag, identity_bytes(value)) for tag, value in dependencies}
        if not required.issubset(actual):
            raise FormatError("transform profile omits a required dependency")
    elif (
        decoder is not None
        or contract is not None
        or runtime is not None
        or parameters
        or dependencies != [(0, specification)]
    ):
        raise FormatError("built-in profile carries transform fields")
    profile = {
        "version": version,
        "kind": kind,
        "decoder": decoder,
        "contract": contract,
        "runtime": runtime,
        "parameters": parameters,
        "dependencies": dependencies,
        "bounds_version": bounds_version,
        "bounds": bounds,
        "specification": specification,
    }
    if encode_profile(profile) != data:
        raise FormatError("non-canonical profile encoding")
    return profile


def encode_profile(profile):
    output = bytearray(struct.pack("<HB", profile["version"], profile["kind"]))
    output += encode_optional(profile["decoder"])
    output += encode_optional(profile["contract"])
    output += encode_optional(profile["runtime"])
    output += struct.pack("<Q", len(profile["parameters"])) + profile["parameters"]
    output += struct.pack("<Q", len(profile["dependencies"]))
    for dependency in profile["dependencies"]:
        output += encode_profile_dependency(dependency)
    output += struct.pack("<HIIQQQQQ", profile["bounds_version"], *profile["bounds"])
    output += identity_bytes(profile["specification"])
    return bytes(output)


def decode_chunking_profile(cursor):
    algorithm = cursor.integer(1)
    revision = cursor.integer(2)
    normalization = cursor.integer(1)
    minimum = cursor.integer(4)
    average = cursor.integer(4)
    maximum = cursor.integer(4)
    seed = cursor.integer(8)
    if (algorithm, revision, normalization) != (1, 1, 1):
        raise FormatError("unsupported chunking profile")
    if (
        not 64 <= minimum <= 1_048_576
        or not 256 <= average <= 4_194_304
        or not 1024 <= maximum <= 16_777_216
        or not minimum < average < maximum
        or average & (average - 1)
    ):
        raise FormatError("invalid chunking profile")
    return (algorithm, revision, normalization, minimum, average, maximum, seed)


def encode_chunking_profile(profile):
    return struct.pack("<BHBIIIQ", *profile)


def decode_coverage(cursor):
    tag = cursor.integer(1)
    if tag == 0:
        value = (tag, identity(cursor, LOGICAL_SCHEME), cursor.integer(8))
        if not value[2]:
            raise FormatError("zero exact canonical record length")
        return value
    if tag == 1:
        file_id = identity(cursor, LOGICAL_SCHEME)
        root = optional_identity(cursor, LOGICAL_SCHEME)
        logical_bytes = cursor.integer(8)
        chunk_count = cursor.integer(8)
        profile = decode_chunking_profile(cursor)
        if not logical_bytes:
            if root is not None or chunk_count:
                raise FormatError("empty file has content coverage")
        elif root is None or not chunk_count or ((chunk_count == 1) != (logical_bytes <= profile[5])):
            raise FormatError("non-canonical file coverage shape")
        return (tag, file_id, root, logical_bytes, chunk_count, profile)
    raise FormatError("unknown coverage tag")


def encode_coverage(coverage):
    if coverage[0] == 0:
        return b"\0" + identity_bytes(coverage[1]) + struct.pack("<Q", coverage[2])
    return (
        b"\1"
        + identity_bytes(coverage[1])
        + encode_optional(coverage[2])
        + struct.pack("<QQ", coverage[3], coverage[4])
        + encode_chunking_profile(coverage[5])
    )


def decode_recipe(cursor):
    tag = cursor.integer(1)
    if tag == 0:
        return (tag, identity(cursor, PHYSICAL_SCHEME))
    if tag == 1:
        recipe = (
            tag,
            identity(cursor, PHYSICAL_SCHEME),
            cursor.integer(8),
            cursor.integer(8),
        )
        if not recipe[3] or recipe[2] + recipe[3] > (1 << 64) - 1:
            raise FormatError("unbounded packed-slice range")
        return recipe
    if tag == 2:
        return (tag, identity(cursor, PHYSICAL_SCHEME))
    if tag == 3:
        return (
            tag,
            identity(cursor, PHYSICAL_SCHEME),
            optional_identity(cursor, PHYSICAL_SCHEME),
        )
    if tag == 4:
        return (
            tag,
            identity(cursor, PHYSICAL_SCHEME),
            identity(cursor, LOGICAL_SCHEME),
        )
    if tag == 5:
        return (
            tag,
            identity(cursor, LOGICAL_SCHEME),
            cursor.integer(4),
            identity(cursor, LOGICAL_SCHEME),
        )
    raise FormatError("unknown recipe tag")


def encode_recipe(recipe):
    output = bytearray([recipe[0]])
    output += identity_bytes(recipe[1])
    if recipe[0] == 1:
        output += struct.pack("<QQ", recipe[2], recipe[3])
    elif recipe[0] == 3:
        output += encode_optional(recipe[2])
    elif recipe[0] == 4:
        output += identity_bytes(recipe[2])
    elif recipe[0] == 5:
        output += struct.pack("<I", recipe[2]) + identity_bytes(recipe[3])
    return bytes(output)


def decode_dependency(cursor):
    tag = cursor.integer(1)
    if tag in (0, 4, 5):
        value = identity(cursor, LOGICAL_SCHEME)
    elif tag in (1, 2, 3):
        value = identity(cursor, PHYSICAL_SCHEME)
    else:
        raise FormatError("unknown representation dependency tag")
    return (tag, value)


def encode_dependency(value):
    return bytes([value[0]]) + identity_bytes(value[1])


def derived_dependencies(profile, recipe, evidence):
    dependencies = [(3, profile)]
    tag = recipe[0]
    if tag in (0, 1, 2):
        dependencies.append((1, recipe[1]))
    elif tag == 3:
        dependencies.append((1, recipe[1]))
        if recipe[2] is not None:
            dependencies.append((1, recipe[2]))
    elif tag == 4:
        dependencies.extend(((1, recipe[1]), (0, recipe[2])))
    else:
        dependencies.extend(((4, recipe[1]), (5, recipe[3])))
    if evidence is not None:
        dependencies.append((5, evidence))
    unique = {encode_dependency(value): value for value in dependencies}
    return [unique[key] for key in sorted(unique)]


def decode_representation(data):
    cursor = Cursor(data)
    version = cursor.integer(2)
    if version != 1:
        raise FormatError("unsupported representation record version")
    profile = identity(cursor, PHYSICAL_SCHEME)
    coverage = decode_coverage(cursor)
    recipe = decode_recipe(cursor)
    dependencies = [decode_dependency(cursor) for _ in range(cursor.integer(8))]
    canonical_output_bytes = cursor.integer(8)
    maximum_reconstruction_bytes = cursor.integer(8)
    evidence = optional_identity(cursor, LOGICAL_SCHEME)
    cursor.done()
    encoded_dependencies = [encode_dependency(value) for value in dependencies]
    if any(
        left >= right
        for left, right in zip(encoded_dependencies, encoded_dependencies[1:])
    ):
        raise FormatError("non-canonical representation dependencies")
    if dependencies != derived_dependencies(profile, recipe, evidence):
        raise FormatError("forged representation dependency set")
    if not maximum_reconstruction_bytes or canonical_output_bytes > maximum_reconstruction_bytes:
        raise FormatError("invalid representation output bound")
    if coverage[0] == 0 and canonical_output_bytes != coverage[2]:
        raise FormatError("exact output byte count mismatch")
    if coverage[0] == 1 and ((coverage[4] == 0) != (canonical_output_bytes == 0)):
        raise FormatError("file output byte count mismatch")
    if recipe[0] == 0:
        if coverage[0] != 0:
            raise FormatError("direct recipe has non-exact coverage")
    elif recipe[0] == 2:
        if coverage[0] != 1 or evidence is None:
            raise FormatError("contiguous recipe lacks file coverage or evidence")
    elif recipe[0] == 5:
        if coverage[0] != 0 or evidence != recipe[3]:
            raise FormatError("generated recipe evidence mismatch")
    elif coverage[0] != 0 or evidence is None:
        raise FormatError("alternate recipe lacks exact coverage or evidence")
    elif recipe[0] == 1 and recipe[3] != canonical_output_bytes:
        raise FormatError("packed slice length differs from canonical output")
    record = {
        "version": version,
        "profile": profile,
        "coverage": coverage,
        "recipe": recipe,
        "dependencies": dependencies,
        "canonical_output_bytes": canonical_output_bytes,
        "maximum_reconstruction_bytes": maximum_reconstruction_bytes,
        "evidence": evidence,
    }
    if encode_representation(record) != data:
        raise FormatError("non-canonical representation encoding")
    return record


def encode_representation(record):
    output = bytearray(struct.pack("<H", record["version"]))
    output += identity_bytes(record["profile"])
    output += encode_coverage(record["coverage"])
    output += encode_recipe(record["recipe"])
    output += struct.pack("<Q", len(record["dependencies"]))
    for dependency in record["dependencies"]:
        output += encode_dependency(dependency)
    output += struct.pack(
        "<QQ",
        record["canonical_output_bytes"],
        record["maximum_reconstruction_bytes"],
    )
    output += encode_optional(record["evidence"])
    return bytes(output)


def physical_identity(context, material):
    return (1, 2, derive_key(context, material))


def decode_map_node(data):
    cursor = Cursor(data)
    version = cursor.integer(2)
    domain = cursor.integer(1)
    tag = cursor.integer(1)
    if version != 1 or domain > 2:
        raise FormatError("unsupported physical map node")
    if tag == 0:
        node = {
            "version": version,
            "domain": domain,
            "tag": tag,
            "key": identity(cursor, PHYSICAL_SCHEME),
            "value": cursor.byte_string(),
        }
    elif tag == 1:
        prefix_bits = cursor.integer(4)
        if prefix_bits >= 352:
            raise FormatError("physical map prefix consumes key")
        prefix = cursor.take((prefix_bits + 7) // 8)
        if prefix_bits % 8 and prefix[-1] & ((1 << (8 - prefix_bits % 8)) - 1):
            raise FormatError("physical map prefix has non-zero unused bits")
        zero = identity(cursor, PHYSICAL_SCHEME)
        one = identity(cursor, PHYSICAL_SCHEME)
        subtree_entries = cursor.integer(8)
        if zero == one or subtree_entries < 2:
            raise FormatError("physical map branch is unary")
        node = {
            "version": version,
            "domain": domain,
            "tag": tag,
            "prefix_bits": prefix_bits,
            "prefix": prefix,
            "zero": zero,
            "one": one,
            "subtree_entries": subtree_entries,
        }
    else:
        raise FormatError("unknown physical map node tag")
    cursor.done()
    if encode_map_node(node) != data:
        raise FormatError("non-canonical physical map node")
    return node


def encode_map_node(node):
    output = bytearray(struct.pack("<HBB", node["version"], node["domain"], node["tag"]))
    if node["tag"] == 0:
        output += identity_bytes(node["key"])
        output += struct.pack("<Q", len(node["value"])) + node["value"]
    else:
        output += struct.pack("<I", node["prefix_bits"]) + node["prefix"]
        output += identity_bytes(node["zero"]) + identity_bytes(node["one"])
        output += struct.pack("<Q", node["subtree_entries"])
    return bytes(output)


def decode_catalogue_root(data):
    cursor = Cursor(data)
    version = cursor.integer(2)
    if version != 1:
        raise FormatError("unsupported representation catalogue root")
    value = {
        "version": version,
        "generation": cursor.integer(8),
        "profiles_root": optional_identity(cursor, PHYSICAL_SCHEME),
        "profile_count": cursor.integer(8),
        "representations_root": optional_identity(cursor, PHYSICAL_SCHEME),
        "representation_count": cursor.integer(8),
    }
    cursor.done()
    for root, count in (
        (value["profiles_root"], value["profile_count"]),
        (value["representations_root"], value["representation_count"]),
    ):
        if (root is None) != (count == 0):
            raise FormatError("catalogue map root and count disagree")
    if encode_catalogue_root(value) != data:
        raise FormatError("non-canonical catalogue root")
    return value


def encode_catalogue_root(value):
    return (
        struct.pack("<HQ", value["version"], value["generation"])
        + encode_optional(value["profiles_root"])
        + struct.pack("<Q", value["profile_count"])
        + encode_optional(value["representations_root"])
        + struct.pack("<Q", value["representation_count"])
    )


def decode_locator(cursor):
    tag = cursor.integer(1)
    if tag == 0:
        locator = (tag, cursor.integer(8), cursor.integer(8), cursor.integer(8), cursor.take(32))
        if not locator[3]:
            raise FormatError("arena locator has zero payload")
        return locator
    if tag == 1:
        return (tag, cursor.integer(8))
    if tag == 2:
        locator = (tag, cursor.integer(8), cursor.integer(8), cursor.integer(8), cursor.take(32))
        if locator[3] <= 52:
            raise FormatError("pack locator has no payload")
        return locator
    raise FormatError("unknown replica locator")


def encode_locator(locator):
    output = bytearray([locator[0]])
    if locator[0] == 1:
        output += struct.pack("<Q", locator[1])
    else:
        output += struct.pack("<QQQ", locator[1], locator[2], locator[3]) + locator[4]
    return bytes(output)


def decode_placement_entry(data):
    cursor = Cursor(data)
    value = {
        "blob": identity(cursor, PHYSICAL_SCHEME),
        "profile": identity(cursor, PHYSICAL_SCHEME),
        "encoded_length": cursor.integer(8),
        "replicas": [],
    }
    for _ in range(cursor.integer(8)):
        value["replicas"].append((cursor.integer(4), decode_locator(cursor)))
    cursor.done()
    encoded = [encode_replica(replica) for replica in value["replicas"]]
    sort_keys = [(replica[0], replica[1][0], encode_locator(replica[1])) for replica in value["replicas"]]
    if not encoded or any(left >= right for left, right in zip(sort_keys, sort_keys[1:])):
        raise FormatError("non-canonical replica set")
    if encode_placement_entry(value) != data:
        raise FormatError("non-canonical placement entry")
    return value


def encode_replica(replica):
    return struct.pack("<I", replica[0]) + encode_locator(replica[1])


def encode_placement_entry(value):
    output = bytearray(identity_bytes(value["blob"]) + identity_bytes(value["profile"]))
    output += struct.pack("<QQ", value["encoded_length"], len(value["replicas"]))
    for replica in value["replicas"]:
        output += encode_replica(replica)
    return bytes(output)


def decode_placement_set(data):
    cursor = Cursor(data)
    version = cursor.integer(2)
    if version != 1:
        raise FormatError("unsupported placement set")
    value = {
        "version": version,
        "epoch": cursor.integer(8),
        "entries_root": optional_identity(cursor, PHYSICAL_SCHEME),
        "blob_count": cursor.integer(8),
        "replica_extent_count": cursor.integer(8),
    }
    cursor.done()
    if (value["entries_root"] is None) != (value["blob_count"] == 0):
        raise FormatError("placement root and blob count disagree")
    if (value["blob_count"] == 0) != (value["replica_extent_count"] == 0):
        raise FormatError("placement blob and replica counts disagree")
    if value["replica_extent_count"] < value["blob_count"]:
        raise FormatError("placement replica count is too small")
    if encode_placement_set(value) != data:
        raise FormatError("non-canonical placement set")
    return value


def encode_placement_set(value):
    return (
        struct.pack("<HQ", value["version"], value["epoch"])
        + encode_optional(value["entries_root"])
        + struct.pack("<QQ", value["blob_count"], value["replica_extent_count"])
    )


def decode_representation_state(data):
    cursor = Cursor(data)
    version = cursor.integer(2)
    if version != 1:
        raise FormatError("unsupported representation state")
    value = {
        "version": version,
        "generation": cursor.integer(8),
        "previous": optional_identity(cursor, PHYSICAL_SCHEME),
        "catalogue": identity(cursor, PHYSICAL_SCHEME),
        "placements": identity(cursor, PHYSICAL_SCHEME),
    }
    cursor.done()
    if not value["generation"] or ((value["generation"] == 1) != (value["previous"] is None)):
        raise FormatError("representation-state generation shape is invalid")
    if encode_representation_state(value) != data:
        raise FormatError("non-canonical representation state")
    return value


def encode_representation_state(value):
    return (
        struct.pack("<HQ", value["version"], value["generation"])
        + encode_optional(value["previous"])
        + identity_bytes(value["catalogue"])
        + identity_bytes(value["placements"])
    )


def search_key(tagged):
    encoded = identity_bytes(tagged)
    return len(encoded).to_bytes(4, "big") + encoded


def key_bit(key, offset):
    return bool(key[offset // 8] & (1 << (7 - offset % 8)))


def prefix_bits(left, right):
    for index, (left_byte, right_byte) in enumerate(zip(left, right)):
        if left_byte != right_byte:
            return index * 8 + (left_byte ^ right_byte).bit_length().__rsub__(8)
    return len(left) * 8


def canonical_prefix(key, bits):
    prefix = bytearray(key[: (bits + 7) // 8])
    remainder = bits % 8
    if remainder:
        prefix[-1] &= 0xFF << (8 - remainder)
    return bytes(prefix)


def validate_map(root, expected_domain, expected_count, nodes, decode_value):
    if root is None:
        if expected_count:
            raise FormatError("absent map has a positive count")
        return
    stack = [(root, False)]
    visiting = set()
    complete = {}
    while stack:
        node_id, expanded = stack.pop()
        key_id = identity_bytes(node_id)
        if expanded:
            node = nodes[key_id]
            if node["tag"] == 0:
                key = search_key(node["key"])
                complete[key_id] = (1, key, key)
                decode_value(node["key"], node["value"])
            else:
                zero = complete[identity_bytes(node["zero"])]
                one = complete[identity_bytes(node["one"])]
                count = zero[0] + one[0]
                if count != node["subtree_entries"]:
                    raise FormatError("physical map subtree count mismatch")
                minimum, maximum = zero[1], one[2]
                if prefix_bits(minimum, maximum) != node["prefix_bits"]:
                    raise FormatError("physical map branch is not the longest common prefix")
                if canonical_prefix(minimum, node["prefix_bits"]) != node["prefix"]:
                    raise FormatError("physical map branch prefix bytes are not canonical")
                if key_bit(zero[1], node["prefix_bits"]) or key_bit(zero[2], node["prefix_bits"]):
                    raise FormatError("physical map zero child crosses split")
                if not key_bit(one[1], node["prefix_bits"]) or not key_bit(one[2], node["prefix_bits"]):
                    raise FormatError("physical map one child crosses split")
                complete[key_id] = (count, minimum, maximum)
            visiting.remove(key_id)
            continue
        if key_id in visiting or key_id in complete:
            raise FormatError("physical map node is cyclic or shared")
        node = nodes.get(key_id)
        if node is None or node["domain"] != expected_domain:
            raise FormatError("physical map node is missing or in the wrong domain")
        visiting.add(key_id)
        stack.append((node_id, True))
        if node["tag"] == 1:
            stack.append((node["one"], False))
            stack.append((node["zero"], False))
    if complete[identity_bytes(root)][0] != expected_count:
        raise FormatError("physical map root count mismatch")


def decode_catalogue_fixture(fixture, profile_id, profile_bytes, record_id, record_bytes, blob_id):
    section = fixture["catalogue"]
    nodes = {}
    for encoded_node in section["nodes"]:
        data = bytes.fromhex(encoded_node["canonical_hex"])
        node = decode_map_node(data)
        node_id = physical_identity(MAP_CONTEXT, data)
        if identity_text(node_id) != encoded_node["id"] or identity_bytes(node_id) in nodes:
            raise FormatError("physical map node identity mismatch or duplicate")
        nodes[identity_bytes(node_id)] = node

    catalogue_bytes = bytes.fromhex(section["root"]["canonical_hex"])
    catalogue = decode_catalogue_root(catalogue_bytes)
    catalogue_id = physical_identity(CATALOGUE_CONTEXT, catalogue_bytes)
    if identity_text(catalogue_id) != section["root"]["id"]:
        raise FormatError("catalogue-root identity mismatch")

    def check_profile(key, value):
        decoded = decode_profile(value)
        actual = physical_identity(PROFILE_CONTEXT, value)
        if key != actual:
            raise FormatError("profile map leaf does not rederive its key")
        if key == profile_id and value != profile_bytes:
            raise FormatError("fixture profile differs from catalogue profile")
        return decoded

    def check_record(key, value):
        decode_representation(value)
        actual = physical_identity(RECORD_CONTEXT, value)
        if key != actual:
            raise FormatError("representation map leaf does not rederive its key")
        if key == record_id and value != record_bytes:
            raise FormatError("fixture record differs from catalogue record")

    validate_map(catalogue["profiles_root"], 0, catalogue["profile_count"], nodes, check_profile)
    validate_map(
        catalogue["representations_root"],
        1,
        catalogue["representation_count"],
        nodes,
        check_record,
    )

    placement_bytes = bytes.fromhex(section["placement_set"]["canonical_hex"])
    placement = decode_placement_set(placement_bytes)
    placement_id = physical_identity(PLACEMENT_CONTEXT, placement_bytes)
    if identity_text(placement_id) != section["placement_set"]["id"]:
        raise FormatError("placement-set identity mismatch")

    replica_total = 0

    def check_placement(key, value):
        nonlocal replica_total
        entry = decode_placement_entry(value)
        if key != entry["blob"] or key != blob_id:
            raise FormatError("placement leaf key does not match its blob")
        replica_total += len(entry["replicas"])

    validate_map(placement["entries_root"], 2, placement["blob_count"], nodes, check_placement)
    if replica_total != placement["replica_extent_count"]:
        raise FormatError("placement replica extent count mismatch")

    state_bytes = bytes.fromhex(section["state"]["canonical_hex"])
    state = decode_representation_state(state_bytes)
    state_id = physical_identity(STATE_CONTEXT, state_bytes)
    if identity_text(state_id) != section["state"]["id"]:
        raise FormatError("representation-state identity mismatch")
    if state["catalogue"] != catalogue_id or state["placements"] != placement_id:
        raise FormatError("representation state does not bind the fixture roots")
    return (catalogue_id, placement_id, state_id)


def decode_fixture(path):
    fixture = json.loads(path.read_text(encoding="utf-8"))
    profile_bytes = bytes.fromhex(fixture["profile"]["canonical_hex"])
    profile = decode_profile(profile_bytes)
    profile_id = physical_identity(PROFILE_CONTEXT, profile_bytes)
    if identity_text(profile_id) != fixture["profile"]["id"]:
        raise FormatError("profile identity mismatch")

    encoded_blob = bytes.fromhex(fixture["blob"]["encoded_hex"])
    blob_material = identity_bytes(profile_id) + struct.pack("<Q", len(encoded_blob)) + encoded_blob
    blob_id = physical_identity(BLOB_CONTEXT, blob_material)
    if identity_text(blob_id) != fixture["blob"]["id"]:
        raise FormatError("blob identity mismatch")
    if fixture["blob"]["profile"] != identity_text(profile_id):
        raise FormatError("blob profile mismatch")

    record_bytes = bytes.fromhex(fixture["representation"]["canonical_hex"])
    record = decode_representation(record_bytes)
    record_id = physical_identity(RECORD_CONTEXT, record_bytes)
    if identity_text(record_id) != fixture["representation"]["id"]:
        raise FormatError("representation identity mismatch")
    if record["profile"] != profile_id:
        raise FormatError("representation names another profile")
    compatible = (
        (profile["kind"], record["recipe"][0], record["coverage"][0])
        in ((0, 0, 0), (1, 1, 0), (2, 2, 1), (3, 3, 0), (3, 4, 0), (3, 5, 0))
    )
    if not compatible:
        raise FormatError("profile, recipe, and coverage are incompatible")
    maximum_fanout = profile["bounds"][1]
    maximum_output_bytes = profile["bounds"][3]
    if len(record["dependencies"]) > maximum_fanout:
        raise FormatError("representation exceeds its reconstruction fanout bound")
    if (
        record["canonical_output_bytes"] > maximum_output_bytes
        or record["maximum_reconstruction_bytes"] > maximum_output_bytes
    ):
        raise FormatError("representation exceeds its profile output bound")
    if record["recipe"][0] <= 4 and record["recipe"][1] != blob_id:
        raise FormatError("representation primary blob does not match fixture blob")
    if record["recipe"][0] == 0:
        if len(encoded_blob) > profile["bounds"][2]:
            raise FormatError("direct blob exceeds its profile input bound")
        if len(encoded_blob) != record["canonical_output_bytes"]:
            raise FormatError("direct blob length differs from canonical output")
    if record["recipe"][0] == 2 and len(encoded_blob) != record["coverage"][3]:
        raise FormatError("contiguous blob length differs from logical file length")
    result = {
        "profile": identity_text(profile_id),
        "blob": identity_text(blob_id),
        "representation": identity_text(record_id),
        "profile_kind": profile["kind"],
        "recipe_kind": record["recipe"][0],
        "coverage_kind": record["coverage"][0],
    }
    if "catalogue" in fixture:
        catalogue_id, placement_id, state_id = decode_catalogue_fixture(
            fixture,
            profile_id,
            profile_bytes,
            record_id,
            record_bytes,
            blob_id,
        )
        result.update(
            {
                "catalogue": identity_text(catalogue_id),
                "placements": identity_text(placement_id),
                "state": identity_text(state_id),
            }
        )
    return result


def decode_store(store, bootstrap_objects=None):
    from runatal_v1_physical_store import decode_store as decode_authoritative_store

    if bootstrap_objects is None:
        from runatal_v1_reader import LEGACY_FORMAT_SPECIFICATIONS, parse_metadata

        specification, catalog_specification = parse_metadata(store / "store.meta")
        bootstrap_objects = {
            identity_bytes(identifier)
            for identifier in LEGACY_FORMAT_SPECIFICATIONS | {specification}
        }
        if catalog_specification is not None:
            bootstrap_objects.add(identity_bytes(catalog_specification))
    return decode_authoritative_store(store, bootstrap_objects)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--store", action="store_true")
    arguments = parser.parse_args()
    try:
        result = decode_store(arguments.path) if arguments.store else decode_fixture(arguments.path)
    except (FormatError, OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"runatal-v1-physical: {error}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
