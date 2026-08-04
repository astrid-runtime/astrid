#!/usr/bin/env python3
"""Independent primitive decoder for Astrid format-one physical records."""

import argparse
import json
import struct
import sys
from pathlib import Path

from runatal_v1_blake3 import derive_key

LOGICAL_SCHEME = (1, 1, 32)
PHYSICAL_SCHEME = (1, 2, 32)
PROFILE_CONTEXT = "astrid-representation-profile-v1\0"
BLOB_CONTEXT = "astrid-blob-identity-v1\0"
RECORD_CONTEXT = "astrid-representation-record-v1\0"


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
    return {
        "profile": identity_text(profile_id),
        "blob": identity_text(blob_id),
        "representation": identity_text(record_id),
        "profile_kind": profile["kind"],
        "recipe_kind": record["recipe"][0],
        "coverage_kind": record["coverage"][0],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    arguments = parser.parse_args()
    try:
        result = decode_fixture(arguments.fixture)
    except (FormatError, OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"runatal-v1-physical: {error}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
