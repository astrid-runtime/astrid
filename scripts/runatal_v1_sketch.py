"""Primitive independent verifier for format-1 bottom-k sketch records."""

import struct

from runatal_v1_blake3 import derive_key

DESCRIPTOR_MAGIC = b"astrid-bottom-k-descriptor-v1\0"
SKETCH_MAGIC = b"astrid-bottom-k-sketch-v1\0"
SCORE_DOMAIN = "astrid bottom-k chunk score v1"
PASS_LABEL = b"00-pass-descriptor"
SOURCE_LABEL = b"01-source-file"


class SketchFormatError(ValueError):
    pass


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise SketchFormatError("truncated bottom-k record")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def expect(self, expected):
        if self.take(len(expected)) != expected:
            raise SketchFormatError("bottom-k magic or constant mismatch")

    def done(self):
        if self.offset != len(self.data):
            raise SketchFormatError("bottom-k record has trailing bytes")


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def tagged_identity(cursor):
    algorithm = cursor.integer(2)
    construction = cursor.integer(2)
    length = cursor.integer(4)
    if not algorithm or not construction or not length:
        raise SketchFormatError("bottom-k record has a zero identity tag")
    return algorithm, construction, cursor.take(length)


def require_metadata(record, kind):
    if (
        record["kind"] != kind
        or record["version"] != 1
        or record["class"] != 1
        or record["logical_bytes"] != 0
    ):
        raise SketchFormatError("invalid bottom-k object header")


def decode_descriptor(record):
    require_metadata(record, 10)
    if record["references"]:
        raise SketchFormatError("bottom-k descriptor has references")
    cursor = Cursor(record["canonical"])
    cursor.expect(DESCRIPTOR_MAGIC)
    if cursor.integer(2) != 1 or cursor.integer(2) != 1:
        raise SketchFormatError("unknown bottom-k construction or hash")
    width_code = cursor.integer(2)
    width = {1: 16, 2: 32}.get(width_code)
    if width is None:
        raise SketchFormatError("unknown bottom-k score width")
    if cursor.integer(2) != 1 or cursor.integer(2) != 1:
        raise SketchFormatError("unknown bottom-k set or ordering rule")
    sample_size = cursor.integer(2)
    if not sample_size:
        raise SketchFormatError("bottom-k sample size is zero")
    if (
        cursor.integer(2) != 1
        or cursor.integer(2) != 1
        or cursor.integer(2) != 1
    ):
        raise SketchFormatError("unknown bottom-k input or profile rule")
    domain = cursor.take(cursor.integer(2))
    if domain != SCORE_DOMAIN.encode("utf-8"):
        raise SketchFormatError("bottom-k score domain mismatch")
    cursor.done()
    return width_code, width, sample_size


def decode_file(record):
    if (
        record["kind"] != 2
        or record["version"] != 1
        or record["class"] != 1
        or record["logical_bytes"] != 0
        or len(record["canonical"]) != 40
    ):
        raise SketchFormatError("bottom-k source is not a canonical File")
    fields = struct.unpack("<BHBIIIQQQ", record["canonical"])
    minimum, average, maximum, seed = fields[3:7]
    logical_bytes, chunk_count = fields[7:9]
    references = record["references"]
    if not chunk_count:
        if logical_bytes or references:
            raise SketchFormatError("empty bottom-k source has content")
        content = None
    else:
        if (
            len(references) != 1
            or references[0]["label"] != b"content"
            or references[0]["kind"] != 0
        ):
            raise SketchFormatError("bottom-k source has invalid content reference")
        content = references[0]["target"]
    return minimum, average, maximum, seed, logical_bytes, chunk_count, content


def source_chunks(objects, content):
    if content is None:
        return {}
    chunks = {}
    seen = set()
    stack = [content]
    while stack:
        object_id = stack.pop()
        key = identity_text(object_id)
        if key in seen:
            continue
        seen.add(key)
        record = objects.get(key)
        if record is None:
            raise SketchFormatError("bottom-k source closure is incomplete")
        if record["kind"] == 0:
            if (
                record["version"] != 1
                or record["class"] != 0
                or record["logical_bytes"] != 0
                or record["references"]
            ):
                raise SketchFormatError("invalid Chunk in bottom-k source")
            chunks[key] = record["canonical"]
        elif record["kind"] == 1:
            if record["version"] != 1 or record["class"] != 1:
                raise SketchFormatError("invalid ChunkTree in bottom-k source")
            for reference in reversed(record["references"]):
                if reference["kind"] != 0:
                    raise SketchFormatError("non-owning ChunkTree edge in bottom-k source")
                stack.append(reference["target"])
        else:
            raise SketchFormatError("unexpected object in bottom-k source closure")
    return chunks


def verify_sketch(objects, record, descriptors, validate_file):
    require_metadata(record, 11)
    references = record["references"]
    if (
        len(references) != 2
        or references[0]["label"] != PASS_LABEL
        or references[0]["kind"] != 1
        or references[1]["label"] != SOURCE_LABEL
        or references[1]["kind"] != 1
    ):
        raise SketchFormatError("invalid bottom-k references")

    cursor = Cursor(record["canonical"])
    cursor.expect(SKETCH_MAGIC)
    if cursor.integer(2) != 1:
        raise SketchFormatError("unknown bottom-k sketch construction")
    width_code = cursor.integer(2)
    sample_size = cursor.integer(2)
    score_count = cursor.integer(2)
    descriptor = tagged_identity(cursor)
    source = tagged_identity(cursor)
    if descriptor != references[0]["target"] or source != references[1]["target"]:
        raise SketchFormatError("bottom-k identities differ from their references")
    descriptor_shape = descriptors.get(identity_text(descriptor))
    if descriptor_shape is None:
        raise SketchFormatError("bottom-k descriptor is missing")
    expected_width_code, score_width, expected_sample = descriptor_shape
    if width_code != expected_width_code or sample_size != expected_sample:
        raise SketchFormatError("bottom-k sketch differs from its descriptor")
    if score_count > sample_size:
        raise SketchFormatError("bottom-k sketch retains too many scores")

    declared_profile = tuple(cursor.integer(4) for _ in range(3)) + (
        cursor.integer(8),
    )
    declared_logical = cursor.integer(8)
    declared_chunks = cursor.integer(8)
    declared_unique = cursor.integer(8)
    scores = [cursor.take(score_width) for _ in range(score_count)]
    cursor.done()
    if any(left >= right for left, right in zip(scores, scores[1:])):
        raise SketchFormatError("bottom-k scores are not a canonical set")

    source_record = objects.get(identity_text(source))
    if source_record is None:
        raise SketchFormatError("bottom-k source File is missing")
    validate_file(objects, source_record)
    minimum, average, maximum, seed, logical, chunks, content = decode_file(source_record)
    if declared_profile != (minimum, average, maximum, seed):
        raise SketchFormatError("bottom-k profile differs from its source")
    if declared_logical != logical or declared_chunks != chunks:
        raise SketchFormatError("bottom-k source totals differ from its File")

    chunk_records = source_chunks(objects, content)
    if declared_unique != len(chunk_records):
        raise SketchFormatError("bottom-k unique Chunk count mismatch")
    expected_scores = sorted(
        {
            derive_key(SCORE_DOMAIN, len(chunk).to_bytes(8, "little") + chunk)[
                :score_width
            ]
            for chunk in chunk_records.values()
        }
    )[:sample_size]
    if scores != expected_scores:
        raise SketchFormatError("bottom-k scores differ from independent recomputation")


def verify_bottom_k_sketches(objects, validate_file):
    descriptors = {}
    for key, record in objects.items():
        if record["kind"] == 10 and record["canonical"].startswith(DESCRIPTOR_MAGIC):
            descriptors[key] = decode_descriptor(record)
    for record in objects.values():
        if record["kind"] == 11 and record["canonical"].startswith(SKETCH_MAGIC):
            verify_sketch(objects, record, descriptors, validate_file)
