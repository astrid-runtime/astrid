#!/usr/bin/env python3
"""Independent reader for the Astrid hosted-volume recovery format."""

import struct
import unicodedata
from dataclasses import dataclass

from runatal_v1_blake3 import derive_key

VOLUME_MAGIC = b"ASTVOL1\0"
VOLUME_RECORD_MAGIC = b"ASTREG1\0"
VOLUME_RECORD_BYTES = 75
VOLUME_CONTEXT = "astrid volume record v1"
VOLUME_TRANSACTION_REGION = "system/volume-metadata-transaction"
VOLUME_COMMIT_REGION = "system/volume-commit"
# Framing/allocation guard for one commit catalogue, matching hosted recover.
MAX_COMMIT_SNAPSHOT_BYTES = 16 * 1024 * 1024
LEGACY_SNAPSHOT_MAGIC = b"ASTMAP1\0"
INDEX_PAGE_REGION = b"system/volume-extent-index"
INDEX_PAGE_BYTES = 4096
INDEX_RECORD_BYTES = VOLUME_RECORD_BYTES + len(INDEX_PAGE_REGION) + INDEX_PAGE_BYTES


class VolumeFormatError(Exception):
    pass


class RegionPath:
    """Read-only path view over recovered regions for the existing store reader."""

    def __init__(self, regions, parts=()):
        self.regions = regions
        self.parts = parts

    def __truediv__(self, part):
        return RegionPath(self.regions, self.parts + (str(part),))

    def __str__(self):
        return "/".join(self.parts)

    def read_bytes(self):
        try:
            return self.regions[str(self)]
        except KeyError as error:
            raise VolumeFormatError(f"missing recovered volume region: {self}") from error


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise VolumeFormatError("truncated payload")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def done(self):
        if self.offset != len(self.data):
            raise VolumeFormatError("trailing payload bytes")


def volume_region_name(raw):
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VolumeFormatError("non-UTF-8 volume region") from error
    parts = name.split("/")
    if (
        not name
        or len(raw) > 512
        or name.startswith("/")
        or name.endswith("/")
        or "\\" in name
        or any(not part or part in (".", "..") for part in parts)
        or any(unicodedata.category(character) == "Cc" for character in name)
    ):
        raise VolumeFormatError("invalid volume region name")
    return name


def physically_valid_record_at(data, offset):
    if len(data) - offset < VOLUME_RECORD_BYTES:
        return False
    header = data[offset : offset + VOLUME_RECORD_BYTES]
    if header[:8] != VOLUME_RECORD_MAGIC:
        return False
    total = int.from_bytes(header[8:16], "little")
    operation = header[24]
    name_length = int.from_bytes(header[25:27], "little")
    payload_length = int.from_bytes(header[35:43], "little")
    if (
        total != VOLUME_RECORD_BYTES + name_length + payload_length
        or offset + total > len(data)
        or operation not in range(1, 10)
        or not 1 <= name_length <= 512
    ):
        return False
    name_start = offset + VOLUME_RECORD_BYTES
    payload_start = name_start + name_length
    name_raw = data[name_start:payload_start]
    try:
        volume_region_name(name_raw)
    except VolumeFormatError:
        return False
    material = (
        header[16:24]
        + header[24:25]
        + header[25:27]
        + header[27:35]
        + header[35:43]
        + name_raw
        + data[payload_start : offset + total]
    )
    return derive_key(VOLUME_CONTEXT, material) == header[43:75]


def has_physically_valid_record_after(data, start):
    candidate = data.find(VOLUME_RECORD_MAGIC, start)
    while candidate >= 0:
        if physically_valid_record_at(data, candidate):
            return True
        candidate = data.find(VOLUME_RECORD_MAGIC, candidate + 1)
    return False


def volume_metadata_mutations(payload):
    cursor = Cursor(payload)
    count = cursor.integer(2)
    if not 1 <= count <= 1024:
        raise VolumeFormatError("invalid volume metadata transaction count")
    mutations = []
    for _ in range(count):
        kind = cursor.integer(1)
        source = volume_region_name(cursor.take(cursor.integer(2)))
        destination = volume_region_name(cursor.take(cursor.integer(2)))
        if kind not in (1, 2):
            raise VolumeFormatError("unknown volume metadata mutation")
        mutations.append((kind, source, destination))
    cursor.done()
    return mutations


def apply_volume_mutations(regions, mutations):
    for kind, source, destination in mutations:
        if source not in regions:
            raise VolumeFormatError("volume metadata source is absent")
        if kind == 1 and destination in regions:
            raise VolumeFormatError("volume metadata rename destination exists")
        if kind == 2 and destination not in regions:
            raise VolumeFormatError("volume metadata replace destination is absent")
        value = regions.pop(source)
        regions[destination] = value


@dataclass(frozen=True)
class IndexReference:
    offset: int
    sequence: int
    checksum: bytes
    start: int
    end: int
    count: int
    level: int

    def require_before(self, offset, sequence):
        if self.offset + INDEX_RECORD_BYTES > offset or self.sequence >= sequence:
            raise VolumeFormatError("extent-index record does not precede parent")


def index_reference(raw):
    if len(raw) != 80 or any(raw[73:]):
        raise VolumeFormatError("invalid extent-index reference framing")
    offset, sequence = struct.unpack("<QQ", raw[:16])
    start, end, count = struct.unpack("<QQQ", raw[48:72])
    level = raw[72]
    if (
        offset < 8 or not sequence or start >= end or level >= 64
        or not 1 <= count <= end - start or count < 1 << level
    ):
        raise VolumeFormatError("invalid extent-index reference summary")
    return IndexReference(offset, sequence, raw[16:48], start, end, count, level)


def index_page(payload, offset, sequence, checksum):
    if (
        len(payload) != INDEX_PAGE_BYTES or payload[:8] != b"ASTXPG1\0"
        or any(payload[9:12]) or any(payload[14:16])
    ):
        raise VolumeFormatError("invalid extent-index page framing")
    level = payload[8]
    count = int.from_bytes(payload[12:14], "little")
    width = 24 if level == 0 else 80
    if not (1 if level == 0 else 2) <= count <= (INDEX_PAGE_BYTES - 16) // width:
        raise VolumeFormatError("invalid extent-index page count")
    used = 16 + count * width
    if level >= 64 or any(payload[used:]):
        raise VolumeFormatError("invalid extent-index page padding or level")
    extents, children = [], []
    previous_end, total = None, 0
    for position in range(16, used, width):
        raw = payload[position:position + width]
        if level == 0:
            start, end, physical = struct.unpack("<QQQ", raw)
            if start >= end or physical < 8 or physical + end - start > offset:
                raise VolumeFormatError("invalid extent-index payload bounds")
            extents.append((start, end, physical))
            total += 1
        else:
            child = index_reference(raw)
            child.require_before(offset, sequence)
            if child.level + 1 != level:
                raise VolumeFormatError("invalid extent-index child level")
            start, end = child.start, child.end
            total += child.count
            children.append(child)
        if previous_end is not None and start < previous_end:
            raise VolumeFormatError("overlapping extent-index ranges")
        previous_end = end
    start = extents[0][0] if extents else children[0].start
    raw_reference = (
        struct.pack("<QQ", offset, sequence) + checksum
        + struct.pack("<QQQ", start, previous_end, total) + bytes([level]) + bytes(7)
    ) if total < 1 << 64 else b""
    return index_reference(raw_reference), extents, children


def indexed_extents(data, reference, parent_offset, parent_sequence):
    # Strict level descent bounds recursion to 64; no all-page cache or map.
    reference.require_before(parent_offset, parent_sequence)
    offset = reference.offset
    header = data[offset:offset + VOLUME_RECORD_BYTES]
    if len(header) != VOLUME_RECORD_BYTES or header[:8] != VOLUME_RECORD_MAGIC:
        raise VolumeFormatError("invalid extent-index record header")
    total, sequence = struct.unpack("<QQ", header[8:24])
    name_length = int.from_bytes(header[25:27], "little")
    logical, length = struct.unpack("<QQ", header[27:43])
    name_start = offset + VOLUME_RECORD_BYTES
    payload_start = name_start + name_length
    if (
        total != INDEX_RECORD_BYTES or offset + total > len(data)
        or header[24] != 9 or logical != 0 or length != INDEX_PAGE_BYTES
        or name_length != len(INDEX_PAGE_REGION)
        or data[name_start:payload_start] != INDEX_PAGE_REGION
        or sequence != reference.sequence or header[43:75] != reference.checksum
    ):
        raise VolumeFormatError("invalid extent-index record identity or envelope")
    payload = data[payload_start:offset + total]
    if derive_key(VOLUME_CONTEXT, header[16:43] + INDEX_PAGE_REGION + payload) != reference.checksum:
        raise VolumeFormatError("extent-index record checksum mismatch")
    actual, extents, children = index_page(payload, offset, sequence, reference.checksum)
    if actual != reference:
        raise VolumeFormatError("extent-index reference contradicts page")
    yield from extents
    for child in children:
        yield from indexed_extents(data, child, offset, sequence)


def validate_paged_checkpoint(data, payload, offset, sequence, regions):
    if len(payload) > MAX_COMMIT_SNAPSHOT_BYTES:
        raise VolumeFormatError("paged catalogue exceeds format bound")
    cursor = Cursor(payload)
    if cursor.take(8) != b"ASTMAP2\0":
        raise VolumeFormatError("invalid paged checkpoint magic")
    names, previous = set(), None
    for _ in range(cursor.integer(4)):
        raw_name = cursor.take(cursor.integer(2))
        name = volume_region_name(raw_name)
        length, flag = cursor.integer(8), cursor.integer(1)
        if previous is not None and raw_name <= previous:
            raise VolumeFormatError("unordered or duplicate paged region")
        previous = raw_name
        names.add(name)
        if name not in regions or len(regions[name]) != length or flag not in (0, 1):
            raise VolumeFormatError("paged catalogue contradicts recovered namespace")
        logical = memoryview(regions[name])
        end = 0
        if flag:
            root = index_reference(cursor.take(80))
            if root.end > length:
                raise VolumeFormatError("extent-index root exceeds region")
            for start, extent_end, physical in indexed_extents(data, root, offset, sequence):
                if start < end or any(logical[end:start]):
                    raise VolumeFormatError("extent-index hole contradicts recovered bytes")
                if logical[start:extent_end] != memoryview(data)[physical:physical + extent_end - start]:
                    raise VolumeFormatError("extent-index payload contradicts recovered bytes")
                end = extent_end
        if any(logical[end:]):
            raise VolumeFormatError("extent-index sparse tail contradicts recovered bytes")
    cursor.done()
    if names != set(regions):
        raise VolumeFormatError("paged catalogue omits recovered regions")


def validate_legacy_snapshot(data, payload, commit_offset, regions):
    if len(payload) > MAX_COMMIT_SNAPSHOT_BYTES or len(payload) < 12:
        raise VolumeFormatError("invalid commit snapshot length")
    cursor = Cursor(payload)
    if cursor.take(8) != LEGACY_SNAPSHOT_MAGIC:
        raise VolumeFormatError("invalid commit snapshot magic")
    names = set()
    for _ in range(cursor.integer(4)):
        name = volume_region_name(cursor.take(cursor.integer(2)))
        length = cursor.integer(8)
        if name in names:
            raise VolumeFormatError("duplicate commit snapshot region")
        names.add(name)
        if name not in regions or len(regions[name]) != length:
            raise VolumeFormatError("legacy snapshot contradicts recovered namespace")
        logical = memoryview(regions[name])
        previous_end = 0
        for _ in range(cursor.integer(4)):
            start = cursor.integer(8)
            logical_end = cursor.integer(8)
            physical = cursor.integer(8)
            if start >= logical_end or start < previous_end or logical_end > length:
                raise VolumeFormatError("invalid commit snapshot extent")
            extent_len = logical_end - start
            if physical > commit_offset or extent_len > commit_offset - physical:
                raise VolumeFormatError("invalid commit snapshot extent")
            if any(logical[previous_end:start]):
                raise VolumeFormatError("legacy snapshot hole contradicts recovered bytes")
            if logical[start:logical_end] != memoryview(data)[physical:physical + extent_len]:
                raise VolumeFormatError("legacy snapshot payload contradicts recovered bytes")
            previous_end = logical_end
        if any(logical[previous_end:]):
            raise VolumeFormatError("legacy snapshot sparse tail contradicts recovered bytes")
    cursor.done()
    if names != set(regions):
        raise VolumeFormatError("legacy snapshot omits recovered regions")


def recover_volume(path):
    data = path.read_bytes()
    if not data.startswith(VOLUME_MAGIC):
        raise VolumeFormatError("invalid Astrid volume header")
    committed_regions = {}
    regions = {}
    sequence = 0
    offset = len(VOLUME_MAGIC)
    while offset < len(data):
        if len(data) - offset < VOLUME_RECORD_BYTES:
            break
        header = data[offset : offset + VOLUME_RECORD_BYTES]
        if header[:8] != VOLUME_RECORD_MAGIC:
            raise VolumeFormatError(f"invalid volume record magic at byte {offset}")
        total, current = struct.unpack("<QQ", header[8:24])
        operation = header[24]
        name_length = int.from_bytes(header[25:27], "little")
        logical_offset, payload_length = struct.unpack("<QQ", header[27:43])
        if (
            total < VOLUME_RECORD_BYTES
            or total != VOLUME_RECORD_BYTES + name_length + payload_length
            or not 1 <= name_length <= 512
        ):
            raise VolumeFormatError(f"invalid volume record lengths at byte {offset}")
        if offset + total > len(data):
            break
        if current != sequence + 1 or operation not in range(1, 10):
            raise VolumeFormatError("invalid volume record sequence or operation")
        name_start = offset + VOLUME_RECORD_BYTES
        payload_start = name_start + name_length
        name_raw = data[name_start:payload_start]
        payload = data[payload_start : offset + total]
        material = (
            header[16:24]
            + header[24:25]
            + header[25:27]
            + header[27:35]
            + header[35:43]
            + name_raw
            + payload
        )
        if derive_key(VOLUME_CONTEXT, material) != header[43:75]:
            if has_physically_valid_record_after(data, offset + 1):
                raise VolumeFormatError(
                    f"interior volume checksum mismatch at byte {offset}"
                )
            break
        name = volume_region_name(name_raw)
        if operation == 1:
            if payload or name in regions:
                raise VolumeFormatError("invalid volume create")
            regions[name] = bytearray()
        elif operation == 2:
            if not payload or name not in regions:
                raise VolumeFormatError("invalid volume write")
            end = logical_offset + len(payload)
            region = regions[name]
            if end > len(region):
                region.extend(bytes(end - len(region)))
            region[logical_offset:end] = payload
        elif operation == 3:
            if payload or name not in regions:
                raise VolumeFormatError("invalid volume truncate")
            region = regions[name]
            if logical_offset < len(region):
                del region[logical_offset:]
            else:
                region.extend(bytes(logical_offset - len(region)))
        elif operation == 4:
            if payload or name not in regions:
                raise VolumeFormatError("invalid volume remove")
            del regions[name]
        elif operation in (5, 6):
            destination = volume_region_name(payload)
            apply_volume_mutations(regions, [(operation - 4, name, destination)])
        elif operation == 7:
            if name != VOLUME_TRANSACTION_REGION or logical_offset != 0:
                raise VolumeFormatError("invalid volume metadata transaction envelope")
            apply_volume_mutations(regions, volume_metadata_mutations(payload))
        elif operation == 9:
            if name_raw != INDEX_PAGE_REGION or logical_offset != 0:
                raise VolumeFormatError("invalid extent-index record envelope")
            index_page(payload, offset, current, header[43:75])
        else:
            # Empty commits keep the replayed namespace. Nonempty payloads are
            # ASTMAP2 or ASTMAP1 catalogues checked against replay; the reader
            # still returns replayed bytes rather than substituting the snapshot.
            if name != VOLUME_COMMIT_REGION or logical_offset != 0:
                raise VolumeFormatError("invalid volume commit boundary")
            if len(payload) > MAX_COMMIT_SNAPSHOT_BYTES:
                raise VolumeFormatError("commit snapshot exceeds format bound")
            if payload:
                if payload.startswith(b"ASTMAP2\0"):
                    validate_paged_checkpoint(data, payload, offset, current, regions)
                else:
                    validate_legacy_snapshot(data, payload, offset, regions)
            committed_regions = {
                name: bytes(value) for name, value in regions.items()
            }
        sequence = current
        offset += total
    return committed_regions
