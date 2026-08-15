#!/usr/bin/env python3
"""Independent reader for the Astrid hosted-volume recovery format."""

import struct

from runatal_v1_blake3 import derive_key

VOLUME_MAGIC = b"ASTVOL1\0"
VOLUME_RECORD_MAGIC = b"ASTREG1\0"
VOLUME_RECORD_BYTES = 75
VOLUME_CONTEXT = "astrid volume record v1"
VOLUME_TRANSACTION_REGION = "system/volume-metadata-transaction"


class VolumeFormatError(Exception):
    pass


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
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise VolumeFormatError("invalid volume region name")
    return name


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


def recover_volume(path):
    data = path.read_bytes()
    if not data.startswith(VOLUME_MAGIC):
        raise VolumeFormatError("invalid Astrid volume header")
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
            or offset + total > len(data)
            or not 1 <= name_length <= 512
        ):
            break
        if current != sequence + 1 or operation not in range(1, 8):
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
            raise VolumeFormatError(f"volume checksum mismatch at byte {offset}")
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
        else:
            if name != VOLUME_TRANSACTION_REGION or logical_offset != 0:
                raise VolumeFormatError("invalid volume metadata transaction envelope")
            apply_volume_mutations(regions, volume_metadata_mutations(payload))
        sequence = current
        offset += total
    return {name: bytes(value) for name, value in regions.items()}
