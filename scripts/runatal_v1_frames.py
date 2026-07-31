"""Primitive durable-frame scanner shared by the RÚNATAL reader."""

import struct

from runatal_v1_blake3 import derive_key

FRAME_CONTEXT = "astrid durable physical frame checksum v1"
HEADER_BYTES = 52


class FrameFormatError(ValueError):
    pass


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
        raise FrameFormatError(f"unsupported frame header at byte {offset}")
    end = offset + HEADER_BYTES + length
    if end > len(data):
        return None
    payload = data[offset + HEADER_BYTES : end]
    if frame_checksum(magic, payload) != header[20:52]:
        return False
    return end, payload


def valid_frame_follows(data, magic, offset):
    candidate = data.find(magic, offset + 1)
    while candidate >= 0:
        try:
            frame = physical_frame(data, magic, candidate)
        except FrameFormatError:
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
                raise FrameFormatError(
                    f"corrupt interior frame at byte {offset} in {path}"
                )
            break
        end, payload = frame
        yield offset, payload
        offset = end
