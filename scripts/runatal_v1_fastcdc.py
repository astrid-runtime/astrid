"""Independent FastCDC format-1 implementation for the RÚNATAL reader.

This module deliberately shares no Rust code with the production builder.  It
implements the byte-level construction frozen by the in-band format document
and carries independent golden vectors for drift detection.
"""

import hashlib

U64_MASK = (1 << 64) - 1
MASKS = (
    0,
    0,
    0,
    0,
    0,
    0x0000000001804110,
    0x0000000001803110,
    0x0000000018035100,
    0x0000001800035300,
    0x0000019000353000,
    0x0000590003530000,
    0x0000D90003530000,
    0x0000D90103530000,
    0x0000D90303530000,
    0x0000D90313530000,
    0x0000D90F03530000,
    0x0000D90303537000,
    0x0000D90703537000,
    0x0000D90707537000,
    0x0000D91707537000,
    0x0000D91747537000,
    0x0000D91767537000,
    0x0000D93767537000,
    0x0000D93777537000,
    0x0000D93777577000,
    0x0000DB3777577000,
)


def _md5(data):
    try:
        return hashlib.md5(data, usedforsecurity=False).digest()
    except TypeError:
        return hashlib.md5(data).digest()


GEAR = tuple(
    int.from_bytes(_md5(bytes((value,)) * 64)[:8], "big")
    for value in range(256)
)

ASTRID_V1 = (1, 1, 1, 16 * 1024, 64 * 1024, 256 * 1024, 0)
GOLDEN_LENGTHS = (
    94_129,
    73_623,
    28_537,
    107_508,
    87_622,
    224_123,
    45_882,
    98_297,
    40_690,
    69_224,
    121_633,
    57_308,
)
SEEDED_GOLDEN_LENGTHS = (
    38_508,
    66_500,
    109_559,
    79_560,
    87_748,
    95_882,
    86_696,
    53_024,
    87_355,
    46_926,
    103_947,
    22_388,
    92_486,
    69_996,
    8_001,
)


def validate_profile(profile):
    algorithm, revision, normalization, minimum, average, maximum, seed = profile
    if (algorithm, revision, normalization) != (1, 1, 1):
        raise ValueError("unsupported FastCDC format-1 profile")
    if not 64 <= minimum <= 1_048_576:
        raise ValueError("FastCDC minimum is outside format-1 bounds")
    if not 256 <= average <= 4_194_304:
        raise ValueError("FastCDC average is outside format-1 bounds")
    if not 1024 <= maximum <= 16_777_216:
        raise ValueError("FastCDC maximum is outside format-1 bounds")
    if not minimum < average < maximum:
        raise ValueError("FastCDC sizes are not strictly increasing")
    if minimum % 2:
        raise ValueError("FastCDC minimum is not even")
    if average & (average - 1):
        raise ValueError("FastCDC average is not a power of two")
    if not 0 <= seed <= U64_MASK:
        raise ValueError("FastCDC gear seed is outside u64")
    return profile


def cut(source, profile):
    _, _, normalization, minimum, average, maximum, seed = validate_profile(profile)
    remaining = len(source)
    if remaining <= minimum:
        return remaining
    remaining = min(remaining, maximum)
    center = min(average, remaining)
    bits = average.bit_length() - 1
    mask_s = MASKS[bits + normalization]
    mask_l = MASKS[bits - normalization]
    mask_s_ls = (mask_s << 1) & U64_MASK
    mask_l_ls = (mask_l << 1) & U64_MASK
    seed_ls = (seed << 1) & U64_MASK
    fingerprint = 0
    index = minimum // 2

    while index < center // 2:
        at = index * 2
        shifted = ((GEAR[source[at]] << 1) & U64_MASK) ^ seed_ls
        fingerprint = ((fingerprint << 2) + shifted) & U64_MASK
        if fingerprint & mask_s_ls == 0:
            return at
        fingerprint = (fingerprint + (GEAR[source[at + 1]] ^ seed)) & U64_MASK
        if fingerprint & mask_s == 0:
            return at + 1
        index += 1

    while index < remaining // 2:
        at = index * 2
        shifted = ((GEAR[source[at]] << 1) & U64_MASK) ^ seed_ls
        fingerprint = ((fingerprint << 2) + shifted) & U64_MASK
        if fingerprint & mask_l_ls == 0:
            return at
        fingerprint = (fingerprint + (GEAR[source[at + 1]] ^ seed)) & U64_MASK
        if fingerprint & mask_l == 0:
            return at + 1
        index += 1
    return remaining


def chunk_lengths(source, profile):
    validate_profile(profile)
    if not source:
        return ()
    maximum = profile[5]
    if len(source) <= maximum:
        return (len(source),)
    lengths = []
    offset = 0
    while offset < len(source):
        length = cut(source[offset:], profile)
        if not length:
            raise ValueError("FastCDC produced an empty chunk")
        lengths.append(length)
        offset += length
    return tuple(lengths)


def validate_boundaries(chunks, profile):
    validate_profile(profile)
    if not chunks:
        return
    maximum = profile[5]
    for index, chunk in enumerate(chunks):
        final = index + 1 == len(chunks)
        if final:
            continue
        window = bytearray(chunk)
        following_index = index + 1
        while following_index < len(chunks):
            remaining = maximum - len(window)
            if remaining <= 0:
                break
            following = chunks[following_index]
            window += following[:remaining]
            following_index += 1
        if cut(window, profile) != len(chunk):
            raise ValueError(f"non-canonical FastCDC boundary at chunk {index}")


def golden_source(length):
    state = 0x4D595DF4D0F33173
    output = bytearray()
    for _ in range(length):
        state = (
            state * 6_364_136_223_846_793_005
            + 1_442_695_040_888_963_407
        ) & U64_MASK
        output.append((state >> 37) & 0xFF)
    return bytes(output)


def verify_golden_vectors():
    odd_minimum = ASTRID_V1[:3] + (16_385,) + ASTRID_V1[4:]
    try:
        validate_profile(odd_minimum)
    except ValueError:
        pass
    else:
        raise ValueError("FastCDC verifier accepted an odd minimum")

    source = golden_source(1024 * 1024)
    actual = chunk_lengths(source, ASTRID_V1)
    if actual != GOLDEN_LENGTHS:
        raise ValueError(
            f"FastCDC format-1 golden mismatch: expected {GOLDEN_LENGTHS}, got {actual}"
        )
    seeded = ASTRID_V1[:-1] + (7,)
    seeded_actual = chunk_lengths(source, seeded)
    if seeded_actual != SEEDED_GOLDEN_LENGTHS:
        raise ValueError(
            "FastCDC seeded format-1 golden mismatch: "
            f"expected {SEEDED_GOLDEN_LENGTHS}, got {seeded_actual}"
        )
    zero_lengths = chunk_lengths(bytes(1024 * 1024), ASTRID_V1)
    if zero_lengths != (262_144, 262_144, 262_144, 262_144):
        raise ValueError(f"FastCDC zero golden mismatch: got {zero_lengths}")

    chunks = []
    offset = 0
    for length in GOLDEN_LENGTHS:
        chunks.append(source[offset : offset + length])
        offset += length
    chunks[0] += chunks[1][:1]
    chunks[1] = chunks[1][1:]
    try:
        validate_boundaries(chunks, ASTRID_V1)
    except ValueError:
        pass
    else:
        raise ValueError("FastCDC verifier accepted a shifted golden boundary")
