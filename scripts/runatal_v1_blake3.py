"""Tiny one-shot BLAKE3 used only by the independent RÚNATAL format-1 reader.

This deliberately shares no code or package with Astrid's Rust implementation.
It implements only unkeyed hashing and derive-key hashing and is not optimized.
"""

import struct

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START = 1
CHUNK_END = 2
PARENT = 4
ROOT = 8
DERIVE_KEY_CONTEXT = 32
DERIVE_KEY_MATERIAL = 64
MASK = 0xFFFFFFFF


def _rotate_right(value, count):
    return ((value >> count) | (value << (32 - count))) & MASK


def _g(state, a, b, c, d, x, y):
    state[a] = (state[a] + state[b] + x) & MASK
    state[d] = _rotate_right(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotate_right(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & MASK
    state[d] = _rotate_right(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotate_right(state[b] ^ state[c], 7)


def _round(state, message):
    _g(state, 0, 4, 8, 12, message[0], message[1])
    _g(state, 1, 5, 9, 13, message[2], message[3])
    _g(state, 2, 6, 10, 14, message[4], message[5])
    _g(state, 3, 7, 11, 15, message[6], message[7])
    _g(state, 0, 5, 10, 15, message[8], message[9])
    _g(state, 1, 6, 11, 12, message[10], message[11])
    _g(state, 2, 7, 8, 13, message[12], message[13])
    _g(state, 3, 4, 9, 14, message[14], message[15])


def _compress(chaining_value, block_words, counter, block_len, flags):
    state = list(chaining_value) + list(IV[:4]) + [
        counter & MASK,
        (counter >> 32) & MASK,
        block_len,
        flags,
    ]
    message = list(block_words)
    for _ in range(7):
        _round(state, message)
        message = [message[index] for index in PERMUTATION]
    return tuple(
        [state[index] ^ state[index + 8] for index in range(8)]
        + [state[index + 8] ^ chaining_value[index] for index in range(8)]
    )


def _words(block):
    return struct.unpack("<16I", block.ljust(64, b"\0"))


class _Output:
    def __init__(self, input_cv, block_words, counter, block_len, flags):
        self.input_cv = input_cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self):
        return _compress(
            self.input_cv,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )[:8]

    def root_bytes(self):
        words = _compress(
            self.input_cv,
            self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        )
        return struct.pack("<16I", *words)[:32]


def _chunk_output(chunk, chunk_counter, key_words, flags):
    chaining_value = key_words
    block_count = max(1, (len(chunk) + 63) // 64)
    for index in range(block_count - 1):
        block = chunk[index * 64 : (index + 1) * 64]
        block_flags = flags | (CHUNK_START if index == 0 else 0)
        chaining_value = _compress(
            chaining_value,
            _words(block),
            chunk_counter,
            len(block),
            block_flags,
        )[:8]
    last = chunk[(block_count - 1) * 64 :]
    last_flags = flags | CHUNK_END
    if block_count == 1:
        last_flags |= CHUNK_START
    return _Output(
        chaining_value,
        _words(last),
        chunk_counter,
        len(last),
        last_flags,
    )


def _parent_output(left, right, key_words, flags):
    return _Output(key_words, tuple(left) + tuple(right), 0, 64, flags | PARENT)


def _subtree_output(data, chunk_counter, key_words, flags):
    chunk_count = max(1, (len(data) + 1023) // 1024)
    if chunk_count == 1:
        return _chunk_output(data, chunk_counter, key_words, flags)
    left_chunks = 1 << ((chunk_count - 1).bit_length() - 1)
    split = left_chunks * 1024
    left = _subtree_output(data[:split], chunk_counter, key_words, flags)
    right = _subtree_output(
        data[split:],
        chunk_counter + left_chunks,
        key_words,
        flags,
    )
    return _parent_output(
        left.chaining_value(),
        right.chaining_value(),
        key_words,
        flags,
    )


def _hash(data, key_words=IV, flags=0):
    return _subtree_output(data, 0, tuple(key_words), flags).root_bytes()


def digest(data):
    """Return the 32-byte ordinary BLAKE3 digest of data."""
    return _hash(data)


def derive_key(context, material):
    """Return BLAKE3 derive_key(context, material), truncated to 32 bytes."""
    context_key = _hash(context.encode("utf-8"), IV, DERIVE_KEY_CONTEXT)
    key_words = struct.unpack("<8I", context_key)
    return _hash(material, key_words, DERIVE_KEY_MATERIAL)
