"""Independent decoding of principal-root journal records and owner names."""

from runatal_v1_codec import Cursor, FormatError, identity

ROOT_SNAPSHOT_SENTINEL = (1 << 64) - 1
ROOT_SNAPSHOT_RECORD = 1
ROOT_REMOVAL_RECORD = 2


def root_state(cursor):
    return (cursor.integer(8), identity(cursor))


def decode_root(payload):
    cursor = Cursor(payload)
    prefix = cursor.integer(8)
    if prefix == ROOT_SNAPSHOT_SENTINEL:
        record = cursor.integer(1)
        if record == ROOT_REMOVAL_RECORD:
            principal = cursor.take(cursor.integer(8))
            expected = root_state(cursor)
            cursor.done()
            return ("remove", principal, expected)
        if record != ROOT_SNAPSHOT_RECORD:
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
    if len(principal) == 33 and principal[:1] == b"\1":
        return principal[1:].hex()
    if len(principal) == 33 and principal[:1] == b"\2":
        return f"fleet:{principal[1:].hex()}"
    raise FormatError("invalid state-owner-v2 encoding")

