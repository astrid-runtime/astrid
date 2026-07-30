"""Independent SHA-384 custody-evidence verifier for the RÚNATAL reader."""

import hashlib
import struct

from runatal_v1_blake3 import derive_key

OBJECT_CONTEXT = "astrid principal store object identity v1"
FANOUT = 128
MAX_LEVEL = 10
LEAF_MAGIC = b"astrid-sha384-leaf-v1\0"
NODE_MAGIC = b"astrid-sha384-node-v1\0"
ATTESTATION_MAGIC = b"astrid-sha384-attestation-v1\0"
OBJECT_DOMAIN = b"astrid sha384 object witness v1\0"
LEAF_DOMAIN = b"astrid sha384 leaf v1\0"
NODE_DOMAIN = b"astrid sha384 node v1\0"
STATEMENT_DOMAIN = b"astrid sha384 attestation statement v1\0"


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise ValueError("truncated SHA-384 Evidence")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def done(self):
        if self.offset != len(self.data):
            raise ValueError("trailing SHA-384 Evidence bytes")


def identity(cursor):
    algorithm = cursor.integer(2)
    construction = cursor.integer(2)
    length = cursor.integer(4)
    if not algorithm or not construction or not length:
        raise ValueError("zero SHA-384 identity tag field")
    return (algorithm, construction, cursor.take(length))


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def encode_identity(value):
    algorithm, construction, digest = value
    return struct.pack("<HHI", algorithm, construction, len(digest)) + digest


def object_material(record):
    output = bytearray()
    output += struct.pack("<HH", record["kind"], record["version"])
    output += len(record["canonical"]).to_bytes(16, "little")
    output += record["canonical"]
    output += struct.pack("<QB", record["logical_bytes"], record["class"])
    output += len(record["references"]).to_bytes(16, "little")
    for reference in record["references"]:
        label = reference["label"]
        target = reference["target"]
        if target[:2] != (1, 1) or len(target[2]) != 32:
            raise ValueError("SHA-384 source uses another identity scheme")
        output += len(label).to_bytes(16, "little")
        output += label
        output += target[2]
        output += struct.pack("<B", reference["kind"])
    return bytes(output)


def record_envelope(record):
    output = bytearray()
    output += struct.pack(
        "<HHBQ",
        record["kind"],
        record["version"],
        record["class"],
        record["logical_bytes"],
    )
    output += struct.pack("<Q", len(record["canonical"]))
    output += record["canonical"]
    output += struct.pack("<Q", len(record["references"]))
    for reference in record["references"]:
        output += struct.pack("<Q", len(reference["label"]))
        output += reference["label"]
        output += encode_identity(reference["target"])
        output += struct.pack("<B", reference["kind"])
    return bytes(output)


def object_digest(object_id, record):
    return hashlib.sha384(
        OBJECT_DOMAIN + encode_identity(object_id) + record_envelope(record)
    ).digest()


def leaf_digest(entries):
    material = bytearray(LEAF_DOMAIN)
    material += struct.pack("<H", len(entries))
    for object_id, digest in entries:
        material += encode_identity(object_id)
        material += digest
    return hashlib.sha384(material).digest()


def node_digest(level, object_count, children):
    material = bytearray(NODE_DOMAIN)
    material += struct.pack("<HHQ", level, len(children), object_count)
    for child in children:
        material += struct.pack("<Q", child["object_count"])
        material += child["digest"]
    return hashlib.sha384(material).digest()


def record_identity(record):
    return (1, 1, derive_key(OBJECT_CONTEXT, object_material(record)))


def leaf_record(entries):
    digest = leaf_digest(entries)
    canonical = bytearray(LEAF_MAGIC)
    canonical += struct.pack("<H", len(entries))
    canonical += digest
    references = []
    for index, (object_id, source_digest) in enumerate(entries):
        canonical += encode_identity(object_id)
        canonical += source_digest
        references.append(
            {
                "label": b"source/" + index.to_bytes(2, "big"),
                "target": object_id,
                "kind": 1,
            }
        )
    record = {
        "kind": 10,
        "version": 1,
        "class": 1,
        "logical_bytes": 0,
        "canonical": bytes(canonical),
        "references": references,
    }
    return {
        "id": record_identity(record),
        "digest": digest,
        "object_count": len(entries),
        "level": 0,
    }


def node_record(children):
    level = children[0]["level"] + 1
    object_count = sum(child["object_count"] for child in children)
    digest = node_digest(level, object_count, children)
    canonical = bytearray(NODE_MAGIC)
    canonical += struct.pack("<HHQ", level, len(children), object_count)
    canonical += digest
    references = []
    for index, child in enumerate(children):
        canonical += struct.pack("<Q", child["object_count"])
        canonical += child["digest"]
        references.append(
            {
                "label": b"child/" + index.to_bytes(2, "big"),
                "target": child["id"],
                "kind": 0,
            }
        )
    record = {
        "kind": 10,
        "version": 1,
        "class": 1,
        "logical_bytes": 0,
        "canonical": bytes(canonical),
        "references": references,
    }
    return {
        "id": record_identity(record),
        "digest": digest,
        "object_count": object_count,
        "level": level,
    }


def rebuild_tree(entries):
    level = [
        leaf_record(entries[offset : offset + FANOUT])
        for offset in range(0, len(entries), FANOUT)
    ]
    if not level:
        raise ValueError("empty SHA-384 evidence tree")
    while len(level) > 1:
        level = [
            node_record(level[offset : offset + FANOUT])
            for offset in range(0, len(level), FANOUT)
        ]
    return level[0]


# Deliberately primitive strict Ed25519 verification. This has no code in
# common with the Rust producer and exists only for archival recovery.
ED25519_P = (1 << 255) - 19
ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
ED25519_I = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_IDENTITY = (0, 1)


def ed25519_xrecover(y):
    xx = (y * y - 1) * pow(ED25519_D * y * y + 1, ED25519_P - 2, ED25519_P)
    x = pow(xx % ED25519_P, (ED25519_P + 3) // 8, ED25519_P)
    if (x * x - xx) % ED25519_P:
        x = (x * ED25519_I) % ED25519_P
    if (x * x - xx) % ED25519_P:
        raise ValueError("Ed25519 point is not on the curve")
    return x


def ed25519_decode_point(encoded):
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point length")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= ED25519_P:
        raise ValueError("non-canonical Ed25519 point")
    x = ed25519_xrecover(y)
    if x & 1 != sign:
        x = ED25519_P - x
    if (-x * x + y * y - 1 - ED25519_D * x * x * y * y) % ED25519_P:
        raise ValueError("invalid Ed25519 point")
    return (x, y)


def ed25519_base_point():
    y = (4 * pow(5, ED25519_P - 2, ED25519_P)) % ED25519_P
    x = ed25519_xrecover(y)
    if x & 1:
        x = ED25519_P - x
    return (x, y)


ED25519_BASE = ed25519_base_point()


def ed25519_add(left, right):
    x1, y1 = left
    x2, y2 = right
    product = (ED25519_D * x1 * x2 * y1 * y2) % ED25519_P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + product, ED25519_P - 2, ED25519_P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, ED25519_P - 2, ED25519_P)
    return (x3 % ED25519_P, y3 % ED25519_P)


def ed25519_multiply(point, scalar):
    result = ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = ed25519_add(result, addend)
        addend = ed25519_add(addend, addend)
        scalar >>= 1
    return result


def ed25519_verify(public_key, statement, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= ED25519_L:
        return False
    try:
        authority = ed25519_decode_point(public_key)
        nonce = ed25519_decode_point(signature[:32])
    except ValueError:
        return False
    if (
        ed25519_multiply(authority, ED25519_L) != ED25519_IDENTITY
        or ed25519_multiply(nonce, ED25519_L) != ED25519_IDENTITY
        or ed25519_multiply(authority, 8) == ED25519_IDENTITY
        or ed25519_multiply(nonce, 8) == ED25519_IDENTITY
    ):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + statement).digest(), "little"
    ) % ED25519_L
    return ed25519_multiply(ED25519_BASE, scalar) == ed25519_add(
        nonce, ed25519_multiply(authority, challenge)
    )


def require_evidence(record):
    if (
        record["kind"] != 10
        or record["version"] != 1
        or record["class"] != 1
        or record["logical_bytes"] != 0
    ):
        raise ValueError("invalid SHA-384 Evidence header")


def decode_leaf(record, objects):
    require_evidence(record)
    cursor = Cursor(record["canonical"])
    if cursor.take(len(LEAF_MAGIC)) != LEAF_MAGIC:
        raise ValueError("invalid SHA-384 leaf magic")
    count = cursor.integer(2)
    declared_digest = cursor.take(48)
    if not count or count > FANOUT or len(record["references"]) != count:
        raise ValueError("invalid SHA-384 leaf count")
    entries = []
    for index in range(count):
        object_id = identity(cursor)
        digest = cursor.take(48)
        reference = record["references"][index]
        if (
            reference["label"] != b"source/" + index.to_bytes(2, "big")
            or reference["target"] != object_id
            or reference["kind"] != 1
        ):
            raise ValueError("invalid SHA-384 leaf reference")
        source = objects.get(identity_text(object_id))
        if source is None:
            raise ValueError("SHA-384 leaf source is missing")
        if object_digest(object_id, source) != digest:
            raise ValueError("SHA-384 object witness mismatch")
        entries.append((object_id, digest))
    cursor.done()
    if any(entries[index - 1][0] >= entries[index][0] for index in range(1, count)):
        raise ValueError("SHA-384 leaf entries are not canonical")
    if leaf_digest(entries) != declared_digest:
        raise ValueError("SHA-384 leaf digest mismatch")
    return {
        "id": None,
        "digest": declared_digest,
        "object_count": count,
        "level": 0,
        "entries": entries,
    }


def decode_node(record, objects, visiting):
    require_evidence(record)
    cursor = Cursor(record["canonical"])
    if cursor.take(len(NODE_MAGIC)) != NODE_MAGIC:
        raise ValueError("invalid SHA-384 node magic")
    level = cursor.integer(2)
    count = cursor.integer(2)
    object_count = cursor.integer(8)
    declared_digest = cursor.take(48)
    if (
        not level
        or level > MAX_LEVEL
        or not count
        or count > FANOUT
        or len(record["references"]) != count
    ):
        raise ValueError("invalid SHA-384 node header")
    declared = []
    references = []
    for index in range(count):
        child_count = cursor.integer(8)
        child_digest = cursor.take(48)
        reference = record["references"][index]
        if (
            not child_count
            or reference["label"] != b"child/" + index.to_bytes(2, "big")
            or reference["kind"] != 0
        ):
            raise ValueError("invalid SHA-384 child reference")
        declared.append((child_count, child_digest))
        references.append(reference["target"])
    cursor.done()

    children = []
    entries = []
    for index, child_id in enumerate(references):
        child = decode_tree(objects, child_id, visiting)
        if child["level"] + 1 != level:
            raise ValueError("SHA-384 tree skips a level")
        if (
            child["object_count"] != declared[index][0]
            or child["digest"] != declared[index][1]
        ):
            raise ValueError("SHA-384 child summary mismatch")
        children.append(child)
        entries.extend(child["entries"])
    if sum(child["object_count"] for child in children) != object_count:
        raise ValueError("SHA-384 subtree count mismatch")
    if node_digest(level, object_count, children) != declared_digest:
        raise ValueError("SHA-384 node digest mismatch")
    return {
        "id": None,
        "digest": declared_digest,
        "object_count": object_count,
        "level": level,
        "entries": entries,
    }


def decode_tree(objects, object_id, visiting):
    key = identity_text(object_id)
    if key in visiting:
        raise ValueError("SHA-384 Evidence tree cycle")
    record = objects.get(key)
    if record is None:
        raise ValueError("SHA-384 Evidence tree object is missing")
    visiting.add(key)
    try:
        if record["canonical"].startswith(LEAF_MAGIC):
            decoded = decode_leaf(record, objects)
        elif record["canonical"].startswith(NODE_MAGIC):
            decoded = decode_node(record, objects, visiting)
        else:
            raise ValueError("unknown SHA-384 Evidence tree record")
    finally:
        visiting.remove(key)
    decoded["id"] = object_id
    return decoded


def validate_closure(objects, root):
    marks = {}
    stack = [(root, False)]
    while stack:
        object_id, leaving = stack.pop()
        key = identity_text(object_id)
        if leaving:
            marks[key] = 2
            continue
        if marks.get(key) == 1:
            raise ValueError(f"ownership cycle at {key}")
        if marks.get(key) == 2:
            continue
        record = objects.get(key)
        if record is None:
            raise ValueError(f"missing owned object {key}")
        marks[key] = 1
        stack.append((object_id, True))
        for reference in reversed(record["references"]):
            if reference["kind"] == 0:
                stack.append((reference["target"], False))
    return set(marks)


def verify_attestation(record, objects):
    require_evidence(record)
    cursor = Cursor(record["canonical"])
    if cursor.take(len(ATTESTATION_MAGIC)) != ATTESTATION_MAGIC:
        raise ValueError("invalid SHA-384 attestation magic")
    if cursor.integer(2) != 1:
        raise ValueError("unsupported SHA-384 ceremony signature")
    root_count = cursor.integer(2)
    object_count = cursor.integer(8)
    placement_epoch = cursor.integer(8)
    tree_digest = cursor.take(48)
    descriptor = identity(cursor)
    snapshot = identity(cursor)
    roots = [identity(cursor) for _ in range(root_count)]
    public_key = cursor.take(32)
    signature = cursor.take(64)
    cursor.done()
    if not root_count or not object_count:
        raise ValueError("empty SHA-384 attestation scope")
    if any(roots[index - 1] >= roots[index] for index in range(1, root_count)):
        raise ValueError("SHA-384 roots are not canonical")
    references = record["references"]
    if len(references) != root_count + 3:
        raise ValueError("invalid SHA-384 attestation reference count")
    if (
        references[0]
        != {"label": b"00-pass-descriptor", "target": descriptor, "kind": 1}
        or references[1]
        != {"label": b"01-snapshot", "target": snapshot, "kind": 1}
    ):
        raise ValueError("invalid SHA-384 ceremony context references")
    for index, root in enumerate(roots):
        if references[index + 2] != {
            "label": b"10-root/" + index.to_bytes(2, "big"),
            "target": root,
            "kind": 1,
        }:
            raise ValueError("invalid SHA-384 selected-root reference")
    tree_reference = references[-1]
    if tree_reference["label"] != b"20-tree" or tree_reference["kind"] != 0:
        raise ValueError("invalid SHA-384 tree reference")

    statement = bytearray(STATEMENT_DOMAIN)
    statement += encode_identity(descriptor)
    statement += encode_identity(snapshot)
    statement += struct.pack("<QH", placement_epoch, root_count)
    for root in roots:
        statement += encode_identity(root)
    statement += struct.pack("<Q", object_count)
    statement += tree_digest
    statement += struct.pack("<H", 1)
    statement += public_key
    if not ed25519_verify(public_key, bytes(statement), signature):
        raise ValueError("invalid SHA-384 ceremony signature")

    tree = decode_tree(objects, tree_reference["target"], set())
    entries = tree["entries"]
    if (
        tree["object_count"] != object_count
        or tree["digest"] != tree_digest
        or len(entries) != object_count
    ):
        raise ValueError("SHA-384 ceremony tree summary mismatch")
    if any(entries[index - 1][0] >= entries[index][0] for index in range(1, len(entries))):
        raise ValueError("SHA-384 object stream is not canonical")
    rebuilt = rebuild_tree(entries)
    if rebuilt["id"] != tree_reference["target"] or rebuilt["digest"] != tree_digest:
        raise ValueError("non-canonical SHA-384 Evidence tree")

    attested = {identity_text(entry[0]) for entry in entries}
    closure = set()
    for root in roots:
        closure.update(validate_closure(objects, root))
    if closure != attested:
        raise ValueError("SHA-384 Evidence does not cover the exact selected closure")


def verify_cross_hash_attestations(objects):
    """Verify every recognized SHA-384 ceremony in a decoded object map."""
    for record in objects.values():
        if record["kind"] == 10 and record["canonical"].startswith(ATTESTATION_MAGIC):
            verify_attestation(record, objects)
