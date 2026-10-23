#!/usr/bin/env python3
"""Independent WorkspaceBranch and indexed workspace-directory grammar."""

from __future__ import annotations

import re

BRANCH_MAGIC = b"astrid-workspace-branch-v1\0"
BRANCH_RECEIPT_MAGIC = b"astrid-workspace-promoted-v1\0"
BRANCH_BASE_LABEL = b"base"
BRANCH_WORKING_LABEL = b"working"
DIRECTORY_LABEL = b"workspace-directory"
VALUE_LABEL = b"workspace-record"
FLAT_BRANCH_PREFIX = b"workspace/"
FLAT_RECEIPT_PREFIX = b"workspace-promoted/"
CONTENT_LABEL = b"content"
LEFT_LABEL = b"left"
RIGHT_LABEL = b"right"
FILE_LABEL = b"file"
NODE_QUOTA_BYTES = 198
LEAF_TAG = 0
BRANCH_TAG = 1
LEAF_FIXED_BYTES = 17
BRANCH_BYTES = 57
WORKSPACE_UID_HEX = re.compile(r"^[0-9a-f]{32}$")
PRINCIPAL_UID_HEX = re.compile(r"^[0-9a-f]{64}$")


class WorkspaceFormatError(ValueError):
    pass


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"


def checked_add(*values):
    total = 0
    for value in values:
        total += value
        if total >= 1 << 64:
            raise WorkspaceFormatError("workspace accounting overflows u64")
    return total


def require_utf8_name(raw, *, allow_empty=False):
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise WorkspaceFormatError("workspace name is not UTF-8") from error
    if "\0" in name:
        raise WorkspaceFormatError("workspace name contains NUL")
    if not allow_empty and not name:
        raise WorkspaceFormatError("workspace name is empty")
    return name


def validate_target_prefix(prefix):
    if prefix is None:
        return None
    if (
        not prefix
        or prefix.startswith("/")
        or prefix.endswith("/")
        or "//" in prefix
        or any(segment in (".", "..") for segment in prefix.split("/"))
    ):
        raise WorkspaceFormatError("workspace target prefix is not canonical")
    return prefix


def decode_root_id(bytes_, offset):
    if offset >= len(bytes_):
        raise WorkspaceFormatError("workspace branch root flag is missing")
    present = bytes_[offset]
    offset += 1
    digest = bytes_[offset : offset + 32]
    if len(digest) != 32:
        raise WorkspaceFormatError("workspace branch root digest is missing")
    offset += 32
    if present == 0:
        if any(digest):
            raise WorkspaceFormatError("absent workspace root digest must be zero")
        return None, offset
    if present != 1:
        raise WorkspaceFormatError("workspace branch root flag is invalid")
    return (1, 1, digest), offset


def decode_workspace_branch(record, *, require_root_references=None):
    """Validate WorkspaceBranch kind 17 and return the decoded state."""
    if (
        record["kind"] != 17
        or record["version"] != 1
        or record["class"] != 1
        or record["logical_bytes"] != 0
    ):
        raise WorkspaceFormatError("workspace branch record has invalid type")
    bytes_ = record["canonical"]
    if bytes_.startswith(BRANCH_RECEIPT_MAGIC):
        magic = BRANCH_RECEIPT_MAGIC
        promoted = True
        if require_root_references is None:
            require_root_references = False
    elif bytes_.startswith(BRANCH_MAGIC):
        magic = BRANCH_MAGIC
        promoted = False
        if require_root_references is None:
            require_root_references = True
    else:
        raise WorkspaceFormatError("workspace branch magic is unknown")

    uid_start = len(magic)
    uid = bytes_[uid_start : uid_start + 16]
    if len(uid) != 16:
        raise WorkspaceFormatError("workspace branch record id is missing")
    legacy_prefix_len_offset = uid_start + 16
    legacy_prefix_len = None
    if len(bytes_) >= legacy_prefix_len_offset + 4:
        legacy_prefix_len = int.from_bytes(
            bytes_[legacy_prefix_len_offset : legacy_prefix_len_offset + 4], "little"
        )
    legacy_roots_offset = None
    if legacy_prefix_len is not None:
        legacy_roots_offset = legacy_prefix_len_offset + 4 + legacy_prefix_len
    legacy_fixed = None
    if legacy_roots_offset is not None:
        legacy_fixed = legacy_roots_offset + 1 + 32 + 1 + 32
    legacy_encoding = legacy_fixed == len(bytes_)
    if legacy_encoding:
        binding_uid = None
        prefix_len_offset = legacy_prefix_len_offset
    else:
        if legacy_prefix_len_offset >= len(bytes_):
            raise WorkspaceFormatError("workspace branch binding UID flag is missing")
        binding_flag = bytes_[legacy_prefix_len_offset]
        binding_bytes = bytes_[
            legacy_prefix_len_offset + 1 : legacy_prefix_len_offset + 1 + 32
        ]
        if len(binding_bytes) != 32:
            raise WorkspaceFormatError("workspace branch binding UID is missing")
        if binding_flag == 1:
            binding_uid = binding_bytes
        elif binding_flag == 0 and not any(binding_bytes):
            binding_uid = None
        else:
            raise WorkspaceFormatError("workspace branch binding UID flag is invalid")
        prefix_len_offset = legacy_prefix_len_offset + 1 + 32

    if prefix_len_offset + 4 > len(bytes_):
        raise WorkspaceFormatError("workspace branch target prefix length is missing")
    prefix_len = int.from_bytes(bytes_[prefix_len_offset : prefix_len_offset + 4], "little")
    roots_offset = prefix_len_offset + 4 + prefix_len
    fixed = roots_offset + 1 + 32 + 1 + 32
    if len(bytes_) != fixed:
        raise WorkspaceFormatError("workspace branch record bytes are malformed")
    prefix_bytes = bytes_[prefix_len_offset + 4 : roots_offset]
    if prefix_len and len(prefix_bytes) != prefix_len:
        raise WorkspaceFormatError("workspace branch target prefix bytes are missing")
    target_prefix = None
    if prefix_bytes:
        target_prefix = validate_target_prefix(require_utf8_name(prefix_bytes))
    if binding_uid is not None and not target_prefix:
        raise WorkspaceFormatError("bound workspace has no prefix")

    offset = roots_offset
    base_id, offset = decode_root_id(bytes_, offset)
    working_id, offset = decode_root_id(bytes_, offset)
    if offset != len(bytes_):
        raise WorkspaceFormatError("workspace branch record has trailing bytes")

    expected_labels = []
    if base_id is not None:
        expected_labels.append(BRANCH_BASE_LABEL)
    if working_id is not None:
        expected_labels.append(BRANCH_WORKING_LABEL)
    base = None
    working = None
    for reference in record["references"]:
        if reference["kind"] != 0:
            raise WorkspaceFormatError("workspace branch root reference is not owning")
        label = reference["label"]
        target = reference["target"]
        if label == BRANCH_BASE_LABEL and base_id == target:
            base = target
        elif label == BRANCH_WORKING_LABEL and working_id == target:
            working = target
        else:
            raise WorkspaceFormatError(
                "workspace branch root reference disagrees with bytes"
            )
    expected_count = len(expected_labels)
    if require_root_references:
        if len(record["references"]) != expected_count:
            raise WorkspaceFormatError("workspace branch root references are not canonical")
        for reference, expected in zip(record["references"], expected_labels):
            if reference["label"] != expected:
                raise WorkspaceFormatError(
                    "workspace branch root references are not canonical"
                )
    elif record["references"]:
        raise WorkspaceFormatError("workspace branch root references are not canonical")

    return {
        "promoted": promoted,
        "id": uid,
        "id_hex": uid.hex(),
        "binding_uid": binding_uid,
        "binding_uid_hex": None if binding_uid is None else binding_uid.hex(),
        "target_prefix": target_prefix,
        "base": base if base is not None else base_id,
        "working": working if working is not None else working_id,
        "legacy_encoding": legacy_encoding,
    }


def validate_workspace_branch_schema(record):
    decode_workspace_branch(record)


def key_bit(name, bit):
    byte_index, bit_index = divmod(bit, 8)
    raw = name.encode("utf-8") + b"\0"
    if byte_index >= len(raw):
        return 0
    return (raw[byte_index] >> (7 - bit_index)) & 1


def first_differing_bit(left, right):
    left_bytes = left.encode("utf-8") + b"\0"
    right_bytes = right.encode("utf-8") + b"\0"
    limit = max(len(left_bytes), len(right_bytes)) * 8
    for bit in range(limit):
        if key_bit(left, bit) != key_bit(right, bit):
            return bit
    raise WorkspaceFormatError("workspace directory keys are not distinct")


def leaf_summary(name, logical_bytes, *, node_quota_bytes):
    name_bytes = len(name.encode("utf-8"))
    return {
        "logical_bytes": logical_bytes,
        "quota_bytes": checked_add(logical_bytes, name_bytes, node_quota_bytes),
        "entries": 1,
    }


def combine_summary(left, right):
    return {
        "logical_bytes": checked_add(left["logical_bytes"], right["logical_bytes"]),
        "quota_bytes": checked_add(left["quota_bytes"], right["quota_bytes"]),
        "entries": checked_add(left["entries"], right["entries"]),
    }


def decode_summary(bytes_, offset):
    return {
        "logical_bytes": int.from_bytes(bytes_[offset : offset + 8], "little"),
        "quota_bytes": int.from_bytes(bytes_[offset + 8 : offset + 16], "little"),
        "entries": int.from_bytes(bytes_[offset + 16 : offset + 24], "little"),
    }


def exact_reference(record, label, kind, required=True):
    matches = [
        reference
        for reference in record["references"]
        if reference["label"] == label and reference["kind"] == kind
    ]
    if len(matches) > 1:
        raise WorkspaceFormatError("missing or duplicate directory reference")
    if not matches:
        if required:
            raise WorkspaceFormatError("missing or duplicate directory reference")
        return None
    return matches[0]["target"]


def object_at(objects, object_id, kind, version):
    record = objects.get(identity_text(object_id))
    if record is None:
        raise WorkspaceFormatError("missing directory object")
    if record["kind"] != kind or record["version"] != version:
        raise WorkspaceFormatError("directory object has the wrong kind or version")
    return record


def decode_directory_node(objects, object_id, *, version, value_label, node_quota_bytes):
    record = object_at(objects, object_id, 4, version)
    if record["class"] != 1:
        raise WorkspaceFormatError("directory node has invalid class")
    bytes_ = record["canonical"]
    if not bytes_:
        raise WorkspaceFormatError("invalid directory node tag")
    tag = bytes_[0]
    if tag == LEAF_TAG:
        if len(bytes_) < LEAF_FIXED_BYTES or len(record["references"]) != 1:
            raise WorkspaceFormatError("invalid directory leaf")
        logical_bytes = int.from_bytes(bytes_[1:9], "little")
        name_len = int.from_bytes(bytes_[9:17], "little")
        if len(bytes_) != LEAF_FIXED_BYTES + name_len:
            raise WorkspaceFormatError("directory leaf name length disagrees")
        reference = record["references"][0]
        if reference["kind"] != 0 or reference["label"] != value_label:
            raise WorkspaceFormatError("directory leaf has invalid value reference")
        if record["logical_bytes"] != logical_bytes:
            raise WorkspaceFormatError("directory leaf logical length disagrees")
        name = require_utf8_name(bytes_[LEAF_FIXED_BYTES:])
        summary = leaf_summary(name, logical_bytes, node_quota_bytes=node_quota_bytes)
        return {
            "tag": "leaf",
            "name": name,
            "value": {"target": reference["target"], "logical_bytes": logical_bytes},
            "summary": summary,
            "record": record,
        }
    if tag == BRANCH_TAG:
        if len(bytes_) != BRANCH_BYTES or len(record["references"]) != 2:
            raise WorkspaceFormatError("invalid directory branch")
        left = record["references"][0]
        right = record["references"][1]
        if (
            left["kind"] != 0
            or left["label"] != LEFT_LABEL
            or right["kind"] != 0
            or right["label"] != RIGHT_LABEL
        ):
            raise WorkspaceFormatError("directory branch has invalid child references")
        bit = int.from_bytes(bytes_[1:9], "little")
        left_summary = decode_summary(bytes_, 9)
        right_summary = decode_summary(bytes_, 33)
        combine_summary(left_summary, right_summary)
        if record["logical_bytes"] != 0:
            raise WorkspaceFormatError("directory branch contributes visible bytes")
        return {
            "tag": "branch",
            "bit": bit,
            "left": {"object": left["target"], "summary": left_summary},
            "right": {"object": right["target"], "summary": right_summary},
            "summary": combine_summary(left_summary, right_summary),
            "record": record,
        }
    raise WorkspaceFormatError("invalid directory node tag")


def validate_directory_tree(
    objects,
    root_id,
    *,
    version,
    value_label,
    node_quota_bytes,
    validate_value,
):
    """Validate a compressed binary radix directory and return sorted leaves."""
    root_record = object_at(objects, root_id, 4, version)
    # Parent summary for the PrincipalState Owns edge is not stored; validate
    # the tree against recomputed child summaries only.
    stack = [("enter", root_id, None)]
    seen = set()
    values = {}
    leaves = []
    root_node = None

    while stack:
        frame = stack.pop()
        action = frame[0]
        object_id = frame[1]
        key = identity_text(object_id)
        if action == "enter":
            parent_bit = frame[2]
            if key in seen:
                raise WorkspaceFormatError("directory reuses a node or contains a cycle")
            seen.add(key)
            node = decode_directory_node(
                objects,
                object_id,
                version=version,
                value_label=value_label,
                node_quota_bytes=node_quota_bytes,
            )
            if root_node is None:
                root_node = node
            stack.append(("exit", object_id, node))
            if node["tag"] == "leaf":
                validate_value(node["name"], node["value"], node)
                leaves.append(node)
                values[key] = {
                    "min": node["name"],
                    "max": node["name"],
                    "summary": node["summary"],
                }
            else:
                if parent_bit is not None and not (node["bit"] > parent_bit):
                    raise WorkspaceFormatError("directory branch bits do not increase")
                stack.append(("enter", node["right"]["object"], node["bit"]))
                stack.append(("enter", node["left"]["object"], node["bit"]))
        else:
            node = frame[2]
            if node["tag"] == "branch":
                left_key = identity_text(node["left"]["object"])
                right_key = identity_text(node["right"]["object"])
                left = values[left_key]
                right = values[right_key]
                if left["summary"] != node["left"]["summary"]:
                    raise WorkspaceFormatError("directory parent summary disagrees")
                if right["summary"] != node["right"]["summary"]:
                    raise WorkspaceFormatError("directory parent summary disagrees")
                if first_differing_bit(left["max"], right["min"]) != node["bit"]:
                    raise WorkspaceFormatError("directory branch is not canonical")
                if key_bit(left["max"], node["bit"]) != 0 or key_bit(right["min"], node["bit"]) != 1:
                    raise WorkspaceFormatError("directory branch partition is invalid")
                values[key] = {
                    "min": left["min"],
                    "max": right["max"],
                    "summary": combine_summary(left["summary"], right["summary"]),
                }
                if values[key]["summary"] != node["summary"]:
                    raise WorkspaceFormatError("directory parent summary disagrees")

    leaves.sort(key=lambda node: node["name"])
    previous = None
    for leaf in leaves:
        if previous is not None and leaf["name"] <= previous:
            raise WorkspaceFormatError("directory leaves are not strictly ordered")
        previous = leaf["name"]
    return {
        "root": root_id,
        "summary": values[identity_text(root_id)]["summary"],
        "leaves": leaves,
        "root_record": root_record,
        "root_node": root_node,
    }


def row_charge(record, branch, *, promoted, working_quota_bytes):
    metadata = len(record["canonical"])
    for reference in record["references"]:
        metadata = checked_add(metadata, 33, len(reference["label"]))
    if promoted:
        return metadata
    return checked_add(metadata, working_quota_bytes)




def require_workspace_hex(value):
    if not WORKSPACE_UID_HEX.fullmatch(value):
        raise WorkspaceFormatError("workspace directory workspace uid is not canonical hex")
    return value


def require_principal_hex(value):
    if not PRINCIPAL_UID_HEX.fullmatch(value):
        raise WorkspaceFormatError("workspace directory principal uid is not canonical hex")
    return value

def primary_key(promoted, workspace_hex):
    require_workspace_hex(workspace_hex)
    return f"{'r' if promoted else 'b'}/{workspace_hex}"


def inventory_key(binding_hex, workspace_hex):
    require_principal_hex(binding_hex)
    require_workspace_hex(workspace_hex)
    return f"a/{binding_hex}/{workspace_hex}"


def selector_key(binding_hex, prefix):
    require_principal_hex(binding_hex)
    validate_target_prefix(prefix)
    return f"u/{binding_hex}/{prefix}"


FILE_CANONICAL_BYTES = 40


def file_payload_logical_bytes(record):
    """Return the File payload length from canonical bytes.

    File object headers always store logical_bytes=0; the reconstructed content
    length lives in the 40-byte File canonical (ASTRID_V1 profile fields).
    """
    if (
        record["kind"] != 2
        or record["version"] != 1
        or record["class"] != 1
        or record["logical_bytes"] != 0
        or len(record["canonical"]) != FILE_CANONICAL_BYTES
    ):
        raise WorkspaceFormatError("content catalog leaf does not own a File")
    return int.from_bytes(record["canonical"][24:32], "little")


def validate_content_catalog(objects, root_id):
    def validate_file_leaf(name, value, _node):
        file_record = objects.get(identity_text(value["target"]))
        if file_record is None:
            raise WorkspaceFormatError("content catalog leaf does not own a File")
        # Compare against File payload length, never the zero object-header field.
        if file_payload_logical_bytes(file_record) != value["logical_bytes"]:
            raise WorkspaceFormatError("content catalog leaf length disagrees with File")

    return validate_directory_tree(
        objects,
        root_id,
        version=2,
        value_label=FILE_LABEL,
        node_quota_bytes=0,
        validate_value=validate_file_leaf,
    )


def validate_workspace_directory(objects, directory_id):
    def validate_row(name, value, node):
        record = objects.get(identity_text(value["target"]))
        if record is None:
            raise WorkspaceFormatError("workspace-record target is missing")
        branch = decode_workspace_branch(record)
        expected = primary_key(branch["promoted"], branch["id_hex"])
        binding = None
        inventory = None
        if branch["binding_uid_hex"] is not None:
            if not branch["target_prefix"]:
                raise WorkspaceFormatError("bound workspace has no prefix")
            binding = selector_key(branch["binding_uid_hex"], branch["target_prefix"])
            inventory = inventory_key(branch["binding_uid_hex"], branch["id_hex"])
        working_quota = 0
        if name == expected:
            if not branch["promoted"]:
                if branch["base"] is not None:
                    validate_content_catalog(objects, branch["base"])
                if branch["working"] is not None:
                    working_quota = validate_content_catalog(
                        objects, branch["working"]
                    )["summary"]["quota_bytes"]
            charge = row_charge(
                record,
                branch,
                promoted=branch["promoted"],
                working_quota_bytes=working_quota,
            )
        elif binding == name or inventory == name:
            charge = 0
        else:
            raise WorkspaceFormatError("workspace directory key and record disagree")
        if value["logical_bytes"] != charge:
            raise WorkspaceFormatError("workspace directory quota disagrees")
        node["branch"] = branch
        node["expected_primary"] = expected
        node["binding"] = binding
        node["inventory"] = inventory

    validated = validate_directory_tree(
        objects,
        directory_id,
        version=3,
        value_label=VALUE_LABEL,
        node_quota_bytes=NODE_QUOTA_BYTES,
        validate_value=validate_row,
    )

    groups = {}
    expected_inventory = {}
    actual_inventory = {}
    selectors = {}
    ids = set()
    for leaf in validated["leaves"]:
        name = leaf["name"]
        branch = leaf["branch"]
        if name.startswith("u/"):
            selectors[name] = leaf["value"]["target"]
            continue
        if name.startswith("a/"):
            actual_inventory[name] = leaf["value"]["target"]
            continue
        if branch["id_hex"] in ids:
            raise WorkspaceFormatError("workspace is both live and promoted")
        ids.add(branch["id_hex"])
        if leaf["binding"] is not None:
            groups.setdefault(leaf["binding"], []).append(
                (leaf["value"]["target"], branch["promoted"])
            )
            if leaf["inventory"] is not None:
                expected_inventory[leaf["inventory"]] = leaf["value"]["target"]
        elif name != leaf["expected_primary"]:
            raise WorkspaceFormatError("unbound workspace directory key is invalid")

    if actual_inventory != expected_inventory or len(groups) != len(selectors):
        raise WorkspaceFormatError("workspace directory binding inventory disagrees")
    for binding, members in groups.items():
        live = [object_id for object_id, promoted in members if not promoted]
        selected = selectors.get(binding)
        if (
            len(live) > 1
            or selected is None
            or not any(object_id == selected for object_id, _ in members)
            or (live and live[0] != selected)
        ):
            raise WorkspaceFormatError("workspace directory current binding disagrees")
    return validated


def parse_flat_workspace_label(label):
    """Return (workspace_hex, promoted) for a flat PrincipalState edge label."""
    if label.startswith(FLAT_RECEIPT_PREFIX):
        suffix = label[len(FLAT_RECEIPT_PREFIX) :]
        promoted = True
    elif label.startswith(FLAT_BRANCH_PREFIX):
        suffix = label[len(FLAT_BRANCH_PREFIX) :]
        promoted = False
    else:
        return None
    try:
        text = suffix.decode("utf-8")
    except UnicodeDecodeError as error:
        raise WorkspaceFormatError("flat workspace label is not UTF-8") from error
    # Receipt Display historically nests `workspace/<hex>` after the receipt prefix.
    if text.startswith("workspace/"):
        text = text[len("workspace/") :]
    require_workspace_hex(text)
    return text, promoted


def validate_flat_workspace_reference(objects, reference):
    parsed = parse_flat_workspace_label(reference["label"])
    if parsed is None:
        return None
    workspace_hex, promoted = parsed
    if reference["kind"] != 0:
        raise WorkspaceFormatError("flat workspace reference is not owning")
    record = objects.get(identity_text(reference["target"]))
    if record is None:
        raise WorkspaceFormatError("flat workspace target is missing")
    branch = decode_workspace_branch(record)
    if branch["id_hex"] != workspace_hex:
        raise WorkspaceFormatError("flat workspace label disagrees with record uid")
    if branch["promoted"] != promoted:
        raise WorkspaceFormatError("flat workspace label disagrees with lifecycle")
    return branch


def validate_principal_workspace(objects, commit_id):
    """Validate optional workspace-directory / reject mixed flat+indexed state."""
    commit = objects.get(identity_text(commit_id))
    if commit is None or commit["kind"] != 9 or commit["version"] not in (3, 4):
        raise WorkspaceFormatError("principal root is not a supported Commit")
    state_matches = [
        reference
        for reference in commit["references"]
        if reference["label"] == b"state" and reference["kind"] == 0
    ]
    if len(state_matches) != 1:
        raise WorkspaceFormatError("commit state reference is missing")
    state = objects.get(identity_text(state_matches[0]["target"]))
    if state is None or state["kind"] != 8 or state["version"] != commit["version"]:
        raise WorkspaceFormatError("commit state object is invalid")

    directory = None
    flat_branches = []
    for reference in state["references"]:
        label = reference["label"]
        if label == DIRECTORY_LABEL:
            if reference["kind"] != 0:
                raise WorkspaceFormatError("workspace-directory reference is not owning")
            if directory is not None:
                raise WorkspaceFormatError("duplicate workspace-directory reference")
            directory = reference["target"]
            continue
        branch = validate_flat_workspace_reference(objects, reference)
        if branch is not None:
            flat_branches.append(branch)
    if directory is not None and flat_branches:
        raise WorkspaceFormatError("mixed flat and indexed workspace state")
    if directory is None:
        if not flat_branches:
            return None
        ids = set()
        for branch in flat_branches:
            if branch["id_hex"] in ids:
                raise WorkspaceFormatError("workspace is both live and promoted")
            ids.add(branch["id_hex"])
        return {"layout": "flat", "branches": flat_branches}
    return validate_workspace_directory(objects, directory)
