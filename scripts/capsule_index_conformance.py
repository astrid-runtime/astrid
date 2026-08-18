#!/usr/bin/env python3
"""Deterministic, stdlib-only conformance runner for Capsule Index fixtures.

The runner checks the implementation-neutral rules in
``docs/capsule-index/CONFORMANCE.md``.  It intentionally does not implement
TUF signatures or threshold cryptography.  An implementation under test can
be supplied; it receives one fixture JSON document on stdin and is invoked in
JSON mode.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


SCHEMA = "astrid.capsule-index.conformance/v1"
MAX_FIXTURE_BYTES = 1_048_576
MAX_FIXTURES = 256
MAX_JSON_DEPTH = 24
MAX_SUBPROCESS_OUTPUT = 1_048_576
MAX_SUBPROCESS_TIMEOUT = 10.0

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_DIGEST_RE = re.compile(r"^(sha256|sha384|sha512|blake3):[0-9a-f]+$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_CASE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)

IMMUTABLE_FIELDS = (
    "schema",
    "index_id",
    "coordinate",
    "version",
    "artifact",
    "package",
    "publisher",
    "source",
    "provenance",
    "metadata",
)
PUBLICATION_FIELDS = frozenset((*IMMUTABLE_FIELDS, "publication_digest"))


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def _json_loads(payload: bytes) -> Any:
    text = payload.decode("utf-8")
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    _check_depth(value)
    return value


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object key is not a string")
            _check_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_depth(child, depth + 1)


def canonical_json(value: Any) -> bytes:
    """Return the constrained JCS representation used by the vectors."""

    _check_json_scalars(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# The protocol worker uses BLAKE3 for the publication identity.  The runner is
# intentionally dependency-free, so this is the small one-shot BLAKE3
# implementation needed for the fixed 32-byte digest (the implementation under
# test remains the authority for signatures and TUF cryptography).
_B3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_B3_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_B3_CHUNK_START = 1
_B3_CHUNK_END = 2
_B3_PARENT = 4
_B3_ROOT = 8
_B3_MASK = 0xFFFFFFFF
_B3_DOMAIN = b"astrid:capsule-index:publication:v1\0"


def _b3_rotr(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & _B3_MASK


def _b3_g(words: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    words[a] = (words[a] + words[b] + x) & _B3_MASK
    words[d] = _b3_rotr(words[d] ^ words[a], 16)
    words[c] = (words[c] + words[d]) & _B3_MASK
    words[b] = _b3_rotr(words[b] ^ words[c], 12)
    words[a] = (words[a] + words[b] + y) & _B3_MASK
    words[d] = _b3_rotr(words[d] ^ words[a], 8)
    words[c] = (words[c] + words[d]) & _B3_MASK
    words[b] = _b3_rotr(words[b] ^ words[c], 7)


def _b3_compress(cv: Sequence[int], block_words: Sequence[int], counter: int, block_len: int, flags: int) -> list[int]:
    state = list(cv) + list(_B3_IV[:4]) + [counter & _B3_MASK, (counter >> 32) & _B3_MASK, block_len, flags]
    message = list(block_words)
    for round_index in range(7):
        _b3_g(state, 0, 4, 8, 12, message[0], message[1])
        _b3_g(state, 1, 5, 9, 13, message[2], message[3])
        _b3_g(state, 2, 6, 10, 14, message[4], message[5])
        _b3_g(state, 3, 7, 11, 15, message[6], message[7])
        _b3_g(state, 0, 5, 10, 15, message[8], message[9])
        _b3_g(state, 1, 6, 11, 12, message[10], message[11])
        _b3_g(state, 2, 7, 8, 13, message[12], message[13])
        _b3_g(state, 3, 4, 9, 14, message[14], message[15])
        if round_index != 6:
            message = [message[index] for index in _B3_PERMUTATION]
    return [
        *(state[index] ^ state[index + 8] for index in range(8)),
        *(state[index + 8] ^ cv[index] for index in range(8)),
    ]


def _b3_words(block: bytes) -> list[int]:
    padded = block + b"\0" * (64 - len(block))
    return [int.from_bytes(padded[index : index + 4], "little") for index in range(0, 64, 4)]


def _b3_chunk_output(chunk: bytes, counter: int) -> tuple[tuple[int, ...], tuple[int, ...], int, int]:
    cv = _B3_IV
    blocks = max(1, (len(chunk) + 63) // 64)
    for block_index in range(blocks):
        block = chunk[block_index * 64 : (block_index + 1) * 64]
        flags = _B3_CHUNK_START if block_index == 0 else 0
        if block_index == blocks - 1:
            flags |= _B3_CHUNK_END
            return cv, tuple(_b3_words(block)), len(block), flags
        cv = tuple(_b3_compress(cv, _b3_words(block), counter, 64, flags)[:8])
    raise AssertionError("chunk has at least one block")


def _b3_parent_output(left: Sequence[int], right: Sequence[int]) -> tuple[tuple[int, ...], tuple[int, ...], int, int]:
    return _B3_IV, tuple((*left, *right)), 64, _B3_PARENT


def _b3_output_cv(output: tuple[tuple[int, ...], tuple[int, ...], int, int], counter: int = 0) -> tuple[int, ...]:
    cv, words, block_len, flags = output
    return tuple(_b3_compress(cv, words, counter, block_len, flags)[:8])


def _blake3(payload: bytes) -> bytes:
    chunks = [payload[index : index + 1024] for index in range(0, len(payload), 1024)] or [b""]
    cv_stack: list[tuple[int, ...]] = []
    # Keep every chunk except the final one in the left-subtree stack.  The
    # final chunk's Output is needed to set ROOT on the final compression; a
    # stack of already-merged CVs alone would lose that block input.
    for chunk_index, chunk in enumerate(chunks[:-1]):
        output = _b3_chunk_output(chunk, chunk_index)
        cv = _b3_output_cv(output, chunk_index)
        total = chunk_index + 1
        while total & 1 == 0:
            left = cv_stack.pop()
            cv = _b3_output_cv(_b3_parent_output(left, cv))
            total >>= 1
        cv_stack.append(cv)
    output = _b3_chunk_output(chunks[-1], len(chunks) - 1)
    right = _b3_output_cv(output, len(chunks) - 1)
    for left in reversed(cv_stack):
        output = _b3_parent_output(left, right)
        right = _b3_output_cv(output)
    cv, words, block_len, flags = output
    root_words = _b3_compress(cv, words, 0, block_len, flags | _B3_ROOT)
    return b"".join(word.to_bytes(4, "little") for word in root_words[:8])


def _check_json_scalars(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floating-point values are not permitted in vectors")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object key is not a string")
            _check_json_scalars(child)
    elif isinstance(value, list):
        for child in value:
            _check_json_scalars(child)


def publication_digest(publication: Mapping[str, Any]) -> str:
    """Compute the v1 domain-separated BLAKE3 publication identity.

    This byte layout is intentionally the same length-prefixed projection used
    by the Rust protocol worker.  It is not JSON canonicalization: JSON is the
    interchange envelope, while this projection is the identity boundary.
    """

    def put_u64(buffer: bytearray, value: int) -> None:
        buffer.extend(value.to_bytes(8, "little", signed=False))

    def put_text(buffer: bytearray, value: str) -> None:
        encoded = value.encode("utf-8")
        put_u64(buffer, len(encoded))
        buffer.extend(encoded)

    def put_digest(buffer: bytearray, value: str) -> None:
        algorithm, encoded = value.split(":", 1)
        raw = bytes.fromhex(encoded)
        put_text(buffer, algorithm)
        put_u64(buffer, len(raw))
        buffer.extend(raw)

    def put_optional_text(buffer: bytearray, value: str | None) -> None:
        if value is None:
            buffer.append(0)
        else:
            buffer.append(1)
            put_text(buffer, value)

    def digest_sort_key(value: str) -> tuple[int, str]:
        # Digest derives Ord in Rust: enum declaration order is sha256,
        # sha384, sha512, blake3, then raw bytes.
        algorithm, encoded = value.split(":", 1)
        return ({"sha256": 0, "sha384": 1, "sha512": 2, "blake3": 3}[algorithm], encoded)

    buffer = bytearray()
    put_text(buffer, publication["schema"])
    put_text(buffer, publication["index_id"])
    coordinate = publication["coordinate"]
    put_text(buffer, coordinate["namespace"])
    put_text(buffer, coordinate["name"])
    put_text(buffer, publication["version"])

    artifact = publication["artifact"]
    put_u64(buffer, artifact["size"])
    put_text(buffer, artifact["media_type"])
    locations = artifact["locations"]
    put_u64(buffer, len(locations))
    for location in locations:
        put_text(buffer, location)
    publisher = publication["publisher"]
    digests = artifact["digests"]
    put_u64(buffer, len(digests))
    for digest in sorted(digests, key=digest_sort_key):
        put_digest(buffer, digest)
    put_text(buffer, publisher["identity"])
    put_digest(buffer, publisher["signing_key"])

    source = publication["source"]
    put_text(buffer, source["repository_url"])
    put_u64(buffer, source["github_owner_id"])
    put_u64(buffer, source["github_repository_id"])
    put_text(buffer, source["commit"])
    put_text(buffer, source["tree"])
    put_text(buffer, source["tag"])
    put_optional_text(buffer, source["subdirectory"])
    put_digest(buffer, source["source_digest"])

    package = publication["package"]
    runtime = package["runtime"]
    put_text(buffer, runtime["runtime"])
    put_text(buffer, runtime["abi"])
    put_digest(buffer, runtime["digest"])
    embedded = package["embedded_identity"]
    embedded_coordinate = embedded["coordinate"]
    put_text(buffer, embedded_coordinate["namespace"])
    put_text(buffer, embedded_coordinate["name"])
    put_text(buffer, embedded["version"])
    put_digest(buffer, embedded["package_digest"])
    for field in ("manifest_digest", "component_digest", "wit_digest"):
        put_digest(buffer, package[field])
    capabilities = package["capabilities"]
    put_u64(buffer, len(capabilities))
    for capability in capabilities:
        put_text(buffer, capability)
    put_digest(buffer, package["capability_digest"])
    put_digest(buffer, package["ipc_digest"])
    # The Rust projection includes runtime requirements again at the package
    # claims boundary; retain that exact wire order for cross-language parity.
    put_text(buffer, runtime["runtime"])
    put_text(buffer, runtime["abi"])
    put_digest(buffer, runtime["digest"])
    dependencies = package["dependencies"]
    put_u64(buffer, len(dependencies))
    for dependency in dependencies:
        dependency_coordinate = dependency["coordinate"]
        put_text(buffer, dependency_coordinate["namespace"])
        put_text(buffer, dependency_coordinate["name"])
        put_text(buffer, dependency["requirement"])
        buffer.append(1 if dependency["optional"] else 0)
    put_digest(buffer, package["dependency_digest"])

    provenance = publication["provenance"]
    put_text(buffer, provenance["predicate_type"])
    put_digest(buffer, provenance["statement_digest"])
    put_text(buffer, provenance["builder_identity"])
    put_text(buffer, provenance["attestation_identity"])
    metadata = publication["metadata"]
    put_u64(buffer, len(metadata))
    for key in sorted(metadata):
        put_text(buffer, key)
        put_text(buffer, metadata[key])
    return "blake3:" + _blake3(_B3_DOMAIN + bytes(buffer)).hex()


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _exact_keys(
    value: Any,
    required: Iterable[str],
    allowed: Iterable[str] | None,
    path: str,
    errors: list[dict[str, str]],
) -> bool:
    if not isinstance(value, dict):
        errors.append({"code": "expected_object", "path": path, "message": "expected JSON object"})
        return False
    required_set = set(required)
    allowed_set = required_set if allowed is None else set(allowed)
    for key in sorted(required_set - value.keys()):
        errors.append({"code": "missing_field", "path": f"{path}.{key}", "message": "required field is missing"})
    for key in sorted(value.keys() - allowed_set):
        errors.append({"code": "unknown_field", "path": f"{path}.{key}", "message": "field is not part of the protocol"})
    return required_set.issubset(value.keys()) and set(value.keys()).issubset(allowed_set)


def _valid_name(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        errors.append({"code": "invalid_name", "path": path, "message": "must be a lower-case ASCII name"})
        return False
    return True


def _valid_index_id(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    if not isinstance(value, str) or not _INDEX_RE.fullmatch(value) or value in {".", ".."}:
        errors.append({"code": "invalid_index_id", "path": path, "message": "must be a lower-case Index identifier"})
        return False
    return True


def _valid_semver(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    if not isinstance(value, str) or not _SEMVER_RE.fullmatch(value):
        errors.append({"code": "invalid_version", "path": path, "message": "must be canonical SemVer 2.0.0"})
        return False
    match = _SEMVER_RE.fullmatch(value)
    assert match is not None
    for identifier in (match.group(4) or "").split("."):
        if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
            errors.append({"code": "invalid_version", "path": path, "message": "numeric prerelease identifier has a leading zero"})
            return False
    return True


def _valid_digest(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    expected_lengths = {"sha256": 64, "sha384": 96, "sha512": 128, "blake3": 64}
    algorithm = value.split(":", 1)[0] if isinstance(value, str) and ":" in value else ""
    encoded = value.split(":", 1)[1] if isinstance(value, str) and ":" in value else ""
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value) or len(encoded) != expected_lengths.get(algorithm, -1):
        errors.append({"code": "invalid_digest", "path": path, "message": "must be a tagged lower-case digest with the algorithm's exact length"})
        return False
    return True


def _valid_https_url(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    if not isinstance(value, str):
        errors.append({"code": "invalid_url", "path": path, "message": "must be an HTTPS URL"})
        return False
    parsed = urlsplit(value)
    authority = parsed.netloc
    bad_path = any(part in {".", ".."} for part in parsed.path.split("/"))
    bad_authority = (
        not authority
        or parsed.username is not None
        or parsed.password is not None
        or ":" in authority
        or any(character.isspace() or ord(character) < 0x20 for character in authority)
    )
    if (
        parsed.scheme != "https"
        or bad_authority
        or parsed.fragment
        or parsed.query
        or "\\" in parsed.path
        or "%" in parsed.path
        or bad_path
    ):
        errors.append({"code": "invalid_url", "path": path, "message": "must be an HTTPS URL without credentials, fragments, or traversal"})
        return False
    return True


def _valid_rfc3339(value: Any, path: str, errors: list[dict[str, str]]) -> _datetime.datetime | None:
    if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
        errors.append({"code": "invalid_timestamp", "path": path, "message": "must be an RFC 3339 UTC instant"})
        return None
    try:
        return _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append({"code": "invalid_timestamp", "path": path, "message": "is not a real UTC instant"})
        return None


def _valid_array_of_strings(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        errors.append({"code": "invalid_string_array", "path": path, "message": "must be a non-empty-string array"})
        return False
    if len(set(value)) != len(value):
        errors.append({"code": "duplicate_value", "path": path, "message": "values must be unique"})
        return False
    if value != sorted(value):
        errors.append({"code": "array_not_sorted", "path": path, "message": "values must be sorted"})
        return False
    return True


def _validate_publication(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    required = IMMUTABLE_FIELDS + ("publication_digest",)
    if not _exact_keys(value, required, None, path, errors):
        return False
    assert isinstance(value, dict)
    ok = True
    if value["schema"] != "publication-v1":
        errors.append({"code": "invalid_publication_schema", "path": f"{path}.schema", "message": "must be publication-v1"})
        ok = False
    ok &= _valid_index_id(value["index_id"], f"{path}.index_id", errors)
    coordinate = value["coordinate"]
    if _exact_keys(coordinate, ("namespace", "name"), None, f"{path}.coordinate", errors):
        assert isinstance(coordinate, dict)
        ok &= _valid_name(coordinate["namespace"], f"{path}.coordinate.namespace", errors)
        ok &= _valid_name(coordinate["name"], f"{path}.coordinate.name", errors)
    else:
        ok = False
    ok &= _valid_semver(value["version"], f"{path}.version", errors)

    artifact = value["artifact"]
    if _exact_keys(artifact, ("digests", "size", "media_type", "locations"), None, f"{path}.artifact", errors):
        assert isinstance(artifact, dict)
        digests = artifact["digests"]
        if not isinstance(digests, list) or not digests:
            errors.append({"code": "invalid_artifact_digests", "path": f"{path}.artifact.digests", "message": "must be a non-empty digest array"})
            ok = False
        else:
            for index, digest in enumerate(digests):
                ok &= _valid_digest(digest, f"{path}.artifact.digests[{index}]", errors)
            if len(set(digests)) != len(digests):
                errors.append({"code": "duplicate_value", "path": f"{path}.artifact.digests", "message": "digests must be unique"})
                ok = False
            def digest_key(item: Any) -> tuple[int, str]:
                algorithm, encoded = item.split(":", 1)
                return ({"sha256": 0, "sha384": 1, "sha512": 2, "blake3": 3}.get(algorithm, 99), encoded)
            if all(isinstance(item, str) and ":" in item for item in digests) and digests != sorted(digests, key=digest_key):
                errors.append({"code": "array_not_sorted", "path": f"{path}.artifact.digests", "message": "digests must use Rust Digest ordering"})
                ok = False
        if not _is_int(artifact["size"]) or artifact["size"] < 0:
            errors.append({"code": "invalid_size", "path": f"{path}.artifact.size", "message": "must be a non-negative integer"})
            ok = False
        if not isinstance(artifact["media_type"], str) or not artifact["media_type"] or any(ord(char) < 0x20 or char == " " for char in artifact["media_type"]):
            errors.append({"code": "invalid_media_type", "path": f"{path}.artifact.media_type", "message": "must be a non-empty ASCII media type"})
            ok = False
        locations = artifact["locations"]
        if not isinstance(locations, list) or not locations:
            errors.append({"code": "invalid_locations", "path": f"{path}.artifact.locations", "message": "must be a non-empty HTTPS URL array"})
            ok = False
        else:
            for index, item in enumerate(locations):
                ok &= _valid_https_url(item, f"{path}.artifact.locations[{index}]", errors)
            if len(set(locations)) != len(locations) or locations != sorted(locations):
                errors.append({"code": "locations_not_canonical", "path": f"{path}.artifact.locations", "message": "locations must be unique and sorted"})
                ok = False
    else:
        ok = False

    package_fields = ("embedded_identity", "manifest_digest", "component_digest", "wit_digest", "capability_digest", "ipc_digest", "runtime_abi_digest", "dependency_digest", "capabilities", "dependencies", "runtime")
    package = value["package"]
    if _exact_keys(package, package_fields, None, f"{path}.package", errors):
        assert isinstance(package, dict)
        embedded = package["embedded_identity"]
        if _exact_keys(embedded, ("coordinate", "version", "package_digest"), None, f"{path}.package.embedded_identity", errors):
            assert isinstance(embedded, dict)
            embedded_coord = embedded["coordinate"]
            if _exact_keys(embedded_coord, ("namespace", "name"), None, f"{path}.package.embedded_identity.coordinate", errors):
                assert isinstance(embedded_coord, dict)
                ok &= _valid_name(embedded_coord["namespace"], f"{path}.package.embedded_identity.coordinate.namespace", errors)
                ok &= _valid_name(embedded_coord["name"], f"{path}.package.embedded_identity.coordinate.name", errors)
                if embedded_coord != coordinate:
                    errors.append({"code": "embedded_identity_mismatch", "path": f"{path}.package.embedded_identity.coordinate", "message": "must match publication coordinate"})
                    ok = False
            else:
                ok = False
            ok &= _valid_semver(embedded["version"], f"{path}.package.embedded_identity.version", errors)
            if embedded["version"] != value["version"]:
                errors.append({"code": "embedded_identity_mismatch", "path": f"{path}.package.embedded_identity.version", "message": "must match publication version"})
                ok = False
            ok &= _valid_digest(embedded["package_digest"], f"{path}.package.embedded_identity.package_digest", errors)
        else:
            ok = False
        for field in ("manifest_digest", "component_digest", "wit_digest", "capability_digest", "ipc_digest", "runtime_abi_digest", "dependency_digest"):
            ok &= _valid_digest(package[field], f"{path}.package.{field}", errors)
        capabilities = package["capabilities"]
        if not isinstance(capabilities, list) or any(not isinstance(item, str) or not item or any(ord(char) < 0x20 or char == "\0" for char in item) for item in capabilities):
            errors.append({"code": "invalid_capabilities", "path": f"{path}.package.capabilities", "message": "must be a string array without control characters"})
            ok = False
        elif len(set(capabilities)) != len(capabilities) or capabilities != sorted(capabilities):
            errors.append({"code": "capabilities_not_canonical", "path": f"{path}.package.capabilities", "message": "capabilities must be unique and sorted"})
            ok = False
        dependencies = package["dependencies"]
        if not isinstance(dependencies, list):
            errors.append({"code": "invalid_dependencies", "path": f"{path}.package.dependencies", "message": "must be an array"})
            ok = False
        else:
            dependency_keys: list[tuple[str, str, str, bool]] = []
            for index, dependency in enumerate(dependencies):
                dependency_path = f"{path}.package.dependencies[{index}]"
                if not _exact_keys(dependency, ("coordinate", "requirement", "optional"), None, dependency_path, errors):
                    ok = False
                    continue
                assert isinstance(dependency, dict)
                dep_coord = dependency["coordinate"]
                if _exact_keys(dep_coord, ("namespace", "name"), None, f"{dependency_path}.coordinate", errors):
                    assert isinstance(dep_coord, dict)
                    ok &= _valid_name(dep_coord["namespace"], f"{dependency_path}.coordinate.namespace", errors)
                    ok &= _valid_name(dep_coord["name"], f"{dependency_path}.coordinate.name", errors)
                    dep_namespace, dep_name = dep_coord["namespace"], dep_coord["name"]
                else:
                    ok = False
                    dep_namespace, dep_name = "", ""
                requirement = dependency["requirement"]
                if not isinstance(requirement, str) or not requirement or any(ord(char) < 0x20 or char == "\0" for char in requirement):
                    errors.append({"code": "invalid_version_requirement", "path": f"{dependency_path}.requirement", "message": "must be a non-empty SemVer requirement"})
                    ok = False
                optional = dependency["optional"]
                if not _is_bool(optional):
                    errors.append({"code": "invalid_optional", "path": f"{dependency_path}.optional", "message": "must be boolean"})
                    ok = False
                    optional = False
                dependency_keys.append((dep_namespace, dep_name, requirement, optional))
            if len(set(dependency_keys)) != len(dependency_keys):
                errors.append({"code": "duplicate_dependency", "path": f"{path}.package.dependencies", "message": "dependencies must be unique"})
                ok = False
            if dependency_keys != sorted(dependency_keys):
                errors.append({"code": "dependencies_not_canonical", "path": f"{path}.package.dependencies", "message": "dependencies must use Rust ordering"})
                ok = False
        runtime = package["runtime"]
        if _exact_keys(runtime, ("runtime", "abi", "digest"), None, f"{path}.package.runtime", errors):
            assert isinstance(runtime, dict)
            for field in ("runtime", "abi"):
                if not isinstance(runtime[field], str) or not runtime[field] or any(ord(char) < 0x20 or char == "\0" for char in runtime[field]):
                    errors.append({"code": "invalid_runtime_requirement", "path": f"{path}.package.runtime.{field}", "message": "must be non-empty text without controls"})
                    ok = False
            ok &= _valid_digest(runtime["digest"], f"{path}.package.runtime.digest", errors)
            if package["runtime_abi_digest"] != runtime.get("digest"):
                errors.append({"code": "runtime_digest_mismatch", "path": f"{path}.package.runtime_abi_digest", "message": "must equal package.runtime.digest"})
                ok = False
        else:
            ok = False
    else:
        ok = False

    publisher = value["publisher"]
    if _exact_keys(publisher, ("identity", "signing_key"), None, f"{path}.publisher", errors):
        assert isinstance(publisher, dict)
        if not isinstance(publisher["identity"], str) or not publisher["identity"] or any(ord(char) < 0x20 for char in publisher["identity"]):
            errors.append({"code": "invalid_publisher_identity", "path": f"{path}.publisher.identity", "message": "must be non-empty actor text without controls"})
            ok = False
        ok &= _valid_digest(publisher["signing_key"], f"{path}.publisher.signing_key", errors)
    else:
        ok = False

    source_fields = ("repository_url", "github_owner_id", "github_repository_id", "commit", "tree", "tag", "subdirectory", "source_digest")
    source = value["source"]
    if _exact_keys(source, source_fields, None, f"{path}.source", errors):
        assert isinstance(source, dict)
        ok &= _valid_https_url(source["repository_url"], f"{path}.source.repository_url", errors)
        for field in ("github_owner_id", "github_repository_id"):
            if not _is_int(source[field]) or source[field] <= 0:
                errors.append({"code": "invalid_repository_id", "path": f"{path}.source.{field}", "message": "must be a non-zero integer"})
                ok = False
        for field in ("commit", "tree"):
            if not isinstance(source[field], str) or not _COMMIT_RE.fullmatch(source[field]):
                errors.append({"code": "invalid_source_object", "path": f"{path}.source.{field}", "message": "must be lower-case 40 or 64 hexadecimal characters"})
                ok = False
        tag = source["tag"]
        if not isinstance(tag, str) or not tag or any(ord(char) < 0x20 or char.isspace() or char in "/\\" for char in tag) or ".." in tag or tag.startswith("."):
            errors.append({"code": "invalid_source_tag", "path": f"{path}.source.tag", "message": "must be a non-empty release ref without traversal"})
            ok = False
        subdirectory = source["subdirectory"]
        if subdirectory is not None and (not isinstance(subdirectory, str) or not subdirectory or subdirectory.startswith("/") or subdirectory.endswith("/") or "\\" in subdirectory or "%" in subdirectory or any(part in {"", ".", ".."} for part in subdirectory.split("/")) or any(ord(char) < 0x20 for char in subdirectory)):
            errors.append({"code": "invalid_source_subdirectory", "path": f"{path}.source.subdirectory", "message": "must be null or a canonical relative path"})
            ok = False
        ok &= _valid_digest(source["source_digest"], f"{path}.source.source_digest", errors)
    else:
        ok = False

    provenance = value["provenance"]
    if _exact_keys(provenance, ("predicate_type", "statement_digest", "builder_identity", "attestation_identity"), None, f"{path}.provenance", errors):
        assert isinstance(provenance, dict)
        for field in ("predicate_type", "attestation_identity"):
            if not isinstance(provenance[field], str) or not provenance[field] or any(ord(char) < 0x20 or char == "\0" for char in provenance[field]):
                errors.append({"code": "invalid_provenance_identity", "path": f"{path}.provenance.{field}", "message": "must be non-empty text without controls"})
                ok = False
        ok &= _valid_digest(provenance["statement_digest"], f"{path}.provenance.statement_digest", errors)
        ok &= _valid_https_url(provenance["builder_identity"], f"{path}.provenance.builder_identity", errors)
    else:
        ok = False

    metadata = value["metadata"]
    if not isinstance(metadata, dict):
        errors.append({"code": "invalid_metadata", "path": f"{path}.metadata", "message": "must be a string map"})
        ok = False
    else:
        for key, item in metadata.items():
            if not isinstance(key, str) or not key or "\0" in key or not isinstance(item, str) or "\0" in item:
                errors.append({"code": "invalid_metadata", "path": f"{path}.metadata", "message": "metadata keys/values must be non-empty-safe strings"})
                ok = False

    if not isinstance(value["publication_digest"], str) or not value["publication_digest"].startswith("blake3:"):
        errors.append({"code": "invalid_publication_digest", "path": f"{path}.publication_digest", "message": "publication identity must be tagged blake3"})
        ok = False
    elif ok and value["publication_digest"] != publication_digest(value):
        errors.append({"code": "publication_digest_mismatch", "path": f"{path}.publication_digest", "message": "does not match the domain-separated BLAKE3 projection"})
        ok = False
    return bool(ok)


def _validate_source(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    if not _exact_keys(value, ("index_id", "base_url", "root_fingerprint"), None, path, errors):
        return False
    assert isinstance(value, dict)
    ok = _valid_index_id(value["index_id"], f"{path}.index_id", errors)
    ok &= _valid_https_url(value["base_url"], f"{path}.base_url", errors)
    root = value["root_fingerprint"]
    ok &= _valid_digest(root, f"{path}.root_fingerprint", errors)
    if isinstance(root, str) and not root.startswith("sha256:"):
        errors.append({"code": "invalid_root_fingerprint", "path": f"{path}.root_fingerprint", "message": "Index root fingerprints must use tagged sha256"})
        ok = False
    return bool(ok)


def _coord(publication: Mapping[str, Any]) -> tuple[str, str, str]:
    return publication["coordinate"]["namespace"], publication["coordinate"]["name"], publication["version"]


def _validate_publication_key(
    value: Any,
    path: str,
    publication: Mapping[str, Any],
    errors: list[dict[str, str]],
) -> bool:
    if not _exact_keys(value, ("index_id", "coordinate", "version"), None, path, errors):
        return False
    assert isinstance(value, dict)
    ok = _valid_index_id(value["index_id"], f"{path}.index_id", errors)
    coordinate = value["coordinate"]
    if _exact_keys(coordinate, ("namespace", "name"), None, f"{path}.coordinate", errors):
        assert isinstance(coordinate, dict)
        ok &= _valid_name(coordinate["namespace"], f"{path}.coordinate.namespace", errors)
        ok &= _valid_name(coordinate["name"], f"{path}.coordinate.name", errors)
    else:
        ok = False
    ok &= _valid_semver(value["version"], f"{path}.version", errors)
    expected = {"index_id": publication["index_id"], "coordinate": publication["coordinate"], "version": publication["version"]}
    if value != expected:
        errors.append({"code": "event_target_mismatch", "path": path, "message": "event targets another publication key"})
        ok = False
    return bool(ok)


def _validate_event(
    event: Any,
    index: int,
    publication: Mapping[str, Any],
    errors: list[dict[str, str]],
) -> tuple[str | None, dict[str, Any] | None]:
    path = f"input.events[{index}]"
    if not isinstance(event, dict) or len(event) != 1:
        errors.append({"code": "expected_event_variant", "path": path, "message": "event must be one externally tagged IndexEvent variant"})
        return None, None
    event_type, payload = next(iter(event.items()))
    variants = {
        "Yank": ("actor", "publication", "reason"),
        "Unyank": ("actor", "publication"),
        "Deprecate": ("actor", "publication", "replacement", "note"),
        "Revoke": ("actor", "publication", "reason"),
        "Tombstone": ("actor", "publication", "reason"),
        "OwnerChange": ("actor", "publication", "from", "to"),
        "AddMirror": ("actor", "publication", "mirror"),
        "AddAttestation": ("actor", "publication", "attestation"),
        "Annotation": ("actor", "publication", "key", "value"),
    }
    if event_type not in variants:
        errors.append({"code": "invalid_event_type", "path": path, "message": "event variant is not allowed"})
        return event_type if isinstance(event_type, str) else None, None
    required = variants[event_type]
    if not _exact_keys(payload, required, None, f"{path}.{event_type}", errors):
        return event_type, None
    assert isinstance(payload, dict)
    ok = True
    actor = payload["actor"]
    if not isinstance(actor, str) or not actor or any(ord(char) < 0x20 for char in actor):
        errors.append({"code": "invalid_actor", "path": f"{path}.{event_type}.actor", "message": "must be non-empty actor text without controls"})
        ok = False
    ok &= _validate_publication_key(payload["publication"], f"{path}.{event_type}.publication", publication, errors)
    if event_type in {"Yank", "Revoke", "Tombstone"}:
        reason = payload["reason"]
        if event_type == "Yank":
            if reason is not None and (not isinstance(reason, str) or any(ord(char) < 0x20 for char in reason)):
                errors.append({"code": "invalid_reason", "path": f"{path}.{event_type}.reason", "message": "must be null or control-free text"})
                ok = False
        elif not isinstance(reason, str) or not reason.strip() or any(ord(char) < 0x20 for char in reason):
            errors.append({"code": "invalid_reason", "path": f"{path}.{event_type}.reason", "message": "must be non-empty reason text"})
            ok = False
    if event_type == "Deprecate":
        for field in ("replacement",):
            replacement = payload[field]
            if replacement is not None:
                # A replacement is intentionally allowed to point at another
                # coordinate; validate its shape without requiring equality.
                if not _exact_keys(replacement, ("index_id", "coordinate", "version"), None, f"{path}.{event_type}.{field}", errors):
                    ok = False
                elif isinstance(replacement, dict):
                    ok &= _valid_index_id(replacement["index_id"], f"{path}.{event_type}.{field}.index_id", errors)
                    replacement_coordinate = replacement["coordinate"]
                    if _exact_keys(replacement_coordinate, ("namespace", "name"), None, f"{path}.{event_type}.{field}.coordinate", errors):
                        assert isinstance(replacement_coordinate, dict)
                        ok &= _valid_name(replacement_coordinate["namespace"], f"{path}.{event_type}.{field}.coordinate.namespace", errors)
                        ok &= _valid_name(replacement_coordinate["name"], f"{path}.{event_type}.{field}.coordinate.name", errors)
                    else:
                        ok = False
                    ok &= _valid_semver(replacement["version"], f"{path}.{event_type}.{field}.version", errors)
        note = payload["note"]
        if note is not None and (not isinstance(note, str) or any(ord(char) < 0x20 for char in note)):
            errors.append({"code": "invalid_note", "path": f"{path}.{event_type}.note", "message": "must be null or control-free text"})
            ok = False
    if event_type == "OwnerChange":
        for field in ("from", "to"):
            if not isinstance(payload[field], str) or not payload[field] or any(ord(char) < 0x20 for char in payload[field]):
                errors.append({"code": "invalid_actor", "path": f"{path}.{event_type}.{field}", "message": "must be non-empty actor text without controls"})
                ok = False
        if payload["from"] == payload["to"]:
            errors.append({"code": "invalid_transition", "path": f"{path}.{event_type}", "message": "owner must change"})
            ok = False
    if event_type == "AddMirror":
        ok &= _valid_https_url(payload["mirror"], f"{path}.{event_type}.mirror", errors)
    if event_type == "AddAttestation":
        ok &= _valid_digest(payload["attestation"], f"{path}.{event_type}.attestation", errors)
    if event_type == "Annotation":
        if not isinstance(payload["key"], str) or not payload["key"].strip() or "\0" in payload["key"]:
            errors.append({"code": "invalid_annotation", "path": f"{path}.{event_type}.key", "message": "annotation key must be non-empty"})
            ok = False
        if not isinstance(payload["value"], str) or "\0" in payload["value"]:
            errors.append({"code": "invalid_annotation", "path": f"{path}.{event_type}.value", "message": "annotation value must not contain NUL"})
            ok = False
    return event_type, payload if ok else None


def _history(
    publication: Any,
    events: Any,
    errors: list[dict[str, str]],
) -> dict[str, Any] | None:
    if not _validate_publication(publication, "input.publication", errors):
        return None
    if not isinstance(events, list):
        errors.append({"code": "invalid_events", "path": "input.events", "message": "must be an array"})
        return None
    state: dict[str, Any] = {
        "yanked": False,
        "revoked": False,
        "deprecated": False,
        "tombstoned": False,
        "mirrors": [],
    }
    seen_mirrors: set[str] = set()
    seen_attestations: set[str] = set()
    for index, event in enumerate(events):
        event_type, valid_event = _validate_event(event, index, publication, errors)
        if valid_event is None:
            continue
        if state["tombstoned"] and event_type != "AddMirror":
            errors.append({"code": "invalid_transition", "path": f"input.events[{index}]", "message": "only AddMirror is allowed after tombstone"})
            continue
        if event_type == "Yank":
            if state["yanked"] or state["revoked"] or state["tombstoned"]:
                errors.append({"code": "invalid_transition", "path": f"input.events[{index}]", "message": "cannot yank current lifecycle state"})
            state["yanked"] = True
        elif event_type == "Unyank":
            if not state["yanked"] or state["revoked"] or state["tombstoned"]:
                errors.append({"code": "invalid_transition", "path": f"input.events[{index}]", "message": "unyank requires a live yanked publication"})
            state["yanked"] = False
        elif event_type == "Revoke":
            if state["revoked"] or state["tombstoned"]:
                errors.append({"code": "invalid_transition", "path": f"input.events[{index}]", "message": "publication is already revoked"})
            state["revoked"] = True
        elif event_type == "Deprecate":
            if state["tombstoned"] or state["revoked"] or state["deprecated"]:
                errors.append({"code": "invalid_transition", "path": f"input.events[{index}]", "message": "cannot deprecate a tombstone"})
            state["deprecated"] = True
        elif event_type == "Tombstone":
            if state["tombstoned"] or state["revoked"]:
                errors.append({"code": "invalid_transition", "path": f"input.events[{index}]", "message": "publication is already tombstoned"})
            state["tombstoned"] = True
        elif event_type == "AddMirror":
            mirror = valid_event["mirror"]
            if mirror in seen_mirrors:
                errors.append({"code": "duplicate_mirror", "path": f"input.events[{index}].AddMirror.mirror", "message": "mirror locator is already present"})
            seen_mirrors.add(mirror)
            state["mirrors"].append(mirror)
        elif event_type == "AddAttestation":
            attestation = valid_event["attestation"]
            if attestation in seen_attestations:
                errors.append({"code": "duplicate_attestation", "path": f"input.events[{index}].AddAttestation.attestation", "message": "attestation is already present"})
            seen_attestations.add(attestation)
    if state["tombstoned"]:
        state["status"] = "tombstoned"
    elif state["revoked"]:
        state["status"] = "revoked"
    elif state["yanked"]:
        state["status"] = "yanked"
    elif state["deprecated"]:
        state["status"] = "deprecated"
    else:
        state["status"] = "published"
    return state


def _canonical_rfc3339(value: Any, path: str, errors: list[dict[str, str]]) -> str | None:
    parsed = _valid_rfc3339(value, path, errors)
    if parsed is None or not isinstance(value, str):
        return None
    if "." not in value:
        return value
    prefix, suffix = value[:-1].split(".", 1)
    fraction = suffix.rstrip("0")
    return f"{prefix}.{fraction}Z" if fraction else f"{prefix}Z"


def _event_digest(publication_event: Mapping[str, Any], envelope: Mapping[str, Any]) -> str:
    """Compute the Rust event-envelope digest for a Publication body."""

    def put_u64(buffer: bytearray, value: int) -> None:
        buffer.extend(value.to_bytes(8, "little", signed=False))

    def put_text(buffer: bytearray, value: str) -> None:
        encoded = value.encode("utf-8")
        put_u64(buffer, len(encoded))
        buffer.extend(encoded)

    def put_digest(buffer: bytearray, value: str) -> None:
        algorithm, encoded = value.split(":", 1)
        raw = bytes.fromhex(encoded)
        put_text(buffer, algorithm)
        put_u64(buffer, len(raw))
        buffer.extend(raw)

    def put_optional_text(buffer: bytearray, value: Any) -> None:
        if value is None:
            buffer.append(0)
        else:
            buffer.append(1)
            put_text(buffer, value)

    def put_key(buffer: bytearray, value: Mapping[str, Any]) -> None:
        put_text(buffer, value["index_id"])
        put_text(buffer, value["coordinate"]["namespace"])
        put_text(buffer, value["coordinate"]["name"])
        put_text(buffer, value["version"])

    def put_optional_key(buffer: bytearray, value: Any) -> None:
        if value is None:
            buffer.append(0)
        else:
            buffer.append(1)
            put_key(buffer, value)

    variant, payload = next(iter(publication_event.items()))
    buffer = bytearray()
    buffer.extend(b"astrid:capsule-index:event:v1\0")
    put_text(buffer, envelope["schema"])
    put_text(buffer, envelope["index"]["id"])
    put_digest(buffer, envelope["index"]["trust_root"])
    put_u64(buffer, envelope["sequence"])
    put_text(buffer, envelope["recorded_at"])
    put_text(buffer, envelope["actor"])
    authorization = envelope["authorization"]
    put_text(buffer, authorization["actor"])
    put_text(buffer, authorization["evidence"])
    put_digest(buffer, authorization["signature_digest"])
    prior = envelope["prior_event_digest"]
    if prior is None:
        buffer.append(0)
    else:
        buffer.append(1)
        put_digest(buffer, prior)
    put_text(buffer, "publication")
    labels = {
        "Yank": "yank", "Unyank": "unyank", "Deprecate": "deprecate",
        "Revoke": "revoke", "Tombstone": "tombstone", "OwnerChange": "owner-change",
        "AddMirror": "add-mirror", "AddAttestation": "add-attestation", "Annotation": "annotation",
    }
    put_text(buffer, labels[variant])
    put_text(buffer, payload["actor"])
    put_key(buffer, payload["publication"])
    if variant == "Yank":
        put_optional_text(buffer, payload["reason"])
    elif variant == "Deprecate":
        put_optional_key(buffer, payload["replacement"])
        put_optional_text(buffer, payload["note"])
    elif variant in {"Revoke", "Tombstone"}:
        put_text(buffer, payload["reason"])
    elif variant == "OwnerChange":
        put_text(buffer, payload["from"])
        put_text(buffer, payload["to"])
    elif variant == "AddMirror":
        put_text(buffer, payload["mirror"])
    elif variant == "AddAttestation":
        put_digest(buffer, payload["attestation"])
    elif variant == "Annotation":
        put_text(buffer, payload["key"])
        put_text(buffer, payload["value"])
    return "blake3:" + _blake3(bytes(buffer)).hex()


def _validate_envelope(
    value: Any,
    index: int,
    publication: Mapping[str, Any],
    prior_digest: str | None,
    errors: list[dict[str, str]],
) -> str | None:
    path = f"input.envelopes[{index}]"
    required = ("schema", "index", "sequence", "recorded_at", "actor", "authorization", "prior_event_digest", "body", "event_digest")
    if not _exact_keys(value, required, None, path, errors):
        return None
    assert isinstance(value, dict)
    ok = value["schema"] == "event-envelope-v1"
    if not ok:
        errors.append({"code": "invalid_event_schema", "path": f"{path}.schema", "message": "must be event-envelope-v1"})
    index_identity = value["index"]
    if _exact_keys(index_identity, ("id", "trust_root"), None, f"{path}.index", errors):
        assert isinstance(index_identity, dict)
        ok &= _valid_index_id(index_identity["id"], f"{path}.index.id", errors)
        ok &= _valid_digest(index_identity["trust_root"], f"{path}.index.trust_root", errors)
        if isinstance(index_identity["trust_root"], str) and not index_identity["trust_root"].startswith("sha256:"):
            errors.append({"code": "invalid_root_fingerprint", "path": f"{path}.index.trust_root", "message": "must be tagged sha256"})
            ok = False
        if index_identity["id"] != publication["index_id"]:
            errors.append({"code": "event_index_mismatch", "path": f"{path}.index.id", "message": "envelope index differs from publication"})
            ok = False
    else:
        ok = False
    if not _is_int(value["sequence"]) or value["sequence"] <= 0:
        errors.append({"code": "invalid_sequence", "path": f"{path}.sequence", "message": "must be a positive integer"})
        ok = False
    if index == 0 and value["sequence"] != 1:
        errors.append({"code": "sequence_gap", "path": f"{path}.sequence", "message": "first envelope must have sequence 1"})
        ok = False
    if index > 0 and value["sequence"] != index + 1:
        errors.append({"code": "sequence_gap", "path": f"{path}.sequence", "message": "envelope sequence must be contiguous"})
        ok = False
    canonical_time = _canonical_rfc3339(value["recorded_at"], f"{path}.recorded_at", errors)
    if canonical_time != value["recorded_at"]:
        errors.append({"code": "noncanonical_timestamp", "path": f"{path}.recorded_at", "message": "timestamp must use canonical UTC formatting"})
        ok = False
    for field in ("actor",):
        if not isinstance(value[field], str) or not value[field] or any(ord(char) < 0x20 for char in value[field]):
            errors.append({"code": "invalid_actor", "path": f"{path}.{field}", "message": "must be non-empty actor text"})
            ok = False
    authorization = value["authorization"]
    if _exact_keys(authorization, ("actor", "evidence", "signature_digest"), None, f"{path}.authorization", errors):
        assert isinstance(authorization, dict)
        if authorization["actor"] != value["actor"]:
            errors.append({"code": "authorization_actor_mismatch", "path": f"{path}.authorization.actor", "message": "authorization actor must match envelope actor"})
            ok = False
        if not isinstance(authorization["evidence"], str) or not authorization["evidence"] or any(ord(char) < 0x20 for char in authorization["evidence"]):
            errors.append({"code": "invalid_authorization", "path": f"{path}.authorization.evidence", "message": "must be non-empty evidence text"})
            ok = False
        ok &= _valid_digest(authorization["signature_digest"], f"{path}.authorization.signature_digest", errors)
    else:
        ok = False
    prior = value["prior_event_digest"]
    if prior is not None:
        ok &= _valid_digest(prior, f"{path}.prior_event_digest", errors)
    if (index == 0 and prior is not None) or (index > 0 and prior is None):
        errors.append({"code": "prior_digest_mismatch", "path": f"{path}.prior_event_digest", "message": "prior digest presence must match sequence"})
        ok = False
    if prior_digest is not None and prior != prior_digest:
        errors.append({"code": "prior_digest_mismatch", "path": f"{path}.prior_event_digest", "message": "prior digest does not chain from previous envelope"})
        ok = False
    body = value["body"]
    if not isinstance(body, dict) or len(body) != 1:
        errors.append({"code": "invalid_event_body", "path": f"{path}.body", "message": "body must be one externally tagged variant"})
        return None
    body_type, body_value = next(iter(body.items()))
    if body_type != "Publication":
        errors.append({"code": "unsupported_event_body", "path": f"{path}.body", "message": "NamespaceTransfer validation is delegated to the typed protocol implementation"})
        return None
    event_type, valid_event = _validate_event(body_value, index, publication, errors)
    if valid_event is None or event_type is None:
        return None
    if valid_event["actor"] != value["actor"]:
        errors.append({"code": "event_actor_mismatch", "path": f"{path}.body.Publication.{event_type}.actor", "message": "body actor must match envelope actor"})
        ok = False
    digest = value["event_digest"]
    if not isinstance(digest, str) or not digest.startswith("blake3:"):
        errors.append({"code": "invalid_event_digest", "path": f"{path}.event_digest", "message": "must be tagged blake3"})
        return None
    ok &= _valid_digest(digest, f"{path}.event_digest", errors)
    if ok and digest != _event_digest(body_value, value):
        errors.append({"code": "event_digest_mismatch", "path": f"{path}.event_digest", "message": "does not match the event-envelope projection"})
        ok = False
    return digest if ok else None


def _validate_tuf(value: Any, errors: list[dict[str, str]]) -> bool:
    if not _exact_keys(value, ("checked_at", "trusted_versions", "root", "timestamp", "snapshot", "targets"), None, "input.tuf", errors):
        return False
    assert isinstance(value, dict)
    checked_at = _valid_rfc3339(value["checked_at"], "input.tuf.checked_at", errors)
    ok = checked_at is not None
    trusted = value["trusted_versions"]
    if _exact_keys(trusted, ("root", "timestamp", "snapshot", "targets"), None, "input.tuf.trusted_versions", errors):
        assert isinstance(trusted, dict)
        for role in ("root", "timestamp", "snapshot", "targets"):
            if not _is_int(trusted[role]) or trusted[role] < 0:
                errors.append({"code": "invalid_metadata_version", "path": f"input.tuf.trusted_versions.{role}", "message": "must be a non-negative integer"})
                ok = False
    else:
        trusted = {}
        ok = False
    if _exact_keys(value["root"], ("version", "threshold", "crypto"), None, "input.tuf.root", errors):
        root = value["root"]
        assert isinstance(root, dict)
        if not _is_int(root["version"]) or root["version"] < trusted.get("root", 0):
            errors.append({"code": "rollback", "path": "input.tuf.root.version", "message": "root metadata rolled back"})
            ok = False
        if not _is_int(root["threshold"]) or root["threshold"] <= 0:
            errors.append({"code": "invalid_threshold", "path": "input.tuf.root.threshold", "message": "threshold must be positive"})
            ok = False
        if root["crypto"] != "delegated":
            errors.append({"code": "crypto_not_delegated", "path": "input.tuf.root.crypto", "message": "signature verification belongs to the TUF implementation"})
            ok = False
    else:
        ok = False

    role_fields = {
        "timestamp": ("version", "expires", "snapshot_version", "snapshot_digest", "snapshot_length"),
        "snapshot": ("version", "expires", "digest", "targets_version", "targets_digest", "targets_length"),
        "targets": ("version", "expires", "digest", "records_digest"),
    }
    roles: dict[str, Mapping[str, Any]] = {}
    for role, fields in role_fields.items():
        if not _exact_keys(value[role], fields, None, f"input.tuf.{role}", errors):
            ok = False
            continue
        obj = value[role]
        assert isinstance(obj, dict)
        roles[role] = obj
        if not _is_int(obj["version"]) or obj["version"] < trusted.get(role, 0):
            errors.append({"code": "rollback", "path": f"input.tuf.{role}.version", "message": f"{role} metadata rolled back"})
            ok = False
        expiry = _valid_rfc3339(obj["expires"], f"input.tuf.{role}.expires", errors)
        if expiry is not None and checked_at is not None and expiry <= checked_at:
            errors.append({"code": "metadata_expired", "path": f"input.tuf.{role}.expires", "message": f"{role} metadata is expired"})
            ok = False
        for field in ("snapshot_digest", "targets_digest", "digest", "records_digest"):
            if field in obj:
                ok &= _valid_digest(obj[field], f"input.tuf.{role}.{field}", errors)
        for field in ("snapshot_length", "targets_length"):
            if field in obj and (not _is_int(obj[field]) or obj[field] < 0):
                errors.append({"code": "invalid_metadata_length", "path": f"input.tuf.{role}.{field}", "message": "must be a non-negative integer"})
                ok = False
    if set(roles) == set(role_fields):
        timestamp = roles["timestamp"]
        snapshot = roles["snapshot"]
        targets = roles["targets"]
        if timestamp["snapshot_version"] != snapshot["version"] or timestamp["snapshot_digest"] != snapshot["digest"]:
            errors.append({"code": "snapshot_reference_mismatch", "path": "input.tuf.timestamp", "message": "timestamp does not identify supplied snapshot"})
            ok = False
        if snapshot["targets_version"] != targets["version"] or snapshot["targets_digest"] != targets["digest"]:
            errors.append({"code": "targets_reference_mismatch", "path": "input.tuf.snapshot", "message": "snapshot does not identify supplied targets"})
            ok = False
    return bool(ok)


def _record_entry(value: Any, path: str, errors: list[dict[str, str]]) -> tuple[str, Mapping[str, Any]] | None:
    if not _exact_keys(value, ("index_id", "publication"), None, path, errors):
        return None
    assert isinstance(value, dict)
    if not _valid_index_id(value["index_id"], f"{path}.index_id", errors):
        return None
    if not _validate_publication(value["publication"], f"{path}.publication", errors):
        return None
    assert isinstance(value["publication"], dict)
    if value["publication"]["index_id"] != value["index_id"]:
        errors.append({"code": "record_index_mismatch", "path": f"{path}.publication.index_id", "message": "record index_id must match its source wrapper"})
        return None
    return value["index_id"], value["publication"]


def _validate_lock(value: Any, path: str, errors: list[dict[str, str]]) -> bool:
    required = (
        "index_id", "trust_root", "coordinate", "version", "publication_digest",
        "artifact_digests", "artifact_size", "artifact_media_type",
        "manifest_digest", "component_digest", "wit_digest", "capability_digest",
        "ipc_digest", "runtime_abi_digest", "dependency_digest", "provenance_digest",
        "source_digest",
    )
    if not _exact_keys(value, required, None, path, errors):
        return False
    assert isinstance(value, dict)
    ok = _valid_index_id(value["index_id"], f"{path}.index_id", errors)
    ok &= _valid_digest(value["trust_root"], f"{path}.trust_root", errors)
    if isinstance(value["trust_root"], str) and not value["trust_root"].startswith("sha256:"):
        errors.append({"code": "invalid_root_fingerprint", "path": f"{path}.trust_root", "message": "must be tagged sha256"})
        ok = False
    coordinate = value["coordinate"]
    if _exact_keys(coordinate, ("namespace", "name"), None, f"{path}.coordinate", errors):
        assert isinstance(coordinate, dict)
        ok &= _valid_name(coordinate["namespace"], f"{path}.coordinate.namespace", errors)
        ok &= _valid_name(coordinate["name"], f"{path}.coordinate.name", errors)
    else:
        ok = False
    ok &= _valid_semver(value["version"], f"{path}.version", errors)
    ok &= _valid_digest(value["publication_digest"], f"{path}.publication_digest", errors)
    if isinstance(value["publication_digest"], str) and not value["publication_digest"].startswith("blake3:"):
        errors.append({"code": "invalid_publication_digest", "path": f"{path}.publication_digest", "message": "must be tagged blake3"})
        ok = False
    digests = value["artifact_digests"]
    if not isinstance(digests, list) or not digests:
        errors.append({"code": "invalid_artifact_digests", "path": f"{path}.artifact_digests", "message": "must be a non-empty digest array"})
        ok = False
    else:
        for index, digest in enumerate(digests):
            ok &= _valid_digest(digest, f"{path}.artifact_digests[{index}]", errors)
        if len(set(digests)) != len(digests):
            errors.append({"code": "duplicate_value", "path": f"{path}.artifact_digests", "message": "digests must be unique"})
            ok = False
    if not _is_int(value["artifact_size"]) or value["artifact_size"] < 0:
        errors.append({"code": "invalid_size", "path": f"{path}.artifact_size", "message": "must be a non-negative integer"})
        ok = False
    if not isinstance(value["artifact_media_type"], str) or not value["artifact_media_type"]:
        errors.append({"code": "invalid_media_type", "path": f"{path}.artifact_media_type", "message": "must be non-empty text"})
        ok = False
    for field in ("manifest_digest", "component_digest", "wit_digest", "capability_digest", "ipc_digest", "runtime_abi_digest", "dependency_digest", "provenance_digest", "source_digest"):
        ok &= _valid_digest(value[field], f"{path}.{field}", errors)
    return bool(ok)


def _validate_fixture(data: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    errors: list[dict[str, str]] = []
    derived: dict[str, Any] = {}
    if not isinstance(data, dict):
        return ([{"code": "fixture_object_required", "path": "$", "message": "fixture must be an object"}], derived)
    if data.get("schema") != SCHEMA:
        errors.append({"code": "invalid_schema", "path": "schema", "message": f"must equal {SCHEMA}"})
    if not isinstance(data.get("case_id"), str) or not _CASE_RE.fullmatch(data.get("case_id", "")):
        errors.append({"code": "invalid_case_id", "path": "case_id", "message": "must be a stable lower-case case identifier"})
    kind = data.get("kind")
    allowed_kinds = {"publication", "idempotence", "equivocation", "history", "syntax", "source-collision", "resolution", "tuf", "mirror", "event-envelope"}
    if kind not in allowed_kinds:
        errors.append({"code": "invalid_kind", "path": "kind", "message": "fixture kind is not supported"})
        return errors, derived
    expected = data.get("expected")
    if not isinstance(expected, dict) or not _is_bool(expected.get("accepted")):
        errors.append({"code": "invalid_expectation", "path": "expected.accepted", "message": "expected.accepted must be boolean"})
    elif "error_codes" in expected and (not isinstance(expected["error_codes"], list) or any(not isinstance(item, str) for item in expected["error_codes"])):
        errors.append({"code": "invalid_expectation", "path": "expected.error_codes", "message": "error_codes must be a string array"})
    value = data.get("input")
    if not isinstance(value, dict):
        errors.append({"code": "invalid_input", "path": "input", "message": "input must be an object"})
        return errors, derived

    if kind in {"publication", "syntax"}:
        if "publication" not in value:
            errors.append({"code": "missing_field", "path": "input.publication", "message": "publication is required"})
        else:
            _validate_publication(value["publication"], "input.publication", errors)
    elif kind == "idempotence":
        base = value.get("base")
        candidate = value.get("candidate")
        base_ok = _validate_publication(base, "input.base", errors)
        candidate_ok = _validate_publication(candidate, "input.candidate", errors)
        if base_ok and candidate_ok:
            assert isinstance(base, dict) and isinstance(candidate, dict)
            if base != candidate or base["publication_digest"] != candidate["publication_digest"]:
                errors.append({"code": "not_idempotent", "path": "input.candidate", "message": "candidate is not the same canonical publication"})
    elif kind == "equivocation":
        base = value.get("base")
        if _validate_publication(base, "input.base", errors):
            assert isinstance(base, dict)
            candidates = value.get("mutations")
            if not isinstance(candidates, list) or not candidates:
                errors.append({"code": "invalid_mutations", "path": "input.mutations", "message": "at least one mutation is required"})
            else:
                for index, item in enumerate(candidates):
                    path = f"input.mutations[{index}]"
                    if not isinstance(item, dict):
                        errors.append({"code": "expected_object", "path": path, "message": "mutation must be an object"})
                        continue
                    if "field" in item and "value" in item:
                        if set(item) != {"id", "field", "value"} or not isinstance(item.get("id"), str) or not _CASE_RE.fullmatch(item["id"]):
                            errors.append({"code": "invalid_mutation", "path": path, "message": "descriptor requires id, field, and value"})
                            continue
                        candidate = json.loads(json.dumps(base))
                        field_parts = item["field"].split(".")
                        target: Any = candidate
                        try:
                            for part in field_parts[:-1]:
                                target = target[part]
                            target[field_parts[-1]] = item["value"]
                        except (KeyError, TypeError):
                            errors.append({"code": "invalid_mutation_field", "path": f"{path}.field", "message": "field is not immutable publication data"})
                            continue
                        candidate["publication_digest"] = publication_digest(candidate)
                        if _validate_publication(candidate, f"{path}.publication", errors):
                            errors.append({"code": "equivocation", "path": path, "message": "same coordinate has a different immutable publication"})
                        continue
                    if not _exact_keys(item, ("id", "publication"), None, path, errors):
                        continue
                    assert isinstance(item, dict)
                    if not isinstance(item["id"], str) or not _CASE_RE.fullmatch(item["id"]):
                        errors.append({"code": "invalid_mutation_id", "path": f"{path}.id", "message": "mutation id is invalid"})
                    if _validate_publication(item["publication"], f"{path}.publication", errors):
                        candidate = item["publication"]
                        assert isinstance(candidate, dict)
                        if _coord(candidate) != _coord(base):
                            errors.append({"code": "coordinate_changed", "path": f"{path}.publication", "message": "equivocation must retain the same coordinate"})
                        elif candidate["publication_digest"] == base["publication_digest"]:
                            errors.append({"code": "not_equivocation", "path": f"{path}.publication", "message": "mutation retained the original publication digest"})
                        else:
                            errors.append({"code": "equivocation", "path": path, "message": "same coordinate has a different immutable publication"})
    elif kind in {"history", "mirror"}:
        if "histories" in value:
            histories = value.get("histories")
            if not isinstance(histories, dict) or not histories:
                errors.append({"code": "invalid_histories", "path": "input.histories", "message": "histories must be a non-empty object"})
            else:
                derived["histories"] = {}
                for name in sorted(histories):
                    state = _history(value.get("publication"), histories[name], errors)
                    if state is not None:
                        derived["histories"][name] = state
        else:
            state = _history(value.get("publication"), value.get("events"), errors)
            if state is not None:
                derived["lifecycle"] = state
                if kind == "mirror" and not any("AddMirror" in event for event in value.get("events", []) if isinstance(event, dict)):
                    errors.append({"code": "missing_mirror_event", "path": "input.events", "message": "mirror fixture requires AddMirror"})
    elif kind == "source-collision":
        records = value.get("records")
        if not isinstance(records, list) or not records:
            errors.append({"code": "invalid_records", "path": "input.records", "message": "records must be a non-empty array"})
        else:
            seen: dict[tuple[str, tuple[str, str, str]], str] = {}
            for index, item in enumerate(records):
                entry = _record_entry(item, f"input.records[{index}]", errors)
                if entry is None:
                    continue
                index_id, publication = entry
                key = (index_id, _coord(publication))
                previous = seen.get(key)
                if previous is not None and previous != publication["publication_digest"]:
                    errors.append({"code": "equivocation", "path": f"input.records[{index}]", "message": "same source coordinate has conflicting digests"})
                seen[key] = publication["publication_digest"]
            attempt = value.get("attempt")
            if attempt is not None:
                entry = _record_entry(attempt, "input.attempt", errors)
                if entry is not None:
                    index_id, publication = entry
                    key = (index_id, _coord(publication))
                    if key in seen and seen[key] != publication["publication_digest"]:
                        errors.append({"code": "equivocation", "path": "input.attempt", "message": "same source coordinate has conflicting digest"})
    elif kind == "resolution":
        source = value.get("source")
        if not _validate_source(source, "input.source", errors):
            source = None
        lock = value.get("lock")
        if not _validate_lock(lock, "input.lock", errors):
            lock = None
        elif isinstance(source, dict):
            assert isinstance(lock, dict)
            if lock["index_id"] != source["index_id"]:
                errors.append({"code": "lock_source_mismatch", "path": "input.lock.index_id", "message": "lock is bound to another source"})
            if lock["trust_root"] != source["root_fingerprint"]:
                errors.append({"code": "lock_root_mismatch", "path": "input.lock.trust_root", "message": "lock trust root differs from source root"})
        candidates = value.get("candidates", [])
        if not isinstance(candidates, list):
            errors.append({"code": "invalid_candidates", "path": "input.candidates", "message": "candidates must be an array"})
        else:
            for index, item in enumerate(candidates):
                entry = _record_entry(item, f"input.candidates[{index}]", errors)
                if entry is None:
                    continue
                index_id, publication = entry
                if isinstance(source, dict) and index_id != source["index_id"]:
                    errors.append({"code": "cross_index_fallback", "path": f"input.candidates[{index}].index_id", "message": "candidate is from another source"})
                if isinstance(lock, dict) and index_id == lock["index_id"]:
                    artifact = publication["artifact"]
                    package = publication["package"]
                    if (
                        publication["coordinate"] != lock["coordinate"]
                        or publication["version"] != lock["version"]
                        or publication["publication_digest"] != lock["publication_digest"]
                        or artifact["digests"] != lock["artifact_digests"]
                        or artifact["size"] != lock["artifact_size"]
                        or artifact["media_type"] != lock["artifact_media_type"]
                        or package["manifest_digest"] != lock["manifest_digest"]
                        or package["component_digest"] != lock["component_digest"]
                        or package["wit_digest"] != lock["wit_digest"]
                        or package["capability_digest"] != lock["capability_digest"]
                        or package["ipc_digest"] != lock["ipc_digest"]
                        or package["runtime_abi_digest"] != lock["runtime_abi_digest"]
                        or package["dependency_digest"] != lock["dependency_digest"]
                        or publication["provenance"]["statement_digest"] != lock["provenance_digest"]
                        or publication["source"]["source_digest"] != lock["source_digest"]
                    ):
                        errors.append({"code": "lock_record_mismatch", "path": f"input.candidates[{index}]", "message": "candidate does not match complete lock binding"})
    elif kind == "event-envelope":
        event_input = value
        publication = event_input.get("publication")
        if not _validate_publication(publication, "input.publication", errors):
            publication = None
        envelopes = event_input.get("envelopes")
        if not isinstance(envelopes, list) or not envelopes:
            errors.append({"code": "invalid_envelopes", "path": "input.envelopes", "message": "envelopes must be a non-empty array"})
        elif isinstance(publication, dict):
            prior_digest: str | None = None
            for index, envelope in enumerate(envelopes):
                digest = _validate_envelope(envelope, index, publication, prior_digest, errors)
                if digest is not None:
                    prior_digest = digest
    elif kind == "tuf":
        _validate_tuf(value.get("tuf"), errors)
    return errors, derived


def _relative_fixture_files(root: Path) -> tuple[list[Path], list[dict[str, str]]]:
    errors: list[dict[str, str]] = []
    if ".." in root.parts:
        return [], [{"code": "traversal_rejected", "path": str(root), "message": "fixture root path contains traversal"}]
    if root.is_symlink():
        return [], [{"code": "symlink_rejected", "path": str(root), "message": "fixture root may not be a symlink"}]
    if not root.exists() or not root.is_dir():
        return [], [{"code": "fixture_root_missing", "path": str(root), "message": "fixture root must be a directory"}]
    root = root.resolve()
    files: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        dirnames.sort()
        filenames.sort()
        for dirname in list(dirnames):
            child = directory_path / dirname
            if child.is_symlink():
                errors.append({"code": "symlink_rejected", "path": str(child.relative_to(root)), "message": "fixture directories may not be symlinks"})
                dirnames.remove(dirname)
        for filename in filenames:
            child = directory_path / filename
            relative = child.relative_to(root)
            if any(part in {"", ".", ".."} for part in relative.parts):
                errors.append({"code": "traversal_rejected", "path": str(relative), "message": "fixture path contains traversal"})
                continue
            if child.is_symlink():
                errors.append({"code": "symlink_rejected", "path": str(relative), "message": "fixture files may not be symlinks"})
                continue
            if child.suffix != ".json":
                continue
            try:
                stat = child.stat()
            except OSError as exc:
                errors.append({"code": "fixture_stat_failed", "path": str(relative), "message": str(exc)})
                continue
            if not child.is_file():
                errors.append({"code": "fixture_not_file", "path": str(relative), "message": "fixture must be a regular file"})
                continue
            if stat.st_size > MAX_FIXTURE_BYTES:
                errors.append({"code": "fixture_too_large", "path": str(relative), "message": f"fixture exceeds {MAX_FIXTURE_BYTES} bytes"})
                continue
            files.append(child)
            if len(files) > MAX_FIXTURES:
                errors.append({"code": "too_many_fixtures", "path": ".", "message": f"fixture count exceeds {MAX_FIXTURES}"})
                return [], errors
    return files, errors


def _read_fixture(path: Path, root: Path) -> tuple[Any | None, list[dict[str, str]]]:
    errors: list[dict[str, str]] = []
    relative = str(path.relative_to(root))
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_FIXTURE_BYTES + 1)
    except OSError as exc:
        return None, [{"code": "fixture_read_failed", "path": relative, "message": str(exc)}]
    if len(payload) > MAX_FIXTURE_BYTES:
        return None, [{"code": "fixture_too_large", "path": relative, "message": f"fixture exceeds {MAX_FIXTURE_BYTES} bytes"}]
    try:
        return _json_loads(payload), errors
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, _DuplicateKey) as exc:
        return None, [{"code": "invalid_json", "path": relative, "message": str(exc)}]


def _run_external(
    command: Sequence[str],
    fixture: Any,
    timeout: float,
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    if not command:
        return None, {"code": "implementation_command_empty", "path": "implementation", "message": "implementation command is empty"}
    payload = canonical_json(fixture)
    argv = list(command)
    if "--json" not in argv:
        argv.append("--json")
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, ValueError) as exc:
        return None, {"code": "implementation_exec_failed", "path": "implementation", "message": str(exc)}
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    os.set_blocking(process.stdin.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE)
    offset = 0
    deadline = time.monotonic() + timeout
    timed_out = False
    output_error: dict[str, str] | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, mask in events:
                stream = key.fileobj
                if stream is process.stdin and mask & selectors.EVENT_WRITE:
                    if offset < len(payload):
                        try:
                            offset += os.write(process.stdin.fileno(), payload[offset:])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                            continue
                    if offset >= len(payload):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                elif mask & selectors.EVENT_READ:
                    try:
                        chunk = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    if chunk:
                        buffer = streams[stream]
                        if len(buffer) + len(chunk) > MAX_SUBPROCESS_OUTPUT:
                            output_error = {"code": "implementation_output_too_large", "path": "implementation", "message": f"implementation output exceeds {MAX_SUBPROCESS_OUTPUT} bytes"}
                            break
                        buffer.extend(chunk)
                    else:
                        selector.unregister(stream)
            if timed_out or output_error is not None:
                break
    finally:
        selector.close()
    if timed_out or output_error is not None:
        process.kill()
        process.wait()
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        if timed_out:
            return None, {"code": "implementation_timeout", "path": "implementation", "message": f"implementation exceeded {timeout:.3f}s"}
        return None, output_error
    process.wait()
    stdout = bytes(streams[process.stdout])
    stderr = bytes(streams[process.stderr])
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()
    if process.returncode != 0:
        return None, {"code": "implementation_exit", "path": "implementation", "message": f"implementation exited {process.returncode}"}
    try:
        result = _json_loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, _DuplicateKey) as exc:
        return None, {"code": "implementation_invalid_json", "path": "implementation.stdout", "message": str(exc)}
    if not isinstance(result, dict) or not _is_bool(result.get("accepted")):
        return None, {"code": "implementation_protocol", "path": "implementation.stdout", "message": "implementation must return an object with boolean accepted"}
    return result, None


def run(fixtures: Path, implementation: Sequence[str] | None = None, timeout: float = 2.0) -> dict[str, Any]:
    """Run all fixtures and return a deterministic machine-readable result."""

    if timeout <= 0 or timeout > MAX_SUBPROCESS_TIMEOUT:
        return {"ok": False, "fixture_errors": [{"code": "invalid_timeout", "path": "timeout", "message": f"timeout must be in (0, {MAX_SUBPROCESS_TIMEOUT}]"}], "cases": []}
    root = Path(fixtures)
    files, discovery_errors = _relative_fixture_files(root)
    cases: list[dict[str, Any]] = []
    for path in files:
        relative = str(path.relative_to(root.resolve()))
        fixture, read_errors = _read_fixture(path, root.resolve())
        if read_errors:
            cases.append({"path": relative, "ok": False, "errors": read_errors})
            continue
        errors, derived = _validate_fixture(fixture)
        assertions: list[dict[str, str]] = []
        expected = fixture.get("expected", {}) if isinstance(fixture, dict) else {}
        expected_accepted = expected.get("accepted") if isinstance(expected, dict) else None
        actual_accepted = not errors
        expected_codes = expected.get("error_codes") if isinstance(expected, dict) else None
        if isinstance(expected_accepted, bool) and expected_accepted != actual_accepted:
            assertions.append({"code": "expected_acceptance_mismatch", "path": "expected.accepted", "message": f"expected {expected_accepted}, observed {actual_accepted}"})
        if isinstance(expected_codes, list):
            observed_codes = sorted({error["code"] for error in errors})
            if sorted(set(expected_codes)) != observed_codes:
                assertions.append({"code": "expected_error_codes_mismatch", "path": "expected.error_codes", "message": f"expected {sorted(set(expected_codes))}, observed {observed_codes}"})
        if isinstance(expected, dict) and "lifecycle" in expected and "lifecycle" in derived and expected["lifecycle"] != derived["lifecycle"]:
            assertions.append({"code": "lifecycle_mismatch", "path": "expected.lifecycle", "message": "derived lifecycle differs from expected"})
        if isinstance(expected, dict) and "statuses" in expected and "histories" in derived:
            observed_statuses = {name: state["status"] for name, state in derived["histories"].items()}
            if expected["statuses"] != observed_statuses:
                assertions.append({"code": "lifecycle_mismatch", "path": "expected.statuses", "message": "derived lifecycle statuses differ from expected"})
        external: dict[str, Any] | None = None
        if implementation is not None and isinstance(fixture, dict):
            external, external_error = _run_external(implementation, fixture, timeout)
            if external_error is not None:
                assertions.append(external_error)
            elif external is not None and isinstance(expected_accepted, bool) and external["accepted"] != expected_accepted:
                assertions.append({"code": "implementation_acceptance_mismatch", "path": "implementation.accepted", "message": f"expected {expected_accepted}, observed {external['accepted']}"})
        case_ok = not assertions
        case: dict[str, Any] = {
            "case_id": fixture.get("case_id") if isinstance(fixture, dict) else None,
            "path": relative,
            "ok": case_ok,
            "accepted": actual_accepted,
            "errors": errors,
        }
        if assertions:
            case["assertions"] = assertions
        if external is not None:
            case["implementation"] = external
        cases.append(case)
    cases.sort(key=lambda item: item["path"])
    fixture_errors = sorted(discovery_errors, key=lambda item: (item["path"], item["code"]))
    ok = not fixture_errors and all(case["ok"] for case in cases) and bool(cases)
    return {"ok": ok, "fixture_errors": fixture_errors, "cases": cases}


def _default_fixture_root() -> Path:
    return Path(__file__).resolve().parents[1] / "tests" / "capsule-index" / "conformance" / "fixtures"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=_default_fixture_root())
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--implementation", nargs="+", help="implementation command; --json is appended")
    args = parser.parse_args(argv)
    result = run(args.fixtures, args.implementation, args.timeout)
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
