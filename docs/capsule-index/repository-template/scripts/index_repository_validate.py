#!/usr/bin/env python3
"""Structural guardrails for a copyable Capsule Index repository.

This script deliberately does not verify cryptographic signatures.  A pinned
TUF implementation must perform that check before Pages publication.  The
guardrails here make accidental history rewrites, same-coordinate
equivocation, malformed event envelopes, private-key commits, and unsafe file
paths fail closed in pull-request CI.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 32
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
DIGEST_RE = re.compile(r"^(sha256|sha384|sha512|blake3):[0-9a-f]+$")
PRIVATE_CONTENT_RE = re.compile(
    rb"BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY|\"(?:private|secret|signing)[_-]?key\"\s*:"
)
PRIVATE_PATH_RE = re.compile(r"(?:^|/)(?:\.secrets?|root[-_]?keys?|private[-_]?keys?)(?:/|$)|(?:private|secret|signing|root[-_]?key)", re.I)
TRUST_ROLES = ("root", "timestamp", "snapshot", "targets")


class ValidationFailure(Exception):
    """One deterministic structural validation failure."""

    def __init__(self, code: str, path: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.message = message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValidationFailure("json_depth", "$", f"JSON nesting exceeds {MAX_JSON_DEPTH}")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValidationFailure("json_key", "$", "JSON object key is not text")
            _depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _depth(child, depth + 1)


def _loads(path: Path, relative: str) -> Any:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValidationFailure("read_failed", relative, str(exc)) from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValidationFailure("file_too_large", relative, f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationFailure("invalid_json", relative, str(exc)) from exc
    _depth(value)
    return value


def _git(root: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True
    )
    if process.returncode != 0:
        raise ValidationFailure("git_failed", "git", process.stderr.strip() or "git command failed")
    return process.stdout


def _files(root: Path) -> list[Path]:
    try:
        output = _git(root, "ls-files", "-co", "--exclude-standard", "-z")
    except ValidationFailure:
        output = "\0".join(str(path.relative_to(root)) for path in root.rglob("*"))
    paths: list[Path] = []
    for raw in output.split("\0"):
        if not raw:
            continue
        relative = Path(raw)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValidationFailure("path_traversal", raw, "repository path contains traversal")
        path = root / relative
        if path.is_symlink():
            raise ValidationFailure("symlink_rejected", raw, "repository files may not be symlinks")
        if path.is_file():
            paths.append(path)
    return sorted(paths, key=lambda path: str(path.relative_to(root)))


def _private_key_scan(root: Path, paths: Iterable[Path]) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    for path in paths:
        relative = str(path.relative_to(root))
        if PRIVATE_PATH_RE.search(relative):
            failures.append(ValidationFailure("private_key_path", relative, "private/root key material must remain offline"))
            continue
        try:
            sample = path.read_bytes()[:MAX_FILE_BYTES]
        except OSError as exc:
            failures.append(ValidationFailure("read_failed", relative, str(exc)))
            continue
        if PRIVATE_CONTENT_RE.search(sample):
            failures.append(ValidationFailure("private_key_content", relative, "private/signing key material is not committable"))
    return failures


def _changed_paths(root: Path, base_ref: str | None, head_ref: str | None) -> list[tuple[str, str]]:
    if not base_ref or not head_ref:
        return []
    output = _git(root, "diff", "--name-status", "--no-renames", base_ref, head_ref, "--")
    changes: list[tuple[str, str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        status, _, relative = line.partition("\t")
        changes.append((status[:1], relative))
    return changes


def _publication(value: Any, path: str) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("publication"), dict):
        value = value["publication"]
    if not isinstance(value, dict):
        raise ValidationFailure("publication_object", path, "publication must be an object")
    required = {"index_id", "coordinate", "version", "publication_digest"}
    missing = sorted(required - value.keys())
    if missing:
        raise ValidationFailure("publication_field", path, f"missing fields: {', '.join(missing)}")
    index_id = value["index_id"]
    if not isinstance(index_id, str) or not INDEX_RE.fullmatch(index_id) or index_id in {".", ".."}:
        raise ValidationFailure("invalid_index_id", f"{path}.index_id", "invalid lower-case index id")
    coordinate = value["coordinate"]
    if not isinstance(coordinate, dict) or set(coordinate) != {"namespace", "name"}:
        raise ValidationFailure("coordinate_shape", f"{path}.coordinate", "coordinate must contain namespace and name")
    for field in ("namespace", "name"):
        item = coordinate[field]
        if not isinstance(item, str) or not NAME_RE.fullmatch(item):
            raise ValidationFailure("invalid_name", f"{path}.coordinate.{field}", "invalid lower-case name")
    version = value["version"]
    if not isinstance(version, str) or "+" in version or not SEMVER_RE.fullmatch(version):
        raise ValidationFailure("invalid_version", f"{path}.version", "invalid canonical SemVer")
    digest = value["publication_digest"]
    if not isinstance(digest, str) or not digest.startswith("blake3:") or not DIGEST_RE.fullmatch(digest) or len(digest.split(":", 1)[1]) != 64:
        raise ValidationFailure("invalid_digest", f"{path}.publication_digest", "publication digest must be tagged blake3")
    return value


def _publication_key(value: Any, path: str) -> None:
    if not isinstance(value, dict) or set(value) != {"index_id", "coordinate", "version"}:
        raise ValidationFailure("event_publication_key", path, "event publication key must contain index_id, coordinate, and version")
    index_id = value["index_id"]
    if not isinstance(index_id, str) or not INDEX_RE.fullmatch(index_id) or index_id in {".", ".."}:
        raise ValidationFailure("invalid_index_id", f"{path}.index_id", "invalid lower-case index id")
    coordinate = value["coordinate"]
    if not isinstance(coordinate, dict) or set(coordinate) != {"namespace", "name"}:
        raise ValidationFailure("coordinate_shape", f"{path}.coordinate", "coordinate must contain namespace and name")
    for field in ("namespace", "name"):
        if not isinstance(coordinate[field], str) or not NAME_RE.fullmatch(coordinate[field]):
            raise ValidationFailure("invalid_name", f"{path}.coordinate.{field}", "invalid lower-case name")
    if not isinstance(value["version"], str) or not SEMVER_RE.fullmatch(value["version"]) or "+" in value["version"]:
        raise ValidationFailure("invalid_version", f"{path}.version", "invalid canonical SemVer")


def _records(root: Path, paths: Iterable[Path]) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    occupied: dict[tuple[str, str, str, str], str] = {}
    for path in paths:
        relative = str(path.relative_to(root))
        if not relative.startswith("records/") or path.suffix != ".json":
            continue
        try:
            value = _loads(path, relative)
            publication = _publication(value, relative)
        except ValidationFailure as failure:
            failures.append(failure)
            continue
        coordinate = publication["coordinate"]
        key = (publication["index_id"], coordinate["namespace"], coordinate["name"], publication["version"])
        digest = publication["publication_digest"]
        previous = occupied.get(key)
        if previous is not None and previous != digest:
            failures.append(ValidationFailure("equivocation", relative, "same index coordinate has conflicting publication digests"))
        occupied[key] = digest
    return failures


def _events(root: Path, paths: Iterable[Path]) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    prior_by_index: dict[str, str | None] = {}
    next_sequence: dict[str, int] = {}
    for path in paths:
        relative = str(path.relative_to(root))
        if not relative.startswith("events/") or path.suffix != ".json":
            continue
        try:
            value = _loads(path, relative)
        except ValidationFailure as failure:
            failures.append(failure)
            continue
        envelopes = value if isinstance(value, list) else [value]
        for offset, envelope in enumerate(envelopes):
            path_name = f"{relative}[{offset}]" if isinstance(value, list) else relative
            if not isinstance(envelope, dict):
                failures.append(ValidationFailure("event_wire", path_name, "event envelope must be an object"))
                continue
            required = {"schema", "index", "sequence", "recorded_at", "actor", "authorization", "prior_event_digest", "body", "event_digest"}
            if not required.issubset(envelope):
                failures.append(ValidationFailure("event_field", path_name, "event envelope is missing required fields"))
                continue
            if envelope["schema"] != "event-envelope-v1":
                failures.append(ValidationFailure("event_schema", f"{path_name}.schema", "must be event-envelope-v1"))
            index = envelope["index"]
            index_id = index.get("id") if isinstance(index, dict) else None
            if not isinstance(index_id, str) or not INDEX_RE.fullmatch(index_id):
                failures.append(ValidationFailure("event_index", f"{path_name}.index.id", "invalid event index id"))
                continue
            sequence = envelope["sequence"]
            expected = next_sequence.get(index_id, 1)
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence != expected:
                failures.append(ValidationFailure("event_sequence", f"{path_name}.sequence", f"expected contiguous sequence {expected}"))
            next_sequence[index_id] = (sequence + 1) if isinstance(sequence, int) and not isinstance(sequence, bool) else expected
            prior = envelope["prior_event_digest"]
            expected_prior = prior_by_index.get(index_id)
            if (sequence == 1 and prior is not None) or (sequence != 1 and prior != expected_prior):
                failures.append(ValidationFailure("event_chain", f"{path_name}.prior_event_digest", "event chain does not match prior envelope"))
            event_digest = envelope["event_digest"]
            if not isinstance(event_digest, str) or not DIGEST_RE.fullmatch(event_digest) or not event_digest.startswith("blake3:") or len(event_digest.split(":", 1)[1]) != 64:
                failures.append(ValidationFailure("event_digest", f"{path_name}.event_digest", "invalid event digest"))
            prior_by_index[index_id] = event_digest if isinstance(event_digest, str) else expected_prior
            authorization = envelope["authorization"]
            if not isinstance(authorization, dict) or authorization.get("actor") != envelope.get("actor"):
                failures.append(ValidationFailure("event_actor", f"{path_name}.authorization.actor", "authorization actor must match envelope actor"))
            body = envelope["body"]
            if not isinstance(body, dict) or len(body) != 1 or not ("Publication" in body or "NamespaceTransfer" in body):
                failures.append(ValidationFailure("event_body", f"{path_name}.body", "body must be Publication or NamespaceTransfer"))
            elif "Publication" in body:
                publication_body = body["Publication"]
                if isinstance(publication_body, dict) and len(publication_body) == 1:
                    payload = next(iter(publication_body.values()))
                    if isinstance(payload, dict):
                        if payload.get("actor") != envelope.get("actor"):
                            failures.append(ValidationFailure("event_actor", f"{path_name}.body", "body actor must match envelope actor"))
                        try:
                            _publication_key(payload.get("publication"), f"{path_name}.body.Publication")
                        except ValidationFailure as failure:
                            failures.append(failure)
                else:
                    failures.append(ValidationFailure("event_body", f"{path_name}.body.Publication", "publication body must be an externally tagged event"))
    return failures


def _namespaces(root: Path, paths: Iterable[Path]) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    for path in paths:
        relative = str(path.relative_to(root))
        if not relative.startswith("namespaces/") or path.suffix != ".json":
            continue
        try:
            value = _loads(path, relative)
        except ValidationFailure as failure:
            failures.append(failure)
            continue
        claims = value if isinstance(value, list) else [value]
        for index, claim in enumerate(claims):
            claim_path = f"{relative}[{index}]" if isinstance(value, list) else relative
            if not isinstance(claim, dict) or not isinstance(claim.get("namespace"), str) or not NAME_RE.fullmatch(claim["namespace"]):
                failures.append(ValidationFailure("invalid_namespace_claim", claim_path, "namespace claim must use a canonical lower-case namespace"))
            if isinstance(claim, dict) and "reserved_authority" in claim and claim["reserved_authority"] is not None:
                authority = claim["reserved_authority"]
                if not isinstance(authority, str) or not INDEX_RE.fullmatch(authority):
                    failures.append(ValidationFailure("invalid_namespace_authority", f"{claim_path}.reserved_authority", "reserved authority must be a lower-case index id"))
    return failures


def _signed_metadata(root: Path, metadata_dir: Path) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    for role in TRUST_ROLES:
        candidates = [metadata_dir / f"{role}.json"]
        if role in {"snapshot", "targets"}:
            candidates.extend(sorted(metadata_dir.glob(f"{role}.*.json")))
        path = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
        relative = str(path.relative_to(root)) if path.is_absolute() and path.is_relative_to(root) else str(path)
        if not path.is_file():
            failures.append(ValidationFailure("trust_role_missing", relative, f"{role}.json or versioned {role}.<version>.json is required"))
            continue
        try:
            value = _loads(path, relative)
        except ValidationFailure as failure:
            failures.append(failure)
            continue
        if not isinstance(value, dict) or not isinstance(value.get("signed"), dict) or not isinstance(value.get("signatures"), list) or not value["signatures"]:
            failures.append(ValidationFailure("unsigned_trust_role", relative, "role must contain signed metadata and at least one signature"))
    return failures


def validate(root: Path, base_ref: str | None, head_ref: str | None, require_signed: bool, protected_main: bool, metadata_dir: Path) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    paths = _files(root)
    failures.extend(_private_key_scan(root, paths))
    for status, relative in _changed_paths(root, base_ref, head_ref):
        if relative.startswith(("records/", "events/", "objects/")) and status in {"M", "D"}:
            failures.append(ValidationFailure("append_only_violation", relative, "published records/events/objects may only be added"))
        if relative.startswith("metadata/") and status in {"A", "M", "D"} and not protected_main:
            failures.append(ValidationFailure("metadata_generated_only", relative, "trust-role metadata is generated on protected main"))
    failures.extend(_records(root, paths))
    failures.extend(_events(root, paths))
    failures.extend(_namespaces(root, paths))
    if require_signed or protected_main:
        failures.extend(_signed_metadata(root, metadata_dir))
    return sorted(failures, key=lambda failure: (failure.path, failure.code, failure.message))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref")
    parser.add_argument("--head-ref")
    parser.add_argument("--metadata-dir", type=Path, default=Path("metadata"))
    parser.add_argument("--require-signed-metadata", action="store_true")
    parser.add_argument("--protected-main", action="store_true")
    parser.add_argument("--json", action="store_true", help="emit machine-readable result")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    metadata_dir = args.metadata_dir if args.metadata_dir.is_absolute() else root / args.metadata_dir
    try:
        failures = validate(root, args.base_ref, args.head_ref, args.require_signed_metadata, args.protected_main, metadata_dir)
    except ValidationFailure as failure:
        failures = [failure]
    result = {"ok": not failures, "errors": [failure.as_dict() for failure in failures]}
    if args.json:
        json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
    else:
        for failure in failures:
            print(f"{failure.code}: {failure.path}: {failure.message}", file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
