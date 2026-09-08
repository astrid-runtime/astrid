#!/usr/bin/env python3
"""Bind an operator's supervised FSKit attestation to one release archive.

This validates evidence identity, not physical execution. The protected release
reviewer attests the local checks; GitHub retains that review and this receipt.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


CHECKS = {
    "apple_trust", "installed_app_bytes", "provider_identity", "mount",
    "write_rename_read", "sync", "delete_sync", "unmount", "stop",
}
TARGET = "aarch64-apple-darwin"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def manifest(directory, source, run_id, attempt):
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid source commit")
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", attempt):
        raise ValueError("invalid run identity")
    archives = list(Path(directory).iterdir())
    if len(archives) != 1:
        raise ValueError("expected exactly one release archive")
    archive = archives[0]
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("archive must be a regular file")
    if not re.fullmatch(r"astrid-[0-9][0-9A-Za-z.+-]*-aarch64-apple-darwin\.tar\.gz", archive.name):
        raise ValueError("unexpected Darwin archive name")
    return {"schema": 1, "source_commit": source, "run_id": run_id,
            "run_attempt": attempt, "target": TARGET, "archive": archive.name,
            "archive_sha256": sha256(archive)}


def approved_receipt(expected, reviews):
    for review in reviews:
        if review.get("state") != "approved":
            continue
        if review.get("user", {}).get("login") != "joshuajbouw":
            continue
        if not any(env.get("name") == "release" for env in review.get("environments", [])):
            continue
        try:
            receipt = json.loads(review.get("comment", ""))
        except (ValueError, TypeError):
            continue
        if not isinstance(receipt, dict):
            continue
        if set(receipt) != set(expected) | {"result", "checks"}:
            continue
        if any(receipt.get(key) != value for key, value in expected.items()):
            continue
        if receipt.get("result") != "PASS":
            continue
        checks = receipt.get("checks")
        if not isinstance(checks, dict) or set(checks) != CHECKS:
            continue
        if not all(value is True for value in checks.values()):
            continue
        return receipt
    raise ValueError("no protected operator approval matches this archive, run attempt and complete PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("manifest")
    for name in ("directory", "source", "run_id", "attempt"):
        build.add_argument(name)
    verify = commands.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("reviews", type=Path)
    args = parser.parse_args()
    if args.command == "manifest":
        result = manifest(args.directory, args.source, args.run_id, args.attempt)
    else:
        result = approved_receipt(json.loads(args.manifest.read_text()), json.loads(args.reviews.read_text()))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
