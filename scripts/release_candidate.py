#!/usr/bin/env python3
"""Validate and stage a dev release candidate from its canonical source version."""

import argparse
from pathlib import Path

import nightly_version
import release_manifest


def validate(root: Path, version: str) -> None:
    if not release_manifest.is_release_candidate(version):
        raise ValueError("release candidate must be X.Y.Z-rc.N with N positive")
    if version.split("-rc.", 1)[0] != nightly_version.source_version(root):
        raise ValueError("release candidate base must match the workspace source version")


def stage(root: Path, version: str) -> None:
    validate(root, version)
    nightly_version.stage_workspace_version(root, version)


def validate_tag(root: Path, version: str) -> None:
    release_manifest.validate_channel_version("dev", version)
    if release_manifest.is_release_candidate(version):
        validate(root, version)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "validate-tag", "stage"))
    parser.add_argument("--root", type=Path, default=nightly_version.ROOT)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    {"stage": stage, "validate": validate, "validate-tag": validate_tag}[args.command](args.root, args.version)
