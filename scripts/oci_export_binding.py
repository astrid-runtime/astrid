#!/usr/bin/env python3
"""Bind a load-tested Docker image to an exact OCI archive export."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import tarfile


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
MAX_JSON_BYTES = 16 * 1024 * 1024
STRUCTURAL_DIRECTORIES = {"blobs", "blobs/sha256"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(value: object, label: str) -> str:
    require(
        isinstance(value, str) and DIGEST.fullmatch(value) is not None,
        f"{label} digest is invalid",
    )
    return value


def read_regular(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    require(name in members, f"OCI archive is missing {name}")
    member = members[name]
    require(member.isreg(), f"OCI archive member is not regular: {name}")
    require(0 < member.size <= max_bytes, f"OCI archive member has invalid size: {name}")
    source = archive.extractfile(member)
    require(source is not None, f"OCI archive member cannot be read: {name}")
    data = source.read(max_bytes + 1)
    require(
        len(data) == member.size and len(data) <= max_bytes,
        f"OCI archive member size changed: {name}",
    )
    return data


def canonical_member_name(member: tarfile.TarInfo) -> str:
    name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
    pure = pathlib.PurePosixPath(name)
    require(
        bool(name)
        and not pure.is_absolute()
        and ".." not in pure.parts
        and str(pure) == name,
        f"OCI archive has an unsafe or non-canonical member: {member.name}",
    )
    return name


def read_json(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
) -> tuple[dict[str, object], bytes]:
    data = read_regular(archive, members, name, max_bytes=MAX_JSON_BYTES)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"OCI archive member is not valid JSON: {name}") from error
    require(isinstance(value, dict), f"OCI archive JSON is not an object: {name}")
    return value, data


def verify_descriptor(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: object,
    label: str,
    *,
    collect: bool,
    max_bytes: int | None = None,
) -> tuple[str, bytes | None, str]:
    require(isinstance(descriptor, dict), f"{label} descriptor is not an object")
    digest = canonical_digest(descriptor.get("digest"), label)
    size = descriptor.get("size")
    require(
        isinstance(size, int) and not isinstance(size, bool) and size > 0,
        f"{label} size is invalid",
    )
    name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
    require(name in members, f"OCI archive is missing {name}")
    member = members[name]
    require(member.isreg(), f"OCI archive member is not regular: {name}")
    require(member.size == size, f"{label} size differs from its descriptor")
    if max_bytes is not None:
        require(size <= max_bytes, f"{label} is too large")
    source = archive.extractfile(member)
    require(source is not None, f"OCI archive member cannot be read: {name}")
    hasher = hashlib.sha256()
    collected = bytearray() if collect else None
    total = 0
    while chunk := source.read(1024 * 1024):
        total += len(chunk)
        require(total <= size, f"{label} data exceeds its descriptor")
        hasher.update(chunk)
        if collected is not None:
            collected.extend(chunk)
    require(total == size, f"{label} size differs from its descriptor")
    require(f"sha256:{hasher.hexdigest()}" == digest, f"{label} digest differs from its descriptor")
    return digest, bytes(collected) if collected is not None else None, name


def verify_binding(
    path: pathlib.Path,
    *,
    image_manifest_digest: str,
    os_name: str,
    architecture: str,
) -> dict[str, object]:
    loaded_manifest_digest = canonical_digest(image_manifest_digest, "loaded image manifest")
    try:
        archive = tarfile.open(path, mode="r")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("OCI export is not a valid tar archive") from error

    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            require(
                member.isdir() or member.isreg(),
                f"OCI archive has a non-file member: {member.name}",
            )
            name = canonical_member_name(member)
            require(name not in members, f"OCI archive has a duplicate member: {member.name}")
            members[name] = member

        layout, _ = read_json(archive, members, "oci-layout")
        require(layout == {"imageLayoutVersion": "1.0.0"}, "OCI layout version is not exact")
        index, _ = read_json(archive, members, "index.json")
        require(index.get("schemaVersion") == 2, "OCI index schema version is not 2")
        require(index.get("mediaType") == INDEX_MEDIA_TYPE, "OCI index media type is invalid")
        manifests = index.get("manifests")
        require(
            isinstance(manifests, list) and len(manifests) == 1,
            "OCI index must contain exactly one image manifest",
        )
        descriptor = manifests[0]
        require(isinstance(descriptor, dict), "OCI image descriptor is not an object")
        require(
            descriptor.get("mediaType") == MANIFEST_MEDIA_TYPE,
            "OCI image descriptor media type is invalid",
        )
        require(
            descriptor.get("platform") == {"architecture": architecture, "os": os_name},
            "OCI image descriptor platform is not exact",
        )

        manifest_digest, manifest_data, manifest_name = verify_descriptor(
            archive,
            members,
            descriptor,
            "OCI image manifest",
            collect=True,
            max_bytes=MAX_JSON_BYTES,
        )
        require(
            manifest_digest == loaded_manifest_digest,
            "loaded Docker image manifest differs from OCI archive manifest",
        )
        require(manifest_data is not None, "OCI image manifest was not collected")
        try:
            manifest = json.loads(manifest_data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("OCI image manifest is not valid JSON") from error
        require(isinstance(manifest, dict), "OCI image manifest is not an object")
        require(manifest.get("schemaVersion") == 2, "OCI image manifest schema version is not 2")
        require(
            manifest.get("mediaType") == MANIFEST_MEDIA_TYPE,
            "OCI image manifest media type is invalid",
        )

        config_descriptor = manifest.get("config")
        require(isinstance(config_descriptor, dict), "OCI image config descriptor is invalid")
        require(
            config_descriptor.get("mediaType") == CONFIG_MEDIA_TYPE,
            "OCI image config media type is invalid",
        )
        config_digest, config_data, config_name = verify_descriptor(
            archive,
            members,
            config_descriptor,
            "OCI image config",
            collect=True,
            max_bytes=MAX_JSON_BYTES,
        )
        require(config_data is not None, "OCI image config was not collected")
        try:
            config = json.loads(config_data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("OCI image config is not valid JSON") from error
        require(isinstance(config, dict), "OCI image config is not an object")
        require(config.get("os") == os_name, "OCI image config operating system is not exact")
        require(
            config.get("architecture") == architecture,
            "OCI image config architecture is not exact",
        )

        layers = manifest.get("layers")
        require(isinstance(layers, list) and layers, "OCI image has no layers")
        layer_results = [
            verify_descriptor(
                archive,
                members,
                layer,
                f"OCI image layer {index}",
                collect=False,
            )
            for index, layer in enumerate(layers)
        ]
        layer_digests = [result[0] for result in layer_results]
        expected_files = {
            "oci-layout",
            "index.json",
            manifest_name,
            config_name,
            *(result[2] for result in layer_results),
        }
        actual_files = {name for name, member in members.items() if member.isreg()}
        require(actual_files == expected_files, "OCI archive file inventory is not exact")
        actual_directories = {name for name, member in members.items() if member.isdir()}
        require(
            actual_directories.issubset(STRUCTURAL_DIRECTORIES),
            "OCI archive directory inventory is not exact",
        )

    return {
        "schema-version": 1,
        "platform": f"{os_name}/{architecture}",
        "oci-archive": path.name,
        "oci-archive-size": path.stat().st_size,
        "oci-archive-sha256": sha256_file(path),
        "manifest-digest": manifest_digest,
        "config-digest": config_digest,
        "loaded-image-manifest-digest": loaded_manifest_digest,
        "layer-digests": layer_digests,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oci-archive", required=True, type=pathlib.Path)
    parser.add_argument("--image-manifest-digest", required=True)
    parser.add_argument("--os", default="linux")
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    receipt = verify_binding(
        args.oci_archive,
        image_manifest_digest=args.image_manifest_digest,
        os_name=args.os,
        architecture=args.architecture,
    )
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, sort_keys=True)
        output.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
