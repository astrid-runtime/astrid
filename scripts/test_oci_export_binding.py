#!/usr/bin/env python3
"""Tests for exact Docker-image to OCI-export binding."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

import oci_export_binding


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def descriptor(data: bytes, media_type: str, **extra: object) -> dict[str, object]:
    return {"mediaType": media_type, "digest": digest(data), "size": len(data), **extra}


def write_archive(
    path: pathlib.Path,
    *,
    architecture: str = "amd64",
    extra_manifest: bool = False,
    corrupt_config: bool = False,
    corrupt_layer: bool = False,
    corrupt_manifest: bool = False,
    extra_files: dict[str, bytes] | None = None,
    platform_extra: dict[str, str] | None = None,
) -> tuple[str, str]:
    layer = b"layer"
    config = encoded(
        {
            "architecture": architecture,
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [digest(layer)]},
        }
    )
    config_descriptor = descriptor(config, oci_export_binding.CONFIG_MEDIA_TYPE)
    manifest = encoded(
        {
            "schemaVersion": 2,
            "mediaType": oci_export_binding.MANIFEST_MEDIA_TYPE,
            "config": config_descriptor,
            "layers": [descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")],
        }
    )
    manifest_descriptor = descriptor(
        manifest,
        oci_export_binding.MANIFEST_MEDIA_TYPE,
        platform={
            "architecture": architecture,
            "os": "linux",
            **(platform_extra or {}),
        },
    )
    manifests = [manifest_descriptor]
    if extra_manifest:
        manifests.append(manifest_descriptor)
    index = encoded(
        {
            "schemaVersion": 2,
            "mediaType": oci_export_binding.INDEX_MEDIA_TYPE,
            "manifests": manifests,
        }
    )
    blobs = {
        f"blobs/sha256/{digest(manifest).removeprefix('sha256:')}": (
            manifest + b"corrupt" if corrupt_manifest else manifest
        ),
        f"blobs/sha256/{digest(config).removeprefix('sha256:')}": (
            config + b"corrupt" if corrupt_config else config
        ),
        f"blobs/sha256/{digest(layer).removeprefix('sha256:')}": (
            layer + b"corrupt" if corrupt_layer else layer
        ),
    }
    files = {
        "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
        "index.json": index,
        **blobs,
        **(extra_files or {}),
    }
    with tarfile.open(path, mode="w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return digest(config), digest(manifest)


class ExportBindingTests(unittest.TestCase):
    def test_accepts_exact_single_platform_export_and_image_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            config_digest, manifest_digest = write_archive(archive)
            receipt = oci_export_binding.verify_binding(
                archive,
                image_manifest_digest=manifest_digest,
                os_name="linux",
                architecture="amd64",
            )
            self.assertEqual(receipt["config-digest"], config_digest)
            self.assertEqual(receipt["manifest-digest"], manifest_digest)
            self.assertEqual(receipt["platform"], "linux/amd64")

    def test_rejects_loaded_manifest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            write_archive(archive)
            with self.assertRaisesRegex(ValueError, "loaded Docker image manifest differs"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=f"sha256:{'f' * 64}",
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_wrong_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, architecture="arm64")
            with self.assertRaisesRegex(ValueError, "platform is not exact"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_multiple_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, extra_manifest=True)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_tampered_config_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, corrupt_config=True)
            with self.assertRaisesRegex(ValueError, "invalid size|size differs|digest differs"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_tampered_layer_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, corrupt_layer=True)
            with self.assertRaisesRegex(ValueError, "size differs|digest differs"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_tampered_manifest_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, corrupt_manifest=True)
            with self.assertRaisesRegex(ValueError, "size differs|digest differs"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_unreferenced_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, extra_files={"unexpected": b"data"})
            with self.assertRaisesRegex(ValueError, "file inventory is not exact"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_non_canonical_member_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive, extra_files={"./unexpected": b"data"})
            with self.assertRaisesRegex(ValueError, "unsafe or non-canonical"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_unsafe_parent_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(
                archive,
                extra_files={"../escape": b"data"},
            )
            with self.assertRaisesRegex(ValueError, "unsafe or non-canonical"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_duplicate_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(archive)
            duplicate = b"{}"
            with tarfile.open(archive, mode="a") as tar:
                member = tarfile.TarInfo("index.json")
                member.mode = 0o644
                member.size = len(duplicate)
                tar.addfile(member, io.BytesIO(duplicate))
            with self.assertRaisesRegex(ValueError, "duplicate member"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )

    def test_rejects_unexpected_platform_variant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(
                archive,
                platform_extra={"variant": "v8"},
            )
            with self.assertRaisesRegex(ValueError, "platform is not exact"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="amd64",
                )


if __name__ == "__main__":
    unittest.main()
