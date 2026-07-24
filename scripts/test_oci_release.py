#!/usr/bin/env python3
"""Tests for the Linux amd64 OCI release acquisition contract."""

from __future__ import annotations

import io
import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
import urllib.request
from unittest import mock

import oci_release
import release_manifest


VERSION = "1.2.3"
COMMIT = "a" * 40
TARGET = oci_release.TARGET


def release_asset(name: str, *, size: int = 7, digest: str | None = None) -> dict[str, object]:
    digest = digest or f"sha256:{'b' * 64}"
    return {
        "name": name,
        "state": "uploaded",
        "size": size,
        "digest": digest,
        "browser_download_url": (
            f"https://github.com/{oci_release.REPOSITORY}/releases/download/v{VERSION}/{name}"
        ),
    }


def release(assets: list[dict[str, object]]) -> dict[str, object]:
    return {
        "tag_name": f"v{VERSION}",
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": assets,
    }


def write_archive(path: pathlib.Path, *, unsafe: bool = False, omit: str | None = None) -> None:
    root = f"astrid-{VERSION}-{TARGET}"
    with tarfile.open(path, mode="w:gz") as archive:
        # Match the top-level directory entry emitted by
        # `tar czf "$root.tar.gz" "$root"` in the release workflow.
        directory = tarfile.TarInfo(f"{root}/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for name in (*oci_release.REQUIRED_BINARIES, "README.md"):
            if name == omit:
                continue
            member_name = "../escape" if unsafe and name == "astrid" else f"{root}/{name}"
            content = name.encode()
            member = tarfile.TarInfo(member_name)
            member.mode = 0o755 if name in oci_release.REQUIRED_BINARIES else 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


class ReleaseApiTests(unittest.TestCase):
    def test_requires_immutable_non_draft_release(self) -> None:
        candidate = release([release_asset("asset")])
        oci_release.validate_release(candidate, VERSION)
        candidate["immutable"] = False
        with self.assertRaisesRegex(ValueError, "immutable"):
            oci_release.validate_release(candidate, VERSION)

    def test_rejects_duplicate_asset_names(self) -> None:
        duplicate = release([release_asset("asset"), release_asset("asset")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            oci_release.validate_release(duplicate, VERSION)

    def test_rejects_non_uploaded_asset(self) -> None:
        asset = release_asset("asset")
        asset["state"] = "starter"
        with self.assertRaisesRegex(ValueError, "not uploaded"):
            oci_release.validate_release(release([asset]), VERSION)


class ArchiveTests(unittest.TestCase):
    def test_accepts_exact_release_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "release.tar.gz"
            write_archive(archive)
            oci_release.verify_archive_structure(archive, VERSION)

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "release.tar.gz"
            write_archive(archive, unsafe=True)
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                oci_release.verify_archive_structure(archive, VERSION)

    def test_rejects_missing_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "release.tar.gz"
            write_archive(archive, omit="astrid-daemon")
            with self.assertRaisesRegex(ValueError, "missing required binary"):
                oci_release.verify_archive_structure(archive, VERSION)


class SignatureTests(unittest.TestCase):
    @mock.patch("oci_release.subprocess.run")
    def test_uses_exact_workflow_identity_and_issuer(self, run: mock.Mock) -> None:
        identity = "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/tags/v1.2.3"
        oci_release.verify_sigstore(
            pathlib.Path("payload"),
            pathlib.Path("bundle"),
            identity=identity,
        )
        command = run.call_args.args[0]
        self.assertIn(identity, command)
        self.assertIn(oci_release.ISSUER, command)
        self.assertIn("--use-signed-timestamps", command)
        run.assert_called_once_with(command, check=True)

    @mock.patch("oci_release.subprocess.run")
    def test_invalid_signature_fails_closed(self, run: mock.Mock) -> None:
        run.side_effect = subprocess.CalledProcessError(1, ["cosign"])
        with self.assertRaisesRegex(ValueError, "Sigstore verification failed"):
            oci_release.verify_sigstore(
                pathlib.Path("payload"),
                pathlib.Path("bundle"),
                identity="identity",
            )


class RedirectTests(unittest.TestCase):
    def redirect(
        self,
        source: str,
        destination: str,
        *,
        token: str | None = "secret",
    ) -> urllib.request.Request:
        handler = oci_release.SafeAssetRedirectHandler()
        request = oci_release.request(
            source,
            token=token,
            accept="application/octet-stream",
        )
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            destination,
        )
        self.assertIsNotNone(redirected)
        return redirected

    def test_strips_token_before_allowed_cross_origin_redirect(self) -> None:
        redirected = self.redirect(
            "https://github.com/astrid-runtime/astrid/releases/download/v1.2.3/a.tar.gz",
            "https://release-assets.githubusercontent.com/github-production-release-asset/a",
        )
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_preserves_token_for_same_origin_redirect(self) -> None:
        redirected = self.redirect(
            "https://github.com/astrid-runtime/astrid/releases/download/v1.2.3/a.tar.gz",
            "https://github.com/astrid-runtime/astrid/releases/download/v1.2.3/b.tar.gz",
        )
        self.assertEqual(redirected.get_header("Authorization"), "Bearer secret")

    def test_rejects_redirect_before_requesting_untrusted_host(self) -> None:
        with self.assertRaisesRegex(ValueError, "untrusted host"):
            self.redirect(
                "https://github.com/astrid-runtime/astrid/releases/download/v1.2.3/a.tar.gz",
                "https://attacker.example/a",
            )

    @mock.patch("oci_release.urllib.request.build_opener")
    def test_asset_download_uses_safe_redirect_opener(self, build_opener: mock.Mock) -> None:
        asset = release_asset("payload", size=7)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.headers = {"Content-Length": "7"}
        response.read.side_effect = [b"payload", b""]
        response.geturl.return_value = asset["browser_download_url"]
        opener = mock.MagicMock()
        opener.open.return_value = response
        build_opener.return_value = opener
        asset["digest"] = f"sha256:{hashlib.sha256(b'payload').hexdigest()}"

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / VERSION
            root.mkdir()
            oci_release.download_asset(
                asset,
                root / "payload",
                token="secret",
                max_bytes=1024,
            )

        handler = build_opener.call_args.args[0]
        self.assertIsInstance(handler, oci_release.SafeAssetRedirectHandler)
        sent = opener.open.call_args.args[0]
        self.assertEqual(sent.get_header("Authorization"), "Bearer secret")


class EndToEndAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.asset_root = self.root / "assets"
        self.asset_root.mkdir()
        self.archive_name = f"astrid-{VERSION}-{TARGET}.tar.gz"
        self.manifest_name = f"astrid-{VERSION}-release.toml"
        self.archive_bundle_name = f"{self.archive_name}.sigstore.json"
        self.manifest_bundle_name = f"{self.manifest_name}.sigstore.json"
        self.archive_path = self.asset_root / self.archive_name
        write_archive(self.archive_path)
        self.archive_sha256 = oci_release.sha256_file(self.archive_path)
        self.archive_blake3 = release_manifest.blake3_file(self.archive_path)
        self.manifest = self.make_manifest()
        self.write_fixture()

    def make_manifest(self) -> dict[str, object]:
        targets = []
        for index, triple in enumerate(release_manifest.TARGETS, 1):
            name = release_manifest.expected_asset(VERSION, triple)
            selected = triple == TARGET
            targets.append(
                {
                    "triple": triple,
                    "asset": name,
                    "size": self.archive_path.stat().st_size if selected else index,
                    "blake3": self.archive_blake3 if selected else f"{index:064x}",
                    "sha256": self.archive_sha256 if selected else f"{index + 8:064x}",
                    "sigstore-bundle": f"{name}.sigstore.json",
                }
            )
        return {
            "schema-version": 1,
            "kind": "astrid-release",
            "product": release_manifest.PRODUCT,
            "repository": release_manifest.REPOSITORY,
            "version": VERSION,
            "tag": f"v{VERSION}",
            "source-commit": COMMIT,
            "release-workflow-identity": (
                "https://github.com/astrid-runtime/astrid/.github/workflows/"
                f"release.yml@refs/tags/v{VERSION}"
            ),
            "contracts": {
                "repository": release_manifest.CONTRACTS_REPOSITORY,
                "commit": "c" * 40,
            },
            "targets": targets,
        }

    def write_fixture(self, *, bad_bundle: str | None = None) -> None:
        (self.asset_root / self.manifest_name).write_text(
            release_manifest.render_manifest(self.manifest),
            encoding="utf-8",
        )
        for name in (self.manifest_bundle_name, self.archive_bundle_name):
            (self.asset_root / name).write_text(
                "invalid-bundle" if name == bad_bundle else "valid-bundle",
                encoding="utf-8",
            )

    def api_release(self) -> dict[str, object]:
        names = (
            self.manifest_name,
            self.manifest_bundle_name,
            self.archive_name,
            self.archive_bundle_name,
        )
        assets = []
        for name in names:
            path = self.asset_root / name
            assets.append(
                release_asset(
                    name,
                    size=path.stat().st_size,
                    digest=f"sha256:{oci_release.sha256_file(path)}",
                )
            )
        return release(assets)

    def stage(self) -> pathlib.Path:
        output = self.root / "output"

        def copy_asset(
            asset: dict[str, object],
            destination: pathlib.Path,
            **_: object,
        ) -> None:
            destination.write_bytes((self.asset_root / str(asset["name"])).read_bytes())

        def verify(
            payload: pathlib.Path,
            bundle: pathlib.Path,
            *,
            identity: str,
        ) -> None:
            expected = (
                "https://github.com/astrid-runtime/astrid/.github/workflows/"
                f"release.yml@refs/tags/v{VERSION}"
            )
            if identity != expected or bundle.read_text(encoding="utf-8") != "valid-bundle":
                raise ValueError(f"Sigstore verification failed for {payload.name}")

        with (
            mock.patch.object(oci_release, "fetch_release", return_value=self.api_release()),
            mock.patch.object(oci_release, "download_asset", side_effect=copy_asset),
            mock.patch.object(oci_release, "verify_sigstore", side_effect=verify),
        ):
            oci_release.stage_release(VERSION, COMMIT, output, token="secret")
        return output

    def test_accepts_fully_bound_release_evidence(self) -> None:
        output = self.stage()
        self.assertEqual(
            oci_release.sha256_file(output / "astrid-release.tar.gz"),
            self.archive_sha256,
        )

    def test_rejects_wrong_source_commit_end_to_end(self) -> None:
        self.manifest["source-commit"] = "d" * 40
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "source commit differs"):
            self.stage()

    def test_rejects_wrong_release_workflow_end_to_end(self) -> None:
        path = self.asset_root / self.manifest_name
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                ".github/workflows/release.yml@",
                ".github/workflows/other.yml@",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "workflow identity"):
            self.stage()

    def test_rejects_wrong_archive_digest_end_to_end(self) -> None:
        selected = next(
            target for target in self.manifest["targets"] if target["triple"] == TARGET
        )
        selected["sha256"] = "e" * 64
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "GitHub and signed release manifest"):
            self.stage()

    def test_rejects_invalid_manifest_bundle_end_to_end(self) -> None:
        self.write_fixture(bad_bundle=self.manifest_bundle_name)
        with self.assertRaisesRegex(ValueError, "Sigstore verification failed"):
            self.stage()

    def test_rejects_invalid_archive_bundle_end_to_end(self) -> None:
        self.write_fixture(bad_bundle=self.archive_bundle_name)
        with self.assertRaisesRegex(ValueError, "Sigstore verification failed"):
            self.stage()


class ReceiptTests(unittest.TestCase):
    def test_receipt_serialization_has_no_mutable_channel(self) -> None:
        receipt = {
            "tag": f"v{VERSION}",
            "source-commit": COMMIT,
            "target": TARGET,
        }
        encoded = json.dumps(receipt)
        self.assertNotIn("latest", encoded)
        self.assertNotIn("stable", encoded)
        self.assertNotIn("nightly", encoded)


if __name__ == "__main__":
    unittest.main()
