#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import pathlib
import tempfile
import unittest
from unittest import mock

import channel_metadata
import release_manifest


VERSION = "1.2.3"
COMMIT = "a" * 40
CONTRACTS_COMMIT = "b" * 40
PUBLISHED = "2026-07-16T00:00:00Z"
EXPIRES = "2026-08-15T00:00:00Z"


class ChannelMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        targets = []
        for index, target in enumerate(release_manifest.TARGETS, 1):
            asset = release_manifest.expected_asset(VERSION, target)
            targets.append(
                {
                    "triple": target,
                    "asset": asset,
                    "size": index,
                    "blake3": f"{index:064x}",
                    "sha256": f"{index + 8:064x}",
                    "sigstore-bundle": f"{asset}.sigstore.json",
                }
            )
        manifest = {
            "schema-version": 1,
            "kind": "astrid-release",
            "product": "astrid-runtime",
            "repository": "astrid-runtime/astrid",
            "version": VERSION,
            "tag": f"v{VERSION}",
            "source-commit": COMMIT,
            "release-workflow-identity": (
                "https://github.com/astrid-runtime/astrid/.github/workflows/"
                f"release.yml@refs/tags/v{VERSION}"
            ),
            "contracts": {
                "repository": "astrid-runtime/wit",
                "commit": CONTRACTS_COMMIT,
            },
            "targets": targets,
        }
        self.manifest = self.root / f"astrid-{VERSION}-release.toml"
        self.manifest.write_text(release_manifest.render_manifest(manifest), encoding="utf-8")

    def channel(self, name: str = "stable", generation: int = 1) -> dict[str, object]:
        expires = {
            "stable": EXPIRES,
            "dev": "2026-07-23T00:00:00Z",
            "nightly": "2026-07-18T00:00:00Z",
        }[name]
        with mock.patch.object(channel_metadata, "blake3_file", return_value="f" * 64):
            return channel_metadata.build_channel(
                self.manifest,
                name,
                generation,
                PUBLISHED,
                expires,
            )

    def test_round_trip_is_deterministic(self) -> None:
        rendered = channel_metadata.render_channel(self.channel())
        path = self.root / "channel.toml"
        path.write_text(rendered, encoding="utf-8")
        loaded = channel_metadata.load(path)
        channel_metadata.validate_channel(
            loaded,
            expected_channel="stable",
            now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(channel_metadata.render_channel(loaded), rendered)

    def test_all_three_channels_are_accepted(self) -> None:
        for name in channel_metadata.CHANNELS:
            channel_metadata.validate_channel(self.channel(name))

    def test_stable_rejects_prerelease_version(self) -> None:
        data = self.channel()
        data["release"]["version"] = "1.2.3-rc.1"
        data["release"]["tag"] = "v1.2.3-rc.1"
        data["release"]["metadata-asset"] = "astrid-1.2.3-rc.1-release.toml"
        data["release"]["release-workflow-identity"] = (
            "https://github.com/astrid-runtime/astrid/.github/workflows/"
            "release.yml@refs/tags/v1.2.3-rc.1"
        )
        for target in data["targets"]:
            target["asset"] = target["asset"].replace("astrid-1.2.3-", "astrid-1.2.3-rc.1-")
            target["sigstore-bundle"] = f"{target['asset']}.sigstore.json"
        with self.assertRaisesRegex(ValueError, "stable.*prerelease"):
            channel_metadata.validate_channel(data)

    def test_rejects_unknown_keys_and_scalar_type_confusion(self) -> None:
        extra = self.channel()
        extra["latest"] = True
        with self.assertRaisesRegex(ValueError, "keys differ"):
            channel_metadata.validate_channel(extra)
        for value in (True, 1.0, "1"):
            wrong = self.channel()
            wrong["generation"] = value
            with self.assertRaisesRegex(ValueError, "generation"):
                channel_metadata.validate_channel(wrong)

    def test_rejects_invalid_and_expired_lifetimes(self) -> None:
        backwards = self.channel()
        backwards["expires-at"] = backwards["published-at"]
        with self.assertRaisesRegex(ValueError, "after published-at"):
            channel_metadata.validate_channel(backwards)
        with self.assertRaisesRegex(ValueError, "expired"):
            channel_metadata.validate_channel(
                self.channel(),
                now=dt.datetime(2026, 8, 16, tzinfo=dt.timezone.utc),
            )
        too_long = self.channel("nightly")
        too_long["expires-at"] = "2026-07-18T00:00:01Z"
        with self.assertRaisesRegex(ValueError, "lifetime exceeds"):
            channel_metadata.validate_channel(too_long)
        future = self.channel()
        with self.assertRaisesRegex(ValueError, "future"):
            channel_metadata.validate_channel(
                future,
                now=dt.datetime(2026, 7, 15, 23, 54, tzinfo=dt.timezone.utc),
            )

    def test_rejects_generation_rollback_and_equivocation(self) -> None:
        accepted = self.channel(generation=5)
        with self.assertRaisesRegex(ValueError, "rollback"):
            channel_metadata.enforce_continuity(self.channel(generation=4), accepted)
        equivocation = copy.deepcopy(accepted)
        equivocation["expires-at"] = "2026-08-14T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "equivocation"):
            channel_metadata.enforce_continuity(equivocation, accepted)
        channel_metadata.enforce_continuity(copy.deepcopy(accepted), accepted)
        channel_metadata.enforce_continuity(self.channel(generation=6), accepted)

    def test_rejects_metadata_digest_and_identity_tampering(self) -> None:
        for field, value, message in (
            ("metadata-blake3", "x" * 64, "BLAKE3"),
            (
                "release-workflow-identity",
                "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/heads/main",
                "identity",
            ),
        ):
            data = self.channel()
            data["release"][field] = value
            with self.assertRaisesRegex(ValueError, message):
                channel_metadata.validate_channel(data)

    def test_rejects_noncanonical_target_asset(self) -> None:
        data = self.channel()
        data["targets"][0]["asset"] = "astrid-latest.tar.gz"
        with self.assertRaisesRegex(ValueError, "asset identity"):
            channel_metadata.validate_channel(data)

    def test_generation_is_bounded_for_python_toml_and_rust_i64(self) -> None:
        channel_metadata.validate_channel(
            self.channel(generation=channel_metadata.MAX_GENERATION)
        )
        with self.assertRaisesRegex(ValueError, r"2\^63-1"):
            self.channel(generation=channel_metadata.MAX_GENERATION + 1)

    def test_channel_matches_authenticated_manifest_exactly(self) -> None:
        manifest = release_manifest.load_manifest(self.manifest)
        channel = self.channel(generation=7)
        channel_metadata.validate_channel_manifest(
            channel,
            manifest,
            "f" * 64,
            expected_channel="stable",
            expected_generation=7,
        )

    def test_channel_rejects_different_authenticated_manifest(self) -> None:
        manifest = release_manifest.load_manifest(self.manifest)
        channel = self.channel()
        channel["release"]["source-commit"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "authenticated release manifest"):
            channel_metadata.validate_channel_manifest(channel, manifest, "f" * 64)

    def test_channel_rejects_targets_not_in_authenticated_manifest(self) -> None:
        manifest = release_manifest.load_manifest(self.manifest)
        channel = self.channel()
        channel["targets"][0]["size"] += 1
        with self.assertRaisesRegex(ValueError, "targets do not match"):
            channel_metadata.validate_channel_manifest(channel, manifest, "f" * 64)


if __name__ == "__main__":
    unittest.main()
