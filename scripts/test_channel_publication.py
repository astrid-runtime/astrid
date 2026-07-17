#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import channel_publication


def asset(asset_id: int, name: str, *, size: int = 10, state: str = "uploaded") -> dict[str, object]:
    return {"id": asset_id, "name": name, "size": size, "state": state}


class ChannelPublicationTests(unittest.TestCase):
    def test_plans_exact_uploaded_state(self) -> None:
        result = channel_publication.plan(
            "stable",
            8,
            [
                asset(1, "channel-stable-7.tar.gz"),
                asset(2, "channel-stable-8.tar.gz"),
                asset(3, "channel.toml"),
                asset(4, "channel.toml.sigstore.json"),
            ],
        )
        self.assertEqual(result["history-floor"], 8)
        self.assertTrue(result["requested-history-present"])
        self.assertTrue(result["current-pointer-present"])
        self.assertTrue(result["current-bundle-present"])

    def test_nonuploaded_assets_are_scheduled_for_cleanup(self) -> None:
        result = channel_publication.plan(
            "dev",
            1,
            [asset(9, "channel.toml", size=0, state="starter")],
        )
        self.assertEqual(result["cleanup-asset-ids"], [9])
        self.assertFalse(result["current-pointer-present"])

    def test_empty_uploaded_asset_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty"):
            channel_publication.plan("stable", 1, [asset(1, "channel.toml", size=0)])

    def test_unknown_or_missing_asset_state_fails_closed(self) -> None:
        for state in (None, "processing"):
            with self.subTest(state=state):
                entry = asset(1, "channel.toml")
                if state is None:
                    entry.pop("state")
                else:
                    entry["state"] = state
                with self.assertRaisesRegex(ValueError, "state"):
                    channel_publication.plan("stable", 1, [entry])

    def test_duplicate_uploaded_name_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            channel_publication.plan(
                "stable", 1, [asset(1, "channel.toml"), asset(2, "channel.toml")]
            )

    def test_paginated_api_shape_is_flattened(self) -> None:
        item = asset(1, "channel-nightly-7.tar.gz")
        self.assertEqual(
            channel_publication.plan("nightly", 7, [[item]])["uploaded-names"],
            [item["name"]],
        )

    def test_other_channel_history_does_not_raise_floor(self) -> None:
        result = channel_publication.plan(
            "stable", 1, [asset(1, "channel-dev-99.tar.gz")]
        )
        self.assertEqual(result["history-floor"], 0)

    def test_malformed_or_out_of_range_history_fails_closed(self) -> None:
        for name in (
            "channel-stable-01.tar.gz",
            "channel-stable-9223372036854775808.tar.gz",
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "history"):
                    channel_publication.plan("stable", 1, [asset(1, name)])


if __name__ == "__main__":
    unittest.main()
