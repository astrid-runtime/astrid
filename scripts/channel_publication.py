#!/usr/bin/env python3
"""Plan safe publication against GitHub's release-asset state machine."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


CHANNELS = ("stable", "dev", "nightly")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def flatten_assets(value: object) -> list[object]:
    require(isinstance(value, list), "release assets must be a JSON array")
    flattened: list[object] = []
    for item in value:
        if isinstance(item, list):
            flattened.extend(item)
        else:
            flattened.append(item)
    return flattened


def plan(channel: str, generation: int, value: object) -> dict[str, object]:
    require(channel in CHANNELS, "channel is invalid")
    require(1 <= generation <= (1 << 63) - 1, "generation is invalid")
    uploaded: dict[str, dict[str, object]] = {}
    cleanup: list[int] = []
    for raw in flatten_assets(value):
        require(isinstance(raw, dict), "release asset entry must be an object")
        name = raw.get("name")
        asset_id = raw.get("id")
        state = raw.get("state")
        size = raw.get("size")
        require(isinstance(name, str) and name, "release asset name is invalid")
        require(type(asset_id) is int and asset_id > 0, "release asset id is invalid")
        require(type(size) is int and size >= 0, f"release asset size is invalid for {name}")
        require(
            isinstance(state, str) and state in {"uploaded", "open", "starter"},
            f"release asset state is invalid for {name}",
        )
        if state in {"open", "starter"}:
            cleanup.append(asset_id)
            continue
        require(size > 0, f"uploaded release asset is empty: {name}")
        require(name not in uploaded, f"duplicate uploaded release asset: {name}")
        uploaded[name] = raw

    history_prefix = f"channel-{channel}-"
    history = re.compile(rf"channel-{re.escape(channel)}-([1-9][0-9]{{0,18}})\.tar\.gz")
    generations: list[int] = []
    for name in uploaded:
        if not name.startswith(history_prefix) or not name.endswith(".tar.gz"):
            continue
        match = history.fullmatch(name)
        require(match is not None, f"malformed channel history asset: {name}")
        value = int(match.group(1))
        require(value <= (1 << 63) - 1, f"channel history generation is out of range: {name}")
        generations.append(value)
    generations.sort()
    requested = f"channel-{channel}-{generation}.tar.gz"
    return {
        "cleanup-asset-ids": sorted(cleanup),
        "uploaded-names": sorted(uploaded),
        "history-floor": generations[-1] if generations else 0,
        "requested-history-present": requested in uploaded,
        "current-pointer-present": "channel.toml" in uploaded,
        "current-bundle-present": "channel.toml.sigstore.json" in uploaded,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", choices=CHANNELS, required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    args = parser.parse_args(argv)
    value = json.loads(args.assets.read_text(encoding="utf-8"))
    print(json.dumps(plan(args.channel, args.generation, value), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"channel publication: {error}", file=sys.stderr)
        raise SystemExit(1)
