#!/usr/bin/env python3
"""Select one Cargo test executable while preserving compiler diagnostics."""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="exact Cargo target name")
    target = parser.parse_args().target
    paths = []
    for line in sys.stdin:
        message = json.loads(line)
        if message.get("reason") == "compiler-message":
            diagnostic = message["message"]
            sys.stderr.write(diagnostic.get("rendered") or diagnostic["message"] + "\n")
        if (
            message.get("executable")
            and message.get("target", {}).get("name") == target
            and message.get("profile", {}).get("test")
        ):
            paths.append(message["executable"])
    if len(paths) != 1:
        raise SystemExit(f"Expected exactly one test executable for {target}: {paths!r}")
    print(paths[0])


if __name__ == "__main__":
    main()
