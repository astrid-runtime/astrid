#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import crate_publication


VERSION = "0.10.0"


def package(
    name: str,
    *dependencies: tuple[str, str | None],
    version: str = VERSION,
    publish: object = None,
) -> dict[str, object]:
    return {
        "id": f"path+file:///{name}#{version}",
        "name": name,
        "version": version,
        "source": None,
        "publish": publish,
        "dependencies": [
            {"name": dependency, "kind": kind, "req": f"^{VERSION}"}
            for dependency, kind in dependencies
        ],
    }


def metadata(*packages: dict[str, object]) -> dict[str, object]:
    return {
        "packages": list(packages),
        "workspace_members": [item["id"] for item in packages],
    }


class CratePublicationTests(unittest.TestCase):
    def test_orders_dependencies_before_dependents(self) -> None:
        value = metadata(
            package("astrid-cli", ("astrid-core", None), ("astrid-build", "build")),
            package("astrid-core"),
            package("astrid-build", ("astrid-core", None)),
        )
        self.assertEqual(
            crate_publication.publication_order(value, VERSION),
            ["astrid-core", "astrid-build", "astrid-cli"],
        )

    def test_private_packages_are_excluded(self) -> None:
        value = metadata(package("astrid-core"), package("astrid-test", publish=[]))
        self.assertEqual(crate_publication.publication_order(value, VERSION), ["astrid-core"])

    def test_dev_dependency_does_not_create_publication_cycle(self) -> None:
        value = metadata(
            package("astrid-a", ("astrid-b", "dev")),
            package("astrid-b", ("astrid-a", None)),
        )
        self.assertEqual(
            crate_publication.publication_order(value, VERSION),
            ["astrid-a", "astrid-b"],
        )

    def test_rejects_normal_dependency_cycle(self) -> None:
        value = metadata(
            package("astrid-a", ("astrid-b", None)),
            package("astrid-b", ("astrid-a", None)),
        )
        with self.assertRaisesRegex(ValueError, "cycle"):
            crate_publication.publication_order(value, VERSION)

    def test_rejects_version_drift(self) -> None:
        value = metadata(package("astrid-core", version="0.9.4"))
        with self.assertRaisesRegex(ValueError, "not version"):
            crate_publication.publication_order(value, VERSION)

    def test_rejects_internal_requirement_drift(self) -> None:
        value = metadata(package("astrid-a", ("astrid-b", None)), package("astrid-b"))
        value["packages"][0]["dependencies"][0]["req"] = ">=0.9"
        with self.assertRaisesRegex(ValueError, "must pin"):
            crate_publication.publication_order(value, VERSION)


if __name__ == "__main__":
    unittest.main()
