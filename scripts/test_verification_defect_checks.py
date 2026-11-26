#!/usr/bin/env python3
"""Unit tests for the edit and result helpers of the defect script."""

from __future__ import annotations

import pathlib
import re
import tempfile
import unittest
from unittest.mock import patch


if __package__:
    from . import verification_defect_checks as checks
else:
    import verification_defect_checks as checks

TEXT = "\n".join(
    [
        "fn first(x: int)",
        "    requires x > 0,",
        "{",
        "    let anchor = 1;",
        "}",
        "",
        "proof fn witness() {",
        "    assert(true);",
        "}",
        "",
    ]
)


class ReplaceOnce(unittest.TestCase):
    def test_replaces_the_single_occurrence(self) -> None:
        self.assertEqual(checks.replace_once("a b a", "b", "c"), "a c a")

    def test_refuses_an_anchor_that_is_not_unique(self) -> None:
        with self.assertRaises(ValueError):
            checks.replace_once("a a", "a", "b")
        with self.assertRaises(ValueError):
            checks.replace_once("a", "b", "c")


class EditFunction(unittest.TestCase):
    def test_scope_includes_the_requires_clause(self) -> None:
        edited = checks.edit_function(TEXT, "first", "    requires x > 0,\n", "")
        self.assertIn("fn first(x: int)\n{", edited)

    def test_scope_ends_at_the_item(self) -> None:
        edited = checks.edit_function(TEXT, "first", "anchor", "other")
        self.assertEqual(edited.count("other"), 1)
        self.assertEqual(edited.count("anchor"), 0)

    def test_refuses_text_absent_from_the_item(self) -> None:
        with self.assertRaises(ValueError):
            checks.edit_function(TEXT, "first", "assert(true);", "")


class ContradictFunction(unittest.TestCase):
    def test_puts_the_assertion_first_in_the_body(self) -> None:
        contradicted = checks.contradict_function(TEXT, "witness")
        self.assertIn("proof fn witness() {\n    assert(false);\n", contradicted)


class Results(unittest.TestCase):
    def test_reads_the_counts(self) -> None:
        self.assertEqual(checks.verified_counts("verification results:: 3 verified, 2 errors\n"), (3, 2))

    def test_no_counts_without_a_result_line(self) -> None:
        self.assertIsNone(checks.verified_counts("error[E0063]: missing field"))

    def test_locates_an_error_by_file_name(self) -> None:
        output = "error: assertion failed\n   --> verification/../crates/astrid-capabilities/src/store/authority.rs:131:13\n"
        self.assertTrue(checks.error_in(output, checks.AUTHORITY))
        self.assertFalse(checks.error_in(output, checks.MODEL))

    def test_same_basename_in_another_module_does_not_count(self) -> None:
        output = "error: assertion failed\n   --> another/module/authority.rs:131:13\n"
        self.assertFalse(checks.error_in(output, checks.AUTHORITY))

    def test_ignores_locations_that_are_not_errors(self) -> None:
        output = "\n".join(
            [
                "note: automatically chose triggers for this expression:",
                "   --> verification/hosted_authority_model.rs:449:5",
                "error: assertion failed",
                "   --> verification/../crates/astrid-capabilities/src/store/authority.rs:131:13",
            ]
        )
        self.assertFalse(checks.error_in(output, checks.MODEL))
        self.assertTrue(checks.error_in(output, checks.AUTHORITY))


class Defects(unittest.TestCase):
    def test_every_defect_applies_to_the_sources(self) -> None:
        for name, relative, defect in checks.defects():
            with self.subTest(defect=name):
                defect((checks.ROOT / relative).read_text())

    def test_each_defect_uses_the_verified_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            relative = pathlib.Path("proof.rs")
            working, baseline = root / "working", root / "baseline"
            working.mkdir()
            (working / relative).write_text("original")
            with patch.object(checks, "INPUTS", [relative]), patch.object(checks, "ROOT", working):
                checks.copy_inputs(working, baseline)
                (working / relative).write_text("later edit")
                def inspect(_verus, tree):
                    self.assertEqual((tree / relative).read_text(), "modified original")
                    return 1, "error: assertion failed\n --> proof.rs:1:1\nverification results:: 0 verified, 1 errors"
                with patch.object(checks, "verify", inspect):
                    self.assertTrue(checks.check_defect("verus", baseline, "snapshot", relative, lambda text: "modified " + text))

    def test_names_are_unique(self) -> None:
        names = [name for name, _, _ in checks.defects()]
        self.assertEqual(len(names), len(set(names)))

    def test_every_bridge_has_a_defect(self) -> None:
        source = (checks.ROOT / checks.MODEL).read_text()
        bridges = re.findall(r"^fn (\w+)\(", source, re.MULTILINE)
        self.assertTrue(bridges)
        changed = set()
        for _, relative, defect in checks.defects():
            if relative != checks.MODEL:
                continue
            edited = defect(source)
            for name in bridges:
                start, closing = checks.item(source, name)
                if source[start:closing] != edited[start:closing]:
                    changed.add(name)
        self.assertEqual(set(bridges), changed)


if __name__ == "__main__":
    unittest.main()
