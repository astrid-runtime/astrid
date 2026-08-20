import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import changelog
from changelog import check_pr, entry_from_fragment, extract_notes, fragment_body_errors, roll_changelog


SAMPLE = """# Changelog

## [Unreleased]

### Fixed

- **Existing fix.**
  Still here. Refs #1.

### Added

- **Existing add.** Closes #2.

## [0.1.0] - 2026-01-01

### Added

- **Historical.** Must not change.
"""


class CheckPrTests(unittest.TestCase):
    def test_code_without_fragment_fails(self):
        errors = check_pr(
            labels=[],
            changed_paths=["crates/astrid-kernel/src/lib.rs"],
            added_paths=[],
        )
        self.assertTrue(errors)
        self.assertIn("changes/{issue}.{kind}.md", errors[0])

    def test_code_with_fragment_passes(self):
        self.assertEqual(
            check_pr(
                labels=[],
                changed_paths=["crates/astrid-kernel/src/lib.rs", "changes/1541.fixed.md"],
                added_paths=["changes/1541.fixed.md"],
            ),
            [],
        )

    def test_skip_label_passes_without_fragment(self):
        self.assertEqual(
            check_pr(
                labels=["skip-changelog"],
                changed_paths=["crates/astrid-kernel/src/lib.rs"],
                added_paths=[],
            ),
            [],
        )

    def test_docs_only_passes_without_fragment(self):
        self.assertEqual(
            check_pr(
                labels=[],
                changed_paths=["CONTRIBUTING.md", ".github/workflows/ci.yml"],
                added_paths=[],
            ),
            [],
        )

    def test_cargo_lock_requires_fragment(self):
        errors = check_pr(labels=[], changed_paths=["Cargo.lock"], added_paths=[])
        self.assertTrue(errors)

    def test_invalid_fragment_name_fails(self):
        errors = check_pr(
            labels=[],
            changed_paths=["docs/guide.md"],
            added_paths=["changes/notes.md"],
        )
        self.assertTrue(errors)
        self.assertIn("name must be", errors[0])

    def test_changelog_md_edit_is_not_enough_for_code(self):
        errors = check_pr(
            labels=[],
            changed_paths=["CHANGELOG.md", "crates/astrid-kernel/src/lib.rs"],
            added_paths=[],
        )
        self.assertTrue(errors)

    def test_code_plus_changelog_and_fragment_still_fails(self):
        errors = check_pr(
            labels=[],
            changed_paths=["CHANGELOG.md", "crates/astrid-kernel/src/lib.rs", "changes/9.fixed.md"],
            added_paths=["changes/9.fixed.md"],
        )
        self.assertTrue(errors)
        self.assertIn("must not edit CHANGELOG.md", errors[0])

    def test_release_skip_allows_changelog_and_cargo(self):
        self.assertEqual(
            check_pr(
                labels=["skip-changelog"],
                changed_paths=["CHANGELOG.md", "Cargo.toml", "Cargo.lock"],
                added_paths=[],
            ),
            [],
        )


    def test_empty_fragment_body_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fragment = root / "9.fixed.md"
            fragment.write_text("\n", encoding="utf-8")
            errors = fragment_body_errors(
                [str(fragment)],
                changes_dir=str(root),
            )
            self.assertTrue(errors)
            self.assertIn("empty", errors[0])


class RollNotesTests(unittest.TestCase):

    def test_entry_wraps_prose_as_bullet(self):
        self.assertEqual(
            entry_from_fragment("**New API.**\nMore detail. Closes #9.\n"),
            "- **New API.**\n  More detail. Closes #9.\n",
        )

    def test_roll_moves_unreleased_and_fragments_without_touching_history(self):
        fragments = [
            (
                Path("changes/9.added.md"),
                "added",
                "**Fragment add.**\nCloses #9.\n",
            )
        ]
        rolled = roll_changelog(SAMPLE, version="0.2.0", date="2026-08-20", fragments=fragments)
        self.assertIn("## [Unreleased]\n\n## [0.2.0] - 2026-08-20\n", rolled)
        self.assertIn("- **Fragment add.**\n  Closes #9.\n", rolled)
        self.assertIn("- **Existing fix.**", rolled)
        _, _, rest = changelog.split_changelog(SAMPLE)
        self.assertTrue(rolled.endswith(rest))
        self.assertIn("## [0.1.0] - 2026-01-01", rest)
        self.assertEqual(rest.count("**Historical.** Must not change."), 1)
        self.assertNotIn("**Historical.** Must not change.", rolled[: rolled.index("## [0.1.0]")])

    def test_notes_match_awk_style_section_body(self):
        rolled = roll_changelog(SAMPLE, version="0.2.0", date="2026-08-20", fragments=[])
        notes = extract_notes(rolled, "0.2.0")
        self.assertIn("### Fixed", notes)
        self.assertIn("### Added", notes)
        self.assertNotIn("## [0.2.0]", notes)
        self.assertNotIn("## [0.1.0]", notes)
        self.assertEqual(extract_notes(SAMPLE, "0.1.0"), "### Added\n\n- **Historical.** Must not change.\n")

    def test_roll_command_deletes_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changelog_path = root / "CHANGELOG.md"
            changes = root / "changes"
            changes.mkdir()
            changelog_path.write_text(SAMPLE, encoding="utf-8")
            fragment = changes / "9.fixed.md"
            fragment.write_text("**Rolled fix.** Closes #9.\n", encoding="utf-8")
            ns = changelog.build_parser().parse_args(
                [
                    "roll",
                    "--version",
                    "0.2.0",
                    "--date",
                    "2026-08-20",
                    "--changelog",
                    str(changelog_path),
                    "--changes-dir",
                    str(changes),
                ]
            )
            self.assertEqual(ns.func(ns), 0)
            self.assertFalse(fragment.exists())
            text = changelog_path.read_text(encoding="utf-8")
            self.assertIn("## [0.2.0] - 2026-08-20", text)
            self.assertIn("**Rolled fix.** Closes #9.", text)
            self.assertTrue(text.split("## [0.1.0]", 1)[1].startswith(" - 2026-01-01"))

    def test_notes_require_rolled_fails_on_pending_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changelog_path = root / "CHANGELOG.md"
            changes = root / "changes"
            changes.mkdir()
            changelog_path.write_text(SAMPLE, encoding="utf-8")
            (changes / "9.fixed.md").write_text("x\n", encoding="utf-8")
            ns = changelog.build_parser().parse_args(
                [
                    "notes",
                    "--version",
                    "0.1.0",
                    "--changelog",
                    str(changelog_path),
                    "--changes-dir",
                    str(changes),
                    "--require-rolled",
                ]
            )
            self.assertEqual(ns.func(ns), 1)


if __name__ == "__main__":
    unittest.main()
