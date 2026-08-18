from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryTemplateTests(unittest.TestCase):
    def test_template_lint(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "lint_repository_template.py")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_structural_validator_is_clean_without_trust_material(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "index_repository_validate.py"),
                "--root",
                str(ROOT),
                "--json",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
