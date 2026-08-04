import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from check_dco import check_commits


def commit(
    email="jamie@example.com",
    message="fix: test\n\nSigned-off-by: Jamie <jamie@example.com>",
    parents=1,
    login=None,
):
    return {
        "sha": "0123456789abcdef",
        "parents": [{} for _ in range(parents)],
        "author": {"login": login} if login else None,
        "commit": {"author": {"email": email}, "message": message},
    }


class CheckDcoTests(unittest.TestCase):
    def test_matching_signoff_passes(self):
        self.assertEqual(check_commits([commit()]), [])

    def test_missing_signoff_fails(self):
        errors = check_commits([commit(message="fix: test")])
        self.assertIn("missing Signed-off-by trailer", errors[0])

    def test_mismatched_signoff_fails(self):
        errors = check_commits(
            [commit(message="fix: test\n\nSigned-off-by: Someone <other@example.com>")]
        )
        self.assertIn("must match the commit author email", errors[0])

    def test_merge_commits_are_ignored(self):
        self.assertEqual(check_commits([commit(message="Merge branch main", parents=2)]), [])

    def test_bot_commits_are_ignored(self):
        self.assertEqual(check_commits([commit(message="chore: update", login="dependabot[bot]")]), [])

    def test_paginated_payload_can_be_nested(self):
        self.assertEqual(check_commits([[commit()]]), [])


if __name__ == "__main__":
    unittest.main()
