"""Real Git ancestry regressions for the proposed protected-main import policy."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import check_dco_import_scope as scope
from check_dco import check_commits


class ProtectedMainImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Fixture Author")
        self.git("config", "user.email", "fixture@example.invalid")
        self.base = self.make_commit("base")
        self.main = self.make_commit("previously admitted unsigned main commit")
        self.head = self.make_commit("new unsigned contribution")
        self.git("checkout", "--quiet", self.base)
        self.event = {"pull_request": {
            "base": {"ref": "os/universal", "sha": self.base,
                     "repo": {"full_name": scope.REPOSITORY}},
            "head": {"sha": self.head, "repo": {"full_name": scope.REPOSITORY}},
        }}
        self.branch = {"name": "main", "protected": True, "commit": {"sha": self.main}}
        self.payload = [self.metadata(self.main), self.metadata(self.head)]

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], text=True, stderr=subprocess.DEVNULL
        ).strip()

    def make_commit(self, message):
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def metadata(self, sha, signed=False):
        message = "fixture"
        if signed:
            message += "\n\nSigned-off-by: Fixture Author <fixture@example.invalid>"
        return {"sha": sha, "parents": [{}], "author": None,
                "commit": {"author": {"email": "fixture@example.invalid"}, "message": message}}

    def resolve(self, *, event=None, branch=None, fail_fetch=False, fail_api=False):
        original = scope._run
        branch = self.branch if branch is None else branch

        def run(args):
            if args[0] == "gh":
                return subprocess.CompletedProcess(args, int(fail_api), json.dumps(branch), "")
            if "fetch" in args:
                self.assertIn(f"https://github.com/{scope.REPOSITORY}.git", args)
                self.assertEqual(args[-2:], [branch["commit"]["sha"],
                                            (event or self.event)["pull_request"]["head"]["sha"]])
                return subprocess.CompletedProcess(args, int(fail_fetch), "", "")
            return original(args)

        with patch.object(scope, "_run", side_effect=run):
            return scope.protected_main_imports(self.payload, event or self.event, self.repo)

    def test_only_previously_admitted_ancestor_is_excluded(self):
        result = self.resolve()
        self.assertEqual(result.main_sha, self.main)
        self.assertEqual(result.imported, frozenset([self.main]))
        remaining = [c for c in self.payload if c["sha"] not in result.imported]
        self.assertIn(self.head[:12], check_commits(remaining)[0])

    def test_new_signed_contribution_passes_after_old_history_import(self):
        self.payload[-1] = self.metadata(self.head, signed=True)
        result = self.resolve()
        self.assertEqual(check_commits([c for c in self.payload if c["sha"] not in result.imported]), [])

    def test_similar_message_or_author_does_not_exempt_new_commit(self):
        self.payload[-1]["commit"] = copy.deepcopy(self.payload[0]["commit"])
        result = self.resolve()
        self.assertNotIn(self.head, result.imported)

    def test_side_branch_not_in_main_stays_subject_to_dco(self):
        self.git("checkout", "--quiet", self.base)
        side = self.make_commit("unsigned side branch")
        self.git("checkout", "--quiet", self.base)
        self.event["pull_request"]["head"]["sha"] = side
        self.payload = [self.metadata(side)]
        self.assertEqual(self.resolve().imported, frozenset())
        self.assertTrue(check_commits(self.payload))

    def test_unreachable_metadata_is_rejected(self):
        self.git("checkout", "--quiet", self.base)
        unrelated = self.make_commit("not in PR")
        self.git("checkout", "--quiet", self.base)
        self.payload.append(self.metadata(unrelated))
        with self.assertRaisesRegex(ValueError, "not reachable"):
            self.resolve()

    def test_main_target_and_fork_receive_no_exception_or_api_call(self):
        for target, repository in [("main", scope.REPOSITORY), ("os/universal", "attacker/fork")]:
            event = copy.deepcopy(self.event)
            event["pull_request"]["base"]["ref"] = target
            event["pull_request"]["head"]["repo"]["full_name"] = repository
            with self.subTest(target=target, repository=repository), patch.object(scope, "_run") as run:
                result = scope.protected_main_imports(self.payload, event, self.repo)
                self.assertEqual(result.imported, frozenset())
                run.assert_not_called()
            self.assertTrue(check_commits(self.payload))

    def test_base_checkout_must_match_authenticated_event(self):
        self.git("checkout", "--quiet", self.head)
        with self.assertRaisesRegex(ValueError, "trusted base checkout"):
            self.resolve()

    def test_unprotected_or_malformed_main_fails_closed(self):
        for protected in (False, "true", None):
            branch = copy.deepcopy(self.branch)
            branch["protected"] = protected
            with self.subTest(protected=protected), self.assertRaisesRegex(ValueError, "must be protected"):
                self.resolve(branch=branch)
        branch = copy.deepcopy(self.branch)
        branch["commit"]["sha"] = "refs/heads/main"
        with self.assertRaisesRegex(ValueError, "exact lowercase"):
            self.resolve(branch=branch)

    def test_api_or_fetch_failure_fails_closed(self):
        for kwargs in ({"fail_api": True}, {"fail_fetch": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.resolve(**kwargs)

    def test_missing_object_is_not_assumed_to_be_an_ancestor(self):
        self.payload.append(self.metadata("f" * 40))
        with self.assertRaisesRegex(ValueError, "prove commit ancestry"):
            self.resolve()

    def test_arbitrary_ref_and_abbreviated_metadata_are_rejected(self):
        for value in ("HEAD", self.main[:12], "--all", None):
            self.payload[0]["sha"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "exact lowercase"):
                self.resolve()

    def test_truncated_metadata_cannot_omit_unsigned_head(self):
        self.payload.pop()
        with self.assertRaisesRegex(ValueError, "exact PR range"):
            self.resolve()

    def test_duplicate_metadata_is_rejected(self):
        self.payload.append(self.payload[0])
        with self.assertRaisesRegex(ValueError, "duplicate commit"):
            self.resolve()

    def test_merge_dag_keeps_new_side_contribution_subject_to_dco(self):
        side = self.make_commit("new unsigned OS side contribution")
        self.git("-c", "commit.gpgsign=false", "merge", "--quiet", "--no-ff", self.main, "-m", "merge main")
        merge = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", self.base)
        self.event["pull_request"]["head"]["sha"] = merge
        merger = self.metadata(merge)
        merger["parents"] = [{}, {}]
        self.payload = [self.metadata(self.main), self.metadata(side), merger]
        result = self.resolve()
        self.assertEqual(result.imported, frozenset([self.main]))
        remaining = [c for c in self.payload if c["sha"] not in result.imported]
        errors = check_commits(remaining)
        self.assertEqual(len(errors), 1)
        self.assertIn(side[:12], errors[0])
        remaining[0] = self.metadata(side, signed=True)
        self.assertEqual(check_commits(remaining), [])

    def test_failed_ancestry_command_is_not_a_negative_proof(self):
        original = scope._git
        def git(repo, *args):
            if args[:2] == ("merge-base", "--is-ancestor"):
                return subprocess.CompletedProcess(args, 128, "", "")
            return original(repo, *args)
        with patch.object(scope, "_git", side_effect=git), self.assertRaisesRegex(ValueError, "prove commit ancestry"):
            self.resolve()


if __name__ == "__main__":
    unittest.main()
