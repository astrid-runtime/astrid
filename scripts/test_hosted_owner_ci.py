#!/usr/bin/env python3
"""Exercise shell enrollment sequencing with an inert CLI, never an authority proof."""
import json
import os
from fnmatch import fnmatchcase
from pathlib import Path
import subprocess
import tempfile
import unittest

from check_campaign_ci_triggers import _event_field_values, _has_event

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts/e2e/hosted-owner-ci.sh"
FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\n')
operation = args[1]
if operation == os.environ.get('FAIL_OPERATION'):
    raise SystemExit(23)
record = {'policy': {'generation': 1}, 'installation': 'isolated', 'artifact': 'exact'}
if operation == 'configure':
    record['policy'] = json.load(open(args[args.index('--policy') + 1]))
    pathlib.Path(os.environ['STATE']).write_text(json.dumps(record))
elif operation == 'challenge':
    record = json.loads(pathlib.Path(os.environ['STATE']).read_text())
    if os.environ.get('MISMATCH'):
        record['installation'] = 'other'
elif operation == 'inspect':
    record = {'enrollment': 'unenrolled'} if os.environ.get('NEGATIVE') else {'enrollment': 'enrolled', 'completion': {'receipt': 'exact'}}
elif args[0] == 'agent':
    if operation == 'list':
        record = [{'name': 'default', 'uid': 'same'}]
    elif os.environ.get('UNEXPECTED_SUCCESS'):
        record = {}
    else:
        print('ownership mutation requires an enrolled authority' if operation == 'delete' else 'principal creation requires a current user delegation', file=sys.stderr)
        raise SystemExit(1)
elif operation == 'provision':
    record = {'status': 'enrolled', 'completion': {'receipt': 'exact'}}
else:
    record = {'packet': operation}
print(json.dumps(record))
'''


class EnrollmentShellTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / 'cli'
        self.fake.write_text(FAKE)
        self.fake.chmod(0o700)
        self.fixture = self.root / 'fixture'
        self.env = dict(os.environ, CALLS=str(self.root / 'calls'), STATE=str(self.root / 'state'))

    def run_helper(self, body, **env):
        return subprocess.run(['bash', '-c', 'set -euo pipefail; source "$1"; ' + body,
                               'test', str(HELPER), str(self.fixture), str(self.fake)],
                              env=dict(self.env, **env), capture_output=True, text=True, timeout=15)

    def calls(self):
        path = self.root / 'calls'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_success_uses_independent_private_keys_and_exact_sequence(self):
        result = self.run_helper('configure_hosted_owner_ci "$2" "$3"; provision_hosted_owner_ci "$2" "$3"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([a[1] for a in self.calls()],
                         ['configure', 'prepare', 'challenge', 'sign-owner', 'authorize', 'provision', 'inspect'])
        self.assertIn('--target-default', self.calls()[0])
        self.assertEqual(self.fixture.stat().st_mode & 0o777, 0o700)
        for role in ['owner', 'deployment']:
            self.assertEqual((self.fixture / f'{role}.key').stat().st_mode & 0o777, 0o600)
            self.assertEqual(len((self.fixture / f'{role}.key').read_bytes()), 32)
        self.assertNotEqual((self.fixture / 'owner.key').read_bytes(), (self.fixture / 'deployment.key').read_bytes())

    def test_changed_context_stops_before_signing(self):
        result = self.run_helper('configure_hosted_owner_ci "$2" "$3"; provision_hosted_owner_ci "$2" "$3"', MISMATCH='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([a[1] for a in self.calls()], ['configure', 'prepare', 'challenge'])

    def test_failed_command_is_not_retried_or_followed(self):
        for operation, expected in [('configure', ['configure']),
                                    ('authorize', ['configure', 'prepare', 'challenge', 'sign-owner', 'authorize'])]:
            with self.subTest(operation=operation):
                self.fixture = self.root / operation
                (self.root / 'calls').unlink(missing_ok=True)
                result = self.run_helper('configure_hosted_owner_ci "$2" "$3"; provision_hosted_owner_ci "$2" "$3"', FAIL_OPERATION=operation)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([a[1] for a in self.calls()], expected)

    def test_existing_fixture_refused_before_cli(self):
        self.fixture.mkdir()
        result = self.run_helper('configure_hosted_owner_ci "$2" "$3"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_unenrolled_refusals_preserve_inspection_and_roster(self):
        result = self.run_helper('assert_unenrolled_hosted_owner_ci "$2" "$3"', NEGATIVE='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        claim = next(a for a in self.calls() if a[:2] == ['agent', 'claim'])
        self.assertEqual(claim, ['agent', 'claim', 'default'])

    def test_unexpected_mutation_success_is_failure(self):
        result = self.run_helper('assert_unenrolled_hosted_owner_ci "$2" "$3"', NEGATIVE='1', UNEXPECTED_SUCCESS='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([a[1] for a in self.calls()], ['inspect', 'list', 'create'])

    def test_ci_contract_and_upgrade_order(self):
        paths = ['scripts/e2e/hosted-owner-ci.sh', 'scripts/e2e/fixtures/hosted-owner-ci-keys.json']
        for workflow in ['ci.yml', 'runtime-e2e.yml', 'macos-v0104-upgrade.yml']:
            text = (ROOT / '.github/workflows' / workflow).read_text()
            for event in ['push', 'pull_request']:
                with self.subTest(workflow=workflow, event=event):
                    self.assertTrue(_has_event(text, event))
                    patterns = _event_field_values(text, event, 'paths')
                    for path in paths + ([] if workflow == 'macos-v0104-upgrade.yml' else ['scripts/test_hosted_owner_ci.py']):
                        self.assertTrue(patterns is None or any(fnmatchcase(path, pattern) for pattern in patterns),
                                        f'{workflow} {event} does not cover {path}')
        macos = (ROOT / '.github/workflows/macos-v0104-upgrade.yml').read_text()
        old_macos = macos
        for path in paths:
            old_macos = old_macos.replace(f"      - '{path}'\n", '')
        for event in ['push', 'pull_request']:
            old_patterns = _event_field_values(old_macos, event, 'paths')
            for path in paths:
                self.assertFalse(any(fnmatchcase(path, pattern) for pattern in old_patterns),
                                 'old macOS filter negative control unexpectedly covers helper')
        self.assertIn('python3 scripts/test_hosted_owner_ci.py', (ROOT / 'scripts/ci/test-release-contracts.sh').read_text())
        for platform in ['linux', 'macos']:
            script = (ROOT / f'scripts/test_v0104_{platform}_upgrade.sh').read_text()
            configure = script.index('configure_hosted_owner_ci ')
            provision = script.index('provision_hosted_owner_ci ')
            create = script.index('agent create ', provision)
            self.assertLess(configure, provision)
            self.assertLess(provision, create)
            self.assertIn('stop', script[max(0, configure - 100):configure])


if __name__ == '__main__':
    unittest.main()
