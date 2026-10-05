#!/usr/bin/env python3
"""Regressions for manual boot evidence across supported tracing formats."""

from datetime import datetime, timezone
import json
import unittest

from bench_daemon_boot import assert_boot_inventory


class BootInventoryTests(unittest.TestCase):
    started = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
    old = '2026-10-05T11:59:59.000000Z'
    fresh = '2026-10-05T12:00:01.000000Z'
    registered = 'Registered authority-scoped capsule runtime'
    ready = 'Agent loop ready — a capsule subscribes the prompt topic'

    def test_json_filters_restored_history_and_reads_structured_count(self):
        def event(stamp, message, **fields):
            return json.dumps({'timestamp': stamp, 'fields': {'message': message, **fields}})
        logs = '\n'.join([
            event(self.old, self.registered), event(self.old, self.ready, capsules=22),
            event(self.fresh, self.registered), event(self.fresh, self.ready, capsules=1),
        ])
        self.assertEqual(assert_boot_inventory(logs, self.started, 1), 1)
        with self.assertRaises(AssertionError):
            assert_boot_inventory(logs, self.started, 22)

    def test_compact_full_and_pretty_do_not_require_final_field(self):
        for separator in ('=', ': '):
            with self.subTest(separator=separator):
                logs = '\n'.join([
                    f'{self.old} INFO {self.registered}',
                    f'  {self.fresh} \x1b[32mINFO\x1b[0m astrid: {self.registered}',
                    '    at crates/astrid-capsule/src/registry.rs:295',
                    f'  {self.fresh} INFO astrid: {self.ready}, capsules{separator}1, other=2',
                ])
                self.assertEqual(assert_boot_inventory(logs, self.started, 1), 1)

    def test_duplicate_registration_and_missing_ready_fail(self):
        loaded = f'{self.fresh} INFO {self.registered}'
        ready = f'{self.fresh} INFO {self.ready} capsules=1'
        for logs in (loaded, '\n'.join([loaded, loaded, ready])):
            with self.assertRaises(AssertionError):
                assert_boot_inventory(logs, self.started, 1)

    def test_json_without_timestamp_cannot_certify_a_boot(self):
        with self.assertRaisesRegex(ValueError, 'timestamped'):
            assert_boot_inventory(json.dumps({'fields': {'message': self.ready, 'capsules': 1}}),
                                  self.started, 1)


if __name__ == '__main__':
    unittest.main()
