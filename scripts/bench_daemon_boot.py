#!/usr/bin/env python3
"""Measure cold process boot on a provisioned disposable AOS home.

This is a manual performance regression, not a release certification runner or
CI timing gate. Compare binary sets against the same stopped fixture, CPU count
and capsule inventory. The fixture must contain only astrid.volume when stopped.
No compiler-thread override is supplied. Logs are scoped to this boot, never to
historical readiness messages. --max-seconds is an optional caller-selected bound.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def current_boot_records(text, started_at):
    """Parse timestamped tracing events, not presentation-specific suffixes.

    Stopped volumes restore historical logs at start, so offsets captured in the
    stopped projection cannot exclude that history. Filter parsed event times.
    Pretty-format location/span continuation lines are not independent events.
    """
    for raw in text.splitlines():
        line = re.sub(r'\x1b\[[0-9;]*m', '', raw).strip()
        if line.startswith('{'):
            record = json.loads(line)
            timestamp = record.get('timestamp')
            fields = record.get('fields', {})
            message = fields.get('message', '')
            capsules = fields.get('capsules')
        else:
            match = re.match(r'(\d{4}-\d{2}-\d{2}T\S+)\s+(.*)', line)
            if match is None:
                continue
            timestamp, message = match.groups()
            count = re.search(r'\bcapsules\s*[=:]\s*(\d+)\b', message)
            capsules = int(count.group(1)) if count else None
        if timestamp is None:
            raise ValueError('benchmark requires timestamped daemon events')
        event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if event_time.tzinfo is None:
            raise ValueError('benchmark requires timezone-qualified daemon events')
        if event_time >= started_at:
            yield message, capsules


def assert_boot_inventory(text, started_at, expected):
    records = list(current_boot_records(text, started_at))
    ready = [(message, count) for message, count in records if 'Agent loop ready' in message]
    assert any(count == expected for _, count in ready), ready
    loaded = sum('Registered authority-scoped capsule runtime' in message
                 for message, _ in records)
    assert loaded == expected, loaded
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aos-home', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--capsules', type=int, required=True)
    parser.add_argument('--max-seconds', type=float)
    args = parser.parse_args()
    home, workspace, cli = (p.resolve() for p in (args.aos_home, args.workspace, args.cli))
    runtime = home / 'runtime'
    assert args.capsules > 0 and workspace.is_dir() and cli.is_file()
    assert args.max_seconds is None or args.max_seconds > 0
    assert sorted(p.name for p in runtime.iterdir()) == ['astrid.volume']
    daemon = cli.parent / 'astrid-daemon'
    assert daemon.is_file(), 'co-installed daemon is required for a bound comparison'
    env = dict(os.environ, AOS_HOME=str(home), ASTRID_HOME=str(runtime),
               ASTRID_RUN_DIR=str(home / 'run'), ASTRID_WORKSPACE_STATE_DIR='.aos')
    for key in ('RAYON_NUM_THREADS', 'ASTRID_PRINCIPAL_ID', 'AOS_PRINCIPAL_ID'):
        env.pop(key, None)
    result = {
        'scope': 'manual process-boot benchmark, not release certification',
        'daemon_sha256': hashlib.sha256(daemon.read_bytes()).hexdigest(),
        'available_cpus': os.cpu_count(), 'expected_capsules': args.capsules,
        'max_seconds': args.max_seconds, 'compiler_threads_override': None,
    }
    started_at = datetime.now(timezone.utc)
    timeout = args.max_seconds or 600
    try:
        start = time.monotonic()
        # The daemon inherits launcher output. A PIPE would make communicate()
        # wait for daemon retirement rather than just the start command's exit.
        start_log = workspace / 'boot-benchmark-start.log'
        with start_log.open('wb') as output:
            boot = subprocess.run([str(cli), '--principal', 'default', 'start'],
                                  cwd=workspace, env=env, stdout=output,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        result.update(boot_seconds=time.monotonic() - start, start_exit=boot.returncode)
        assert boot.returncode == 0, start_log.read_text()
        logs = '\n'.join(line for path in (runtime / 'log').glob('*.log')
                         for line in path.read_text().splitlines())
        (workspace / 'boot-benchmark-source.log').write_text(logs + '\n')
        current = [{'message': message, 'capsules': count}
                   for message, count in current_boot_records(logs, started_at)]
        (workspace / 'boot-benchmark-current.log').write_text(
            '\n'.join(json.dumps(record) for record in current) + '\n')
        result['loaded_capsules'] = assert_boot_inventory(logs, started_at, args.capsules)
        if args.max_seconds is not None:
            assert result['boot_seconds'] <= args.max_seconds
    finally:
        stopped = subprocess.run([str(cli), 'stop'], cwd=workspace, env=env,
                                 capture_output=True, text=True, timeout=90)
        (workspace / 'boot-benchmark-stop.log').write_text(stopped.stdout + stopped.stderr)
        result['stop_exit'] = stopped.returncode
        result['stopped_root'] = sorted(p.name for p in runtime.iterdir())
        (workspace / 'boot-benchmark.json').write_text(json.dumps(result, indent=2) + '\n')
        assert stopped.returncode == 0 and result['stopped_root'] == ['astrid.volume']
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
