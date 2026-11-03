"""Publication boundary regressions; only private temporary fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("native250_evidence", Path(__file__).parent / "native250" / "evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceTests(unittest.TestCase):
    def test_publication_contains_receipts_and_logs_but_no_private_build_or_home_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            receipt = {"complete": False, "samples": [{"seconds": 1.234}], "failure": "owned failure"}
            raw = json.dumps(receipt).encode()
            (root / "receipt.json").write_bytes(raw)
            for name in ("cargo-target/private.key", "ownership-root/seed/home/keys/runtime.key",
                         "ownership-root/seed/home/astrid.volume", "capsule-dist/private.capsule"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"FAKE_TEST_ONLY_SECRET")
            log = root / "ownership-root" / "seed" / "bootstrap-daemon.log"
            log.write_bytes(b"owned log")
            MODULE.publish(root)
            public = root / "public"
            self.assertEqual((public / "receipt.json").read_bytes(), raw)
            self.assertEqual((public / "ownership-root/seed/bootstrap-daemon.log").read_bytes(), b"owned log")
            self.assertEqual(sorted(str(p.relative_to(public)) for p in public.rglob("*") if p.is_file()),
                             ["manifest.json", "ownership-root/seed/bootstrap-daemon.log", "receipt.json"])

    def test_logs_are_bounded_and_original_identity_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "receipt.json").write_text('{"complete": false}')
            log = root / "capsule-build.log"
            log.write_bytes(b"0123456789")
            with patch.object(MODULE, "LOG_LIMIT", 4), patch.object(MODULE, "TOTAL_LOG_LIMIT", 4):
                manifest = MODULE.publish(root)
            self.assertEqual((root / "public/capsule-build.log").read_bytes(), b"6789")
            self.assertEqual(manifest["logs"][0]["source_sha256"], MODULE.digest(log))
            self.assertTrue(manifest["logs"][0]["tail_only"])
            self.assertEqual(manifest["logs"][0]["source_bytes"], 10)

    def test_symlink_log_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "receipt.json").write_text('{}')
            target = root / "private.key"
            target.write_bytes(b"FAKE_TEST_ONLY_SECRET")
            (root / "capsule-build.log").symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "aliased log"):
                MODULE.publish(root)
            self.assertFalse((root / "public/capsule-build.log").exists())
