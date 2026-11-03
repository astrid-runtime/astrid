"""Publication boundary regressions; only private temporary fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

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

    def test_final_save_failure_still_publishes_durable_receipt_and_emits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            durable = '{"complete": false, "stage": "previous"}'
            (root / "receipt.json").write_text(durable)
            receipt = {"complete": True}
            emit = MagicMock()
            error = OSError("disk full")
            with self.assertRaisesRegex(OSError, "disk full"):
                MODULE.finalize(root, receipt, MagicMock(side_effect=error), emit)
            self.assertEqual((root / "public/receipt.json").read_text(), durable)
            self.assertFalse(receipt["complete"])
            self.assertIn("disk full", receipt["final_save_error"])
            emit.assert_called_once_with(receipt)

    def test_finalization_preserves_primary_failure_across_all_evidence_failures(self):
        receipt = {"complete": False}
        primary = TimeoutError("original timeout")
        save = MagicMock(side_effect=OSError("save failed"))
        emit = MagicMock()
        with patch.object(MODULE, "publish", side_effect=OSError("publish failed")) as publish:
            MODULE.finalize(Path("unused"), receipt, save, emit, primary_error=primary)
        self.assertEqual(save.call_count, 2)
        publish.assert_called_once()
        emit.assert_called_once_with(receipt)
        self.assertIn("publish failed", receipt["publication_error"])
        self.assertIn("save failed", receipt["publication_error_save_error"])

    def test_successful_finalization_saves_publishes_then_emits(self):
        receipt = {"complete": True}
        operations = []
        with patch.object(MODULE, "publish", side_effect=lambda _: operations.append("publish")):
            MODULE.finalize(Path("unused"), receipt,
                            lambda: operations.append("save"),
                            lambda value: operations.append(("emit", value.copy())))
        self.assertEqual(operations, ["save", "publish", ("emit", receipt)])

    def test_failed_publication_never_exposes_stale_success_receipt(self):
        for failure in ("alias", "disk-full"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                receipt = {"complete": True}
                def save():
                    (root / "receipt.json").write_text(json.dumps(receipt))
                log = root / "capsule-build.log"
                if failure == "alias":
                    target = root / "excluded"
                    target.write_bytes(b"private")
                    log.symlink_to(target)
                else:
                    log.write_bytes(b"diagnostic")
                original = Path.write_bytes
                def write(path, data):
                    if failure == "disk-full" and path.name == "capsule-build.log":
                        raise OSError("disk full while copying log")
                    return original(path, data)
                with patch.object(Path, "write_bytes", write):
                    with self.assertRaises((OSError, RuntimeError)):
                        MODULE.finalize(root, receipt, save, lambda value: None)
                self.assertFalse(json.loads((root / "receipt.json").read_text())["complete"])
                self.assertFalse((root / "public").exists())
                self.assertEqual(list(root.glob(".publication-*")), [])

    def test_evolving_logs_are_byte_complete_with_matching_manifest_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "receipt.json").write_text('{"complete": true, "mode": "evolving-kv"}')
            logs = [root / "sample-00.stdout", root / "sample-01.report.json"]
            for path, raw in zip(logs, [b"raw stdout", b'{"raw":"report"}'], strict=True):
                path.write_bytes(raw)
            manifest = MODULE.publish(root, logs)
            for path, entry in zip(logs, manifest["logs"], strict=True):
                self.assertEqual((root / "public" / path.name).read_bytes(), path.read_bytes())
                self.assertFalse(entry["tail_only"])
                self.assertEqual(entry["source_bytes"], entry["published_bytes"])
                self.assertEqual(entry["source_sha256"], entry["published_sha256"])

    def test_evolving_per_file_and_aggregate_overflow_fail_without_public_success(self):
        for failure in ("file", "aggregate"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                receipt = {"complete": True, "mode": "evolving-kv"}
                emit = MagicMock()
                def save():
                    (root / "receipt.json").write_text(json.dumps(receipt))
                logs = [root / "sample-00.stdout", root / "sample-01.stdout"]
                original = [b"abcdef" if failure == "file" else b"abcd", b"efgh"]
                for path, data in zip(logs, original, strict=True):
                    path.write_bytes(data)
                with patch.object(MODULE, "LOG_LIMIT", 5), patch.object(MODULE, "TOTAL_LOG_LIMIT", 7):
                    with self.assertRaisesRegex(RuntimeError, "raw evidence exceeds publication bounds"):
                        MODULE.finalize(root, receipt, save, emit, log_paths=logs)
                self.assertFalse(receipt["complete"])
                self.assertIn("raw evidence exceeds publication bounds", receipt["publication_error"])
                self.assertFalse((root / "public").exists())
                self.assertEqual(list(root.glob(".publication-*")), [])
                self.assertEqual([path.read_bytes() for path in logs], original)
                self.assertFalse(json.loads((root / "receipt.json").read_text())["complete"])
                emit.assert_called_once_with(receipt)

    def test_evolving_log_changed_during_copy_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "receipt.json").write_text('{"complete": true, "mode": "evolving-kv"}')
            log = root / "sample-00.stdout"
            log.write_bytes(b"before")
            original_digest = MODULE.digest
            def digest(path):
                if path == log:
                    log.write_bytes(b"changed")
                return original_digest(path)
            with patch.object(MODULE, "digest", side_effect=digest):
                with self.assertRaisesRegex(RuntimeError, "raw evidence changed during publication"):
                    MODULE.publish(root, [log])
            self.assertFalse((root / "public").exists())
