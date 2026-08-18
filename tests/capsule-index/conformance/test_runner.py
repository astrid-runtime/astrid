import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parents[3] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
import capsule_index_conformance as conformance  # noqa: E402


FIXTURES = Path(__file__).with_name("fixtures")


class ConformanceRunnerTests(unittest.TestCase):
    def test_checked_vectors_pass(self) -> None:
        result = conformance.run(FIXTURES)
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(len(result["cases"]), 10)
        self.assertEqual(result["fixture_errors"], [])

    def test_publication_digest_uses_known_blake3_vector(self) -> None:
        self.assertEqual(
            conformance._blake3(b"abc").hex(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        )

    def test_publication_fixture_has_rust_wire_golden_digest(self) -> None:
        fixture = json.loads((FIXTURES / "valid-publication.json").read_text(encoding="utf-8"))
        publication = fixture["input"]["publication"]
        self.assertEqual(
            conformance.publication_digest(publication),
            "blake3:12520d71415e6be6e9b6b2d9ba3b032cc44663571961724fa7c309109c0d6618",
        )

    def test_lock_omits_transport_locations(self) -> None:
        fixture = json.loads(
            (FIXTURES / "resolution-no-cross-index-fallback.json").read_text(encoding="utf-8")
        )
        lock = dict(fixture["input"]["lock"])
        lock["artifact_locations"] = [
            "https://github.com/astrid-runtime/hello/releases/download/v1.2.3/hello.capsule"
        ]
        errors: list[dict[str, str]] = []
        self.assertFalse(conformance._validate_lock(lock, "input.lock", errors))
        self.assertEqual(
            [error["code"] for error in errors],
            ["unknown_field"],
        )

    def test_event_envelope_fixture_has_hash_chain_digest(self) -> None:
        fixture = json.loads((FIXTURES / "event-envelope-valid.json").read_text(encoding="utf-8"))
        envelope = fixture["input"]["envelopes"][0]
        self.assertEqual(
            conformance._event_digest(envelope["body"]["Publication"], envelope),
            envelope["event_digest"],
        )

    def test_external_json_mode_is_bounded_and_machine_readable(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import json,sys; x=json.load(sys.stdin); print(json.dumps({'accepted': x['expected']['accepted']}))",
        ]
        result = conformance.run(FIXTURES, implementation=command, timeout=2.0)
        self.assertTrue(result["ok"], result)
        self.assertTrue(all("implementation" in case for case in result["cases"]))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "duplicate.json").write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            result = conformance.run(root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["cases"][0]["errors"][0]["code"], "invalid_json")

    def test_symlink_and_oversized_fixture_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real.json").write_text("{}", encoding="utf-8")
            try:
                (root / "link.json").symlink_to(root / "real.json")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this platform")
            result = conformance.run(root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["fixture_errors"][0]["code"], "symlink_rejected")

    def test_traversal_fixture_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixtures"
            fixture.mkdir()
            (fixture / "ok.json").write_text("{}", encoding="utf-8")
            traversed = fixture / ".." / "fixtures"
            result = conformance.run(traversed)
        # The canonical path is safe after resolution, but the caller-visible
        # path still contains traversal and must be rejected by the runner.
        self.assertFalse(result["ok"])
        self.assertEqual(result["fixture_errors"][0]["code"], "traversal_rejected")

    def test_oversized_fixture_is_rejected_without_loading_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "huge.json").write_bytes(b"{" + b" " * conformance.MAX_FIXTURE_BYTES + b"}")
            result = conformance.run(root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["fixture_errors"][0]["code"], "fixture_too_large")


if __name__ == "__main__":
    unittest.main()
