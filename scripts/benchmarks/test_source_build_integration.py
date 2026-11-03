"""Drive all benchmark build callers through the real artifact freshness guard."""

import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKING = load("packing_freshness_integration", HERE / "matched_volume_packing.py")
NATIVE = load("native_freshness_integration", HERE / "native250" / "build.py")
EVOLVING = PACKING.evolving_kv
HEAD = "a" * 40


class SourceBuildIntegrationTests(unittest.TestCase):
    def test_each_build_rejects_stale_source_before_freezing_and_accepts_recompiled_source(self):
        for mode in ("packing", "native", "evolving"):
            for fresh in (True, False):
                with self.subTest(mode=mode, fresh=fresh), tempfile.TemporaryDirectory() as raw:
                    root = Path(raw).resolve()
                    checkout, output = root / "producer", root / "evidence"
                    checkout.mkdir()
                    output.mkdir()
                    (checkout / "Cargo.lock").write_text("owned synthetic lock")
                    (checkout / "Cargo.toml").write_text("owned synthetic manifest")
                    (checkout / PACKING.INJECTION).parent.mkdir(parents=True)
                    executable = root / "compiled-binary"
                    executable.write_bytes(b"synthetic optimized executable")
                    package_id = f"path+{checkout.as_uri()}#fixture@0.0.0"
                    preparation = {"checkout": str(checkout), "package_ids": [package_id]}
                    target = output / "cargo-target"
                    expected_name = {"packing": "volume_packing_probe", "native": "astrid",
                                     "evolving": "storage_io"}[mode]
                    event = {"reason": "compiler-artifact", "package_id": package_id,
                             "fresh": fresh, "filenames": [str(executable)], "features": [],
                             "profile": {"opt_level": "3"}, "executable": str(executable),
                             "target": {"name": expected_name, "kind": ["bench"],
                                        "src_path": str(checkout / EVOLVING.BENCH_ROOT / "storage_io.rs")}}
                    started = time.monotonic()
                    process = Mock(pid=999999, wait=Mock(return_value=0))
                    def prepare(path, selected_target, log, env, deadline):
                        self.assertEqual((path, selected_target), (checkout, target))
                        self.assertEqual(env["CARGO_TARGET_DIR"], str(target))
                        self.assertLessEqual(deadline, started + (1200 if mode == "native" else 900) + 1)
                        log.write_text('preparation evidence must survive\n')
                        return preparation
                    def launch(command, **kwargs):
                        kwargs["stdout"].write(json.dumps(event) + "\n")
                        kwargs["stdout"].flush()
                        return process
                    helper = NATIVE.packing.source_build if mode == "native" else PACKING.source_build
                    packing = NATIVE.packing if mode == "native" else PACKING
                    with patch.object(helper, "prepare", side_effect=prepare), \
                            patch.object(packing, "clean_checkout"), \
                            patch.object(packing, "command", return_value=HEAD), \
                            patch.object(packing.subprocess, "Popen", side_effect=launch), \
                            patch.object(EVOLVING, "prepare_overlay", return_value=[]), \
                            patch.object(EVOLVING, "verify_overlay", return_value=[]):
                        def build():
                            if mode == "packing":
                                return PACKING.build(checkout, HEAD, HERE / "volume_packing_probe.rs",
                                                     output, "main", started + 10000)
                            if mode == "native":
                                return NATIVE.cargo_build(checkout, HEAD, ["fixture"], target,
                                                          output / "main-build.jsonl", started + 10000)
                            hooks = {"source_build": helper, "sha": PACKING.sha,
                                     "command": Mock(return_value=HEAD)}
                            return EVOLVING.build(checkout, HEAD, root, {}, output, "main",
                                                  started + 10000, hooks)
                        if fresh:
                            with self.assertRaisesRegex(RuntimeError, "must rebuild"):
                                build()
                            self.assertFalse((output / "main-build.binaries").exists())
                            self.assertFalse((output / "main-probe").exists())
                            self.assertFalse((output / "main-storage-io").exists())
                        else:
                            result = build()
                            self.assertIs(result["source_build"], preparation)
                            self.assertIs(result["artifacts"][0]["fresh"], False)
                    self.assertTrue((output / "main-build.jsonl").read_text().startswith(
                        "preparation evidence must survive\n"))
                    self.assertLessEqual(process.wait.call_args.kwargs["timeout"],
                                         1200 if mode == "native" else 900)


if __name__ == "__main__":
    unittest.main()
