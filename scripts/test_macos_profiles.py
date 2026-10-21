#!/usr/bin/env python3
"""Credential-free regression coverage for explicit FSKit profile delivery."""

import base64
import copy
import datetime
import importlib.util
from pathlib import Path
import subprocess
import shlex
import plistlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("profiles", ROOT / "scripts/ci/with_macos_profiles.py")
profiles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profiles)


def profile(extension=False):
    return {
        "UUID": "05175eb6-9df0-4611-8a73-6ea0b38aee2e" if extension else "71d3e1c1-4ed8-4adf-8b55-70d3a6521030",
        "TeamIdentifier": [profiles.TEAM],
        "ProvisionsAllDevices": True,
        "ExpirationDate": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
        "Entitlements": {
            "com.apple.application-identifier": f"{profiles.TEAM}.org.astrid.runtime.fs" + (".AppEx" if extension else ""),
            "com.apple.developer.fskit.fsmodule": extension,
        },
    }


class ProfileTests(unittest.TestCase):
    def test_exact_profiles(self):
        for extension in (False, True):
            data = profile(extension)
            bundle = "org.astrid.runtime.fs" + (".AppEx" if extension else "")
            self.assertEqual(profiles.profile_uuid(data, bundle), data["UUID"])

    def test_invalid_profile_refused(self):
        original = profile(True)
        variants = []
        for key, value in (("TeamIdentifier", ["OTHER"]), ("ProvisionsAllDevices", False), ("ExpirationDate", datetime.datetime(2000, 1, 1)), ("UUID", "../escape")):
            variant = copy.deepcopy(original)
            variant[key] = value
            variants.append(variant)
        for key, value in (("com.apple.application-identifier", "wrong"), ("com.apple.developer.fskit.fsmodule", False), ("get-task-allow", True)):
            variant = copy.deepcopy(original)
            variant["Entitlements"][key] = value
            variants.append(variant)
        for variant in variants:
            with self.subTest(profile=variant), self.assertRaises(ValueError):
                profiles.profile_uuid(variant, "org.astrid.runtime.fs.AppEx")

    def environment(self):
        return {f"ASTRID_MACOS_{kind}_PROVISIONING_PROFILE": base64.b64encode(kind.encode()).decode() for kind, _ in profiles.PROFILES}

    def test_install_binding_cleanup_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def command(args, env, check):
                self.assertEqual(args, ["sign-app"])
                self.assertNotIn("ASTRID_MACOS_APP_PROVISIONING_PROFILE", env)
                for kind, _ in profiles.PROFILES:
                    path = directory / (env[f"ASTRID_FSKIT_{kind}_PROFILE"] + ".provisionprofile")
                    self.assertEqual(path.read_bytes(), kind.encode())
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                return subprocess.CompletedProcess(args, 17)
            with patch.object(profiles, "decode_profile", side_effect=lambda data: profile(data == b"EXTENSION")), patch.object(profiles.subprocess, "run", side_effect=command):
                self.assertEqual(profiles.run_with_profiles(["sign-app"], directory, self.environment()), 17)
            self.assertEqual(list(directory.iterdir()), [])

    def test_existing_profiles_preserved_and_conflicts_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            existing = directory / (profile()["UUID"] + ".provisionprofile")
            existing.write_bytes(b"APP")
            with patch.object(profiles, "decode_profile", side_effect=lambda data: profile(data == b"EXTENSION")), patch.object(profiles.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
                profiles.run_with_profiles(["sign-app"], directory, self.environment())
                self.assertEqual(existing.read_bytes(), b"APP")
                existing.write_bytes(b"different")
                run.reset_mock()
                with self.assertRaises(ValueError):
                    profiles.run_with_profiles(["sign-app"], directory, self.environment())
                run.assert_not_called()
                self.assertEqual(existing.read_bytes(), b"different")

    def test_missing_input_does_not_run_command(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(profiles.subprocess, "run") as run:
            with self.assertRaises(KeyError):
                profiles.run_with_profiles(["sign-app"], Path(temporary), {})
            run.assert_not_called()

    def test_release_wiring(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("python3 scripts/ci/with_macos_profiles.py scripts/ci/import_macos_signing.sh", workflow)
        project = (ROOT / "native/macos/AstridFSKit/AstridFS.xcodeproj/project.pbxproj").read_text()
        build = (ROOT / "scripts/build-macos-fskit.sh").read_text()
        self.assertIn("CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO", build)
        for kind, _ in profiles.PROFILES:
            self.assertIn(f"secrets.ASTRID_MACOS_{kind}_PROVISIONING_PROFILE", workflow)
            self.assertEqual(project.count(f'PROVISIONING_PROFILE_SPECIFIER = "$(ASTRID_FSKIT_{kind}_PROFILE)";'), 2)
            self.assertIn(f'ASTRID_FSKIT_{kind}_PROFILE="${{ASTRID_FSKIT_{kind}_PROFILE:-}}"', build)

    def test_signed_entitlement_check_reads_a_pipe(self):
        build = (ROOT / "scripts/build-macos-fskit.sh").read_text()
        line = next(line for line in build.splitlines() if "distribution signature enables get-task-allow" in line)
        command = shlex.split(line.strip())
        for enabled in (False, True):
            result = subprocess.run(command, input=plistlib.dumps({"com.apple.security.get-task-allow": enabled}), capture_output=True)
            self.assertEqual(result.returncode, int(enabled), result.stderr)


if __name__ == "__main__":
    unittest.main()
