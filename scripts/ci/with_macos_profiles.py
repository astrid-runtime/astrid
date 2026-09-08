#!/usr/bin/env python3
"""Install explicit Developer ID profiles for one command, then restore state."""

import base64
import datetime
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import uuid

TEAM = "9BDSL5BJAP"
PROFILES = (
    ("APP", "org.astrid.runtime.fs"),
    ("EXTENSION", "org.astrid.runtime.fs.AppEx"),
)


def profile_uuid(profile, bundle_id):
    entitlements = profile.get("Entitlements", {})
    if profile.get("TeamIdentifier") != [TEAM]:
        raise ValueError("provisioning profile has the wrong team")
    if entitlements.get("com.apple.application-identifier") != f"{TEAM}.{bundle_id}":
        raise ValueError("provisioning profile has the wrong application identifier")
    if profile.get("ProvisionsAllDevices") is not True or entitlements.get("get-task-allow", False):
        raise ValueError("a Developer ID distribution profile is required")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, datetime.datetime) or expires.replace(tzinfo=datetime.timezone.utc) <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("provisioning profile is expired or lacks an expiration")
    if bundle_id.endswith(".AppEx") and entitlements.get("com.apple.developer.fskit.fsmodule") is not True:
        raise ValueError("extension provisioning profile lacks FSKit Module")
    return str(uuid.UUID(profile["UUID"]))


def decode_profile(data):
    decoded = subprocess.run(
        ["/usr/bin/security", "cms", "-D"], input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return plistlib.loads(decoded.stdout)


def run_with_profiles(command, directory, environment):
    environment = environment.copy()
    # Validate both inputs before installing either profile or running signing.
    profiles = []
    for kind, bundle_id in PROFILES:
        key = f"ASTRID_MACOS_{kind}_PROVISIONING_PROFILE"
        data = base64.b64decode(environment[key], validate=True)
        identifier = profile_uuid(decode_profile(data), bundle_id)
        profiles.append((kind, identifier, data))
        del environment[key]
    directory.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for kind, identifier, data in profiles:
            path = directory / f"{identifier}.provisionprofile"
            if path.is_symlink():
                raise ValueError("refusing a symlink provisioning profile")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                if path.read_bytes() != data:
                    raise ValueError("refusing to replace an existing provisioning profile")
            else:
                created.append(path)
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
            environment[f"ASTRID_FSKIT_{kind}_PROFILE"] = identifier
        return subprocess.run(command, env=environment, check=False).returncode
    finally:
        for path in created:
            path.unlink()


if __name__ == "__main__":
    if sys.platform != "darwin" or len(sys.argv) < 2:
        sys.exit("usage on macOS: with_macos_profiles.py command [args]")
    directory = Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles"
    try:
        sys.exit(run_with_profiles(sys.argv[1:], directory, os.environ))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        # Do not print profile bytes or environment values.
        sys.exit(f"provisioning profile setup failed: {type(error).__name__}")
