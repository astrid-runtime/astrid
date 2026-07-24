#!/usr/bin/env python3
"""Create a minimal signed shuttle for OCI entrypoint integration tests."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import pathlib
import subprocess
import tarfile
import tempfile
import tomllib


DOMAIN = b"astrid-distro-lock-sig-v1\x00"
PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


def blake3(data: bytes) -> str:
    result = subprocess.run(
        ["b3sum", "--no-names"],
        input=data,
        check=True,
        capture_output=True,
    )
    value = result.stdout.decode("ascii").strip()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("b3sum returned a malformed digest")
    return value


def tar_gzip(entries: dict[str, bytes]) -> bytes:
    with tempfile.SpooledTemporaryFile() as compressed:
        with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w") as archive:
                for name in sorted(entries):
                    payload = entries[name]
                    header = tarfile.TarInfo(name)
                    header.mode = 0o644
                    header.uid = 0
                    header.gid = 0
                    header.mtime = 0
                    header.size = len(payload)
                    archive.addfile(header, __import__("io").BytesIO(payload))
        compressed.seek(0)
        return compressed.read()


def create(
    output: pathlib.Path,
    *,
    capsule_path: pathlib.Path | None = None,
    tamper_signature: bool = False,
) -> None:
    capsule_name = "oci-test-uplink"
    capsule_version = "0.1.0"
    if capsule_path is None:
        capsule = tar_gzip(
            {
                "Capsule.toml": (
                    f'[package]\nname = "{capsule_name}"\nversion = "{capsule_version}"\n'
                ).encode()
            }
        )
    else:
        if not capsule_path.is_file() or capsule_path.is_symlink():
            raise ValueError("test uplink capsule must be a regular file")
        capsule = capsule_path.read_bytes()
        if not capsule:
            raise ValueError("test uplink capsule must not be empty")
        with tarfile.open(fileobj=__import__("io").BytesIO(capsule), mode="r:gz") as archive:
            manifest_file = archive.extractfile("Capsule.toml")
            if manifest_file is None:
                raise ValueError("test uplink capsule is missing Capsule.toml")
            capsule_manifest = tomllib.loads(manifest_file.read().decode("utf-8"))
        package = capsule_manifest.get("package")
        if not isinstance(package, dict):
            raise ValueError("test uplink capsule is missing [package]")
        capsule_name = package.get("name")
        capsule_version = package.get("version")
        if not isinstance(capsule_name, str) or not isinstance(capsule_version, str):
            raise ValueError("test uplink capsule package identity is invalid")

    with tempfile.TemporaryDirectory(prefix="astrid-oci-test-key-") as temporary:
        root = pathlib.Path(temporary)
        key = root / "key.pem"
        public_der = root / "public.der"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(public_der),
            ],
            check=True,
            capture_output=True,
        )
        encoded_public = public_der.read_bytes()
        if not encoded_public.startswith(PUBLIC_KEY_DER_PREFIX) or len(encoded_public) != 44:
            raise ValueError("OpenSSL emitted an unexpected Ed25519 public-key encoding")
        public_wire = "ed25519:" + base64.b64encode(encoded_public[-32:]).decode("ascii")

        manifest = (
            "schema-version = 1\n"
            "\n"
            "[distro]\n"
            'id = "oci-entrypoint-test"\n'
            'name = "OCI Entrypoint Test"\n'
            'version = "0.1.0"\n'
            "\n"
            "[distro.signing]\n"
            f'pubkey = "{public_wire}"\n'
            "\n"
            "[[capsule]]\n"
            f'name = "{capsule_name}"\n'
            'source = "@astrid-test/oci-test-uplink"\n'
            f'version = "{capsule_version}"\n'
            'role = "uplink"\n'
        ).encode()
        manifest_hash = f"blake3:{blake3(manifest)}"
        capsule_hash = f"blake3:{blake3(capsule)}"
        lock = (
            "schema-version = 1\n"
            f'manifest-hash = "{manifest_hash}"\n'
            "\n"
            "[distro]\n"
            'id = "oci-entrypoint-test"\n'
            'version = "0.1.0"\n'
            'resolved-at = "1970-01-01T00:00:00+00:00"\n'
            "\n"
            "[[capsule]]\n"
            f'name = "{capsule_name}"\n'
            f'version = "{capsule_version}"\n'
            'source = "@astrid-test/oci-test-uplink"\n'
            f'hash = "{capsule_hash}"\n'
            'resolved_ref = "v0.1.0"\n'
        ).encode()
        canonical_lock = {
            "schema-version": 1,
            "distro": {
                "id": "oci-entrypoint-test",
                "version": "0.1.0",
                "resolved-at": "1970-01-01T00:00:00+00:00",
            },
            "capsule": [
                {
                    "name": capsule_name,
                    "version": capsule_version,
                    "source": "@astrid-test/oci-test-uplink",
                    "hash": capsule_hash,
                    "resolved_ref": "v0.1.0",
                }
            ],
            "manifest-hash": manifest_hash,
        }
        signing_json = json.dumps(canonical_lock, separators=(",", ":")).encode()
        signing_digest = bytes.fromhex(blake3(DOMAIN + signing_json))
        digest_file = root / "digest"
        signature_file = root / "signature"
        digest_file.write_bytes(signing_digest)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                str(digest_file),
                "-out",
                str(signature_file),
            ],
            check=True,
            capture_output=True,
        )
        signature = signature_file.read_bytes()
        if len(signature) != 64:
            raise ValueError("OpenSSL emitted an unexpected Ed25519 signature length")

    output.parent.mkdir(parents=True, exist_ok=True)
    signature_hex = signature.hex()
    if tamper_signature:
        replacement = "0" if signature_hex[0] != "0" else "1"
        signature_hex = replacement + signature_hex[1:]
    output.write_bytes(
        tar_gzip(
            {
                "Distro.lock": lock,
                "Distro.sig": signature_hex.encode(),
                "Distro.toml": manifest,
                f"capsules/{capsule_name}.capsule": capsule,
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--capsule",
        type=pathlib.Path,
        help="real compatible CLI uplink capsule for release-daemon readiness tests",
    )
    parser.add_argument("--tamper-signature", action="store_true")
    args = parser.parse_args()
    create(
        args.output,
        capsule_path=args.capsule,
        tamper_signature=args.tamper_signature,
    )


if __name__ == "__main__":
    main()
