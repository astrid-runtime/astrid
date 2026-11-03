"""Publish receipts and bounded diagnostic logs; never homes, volumes or targets."""
from pathlib import Path
import hashlib
import json

# Artifact-service bounds, not runtime policy. Full log identity is recorded
# even when only its tail fits; measured receipt values are never truncated.
LOG_LIMIT = 8 * 1024**2
TOTAL_LOG_LIMIT = 64 * 1024**2


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def publish(output: Path) -> dict:
    output = output.resolve()
    publication = output / "public"
    publication.mkdir(mode=0o700, exist_ok=False)
    receipt = output / "receipt.json"
    if receipt.is_symlink() or not receipt.is_file():
        raise RuntimeError("publication requires a regular receipt")
    raw = receipt.read_bytes()
    json.loads(raw)  # The measured receipt is copied exactly, not summarized.
    (publication / "receipt.json").write_bytes(raw)
    paths = [output / name for name in ("main-cargo.jsonl", "candidate-cargo.jsonl",
                                       "client-rustc.log", "capsule-build.log")]
    paths.extend(output.glob("ownership-root/seed/*.log"))
    paths.extend(output.glob("ownership-root/life-*/*.log"))
    manifest = {"receipt_sha256": digest(receipt), "logs": [],
                "log_limit_bytes": LOG_LIMIT, "total_log_limit_bytes": TOTAL_LOG_LIMIT}
    remaining = TOTAL_LOG_LIMIT
    for path in sorted(set(paths)):
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError(f"publication refuses aliased log: {path}")
        relative = path.relative_to(output)
        length = path.stat().st_size
        count = min(length, LOG_LIMIT, remaining)
        target = publication / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with path.open("rb") as stream:
            stream.seek(length - count)
            tail = stream.read(count)
        target.write_bytes(tail)
        manifest["logs"].append({"path": str(relative), "source_bytes": length,
                                 "source_sha256": digest(path), "published_bytes": len(tail),
                                 "published_sha256": digest(target), "tail_only": count < length})
        remaining -= count
    (publication / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
