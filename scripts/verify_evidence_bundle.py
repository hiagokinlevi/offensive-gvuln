#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import hashlib
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_bundle(bundle_dir: Path) -> tuple[bool, bool]:
    """Verify evidence bundle integrity.

    Returns:
        (ok, hard_error)
        ok=False means at least one mismatch/missing/parse issue occurred.
        hard_error=True means manifest could not be parsed/read.
    """
    manifest_path = bundle_dir / "manifest.json"

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        print(f"[ERROR] Failed to parse manifest: {manifest_path}")
        return False, True

    files = manifest.get("files", [])
    ok = True

    for entry in files:
        rel = entry.get("path")
        expected = entry.get("sha256")
        if not rel or not expected:
            print("[ERROR] Invalid manifest entry")
            ok = False
            continue

        artifact = bundle_dir / rel
        if not artifact.exists():
            print(f"[MISSING] {rel}")
            ok = False
            continue

        actual = _sha256_file(artifact)
        if actual != expected:
            print(f"[MISMATCH] {rel}")
            ok = False
        else:
            print(f"[OK] {rel}")

    if ok:
        print("Verification complete: all artifacts validated")
    else:
        print("Verification complete: issues detected")

    return ok, False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify tamper-evident evidence bundle")
    parser.add_argument("--bundle", required=True, type=Path, help="Path to evidence bundle directory")
    parser.add_argument(
        "--strict-exit-code",
        action="store_true",
        help="Exit non-zero when mismatches, missing artifacts, or manifest parse errors are detected",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    ok, hard_error = verify_bundle(args.bundle)

    if args.strict_exit_code and (hard_error or not ok):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
