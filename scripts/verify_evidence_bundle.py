#!/usr/bin/env python3
"""Verify a tamper-evident evidence bundle manifest and file hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_bundle(bundle_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "verified": False,
        "bundle_path": str(bundle_path),
        "manifest_checked": False,
        "files_verified": 0,
        "files_mismatched": [],
        "errors": [],
    }

    manifest_path = bundle_path / "manifest.json"
    if not manifest_path.exists():
        result["errors"].append(f"manifest.json not found in {bundle_path}")
        return result

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"failed to parse manifest.json: {exc}")
        return result

    if not isinstance(manifest, dict):
        result["errors"].append("manifest.json must be a JSON object")
        return result

    files = manifest.get("files")
    if not isinstance(files, list):
        result["errors"].append("manifest.json missing 'files' list")
        return result

    result["manifest_checked"] = True

    for entry in files:
        if not isinstance(entry, dict):
            result["errors"].append("manifest entry is not an object")
            continue

        rel_path = entry.get("path")
        expected_sha = entry.get("sha256")

        if not isinstance(rel_path, str) or not isinstance(expected_sha, str):
            result["errors"].append("manifest entry missing string path/sha256")
            continue

        file_path = bundle_path / rel_path
        if not file_path.exists() or not file_path.is_file():
            result["files_mismatched"].append(
                {
                    "path": rel_path,
                    "expected_sha256": expected_sha,
                    "actual_sha256": None,
                    "reason": "missing",
                }
            )
            continue

        actual_sha = _sha256_file(file_path)
        if actual_sha != expected_sha:
            result["files_mismatched"].append(
                {
                    "path": rel_path,
                    "expected_sha256": expected_sha,
                    "actual_sha256": actual_sha,
                    "reason": "sha256_mismatch",
                }
            )
            continue

        result["files_verified"] += 1

    result["verified"] = (
        result["manifest_checked"]
        and not result["errors"]
        and not result["files_mismatched"]
    )
    return result


def _print_human(result: dict[str, Any]) -> None:
    if result["verified"]:
        print(f"[OK] Evidence bundle verified: {result['bundle_path']}")
        print(f"Files verified: {result['files_verified']}")
        return

    print(f"[FAIL] Evidence bundle verification failed: {result['bundle_path']}")
    if result["manifest_checked"]:
        print("Manifest: checked")
    else:
        print("Manifest: not checked")

    print(f"Files verified: {result['files_verified']}")

    if result["files_mismatched"]:
        print("Mismatches:")
        for item in result["files_mismatched"]:
            print(
                f"  - {item['path']}: {item['reason']} "
                f"(expected={item['expected_sha256']}, actual={item['actual_sha256']})"
            )

    if result["errors"]:
        print("Errors:")
        for err in result["errors"]:
            print(f"  - {err}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify tamper-evident evidence bundle")
    parser.add_argument("bundle", help="Path to evidence bundle directory")
    parser.add_argument(
        "--strict-exit-code",
        action="store_true",
        help="Return non-zero when verification fails",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON result object",
    )

    args = parser.parse_args()
    bundle_path = Path(args.bundle)

    result = _verify_bundle(bundle_path)

    if args.json:
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    else:
        _print_human(result)

    if args.strict_exit_code and not result["verified"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
