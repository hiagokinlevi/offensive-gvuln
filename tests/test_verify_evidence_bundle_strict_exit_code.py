from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_strict_exit_code_returns_non_zero_on_mismatch(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    artifact = bundle / "evidence.txt"
    artifact.write_text("actual-content", encoding="utf-8")

    manifest = {
        "files": [
            {
                "path": "evidence.txt",
                "sha256": _sha256_text("different-content"),
            }
        ]
    }
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    script = Path("scripts/verify_evidence_bundle.py")
    proc = subprocess.run(
        [sys.executable, str(script), "--bundle", str(bundle), "--strict-exit-code"],
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
