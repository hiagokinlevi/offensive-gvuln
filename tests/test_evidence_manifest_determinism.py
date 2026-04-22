from __future__ import annotations

import time
from pathlib import Path

from pentest_governance.evidence import generate_evidence_manifest


def test_manifest_hash_stable_for_identical_inputs(tmp_path: Path) -> None:
    a = tmp_path / "b.txt"
    b = tmp_path / "a.txt"
    a.write_text("two", encoding="utf-8")
    b.write_text("one", encoding="utf-8")

    fixed_mtime = 1_700_000_000
    for p in (a, b):
        p.touch()
        p.chmod(0o644)
        time_tuple = (fixed_mtime, fixed_mtime)
        import os

        os.utime(p, time_tuple)

    m1 = generate_evidence_manifest(tmp_path)
    m2 = generate_evidence_manifest(tmp_path)

    assert [e["path"] for e in m1["entries"]] == ["a.txt", "b.txt"]
    assert [e["path"] for e in m2["entries"]] == ["a.txt", "b.txt"]
    assert m1["manifest_sha256"] == m2["manifest_sha256"]
    assert m1["entries"] == m2["entries"]
