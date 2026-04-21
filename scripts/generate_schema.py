#!/usr/bin/env python3
"""Generate JSON Schema artifacts from Pydantic models.

Currently exports the Vulnerability Finding schema to:
  docs/schema/findings.schema.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vuln_management.models import VulnerabilityFinding


def generate_findings_schema(output_path: Path) -> Path:
    """Generate and write the VulnerabilityFinding JSON Schema."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema = VulnerabilityFinding.model_json_schema()
    output_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate JSON Schema for the VulnerabilityFinding model."
    )
    parser.add_argument(
        "--output",
        default="docs/schema/findings.schema.json",
        help="Path to write schema JSON (default: docs/schema/findings.schema.json)",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    written = generate_findings_schema(output_path)
    print(f"Wrote findings schema to {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
