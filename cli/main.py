from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pentest_governance.scope_validator import validate_scope_definition


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m cli.main")
    subparsers = parser.add_subparsers(dest="command")

    scope_validate = subparsers.add_parser(
        "scope-validate",
        help="Validate pentest scope definition JSON before RoE generation",
    )
    scope_validate.add_argument(
        "--scope-file",
        required=True,
        help="Path to scope definition JSON file",
    )

    return parser


def _format_error(err: Any) -> dict[str, Any]:
    if isinstance(err, dict):
        return {
            "target": err.get("target") or err.get("value") or "<unknown>",
            "rule": err.get("rule") or err.get("type") or "validation",
            "reason": err.get("reason") or err.get("message") or "invalid entry",
        }
    return {
        "target": "<unknown>",
        "rule": "validation",
        "reason": str(err),
    }


def _run_scope_validate(scope_file: str) -> int:
    path = Path(scope_file)
    if not path.exists():
        print(
            json.dumps(
                {
                    "status": "fail",
                    "errors": [
                        {
                            "target": str(path),
                            "rule": "file_exists",
                            "reason": "scope file not found",
                        }
                    ],
                },
                indent=2,
            )
        )
        return 2

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "errors": [
                        {
                            "target": str(path),
                            "rule": "json_parse",
                            "reason": str(exc),
                        }
                    ],
                },
                indent=2,
            )
        )
        return 2

    result = validate_scope_definition(payload)

    if isinstance(result, tuple):
        is_valid, errors = result
    elif isinstance(result, dict):
        is_valid = bool(result.get("valid", False))
        errors = result.get("errors", [])
    else:
        is_valid = bool(result)
        errors = []

    if is_valid:
        print(json.dumps({"status": "pass", "errors": []}, indent=2))
        return 0

    formatted_errors = [_format_error(e) for e in (errors or [])]
    print(json.dumps({"status": "fail", "errors": formatted_errors}, indent=2))
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scope-validate":
        return _run_scope_validate(args.scope_file)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
