from __future__ import annotations

import argparse
import sys

from vuln_management.state_machine import is_valid_transition


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="offensive-gvuln")
    subparsers = parser.add_subparsers(dest="command")

    preflight = subparsers.add_parser(
        "preflight-transition",
        help="Verify whether a finding state transition is allowed",
    )
    preflight.add_argument("--finding-id", required=True, help="Finding identifier")
    preflight.add_argument("--current-state", required=True, help="Current finding state")
    preflight.add_argument("--target-state", required=True, help="Desired target finding state")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "preflight-transition":
        allowed = is_valid_transition(args.current_state, args.target_state)
        if allowed:
            print(
                f"PASS: finding {args.finding_id} transition {args.current_state} -> {args.target_state} is allowed"
            )
            return 0

        print(
            f"FAIL: finding {args.finding_id} transition {args.current_state} -> {args.target_state} is not allowed"
        )
        return 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
