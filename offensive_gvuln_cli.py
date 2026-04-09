"""Repository-unique console entrypoint for offensive-gvuln."""
from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cli.main import cli


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
