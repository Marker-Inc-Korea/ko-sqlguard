"""Command-line interface for local SQL policy checks."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .guard import Guard
from .policy import GuardPolicy
from .schema import compile_schema_policy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ko-sqlguard",
        description="Validate one SQL statement without executing it.",
    )
    parser.add_argument("input", nargs="?", default="-", help="SQL file, literal SQL, or -")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--policy", type=Path, help="GuardPolicy JSON file")
    source.add_argument("--schema-catalog", type=Path, help="offline schema catalog JSON")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    parser.add_argument("--version", action="version", version=f"ko-sqlguard {__version__}")
    return parser


def _read_input(value: str) -> str:
    if value == "-":
        return sys.stdin.read()
    path = Path(value)
    return path.read_text("utf-8") if path.is_file() else value


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.policy:
            policy = GuardPolicy.model_validate_json(args.policy.read_text("utf-8"))
        elif args.schema_catalog:
            catalog = json.loads(args.schema_catalog.read_text("utf-8"))
            policy = compile_schema_policy(catalog)
        else:
            policy = GuardPolicy()
        sql = _read_input(args.input)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    result = Guard(policy).check(sql)
    print(
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2 if args.pretty else None,
        )
    )
    return 0 if result.forward_safe else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
