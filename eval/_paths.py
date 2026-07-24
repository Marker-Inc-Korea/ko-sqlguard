"""Portable paths for optional evaluation scripts."""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parent
EVAL_ROOT = Path(
    os.environ.get("KO_GUARD_EVAL_ROOT", REPO_ROOT / ".eval-data")
).expanduser()


def eval_path(*parts: str) -> str:
    return str(EVAL_ROOT.joinpath(*parts))
