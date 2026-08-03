"""Deterministic checks. Each is a pure function over a sqlglot AST + policy."""
from __future__ import annotations

from .allowlist import check_columns, check_tables
from .cartesian import check_cartesian
from .catalog import check_catalog, check_sensitive_columns
from .functions import check_functions
from .inference import check_inference
from .limit import apply_limit
from .pii import check_pii_columns
from .statement_type import check_statement_type
from .tautology import check_tautology
from .where import check_require_where

__all__ = [
    "apply_limit",
    "check_cartesian",
    "check_catalog",
    "check_columns",
    "check_functions",
    "check_inference",
    "check_pii_columns",
    "check_require_where",
    "check_sensitive_columns",
    "check_statement_type",
    "check_tables",
    "check_tautology",
]
