"""Compile an explicit SQL guard policy from an offline schema catalog."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .policy import GuardPolicy


class SchemaPolicyError(ValueError):
    """Raised when a schema catalog is ambiguous or malformed."""


def _columns_for_table(table: str, raw: object) -> Sequence[object]:
    if isinstance(raw, Mapping):
        unknown = set(raw) - {"columns"}
        if unknown:
            names = ", ".join(sorted(str(name) for name in unknown))
            raise SchemaPolicyError(f"table {table!r} has unknown fields: {names}")
        raw = raw.get("columns")
    if isinstance(raw, str) or not isinstance(raw, Sequence):
        raise SchemaPolicyError(f"table {table!r} must contain a columns list")
    return raw


def _column(raw: object, *, table: str) -> tuple[str, bool]:
    name: object
    if isinstance(raw, str):
        name = raw
        pii = False
    elif isinstance(raw, Mapping):
        unknown = set(raw) - {"name", "pii", "pii_label"}
        if unknown:
            fields = ", ".join(sorted(str(field) for field in unknown))
            raise SchemaPolicyError(
                f"column in table {table!r} has unknown fields: {fields}"
            )
        name = raw.get("name")
        pii_value = raw.get("pii", False)
        pii_label = raw.get("pii_label")
        if not isinstance(pii_value, bool):
            raise SchemaPolicyError(f"column {name!r} pii must be boolean")
        if pii_label is not None and (
            not isinstance(pii_label, str) or not pii_label.strip()
        ):
            raise SchemaPolicyError(f"column {name!r} pii_label must be a non-empty string")
        pii = pii_value or pii_label is not None
    else:
        raise SchemaPolicyError(f"column in table {table!r} must be a string or object")
    if not isinstance(name, str) or not name.strip():
        raise SchemaPolicyError(f"table {table!r} contains an empty column name")
    return name.strip(), pii


def compile_schema_policy(
    catalog: Mapping[str, object],
    *,
    base_policy: GuardPolicy | None = None,
    validate_production: bool = True,
) -> GuardPolicy:
    """Build table/column allowlists and PII denylists from trusted metadata.

    Accepted catalog form::

        {
          "public.customers": {
            "columns": [
              "id",
              {"name": "주민등록번호", "pii": true, "pii_label": "RRN"}
            ]
          }
        }

    ``pii_label`` is provenance for the caller and also marks the column as PII;
    ko-sqlguard does not infer labels or inspect a live database.  Generate this
    catalog offline, for example with ko-pii's ``classify_schema_columns`` API.
    """
    if not isinstance(catalog, Mapping):
        raise TypeError("catalog must be a mapping of table names to column lists")

    allowed_tables: dict[str, list[str]] = {}
    pii_columns: dict[str, list[str]] = {}
    normalized_tables: set[str] = set()

    for raw_table, raw_columns in catalog.items():
        if not isinstance(raw_table, str) or not raw_table.strip():
            raise SchemaPolicyError("catalog contains an empty table name")
        table = raw_table.strip()
        table_key = table.lower()
        if table_key in normalized_tables:
            raise SchemaPolicyError(f"duplicate table after normalization: {table!r}")
        normalized_tables.add(table_key)

        names: list[str] = []
        sensitive: list[str] = []
        normalized_columns: set[str] = set()
        for raw_column in _columns_for_table(table, raw_columns):
            name, pii = _column(raw_column, table=table)
            key = name.lower()
            if key in normalized_columns:
                raise SchemaPolicyError(
                    f"duplicate column after normalization: {table}.{name}"
                )
            normalized_columns.add(key)
            names.append(name)
            if pii:
                sensitive.append(name)
        allowed_tables[table] = names
        if sensitive:
            pii_columns[table] = sensitive

    data: dict[str, Any] = (base_policy or GuardPolicy()).model_dump()
    data["allowed_tables"] = allowed_tables
    data["pii_columns"] = pii_columns
    policy = GuardPolicy.model_validate(data)
    return policy.validate_production() if validate_production else policy


__all__ = ["SchemaPolicyError", "compile_schema_policy"]
