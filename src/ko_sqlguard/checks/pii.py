"""Table-specific PII column enforcement."""
from __future__ import annotations

from sqlglot import exp

from ..policy import GuardPolicy
from ..result import Severity, Violation
from ._ast import real_tables, table_key_candidates


def _matched_pii_columns(
    table: exp.Table,
    configured: dict[str, frozenset[str]],
) -> tuple[str, frozenset[str]] | None:
    for candidate in table_key_candidates(table):
        # PII metadata is a denylist. Match quoted identifier casing
        # conservatively rather than allowing a case-only bypass.
        key = candidate.casefold()
        columns = configured.get(key)
        if columns:
            return key, columns
    return None


def _scope_tables(
    node: exp.Expression,
    mapped: list[tuple[exp.Table, str, frozenset[str]]],
) -> list[tuple[exp.Table, str, frozenset[str]]]:
    select = node.find_ancestor(exp.Select)
    if select is None:
        return mapped
    return [entry for entry in mapped if entry[0].find_ancestor(exp.Select) is select]


def _source_names(table: exp.Table) -> set[str]:
    names = {table.name.lower()}
    if table.alias:
        names.add(table.alias.lower())
    return names


def _is_within(node: exp.Expression, ancestor: exp.Expression) -> bool:
    if node is ancestor:
        return True
    current = node.parent
    while current is not None:
        if current is ancestor:
            return True
        current = current.parent
    return False


def _violation(table: str, column: str, *, whole_row: bool = False) -> Violation:
    if whole_row:
        reason = (
            f"whole-row access to {table!r} may expose columns classified as PII "
            "by GuardPolicy.pii_columns"
        )
        fix = "Project explicit non-PII columns instead of the whole row."
    else:
        reason = (
            f"column {column!r} on table {table!r} is classified as PII by "
            "GuardPolicy.pii_columns"
        )
        fix = "Remove the PII column or use an approved downstream masking path."
    return Violation(
        code="pii_column",
        severity=Severity.HIGH,
        reason=reason,
        action="block",
        fix=fix,
    )


def check_pii_columns(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    """Block table-scoped PII reads, including stars and whole-row values.

    The policy is metadata-only and never performs schema discovery or imports a
    PII detector. CTE and derived-table inner queries are checked in their own
    scopes, so a safe projection can be consumed by an outer ``SELECT *`` without
    inheriting every hidden column from the physical source.
    """

    configured = policy.normalized_pii_columns
    if not configured:
        return []

    mapped: list[tuple[exp.Table, str, frozenset[str]]] = []
    for table in real_tables(stmt):
        match = _matched_pii_columns(table, configured)
        if match is not None:
            key, columns = match
            mapped.append((table, key, columns))
    if not mapped:
        return []

    violations: list[Violation] = []
    flagged: set[tuple[str, str]] = set()

    # JOIN ... USING names are Identifiers rather than Columns in sqlglot, and
    # NATURAL JOIN has no explicit column node at all. Walk direct join order so
    # a classified table introduced by a later join cannot create a false hit
    # on an earlier USING clause.
    for select in stmt.find_all(exp.Select):
        scoped = [
            entry for entry in mapped if entry[0].find_ancestor(exp.Select) is select
        ]
        joins = list(select.args.get("joins") or [])
        active = [
            entry
            for entry in scoped
            if not any(_is_within(entry[0], join.this) for join in joins)
        ]
        for join in joins:
            for entry in scoped:
                if entry not in active and _is_within(entry[0], join.this):
                    active.append(entry)
            if (join.args.get("method") or "").upper() == "NATURAL":
                for _table, key, _columns in active:
                    marker = (key, "NATURAL JOIN")
                    if marker not in flagged:
                        flagged.add(marker)
                        violations.append(_violation(key, "NATURAL JOIN"))
            for identifier in join.args.get("using") or []:
                name = identifier.name.casefold()
                for _table, key, columns in active:
                    marker = (key, name)
                    if name in columns and marker not in flagged:
                        flagged.add(marker)
                        violations.append(_violation(key, identifier.name))

    for star in stmt.find_all(exp.Star):
        if star.find_ancestor(exp.Count) is not None:
            continue
        scoped = _scope_tables(star, mapped)
        if not scoped:
            continue
        qualifier = ""
        if isinstance(star.parent, exp.Column):
            qualifier = (star.parent.table or "").lower()
        candidates = scoped
        if qualifier:
            candidates = [
                entry for entry in scoped if qualifier in _source_names(entry[0])
            ]
        for _table, key, _columns in candidates:
            marker = (key, "*")
            if marker not in flagged:
                flagged.add(marker)
                violations.append(_violation(key, "*", whole_row=True))

    for column in stmt.find_all(exp.Column):
        if isinstance(column.this, exp.Star):
            continue
        scoped = _scope_tables(column, mapped)
        if not scoped:
            continue
        qualifier = (column.table or "").lower()
        name = (column.name or "").lower()
        if qualifier:
            scoped = [
                entry for entry in scoped if qualifier in _source_names(entry[0])
            ]
        for table, key, columns in scoped:
            source_names = _source_names(table)
            whole_row = not qualifier and name in source_names
            if not whole_row and name not in columns:
                continue
            marker = (key, "*" if whole_row else name)
            if marker in flagged:
                continue
            flagged.add(marker)
            violations.append(
                _violation(key, column.sql(), whole_row=whole_row)
            )
    return violations
