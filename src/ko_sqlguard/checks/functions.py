"""Block dangerous server-side functions (pg_sleep, pg_read_file, dblink, ...).

Matched on the function name in the AST, never on the raw SQL string, so
comments / casing / whitespace cannot smuggle a call past the check.
"""
from __future__ import annotations

from sqlglot import exp

from ..policy import GuardPolicy
from ..result import Severity, Violation

# Casts to an OID-registry pseudo-type resolve a catalog object by name/OID —
# functionally identical to to_regclass()/to_regproc()/… which ARE on the denylist.
# `'pg_authid'::regclass` probes object existence with no table reference, so the
# table allowlist never engages. Block the cast form to match the function form.
_BLOCKED_CAST_TYPES: frozenset[str] = frozenset(
    {
        "regclass", "regproc", "regprocedure", "regoper", "regoperator",
        "regtype", "regrole", "regnamespace", "regconfig", "regdictionary",
        "regcollation",
    }
)

# Identity/schema recon spellings that PostgreSQL accepts WITHOUT parentheses
# (SQL-standard niladic keywords). sqlglot parses the parenthesised form to a
# typed Func node (caught by the name denylist), but the bare keyword form
# `SELECT current_role` / `SELECT user` parses to an unqualified exp.Column, so
# the Func loop never sees it. We block it as a Column ONLY when it is both
# UNQUALIFIED and UNQUOTED — `o.user`, `t.current_role`, and `"user"` are real
# column references and must stay PASS (recall safety). Matched case-folded.
_BARE_KEYWORD_RECON: frozenset[str] = frozenset(
    {
        "current_user",
        "session_user",
        "current_role",
        "current_catalog",
        "current_schema",
        "user",
    }
)


def _func_name(node: exp.Func) -> str | None:
    if isinstance(node, exp.Anonymous):
        name = node.name
        return name.lower() if name else None
    try:
        sql_name = node.sql_name()
    except Exception:
        return None
    return sql_name.lower() if sql_name else None


def check_functions(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    blocked = {f.lower() for f in policy.blocked_functions}
    # Fail-CLOSED prefix gate: any pg_* built-in not on the benign allowlist is a
    # system/introspection function (WAL/recovery/per-relation-stat/file/admin), the
    # symmetric counterpart to the pg_* table-prefix gate in checks/catalog.py. This
    # closes recon families (pg_current_wal_*, pg_is_in_recovery, pg_stat_get_*,
    # pg_walfile_name, …) without enumerating every version-specific function.
    prefixes = policy.normalized_function_prefixes if policy.block_pg_function_prefix else ()
    pg_allow = policy.normalized_allowed_pg_functions
    if not blocked and not prefixes:
        return []

    violations: list[Violation] = []
    flagged: set[str] = set()
    for node in stmt.find_all(exp.Func):
        name = _func_name(node)
        if not name or name in flagged:
            continue
        if name in blocked:
            flagged.add(name)
            violations.append(
                Violation(
                    code="blocked_function",
                    severity=Severity.HIGH,
                    reason=f"function {name}() is blocked (server-side / delay / file access)",
                    action="block",
                    fix=f"Remove the call to {name}().",
                )
            )
        elif prefixes and name.startswith(prefixes) and name not in pg_allow:
            flagged.add(name)
            violations.append(
                Violation(
                    code="blocked_function",
                    severity=Severity.HIGH,
                    reason=f"built-in function {name}() is a reserved pg_* system/"
                    "introspection call (WAL/recovery/statistics/file/admin) and is "
                    "blocked; only a small benign allowlist of pg_* helpers is permitted",
                    action="block",
                    fix=f"Remove the call to {name}(); use application functions only.",
                )
            )
    # Bare-keyword identity recon (`SELECT current_role` / `SELECT user`): these
    # niladic keywords parse to an unqualified, unquoted exp.Column, not a Func, so
    # the loop above misses them. Only fire when the name is on the denylist AND the
    # Column is unqualified AND unquoted — real columns (o.user, "user") stay PASS.
    if blocked:
        for col in stmt.find_all(exp.Column):
            if col.args.get("table") is not None:
                continue  # qualified -> a genuine column reference
            ident = col.this
            if isinstance(ident, exp.Identifier) and ident.quoted:
                continue  # quoted -> explicit identifier, not the keyword form
            name = (col.name or "").lower()
            if name in _BARE_KEYWORD_RECON and name in blocked and name not in flagged:
                flagged.add(name)
                violations.append(
                    Violation(
                        code="blocked_function",
                        severity=Severity.HIGH,
                        reason=f"{name} is an identity/schema reconnaissance keyword "
                        "(server principal / current schema) and is blocked",
                        action="block",
                        fix=f"Remove the {name} keyword.",
                    )
                )

    # `@@VERSION` / `@@version` (MSSQL/MySQL global-variable version fingerprint).
    # sqlglot reads the `@@<ident>` operator into a MatchAgainst node. Two shapes:
    #   bare     `@@VERSION`        -> MatchAgainst(this=Column(version), expressions=[None])
    #   glued    `1@@VERSION`       -> MatchAgainst(this=Column(version), expressions=[Literal])
    # NEITHER is a real PostgreSQL full-text match: legitimate FTS is
    # `tsv @@ to_tsquery('cat')` -> MatchAgainst(this=<to_tsquery() Func> or a
    # ::tsquery Cast, ...). So a MatchAgainst whose MATCH TARGET (`this`) is anything
    # other than a tsquery-producing function / ::tsquery cast is the `@@<ident>`
    # server-fingerprint recon form — the @@-spelled sibling of the version()/
    # current_version denylist entries. Matched on the AST node shape, never the raw
    # string. (Verified: zero MatchAgainst nodes in the external benign set, so the
    # tsquery carve-out below cannot FP a legitimate full-text read here.)
    for ma in stmt.find_all(exp.MatchAgainst):
        if "@@recon" in flagged:
            break
        target = ma.this
        target_sql = target.sql().lower() if target is not None else "?"
        # Carve out genuine FTS: the match target resolves through a *_tsquery()
        # builder or an explicit ::tsquery cast. Anything else (bare identifier such
        # as `version`, a literal, …) is the fingerprint operator form.
        target_type = target.args.get("to") if isinstance(target, exp.Cast) else None
        target_type_sql = (
            target_type.sql().lower() if isinstance(target_type, exp.Expression) else ""
        )
        is_real_fts = (
            isinstance(target, exp.Func) and "tsquery" in (target_sql or "")
        ) or (isinstance(target, exp.Cast) and "tsquery" in target_type_sql)
        if not is_real_fts:
            flagged.add("@@recon")
            label = (target.name or target_sql) if target is not None else "?"
            violations.append(
                Violation(
                    code="blocked_function",
                    severity=Severity.HIGH,
                    reason=f"@@{label} is a server version/global-variable fingerprint "
                    "(MSSQL/MySQL recon via the @@ operator), the @@-spelled sibling of "
                    "version(); blocked (not a tsquery full-text match)",
                    action="block",
                    fix=f"Remove the @@{label} reference; use to_tsquery() for full-text search.",
                )
            )

    for cast in stmt.find_all(exp.Cast):
        to = cast.args.get("to")
        tname = to.sql().lower() if to is not None else ""
        if tname in _BLOCKED_CAST_TYPES and "::regcast" not in flagged:
            flagged.add("::regcast")
            violations.append(
                Violation(
                    code="blocked_function",
                    severity=Severity.HIGH,
                    reason=f"cast to OID-registry type {tname!r} resolves catalog objects "
                    "(equivalent to the blocked to_reg*() functions)",
                    action="block",
                    fix=f"Remove the ::{tname} cast.",
                )
            )
    return violations
