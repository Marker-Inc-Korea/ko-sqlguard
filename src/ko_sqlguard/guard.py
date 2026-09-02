"""Guard: the deterministic, parse-only entry point.

check() is a pure function: parse the SQL once with sqlglot's postgres dialect,
run every deterministic check over the AST, and return a GuardResult. It never
touches a database, an LLM, or the network. Parsing failure is a BLOCK, not an
exception (fail-closed).
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from . import checks
from .checks._ast import normalized_copy
from .policy import GuardPolicy
from .result import GuardBlocked, GuardResult, Severity, Verdict, Violation

_DIALECT = "postgres"


def _block(original: str, *violations: Violation) -> GuardResult:
    return GuardResult(
        verdict=Verdict.BLOCK,
        sql=None,
        original_sql=original,
        violations=tuple(violations),
    )


def _real_statements(parsed: Iterable[Any]) -> list[exp.Expression]:
    return [s for s in parsed if s is not None and not isinstance(s, exp.Semicolon)]


def _parse_with_fallback(sql: str, policy: GuardPolicy) -> tuple[list[Any] | None, str | None]:
    """policy.dialect 먼저, 실패 시 fallback_dialects 순차 재시도.

    반환: (parsed, 성공 dialect) 또는 (None, None). postgres 가 먼저 성공하면 기존 동작과
    동일(폴백 미발동) — 즉 기존 회귀 없음. 타 다이얼렉트 전용 구문만 폴백으로 파싱된다.
    위험 검사(denylist)는 cross-dialect 라 어느 다이얼렉트로 파싱되든 그대로 적용된다.
    """
    for dialect in (policy.dialect, *policy.fallback_dialects):
        try:
            return sqlglot.parse(sql, read=dialect), dialect
        except (ParseError, TokenError):
            continue
        except Exception:  # noqa: BLE001 - defensive: 어떤 파서 예외도 다음 다이얼렉트로
            continue
    return None, None


class Guard:
    """Reusable guard bound to a policy. Stateless across check() calls."""

    def __init__(self, policy: GuardPolicy | None = None) -> None:
        self.policy = policy or GuardPolicy()

    def check(self, sql: str) -> GuardResult:
        if not isinstance(sql, str):
            raise TypeError(f"check() expects str, got {type(sql).__name__}")
        policy = self.policy
        original = sql

        # Bound raw input before parser allocation/recursion. Character and UTF-8
        # byte limits are intentionally independent for multibyte SQL input.
        if len(sql) > policy.max_query_chars:
            return _block(
                "",
                Violation(
                    code="query_too_many_characters",
                    severity=Severity.CRITICAL,
                    reason=(
                        f"query has {len(sql)} characters; maximum is "
                        f"{policy.max_query_chars}"
                    ),
                    fix=f"Reduce the SQL input to at most {policy.max_query_chars} characters.",
                ),
            )
        try:
            byte_length = len(sql.encode("utf-8"))
        except UnicodeEncodeError:
            return _block(
                "",
                Violation(
                    code="query_invalid_encoding",
                    severity=Severity.CRITICAL,
                    reason="query is not valid UTF-8 text",
                ),
            )
        if byte_length > policy.max_query_bytes:
            return _block(
                "",
                Violation(
                    code="query_too_many_bytes",
                    severity=Severity.CRITICAL,
                    reason=(
                        f"query has {byte_length} UTF-8 bytes; maximum is "
                        f"{policy.max_query_bytes}"
                    ),
                    fix=f"Reduce the SQL input to at most {policy.max_query_bytes} UTF-8 bytes.",
                ),
            )

        if not sql or not sql.strip():
            return _block(
                original,
                Violation(
                    code="empty",
                    severity=Severity.CRITICAL,
                    reason="empty input is not a valid statement",
                ),
            )

        # 1) Parse with dialect fallback. 모든 다이얼렉트에서 실패하면 hard block(안전 증명 불가).
        parsed, parse_dialect = _parse_with_fallback(sql, policy)
        if parsed is None:
            tried = ", ".join((policy.dialect, *policy.fallback_dialects))
            return _block(
                original,
                Violation(
                    code="parse_error",
                    severity=Severity.CRITICAL,
                    reason=f"could not parse SQL in any dialect ({tried})",
                    fix="Send a single, well-formed SQL statement.",
                ),
            )

        statements = _real_statements(parsed)
        if len(statements) == 0:
            return _block(
                original,
                Violation(
                    code="parse_error",
                    severity=Severity.CRITICAL,
                    reason="no executable statement found",
                ),
            )
        if len(statements) > 1:
            return _block(
                original,
                Violation(
                    code="multi_statement",
                    severity=Severity.CRITICAL,
                    reason=f"{len(statements)} statements found; only one is allowed "
                    "(stacked-query / piggyback defense)",
                    fix="Submit exactly one statement.",
                ),
            )

        # 2) Work on a normalized copy so identifier casing follows PG rules and
        #    transforms don't mutate the caller's AST.
        try:
            working = normalized_copy(statements[0])
        except Exception:
            working = statements[0].copy()

        violations: list[Violation] = []
        try:
            violations += checks.check_statement_type(working, policy)
            violations += checks.check_functions(working, policy)
            violations += checks.check_catalog(working, policy)
            violations += checks.check_sensitive_columns(working, policy)
            violations += checks.check_pii_columns(working, policy)
            violations += checks.check_tables(working, policy)
            violations += checks.check_columns(working, policy)
            violations += checks.check_require_where(working, policy)
            violations += checks.check_cartesian(working, policy)
            violations += checks.check_tautology(working, policy)
            violations += checks.check_inference(working, policy)
        except RecursionError:
            # A pathological, deeply-nested AST (e.g. a 1000-deep OR/AND chain
            # crafted to overflow the C stack) must fail CLOSED, never crash the
            # caller. Honor the documented "fail-closed, not fail-crash" contract.
            return _block(
                original,
                Violation(
                    code="parse_error",
                    severity=Severity.CRITICAL,
                    reason="query nesting too deep to analyze safely",
                    fix="Flatten deeply nested boolean/expression chains.",
                ),
            )
        except Exception as exc:  # defensive: any check fault → fail closed, never crash
            return _block(
                original,
                Violation(
                    code="parse_error",
                    severity=Severity.CRITICAL,
                    reason=f"unexpected check error: {type(exc).__name__}",
                ),
            )

        blocking = [
            v
            for v in violations
            if v.action == "block" and v.severity >= policy.min_block_severity
        ]
        if blocking:
            # Re-tag downgraded block-violations as warns for an honest result.
            return GuardResult(
                verdict=Verdict.BLOCK,
                sql=None,
                original_sql=original,
                violations=tuple(violations),
            )

        # 3) No block: apply the transforming LIMIT check and render.
        transformed, limit_violations = checks.apply_limit(working, policy)
        violations += limit_violations
        did_transform = bool(limit_violations)

        if did_transform:
            try:
                rendered = transformed.sql(dialect=parse_dialect or _DIALECT)
            except Exception as exc:
                return GuardResult(
                    verdict=Verdict.BLOCK,
                    sql=None,
                    original_sql=original,
                    violations=(
                        *violations,
                        Violation(
                            code="transform_error",
                            severity=Severity.CRITICAL,
                            reason=f"could not render transformed SQL: {type(exc).__name__}",
                            fix="Reject the query and inspect the parser/dialect configuration.",
                        ),
                    ),
                )
            return GuardResult(
                verdict=Verdict.TRANSFORM,
                sql=rendered,
                original_sql=original,
                violations=tuple(violations),
            )

        return GuardResult(
            verdict=Verdict.PASS,
            sql=original,
            original_sql=original,
            violations=tuple(violations),
        )

    def enforce(self, sql: str) -> str:
        """Return safe SQL (rewritten if transformed) or raise GuardBlocked."""
        result = self.check(sql)
        if result.verdict is Verdict.BLOCK or result.sql is None:
            raise GuardBlocked(result)
        return result.sql

    def check_cost(
        self,
        sql: str,
        connection: object,
        parameters: object | None = None,
    ) -> GuardResult:
        """Tier-2 EXPLAIN cost guard. NOT part of the pure hot path — it talks to
        a database via ``connection`` (any DB-API 2.0 connection). Call this only
        on SQL that already passed ``check()``. See ``ko_sqlguard.cost``."""
        from .cost import explain_cost_guard

        return explain_cost_guard(sql, self.policy, connection, parameters)


def check(sql: str, policy: GuardPolicy | None = None) -> GuardResult:
    """Module-level convenience wrapper around Guard(policy).check(sql)."""
    return Guard(policy).check(sql)
