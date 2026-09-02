"""Explicit DB-API execution seam that cannot bypass the guard decision."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .guard import Guard
from .result import GuardBlocked, GuardResult


@dataclass(frozen=True)
class GuardedExecution:
    """A successful execution and the decisions that authorized it."""

    cursor: Any
    structural_result: GuardResult
    cost_result: GuardResult | None


def execute_guarded(
    connection: Any,
    sql: str,
    parameters: object | None = None,
    *,
    guard: Guard | None = None,
    check_cost: bool = True,
    require_production_policy: bool = True,
) -> GuardedExecution:
    """Validate, optionally cost-check, then execute one DB-API statement.

    The caller owns the connection, transaction, returned cursor, database role,
    and timeout settings.  The default requires an explicit table allowlist.
    ``parameters`` stay separate from SQL and are passed directly to the driver.
    """
    active = guard or Guard()
    if require_production_policy:
        active.policy.validate_production()

    structural = active.check(sql)
    if not structural.forward_safe or structural.sql is None:
        raise GuardBlocked(structural)
    safe_sql = structural.sql

    cost_result: GuardResult | None = None
    if check_cost and (
        active.policy.cost_threshold is not None
        or active.policy.max_estimated_rows is not None
    ):
        cost_result = active.check_cost(safe_sql, connection, parameters)
        if not cost_result.forward_safe:
            raise GuardBlocked(cost_result)

    cursor = connection.cursor()
    try:
        if parameters is None:
            cursor.execute(safe_sql)
        else:
            cursor.execute(safe_sql, parameters)
    except Exception:
        cursor.close()
        raise
    return GuardedExecution(
        cursor=cursor,
        structural_result=structural,
        cost_result=cost_result,
    )


__all__ = ["GuardedExecution", "execute_guarded"]
