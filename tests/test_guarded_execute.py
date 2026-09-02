from __future__ import annotations

import pytest

from ko_sqlguard import Guard, GuardBlocked, GuardPolicy, Verdict, execute_guarded


class FakeCursor:
    def __init__(
        self,
        *,
        error: Exception | None = None,
        row: object | None = None,
    ) -> None:
        self.error = error
        self.row = row
        self.calls: list[tuple[object, ...]] = []
        self.closed = False

    def execute(self, *args: object) -> None:
        self.calls.append(args)
        if self.error:
            raise self.error

    def close(self) -> None:
        self.closed = True

    def fetchone(self) -> object:
        return self.row


class FakeConnection:
    def __init__(
        self,
        *,
        error: Exception | None = None,
        rows: list[object] | None = None,
    ) -> None:
        self.cursors: list[FakeCursor] = []
        self.error = error
        self.rows = list(rows or [])

    def cursor(self) -> FakeCursor:
        row = self.rows.pop(0) if self.rows else None
        cursor = FakeCursor(error=self.error, row=row)
        self.cursors.append(cursor)
        return cursor


def production_guard(**updates: object) -> Guard:
    values = {"allowed_tables": {"orders": ["id", "status"]}, "default_limit": 25}
    values.update(updates)
    return Guard(GuardPolicy(**values))


def test_executes_only_transformed_safe_sql_and_keeps_parameters_separate() -> None:
    connection = FakeConnection()
    execution = execute_guarded(
        connection,
        "SELECT id FROM orders WHERE status = %s",
        ("paid",),
        guard=production_guard(),
    )

    assert execution.structural_result.verdict is Verdict.TRANSFORM
    assert connection.cursors[0].calls == [
        (execution.structural_result.sql, ("paid",))
    ]
    assert "LIMIT 25" in str(execution.structural_result.sql).upper()


def test_blocked_sql_never_opens_execution_cursor() -> None:
    connection = FakeConnection()
    with pytest.raises(GuardBlocked):
        execute_guarded(
            connection,
            "DROP TABLE orders",
            guard=production_guard(),
        )
    assert connection.cursors == []


def test_default_requires_explicit_production_allowlist() -> None:
    connection = FakeConnection()
    with pytest.raises(ValueError, match="explicit allowed_tables"):
        execute_guarded(connection, "SELECT 1", guard=Guard(GuardPolicy()))
    assert connection.cursors == []


def test_driver_error_closes_cursor() -> None:
    connection = FakeConnection(error=RuntimeError("driver failed"))
    with pytest.raises(RuntimeError, match="driver failed"):
        execute_guarded(connection, "SELECT id FROM orders", guard=production_guard())
    assert connection.cursors[0].closed is True


def test_guarded_execution_uses_parameters_for_cost_and_execution() -> None:
    plan = ([{"Plan": {"Total Cost": 10.0, "Plan Rows": 1}}],)
    connection = FakeConnection(rows=[plan])
    parameters = ("paid",)

    execution = execute_guarded(
        connection,
        "SELECT id FROM orders WHERE status = %s",
        parameters,
        guard=production_guard(cost_threshold=100.0),
    )

    assert execution.cost_result is not None
    assert len(connection.cursors) == 2
    assert connection.cursors[0].calls[0][1] is parameters
    assert connection.cursors[1].calls[0][1] is parameters
