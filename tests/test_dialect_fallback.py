"""다이얼렉트 폴백 (opt-in) — 기본은 postgres fail-closed, 명시 설정 시 다중 다이얼렉트.

기본값(`fallback_dialects=()`)은 postgres 전용 fail-closed 를 유지(비-postgres 구문은 잘못
생성된 SQL 일 가능성이 커 BLOCK 이 올바른 방어 — attack recall 보존). MySQL/MSSQL 입력이 정상인
환경은 ``dialect=`` 또는 ``fallback_dialects=`` 로 명시적으로 켠다. 위험 denylist 는 cross-dialect.
"""
from __future__ import annotations

import sqlglot

from ko_sqlguard import Guard, GuardPolicy, Verdict, check

G = Guard()  # 기본(postgres, 폴백 없음)
GFB = Guard(GuardPolicy(fallback_dialects=("mysql", "tsql", "sqlite")))  # 폴백 명시


def _pg_fails(sql: str) -> bool:
    try:
        sqlglot.parse(sql, read="postgres")
        return False
    except Exception:
        return True


# --- 기본: 비-postgres 구문은 fail-closed (회귀 없음) -----------------------------
def test_default_fail_closed_on_nonpostgres() -> None:
    sql = "SELECT `name` FROM `users`"
    assert _pg_fails(sql)
    r = G.check(sql)
    assert r.verdict is Verdict.BLOCK
    assert any(v.code == "parse_error" for v in r.violations)


def test_postgres_unchanged_no_regression() -> None:
    assert check("SELECT * FROM users").verdict is Verdict.TRANSFORM
    assert check("DROP TABLE users").verdict is Verdict.BLOCK
    assert check("DELETE FROM users").verdict is Verdict.BLOCK


# --- opt-in 폴백: MySQL/MSSQL 정상 구문 과탐 방지 ----------------------------------
def test_mysql_backtick_with_fallback_not_overblocked() -> None:
    sql = "SELECT `name` FROM `users` WHERE id = 1"
    assert _pg_fails(sql)
    r = GFB.check(sql)
    assert r.verdict is not Verdict.BLOCK
    assert all(v.code != "parse_error" for v in r.violations)


def test_mssql_top_with_fallback_not_overblocked() -> None:
    sql = "SELECT TOP 10 * FROM users"
    assert _pg_fails(sql)
    assert GFB.check(sql).verdict is not Verdict.BLOCK


def test_cross_dialect_danger_still_blocked_under_fallback() -> None:
    # 폴백을 켜도 위험 denylist 는 그대로 — sleep/waitfor 차단
    assert GFB.check("SELECT * FROM users WHERE id = 1 OR sleep(5) = 0").verdict is Verdict.BLOCK
    assert GFB.check("WAITFOR DELAY '0:0:5'").verdict is Verdict.BLOCK


def test_garbage_blocked_in_any_mode() -> None:
    for g in (G, GFB):
        r = g.check("@#$ this is not sql at all !!!")
        assert r.verdict is Verdict.BLOCK
        assert any(v.code == "parse_error" for v in r.violations)


def test_primary_dialect_override_mysql() -> None:
    # MySQL 배포: 기본 dialect 를 mysql 로 (폴백 없이도 MySQL 구문 정상 파싱)
    g = Guard(GuardPolicy(dialect="mysql"))
    assert g.check("SELECT `c` FROM `t` WHERE id = 1").verdict is not Verdict.BLOCK
    assert g.check("DROP TABLE t").verdict is Verdict.BLOCK
