"""적대적 입력 회귀 테스트: tautology / cartesian heuristic 우회 모음.

Each BLOCK case is a constant-true or unconstrained-product bypass that slipped
through (returned TRANSFORM). Each ALLOW look-alike guards recall — a benign query
that the broadened heuristic must NOT over-block.
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()


def _verdict(sql: str) -> Verdict:
    return check(sql, policy=DEFAULT).verdict


# --- tautology gaps (constant-true predicates) ----------------------------------

TAUTOLOGY_BLOCK = [
    "SELECT * FROM users WHERE id = id",                          # self-equality
    "SELECT * FROM users WHERE id <= id",                         # self <= self
    "SELECT * FROM users WHERE id >= id",
    "SELECT * FROM users WHERE col IS NULL OR col IS NOT NULL",   # null-complement OR
    "SELECT * FROM users WHERE 1 IN (1, 2)",                      # literal in list
    "SELECT * FROM users WHERE 'a' IN ('a', 'b')",
    "SELECT * FROM users WHERE col IN (col)",                     # self-membership
    "SELECT * FROM users WHERE 'a' LIKE 'a'",                     # equal literals
    "SELECT * FROM users WHERE name LIKE '%'",                    # all-wildcard pattern
    "SELECT * FROM users WHERE active = 1 OR id = id",            # OR-branch tautology
]


@pytest.mark.parametrize("sql", TAUTOLOGY_BLOCK, ids=lambda s: s[:48])
def test_tautology_gaps_block(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "tautology" for v in r.violations), [v.code for v in r.violations]


TAUTOLOGY_ALLOW = [
    "SELECT * FROM a JOIN b ON a.id = b.id",                      # different columns
    "SELECT * FROM a JOIN b ON a.id < b.id",
    "SELECT * FROM users WHERE status IN ('active', 'pending')",  # real membership filter
    "SELECT * FROM users WHERE 3 IN (1, 2)",                      # literal NOT in list
    "SELECT * FROM users WHERE name LIKE 'A%'",                   # real prefix pattern
    "SELECT * FROM users WHERE 'a' LIKE 'b'",                     # mismatched literals
    "SELECT * FROM users WHERE col IS NOT NULL",                  # ordinary null check
    "SELECT * FROM users WHERE a IS NULL OR b IS NOT NULL",       # different operands
    "SELECT * FROM users WHERE id = 5",
]


@pytest.mark.parametrize("sql", TAUTOLOGY_ALLOW, ids=lambda s: s[:48])
def test_tautology_lookalikes_allowed(sql: str) -> None:
    assert _verdict(sql) is not Verdict.BLOCK, sql


# --- cartesian gaps (disconnected relation graph) -------------------------------

CARTESIAN_BLOCK = [
    "SELECT * FROM a, b, c, d WHERE a.id = b.id",                 # c,d dangle (repro)
    "SELECT * FROM a, b, c WHERE a.id = b.id AND a.id = 5",       # c dangles
    "SELECT * FROM orders, customers",                            # no link at all
    "SELECT * FROM (SELECT 1 x) a CROSS JOIN (SELECT 2 y) b",     # derived cross
    "WITH a AS (SELECT 1 x), b AS (SELECT 2 y) SELECT * FROM a, b",  # cte comma
]


@pytest.mark.parametrize("sql", CARTESIAN_BLOCK, ids=lambda s: s[:48])
def test_cartesian_gaps_block(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "cartesian" for v in r.violations), [v.code for v in r.violations]


CARTESIAN_ALLOW = [
    "SELECT * FROM a, b WHERE a.id = b.id",                                   # linked pair
    "SELECT * FROM a, b, c, d WHERE a.id=b.id AND b.id=c.id AND c.id=d.id",   # full chain
    "SELECT * FROM a, b, c WHERE a.id = b.id AND a.id = c.id",                # star-linked
    "SELECT * FROM a JOIN b ON a.id = b.id",                                  # explicit join
    "SELECT * FROM a, b JOIN c ON b.id = c.id WHERE a.id = b.id",             # mixed, linked
    "SELECT * FROM orders WHERE id = 1",                                      # single table
]


@pytest.mark.parametrize("sql", CARTESIAN_ALLOW, ids=lambda s: s[:48])
def test_cartesian_lookalikes_allowed(sql: str) -> None:
    assert _verdict(sql) is not Verdict.BLOCK, sql
