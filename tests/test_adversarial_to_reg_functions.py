"""적대적 입력 회귀 테스트: to_reg*() FUNCTION family asymmetry.

One adversarial-input miss under the DEFAULT read-only policy (allowed_tables=None):

  checks/functions.py blocks the cast form for all 11 OID-registry pseudo-types
  (_BLOCKED_CAST_TYPES: regclass/regrole/regoper/regconfig/...), but the FUNCTION
  denylist DEFAULT_BLOCKED_FUNCTIONS enumerated only 4 of the 11 to_reg*() helpers
  (to_regclass / to_regnamespace / to_regtype / to_regproc). The other 7
  (to_regrole / to_regprocedure / to_regoper / to_regoperator / to_regconfig /
  to_regdictionary / to_regcollation) take a STRING LITERAL and reference no
  catalog table, so the table allowlist never engages and the function denylist
  is the only defense — they PASSED. Fix: add the 7 missing names to
  DEFAULT_BLOCKED_FUNCTIONS to restore symmetry with _BLOCKED_CAST_TYPES.

CONTROL families assert recall safety: benign reg-prefixed / to_-prefixed
functions (regexp_*, to_char/to_number/to_date/to_timestamp) and a `region`
column stay non-BLOCK, and normal JOIN/CTE/aggregate queries are unaffected.
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()


# --- Fix: the 7 previously-missing to_reg*() OID-registry probes -----------------

TO_REG_PROBES = [
    "SELECT to_regrole('postgres')",
    "SELECT to_regprocedure('foo(int)')",
    "SELECT to_regoper('+')",
    "SELECT to_regoperator('+(int,int)')",
    "SELECT to_regconfig('english')",
    "SELECT to_regdictionary('english')",
    "SELECT to_regcollation('en_US')",
    # the 4 already on the denylist must keep blocking (symmetry intact)
    "SELECT to_regclass('users')",
    "SELECT to_regnamespace('public')",
    "SELECT to_regtype('int')",
    "SELECT to_regproc('now')",
    # casing must not smuggle it past (matched on the AST name, case-folded)
    "SELECT TO_REGROLE('postgres')",
    "SELECT To_RegConfig('english')",
    # hidden in a subquery / WHERE — still blocks (whole-tree find_all)
    "SELECT o.id FROM orders o WHERE to_regrole('postgres') IS NOT NULL",
    # hidden in a UNION arm — independent of table allowlist, still blocks
    "SELECT name FROM orders UNION SELECT to_regprocedure('f(int)')::text",
]


@pytest.mark.parametrize("sql", TO_REG_PROBES, ids=lambda s: s[:52])
def test_to_reg_function_family_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "blocked_function" for v in r.violations), [
        v.code for v in r.violations
    ]


def test_to_reg_function_symmetric_with_cast_form() -> None:
    # Every reg* pseudo-type blocked as a cast must also block as a to_reg*()
    # function — that is the symmetry the fix restores.
    reg_types = [
        "regclass", "regproc", "regprocedure", "regoper", "regoperator",
        "regtype", "regrole", "regnamespace", "regconfig", "regdictionary",
        "regcollation",
    ]
    for t in reg_types:
        cast = check(f"SELECT 'x'::{t}", policy=DEFAULT)
        func = check(f"SELECT to_{t}('x')", policy=DEFAULT)
        assert cast.verdict is Verdict.BLOCK, f"cast ::{t} should block"
        assert func.verdict is Verdict.BLOCK, f"function to_{t}() should block"


# --- CONTROL: recall safety (benign reg-/to_-prefixed funcs stay non-BLOCK) ------

BENIGN_NEAR_MISS = [
    # regexp_* are ordinary string functions, NOT OID-registry probes
    "SELECT regexp_replace(name, 'a', 'b') FROM users",
    "SELECT regexp_matches(name, '[0-9]+') FROM users",
    "SELECT regexp_split_to_array(name, ',') FROM users",
    "SELECT regexp_split_to_table(name, ',') FROM users",
    "SELECT regexp_count(name, 'x') FROM users",
    # to_* formatting/conversion helpers are not to_reg*()
    "SELECT to_char(created_at, 'YYYY-MM-DD') FROM orders",
    "SELECT to_number('123', '999') FROM orders",
    "SELECT to_date('2024-01-01', 'YYYY-MM-DD') FROM orders",
    "SELECT to_timestamp(1700000000) FROM orders",
    "SELECT to_hex(255)",
    "SELECT to_ascii('abc')",
    # a column literally named region/registration must not be caught
    "SELECT region, COUNT(*) FROM sales GROUP BY region",
    "SELECT registration_date FROM users",
    # normal JOIN / CTE / aggregate stay non-BLOCK
    "SELECT o.id, c.name FROM orders o JOIN customers c ON o.cid = c.id",
    "WITH t AS (SELECT id FROM orders) SELECT * FROM t",
    "SELECT SUM(amount), AVG(amount) FROM orders GROUP BY status",
]


@pytest.mark.parametrize("sql", BENIGN_NEAR_MISS, ids=lambda s: s[:52])
def test_benign_near_miss_not_blocked(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is not Verdict.BLOCK, [v.model_dump() for v in r.violations]
    assert not any(v.code == "blocked_function" for v in r.violations), [
        v.code for v in r.violations
    ]


def test_to_reg_blocks_even_with_prefix_gate_off() -> None:
    # to_reg*() carry no pg_ prefix, so they rely on the enumerated denylist, not
    # the pg_*-function prefix gate. They must block even with that gate disabled.
    pol = GuardPolicy(block_pg_function_prefix=False)
    for sql in (
        "SELECT to_regrole('postgres')",
        "SELECT to_regconfig('english')",
        "SELECT to_regcollation('en_US')",
    ):
        assert check(sql, policy=pol).verdict is Verdict.BLOCK, sql
