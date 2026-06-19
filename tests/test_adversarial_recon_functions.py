"""적대적 입력 회귀: identity / version / schema / txid recon family.

captured misses under the DEFAULT read-only policy (allowed_tables=None):

  checks/functions.py blocked the dangerous-built-in denylist and the pg_* prefix
  gate, but the no-arg/idempotent server-fingerprint family PASSED:
      current_database() / current_user / session_user / version() / txid_current()
  These take NO table reference, so the table allowlist never engages and the
  function denylist is the only defense. Two parse shapes were both unguarded:

    * typed/Anonymous Func nodes — current_database()/current_user/version()/
      current_schema()/current_catalog()/txid_current()/... — version() resolves to
      the typed CurrentVersion node whose sql_name() is "current_version".
    * bare SQL-standard keywords with NO parentheses — `SELECT current_role` /
      `SELECT user` — which sqlglot parses to an unqualified exp.Column, so the
      Func loop never sees them.

  Fix: enumerate the recon names in DEFAULT_BLOCKED_FUNCTIONS (both spellings of
  version) so the Func loop catches every parenthesised form, AND add a bare-keyword
  exp.Column scan in checks/functions.py that fires ONLY when the column is
  unqualified AND unquoted.

CONTROL families assert recall safety: temporal/type built-ins that resolve to
DISTINCT AST names (now()/current_date/current_timestamp/pg_typeof) stay PASS, and
real columns named user / version / current_role (qualified or quoted) stay
non-BLOCK, as do normal JOIN/CTE/aggregate queries.
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()


# --- Fix: the identity/version/schema/txid recon family now BLOCKS ---------------

RECON_PROBES = [
    # parenthesised function forms (typed + Anonymous nodes)
    "SELECT current_database()",
    "SELECT version()",
    "SELECT current_schema()",
    "SELECT current_schemas(true)",
    "SELECT current_query()",
    "SELECT txid_current()",
    "SELECT txid_current_snapshot()",
    "SELECT txid_status(1)",
    "SELECT pg_current_xact_id()",
    "SELECT pg_current_snapshot()",
    "SELECT user()",
    # niladic forms that parse to a typed Func node (no parens)
    "SELECT current_user",
    "SELECT session_user",
    "SELECT current_catalog",
    "SELECT current_schema",
    # bare SQL-standard keywords that parse to an UNQUALIFIED exp.Column
    "SELECT user",
    "SELECT current_role",
    # casing must not smuggle past (matched on the case-folded AST name)
    "SELECT CURRENT_USER",
    "SELECT Current_Role",
    "SELECT USER",
    "SELECT Version()",
    # hidden in WHERE / subquery — whole-tree find_all still catches it
    "SELECT o.id FROM orders o WHERE current_user = 'admin'",
    # hidden in a UNION arm — independent of any table allowlist
    "SELECT name FROM orders UNION SELECT current_database()",
    # multiple recon calls in one statement
    "SELECT current_user, version()",
]


@pytest.mark.parametrize("sql", RECON_PROBES, ids=lambda s: s[:52])
def test_recon_family_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "blocked_function" for v in r.violations), [
        v.code for v in r.violations
    ]


def test_version_both_spellings_block() -> None:
    # version() parses to the typed CurrentVersion node (sql_name "current_version"),
    # so BOTH names must be on the denylist; verify the function form blocks.
    assert check("SELECT version()", policy=DEFAULT).verdict is Verdict.BLOCK
    assert check("SELECT VERSION()", policy=DEFAULT).verdict is Verdict.BLOCK


# --- CONTROL: recall safety (temporal/type built-ins stay PASS) ------------------

BENIGN_NEAR_MISS = [
    # temporal / type built-ins resolve to DISTINCT AST names — not recon
    "SELECT now()",
    "SELECT current_date",
    "SELECT current_timestamp",
    "SELECT current_date, current_timestamp FROM orders",
    "SELECT pg_typeof(1)",
    "SELECT pg_typeof(now())",
    # real columns named user / version / current_role: QUALIFIED -> a column ref
    "SELECT o.user FROM orders o",
    "SELECT o.version FROM app_releases o",
    "SELECT t.current_role FROM roles t",
    # real columns: QUOTED identifier -> not the keyword form
    'SELECT "user" FROM orders',
    'SELECT "current_role" FROM roles',
    # ordinary user_*/version columns must not be caught (exact-name match)
    "SELECT user_id, user_name FROM users",
    "SELECT version FROM app_releases",
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


def test_bare_keyword_recon_blocks_with_prefix_gate_off() -> None:
    # The recon family is enumerated in the function denylist, not the pg_* prefix
    # gate, so it must block even with that gate disabled.
    pol = GuardPolicy(block_pg_function_prefix=False)
    for sql in (
        "SELECT current_user",
        "SELECT user",
        "SELECT current_role",
        "SELECT version()",
        "SELECT current_database()",
    ):
        assert check(sql, policy=pol).verdict is Verdict.BLOCK, sql
