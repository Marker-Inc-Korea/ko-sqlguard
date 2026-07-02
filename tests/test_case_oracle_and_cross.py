"""Blind-SQLi CASE oracle (lit-op-lit anywhere) + constrained-CROSS relaxation.

- CASE oracle: `SELECT CASE WHEN 1=1 THEN ... END` is a constant-vs-constant test injected
  OUTSIDE the WHERE/HAVING predicate roots that tautology/inference scan — a blind oracle.
  Whole-statement scan flags any literal-vs-literal comparison; benign analytics use
  column-vs-literal / column-vs-column, so they are untouched.
- Constrained CROSS: `a CROSS JOIN b WHERE a.id=b.id` is functionally an inner join, so it
  is routed through the connectivity graph rather than blocked unconditionally; an
  unconstrained CROSS (no cross-table equality) is still blocked.
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()


# --- CASE / projection constant-vs-constant oracle -> BLOCK ------------------------
CASE_ORACLE = [
    "SELECT CASE WHEN 1=1 THEN name ELSE NULL END FROM products",
    "SELECT CASE WHEN 'a'='b' THEN 1 ELSE 1/0 END FROM t",
    "SELECT * FROM generate_series(1,10) g WHERE CASE WHEN 1=1 THEN true ELSE false END",
    "SELECT id, CASE WHEN 2-1=1 THEN 'y' ELSE 'n' END FROM users",
    "SELECT name FROM t WHERE id = 5 OR (CASE WHEN 5>4 THEN 1 ELSE 0 END) = 1",
]


@pytest.mark.parametrize("q", CASE_ORACLE, ids=lambda s: s[:34])
def test_case_oracle_blocked(q: str) -> None:
    assert check(q, DEFAULT).verdict is Verdict.BLOCK, q


# --- benign column-vs-literal / column-vs-column CASE -> not BLOCK -----------------
CASE_BENIGN = [
    "SELECT CASE WHEN status='active' THEN 1 ELSE 0 END FROM users",
    "SELECT SUM(CASE WHEN qty > 0 THEN price ELSE 0 END) FROM orders",
    "SELECT CASE WHEN a.x = b.y THEN 1 ELSE 0 END FROM a JOIN b ON a.id = b.id",
]


@pytest.mark.parametrize("q", CASE_BENIGN, ids=lambda s: s[:34])
def test_case_benign_not_blocked(q: str) -> None:
    assert check(q, DEFAULT).verdict is not Verdict.BLOCK, q


# --- constrained CROSS relaxation --------------------------------------------------
def test_constrained_cross_join_allowed() -> None:
    # cross-table equality constrains the product -> equivalent to an inner join
    assert check("SELECT a.x, b.y FROM a CROSS JOIN b WHERE a.id = b.id", DEFAULT).verdict \
        is not Verdict.BLOCK


CROSS_ATTACK = [
    "SELECT * FROM users CROSS JOIN secrets",          # unconstrained CROSS
    "SELECT a.x FROM a CROSS JOIN b",                  # unconstrained CROSS
    "SELECT * FROM a, b",                              # comma cartesian
    "SELECT * FROM a, b, c WHERE a.id = b.id",         # partial-link bypass
]


@pytest.mark.parametrize("q", CROSS_ATTACK, ids=lambda s: s[:34])
def test_unconstrained_cross_still_blocked(q: str) -> None:
    assert check(q, DEFAULT).verdict is Verdict.BLOCK, q


# --- CROSS/comma + OR-loosened / spoofed equality → still BLOCK (near-cartesian) -----
OR_SPOOF_CARTESIAN = [
    "SELECT * FROM big1 CROSS JOIN big2 WHERE big1.id=big2.id OR big2.active=1",
    "SELECT * FROM a, b WHERE a.id=b.id OR b.active=1",
    "SELECT * FROM a CROSS JOIN b WHERE NOT (a.id=b.id)",
]


@pytest.mark.parametrize("q", OR_SPOOF_CARTESIAN, ids=lambda s: s[:40])
def test_or_spoofed_equality_still_blocked(q: str) -> None:
    # only AND-connected equalities constrain the product; an OR/NOT-buried
    # equality must not mark the CROSS/comma product as constrained.
    assert check(q, DEFAULT).verdict is Verdict.BLOCK, q


AND_CONSTRAINED_OK = [
    "SELECT * FROM a CROSS JOIN b WHERE a.id=b.id AND a.x > 5",
    "SELECT * FROM a, b WHERE a.id=b.id AND (b.x=1 OR b.y=2)",
]


@pytest.mark.parametrize("q", AND_CONSTRAINED_OK, ids=lambda s: s[:40])
def test_and_constrained_not_blocked(q: str) -> None:
    assert check(q, DEFAULT).verdict is not Verdict.BLOCK, q
