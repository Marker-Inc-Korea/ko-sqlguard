"""Adversarial regression tests for the inferential-SQLi probe gap (checks/inference.py).

Each BLOCK case is an uncorrelated scalar-subquery / constant-truth-EXISTS probe
that slipped the tautology gate (returned TRANSFORM) on the external SQLi corpora
(kaburakuria/zrmarine). Each ALLOW look-alike guards recall: a benign analytics
query whose subquery is CORRELATED, FILTERED, or compared subquery-to-subquery, so
the narrow probe rule must NOT over-block it.
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()


# --- inferential probes (uncorrelated subquery vs constant / constant EXISTS) ----

PROBE_BLOCK = [
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users)>1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users)=1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT MAX(id) FROM users)=1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT MIN(id) FROM users)=1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT AVG(id) FROM users)=1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT SUM(id) FROM users)=1",
    "SELECT * FROM users WHERE username='admin' AND EXISTS (SELECT * FROM users)",
    "SELECT * FROM users WHERE username='admin' AND NOT EXISTS (SELECT * FROM users)",
    # comparison may sit on either side of the operator
    "SELECT * FROM users WHERE username='admin' AND 1=(SELECT MAX(id) FROM users)",
    # RHS-surface evasion: the constant RHS may be negated / arithmetic / cast / NULL / range / list
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users) > -1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users) = 1+1",
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users) = CAST(1 AS INT)",
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users) IS NOT NULL",
    "SELECT * FROM users WHERE username='admin' AND (SELECT MAX(id) FROM users) IS NULL",
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users) BETWEEN 1 AND 100",
    "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users) IN (1, 2, 3)",
    # scope evasion: probe in HAVING / JOIN-ON instead of WHERE
    "SELECT dept, COUNT(*) FROM users GROUP BY dept HAVING (SELECT COUNT(*) FROM secrets) > 0",
    "SELECT * FROM users u JOIN orders o ON (SELECT COUNT(*) FROM secrets) > 0",
    # constant-truth EXISTS even with a constant (non-correlated) filter
    "SELECT * FROM users WHERE username='admin' AND EXISTS (SELECT 1 FROM users WHERE id=1)",
    "SELECT * FROM users WHERE username='admin' AND NOT EXISTS (SELECT 1 FROM users WHERE 1=2)",
    # doubly-nested scalar subquery vs literal (Subquery(Subquery(...)))
    "SELECT * FROM users WHERE username='admin' AND ((SELECT (SELECT COUNT(*) FROM users)))=1",
]


@pytest.mark.parametrize("sql", PROBE_BLOCK, ids=lambda s: s[-40:])
def test_inference_probe_block(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "inference_probe" for v in r.violations), [v.code for v in r.violations]


# --- benign look-alikes that MUST stay allowed (recall safety) -------------------

PROBE_ALLOW = [
    # correlated scalar subquery (references the outer row) -- legitimate filter
    "SELECT * FROM users u WHERE u.dept_id = (SELECT d.id FROM depts d WHERE d.name = u.dept)",
    # subquery compared to ANOTHER subquery (analytics), not to a bare constant
    "SELECT policy FROM analysis GROUP BY policy "
    "HAVING COUNT(DISTINCT dept) = (SELECT COUNT(DISTINCT dept) FROM org)",
    # correlated EXISTS semi-join
    "SELECT * FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)",
    # correlated anti-join EXISTS (real dedup pattern; references the outer row)
    "SELECT * FROM staging s WHERE NOT EXISTS (SELECT 1 FROM final f WHERE f.id = s.id)",
    # scalar subquery in the SELECT list (not a row filter) -- not an oracle
    "SELECT id, (SELECT COUNT(*) FROM logs) AS total FROM users WHERE id = 5",
    # ordinary single-table filter
    "SELECT * FROM users WHERE id = 5",
    # IN-subquery membership (handled by tautology/allowlist, not a constant probe)
    "SELECT MIN(amount) FROM donors WHERE donor_id IN (SELECT donor_id FROM gifts)",
    # non-constant RHS shapes must stay allowed:
    # subquery compared to a COLUMN (not a constant) -- legitimate analytics filter
    "SELECT o.id FROM orders o WHERE o.total > (SELECT avg(total) FROM orders)",
    # HAVING subquery-vs-subquery (both sides non-constant)
    "SELECT dept, COUNT(*) FROM u GROUP BY dept "
    "HAVING (SELECT COUNT(*) FROM o WHERE o.d=u.d) > (SELECT AVG(c) FROM s)",
    # BETWEEN whose bounds reference the outer row (non-constant) -- not a probe
    "SELECT o.id FROM orders o WHERE (SELECT max(total) FROM orders) BETWEEN o.lo AND o.hi",
    # IN whose members reference the outer row (non-constant list) -- not a probe
    "SELECT o.id FROM orders o WHERE (SELECT max(total) FROM orders) IN (o.a, o.b)",
    # uncorrelated subquery IN (SELECT ...) semi-join -- query arg, not a const-list
    "SELECT o.id FROM orders o WHERE o.id IN (SELECT id FROM customers)",
]


@pytest.mark.parametrize("sql", PROBE_ALLOW, ids=lambda s: s[:48])
def test_inference_probe_lookalikes_allowed(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert not any(v.code == "inference_probe" for v in r.violations), (
        sql,
        [v.code for v in r.violations],
    )


def test_inference_probe_can_be_disabled() -> None:
    sql = "SELECT * FROM users WHERE username='admin' AND (SELECT COUNT(*) FROM users)>1"
    relaxed = GuardPolicy(block_inference_probe=False)
    r = check(sql, policy=relaxed)
    assert not any(v.code == "inference_probe" for v in r.violations)
