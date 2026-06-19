"""Inferential SQLi probe detector.

Two narrow, recall-safe shapes that the tautology / catalog / function gates let
through because each individual piece parses as ordinary, well-formed SQL:

  1) UNCORRELATED-SUBQUERY PROBE -- a predicate compares an *uncorrelated* scalar
     subquery against a CONSTANT (in any surface form), e.g.

         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) > 1
         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) > -1
         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) = 1+1
         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) = CAST(1 AS INT)
         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) IS NOT NULL
         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) BETWEEN 1 AND 100
         ... WHERE username = 'admin' AND (SELECT COUNT(*) FROM users) IN (1, 2, 3)

     The subquery references no column of the outer row, so its value is a CONSTANT
     for every row -- it cannot legitimately filter the result set. It is the classic
     boolean/inferential blind-SQLi oracle (each probe leaks one bit / one value about
     hidden data). The constant RHS may be a bare Literal, a negated/arithmetic/cast
     constant, NULL, a BETWEEN range, or an IN constant-list -- all are flagged. A
     genuine analytics ``subq vs column`` / ``subq vs subq`` predicate has a
     NON-constant RHS and is left untouched. The probe runs over WHERE, HAVING, and
     JOIN..ON predicates (the same oracle works in any of them), and peels redundant
     nested ``Subquery`` wrappers so ``((SELECT (SELECT ...)))=1`` is still caught.

  2) CONSTANT-TRUTH EXISTS PROBE -- ``EXISTS (subquery)`` / ``NOT EXISTS (subquery)``
     where the subquery is UNCORRELATED, e.g.

         ... WHERE username = 'admin' AND EXISTS (SELECT * FROM users)
         ... WHERE username = 'admin' AND EXISTS (SELECT 1 FROM users WHERE id=1)
         ... WHERE username = 'admin' AND NOT EXISTS (SELECT 1 FROM users WHERE 1=2)

     ``EXISTS`` over an uncorrelated table is a constant (a non-empty table is always
     TRUE, an empty one always FALSE), so like (1) it cannot filter rows -- it is an
     injected existence oracle, even when the subquery carries its own CONSTANT filter
     (a ``WHERE id=1`` that does not correlate to the outer row). A real semi-/anti-join
     EXISTS always correlates to the outer row, so ``_is_uncorrelated`` already returns
     False for it and it stays allowed; keying solely on uncorrelation is both
     recall-safe and closes the constant-filter evasion.

All are AST-shape matches (no raw-string regex, so no ReDoS) and were verified to add
ZERO false-blocks on the external benign SQL corpora.

NOTE (needs-model, deliberately NOT a rule): a third candidate -- blocking a set-op arm
that projects a bare ``*`` (the ``SELECT * ... UNION SELECT * FROM users`` whole-row
exfiltration form) -- was evaluated and REJECTED as not recall-safe. A legitimate
``SELECT * FROM a UNION SELECT * FROM b`` over union-compatible tables is a valid
analytics pattern (the in-repo transform suite treats it as benign), so a bare-shape
rule trades recall for precision on benign UNIONs. Separating the exfil UNION from the
legitimate one needs schema/semantic context -> left to a Tier-2 model.
"""
from __future__ import annotations

from sqlglot import exp

from ..policy import GuardPolicy
from ..result import Severity, Violation

# Comparison operators whose <scalar-subquery> vs <literal> form is an inference
# oracle (each returns one bit / one value about hidden data).
_PROBE_CMP: tuple[type, ...] = (
    exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE,
)


def _unwrap_paren(node: exp.Expression | None) -> exp.Expression | None:
    seen = 0
    while isinstance(node, exp.Paren) and seen < 50:
        node = node.this
        seen += 1
    return node


def _inner_select(node: exp.Expression | None) -> exp.Select | None:
    """The Select wrapped by a (Paren-peeled) Subquery, else None.

    Peels redundant nested Subquery wrappers too: sqlglot parses ``((SELECT ...)))``
    as ``Subquery(Subquery(Select))``, so a doubly-nested scalar subquery would
    otherwise be missed. Bounded loop (<=50) keeps it ReDoS/recursion-safe.
    """
    node = _unwrap_paren(node)
    seen = 0
    while isinstance(node, exp.Subquery) and seen < 50:
        inner = node.this
        if isinstance(inner, exp.Select):
            return inner
        # Subquery wrapping another Subquery (redundant parens) — keep peeling.
        node = _unwrap_paren(inner)
        seen += 1
    return None


def _is_constant_expr(node: exp.Expression | None, _depth: int = 0) -> bool:
    """True if ``node`` is a compile-time CONSTANT with no column reference.

    Covers a bare Literal / Null / Boolean, a negated or cast constant
    (``-1``, ``CAST(1 AS INT)``), and arithmetic over constants (``1+1``,
    ``2*3-1``). An uncorrelated scalar subquery compared against any such constant
    is a blind-SQLi oracle regardless of the constant's surface form. A column (or
    anything containing one) is NOT constant, so legitimate ``subq vs column`` and
    ``subq vs subq`` analytics predicates are untouched. Bounded depth = ReDoS-safe.
    """
    if node is None or _depth >= 50:
        return False
    node = _unwrap_paren(node)
    if isinstance(node, (exp.Literal, exp.Null, exp.Boolean)):
        return True
    if isinstance(node, exp.Neg):
        return _is_constant_expr(node.this, _depth + 1)
    if isinstance(node, exp.Cast):
        return _is_constant_expr(node.this, _depth + 1)
    if isinstance(node, (exp.Add, exp.Sub, exp.Mul, exp.Div)):
        return _is_constant_expr(node.this, _depth + 1) and _is_constant_expr(
            node.expression, _depth + 1
        )
    return False


def _subquery_sources(sel: exp.Select) -> set[str]:
    """Lower-cased table names / aliases / CTE names defined INSIDE the subquery."""
    src: set[str] = set()
    for table in sel.find_all(exp.Table):
        if table.name:
            src.add(table.name.lower())
        alias = table.alias
        if alias:
            src.add(alias.lower())
    for cte in sel.find_all(exp.CTE):
        if cte.alias:
            src.add(cte.alias.lower())
    return src


def _is_uncorrelated(sel: exp.Select) -> bool:
    """True if every qualified column in the subquery binds to a source defined
    inside the subquery -- i.e. it references no outer-row column (no correlation).

    Fail-closed on analysis: an outer-qualified column makes it correlated (legit),
    so an attacker cannot dodge by adding a spurious outer reference -- that merely
    makes the subquery NOT-flagged, never an escalation."""
    inside = _subquery_sources(sel)
    for col in sel.find_all(exp.Column):
        qualifier = (col.table or "").lower()
        if qualifier and qualifier not in inside:
            return False
    return True


def _uncorrelated_scalar_subq(node: exp.Expression | None) -> bool:
    """True if ``node`` is an uncorrelated scalar subquery (Paren/Subquery-peeled)."""
    inner = _inner_select(node)
    return inner is not None and _is_uncorrelated(inner)


def _scalar_subquery_probe(root: exp.Expression) -> bool:
    """An uncorrelated scalar subquery compared against a CONSTANT (any surface form).

    Shapes flagged (subquery on either side where a comparison applies):
      * <subq> {= != > >= < <=} <const>      const = Literal | Null | Boolean |
                                              Neg/Cast/arithmetic over constants.
      * <subq> BETWEEN <const> AND <const>
      * <subq> IN (<const>, ...)             constant value-list, NOT a sub-SELECT.
      * <subq> IS [NOT] NULL                 (an uncorrelated scalar is never NULL
                                              by row, so this leaks one bit too).
    Every one is a blind-SQLi oracle: the subquery is constant for every row, so it
    cannot legitimately filter. A genuine ``subq vs column`` / ``subq vs subq``
    analytics predicate has a non-constant RHS and is left untouched.
    """
    # (a) binary comparisons: <subq> op <const>  (or  <const> op <subq>)
    for cmp in root.find_all(*_PROBE_CMP):
        for side, other in ((cmp.this, cmp.expression), (cmp.expression, cmp.this)):
            if _uncorrelated_scalar_subq(side) and _is_constant_expr(other):
                return True
    # (b) <subq> BETWEEN <const> AND <const>
    for bt in root.find_all(exp.Between):
        if (
            _uncorrelated_scalar_subq(bt.this)
            and _is_constant_expr(bt.args.get("low"))
            and _is_constant_expr(bt.args.get("high"))
        ):
            return True
    # (c) <subq> IN (<const-list>)  — a constant value list, never a sub-SELECT.
    for in_node in root.find_all(exp.In):
        if in_node.args.get("query") is not None:
            continue  # IN (SELECT ...) is a normal semi-join, not a probe
        items = in_node.expressions or []
        if (
            items
            and _uncorrelated_scalar_subq(in_node.this)
            and all(_is_constant_expr(it) for it in items)
        ):
            return True
    # (d) <subq> IS [NOT] NULL  — parses as Is(subq, Null), optionally under Not.
    for is_node in root.find_all(exp.Is):
        if isinstance(is_node.expression, exp.Null) and _uncorrelated_scalar_subq(
            is_node.this
        ):
            return True
    return False


def _constant_exists_probe(root: exp.Expression) -> bool:
    """EXISTS / NOT EXISTS over an UNCORRELATED subquery (constant-truth oracle).

    An EXISTS whose subquery references no outer-row column is a constant (a
    non-empty table is always TRUE, an empty one always FALSE) — an injected
    existence oracle, even if the subquery carries its own constant WHERE
    (``EXISTS (SELECT 1 FROM users WHERE id=1)``). A genuine semi-/anti-join EXISTS
    always correlates to the outer row, so ``_is_uncorrelated`` already returns
    False for it and it stays allowed; keying solely on uncorrelation is therefore
    recall-safe and closes the constant-filter evasion.
    """
    for ex in root.find_all(exp.Exists):
        inner = ex.this
        if isinstance(inner, exp.Subquery):
            inner = inner.this
        if isinstance(inner, exp.Select) and _is_uncorrelated(inner):
            return True
    return False


def _predicate_roots(stmt: exp.Expression) -> list[exp.Expression]:
    """WHERE / HAVING predicate bodies and JOIN..ON predicates.

    Mirrors checks/tautology.py: an inference probe placed in a HAVING or a
    JOIN..ON predicate is the same oracle, just outside the WHERE. LATERAL ``ON
    true`` is a Postgres idiom (correlation lives inside the subquery), so it is
    excluded exactly as the tautology check does.
    """
    roots: list[exp.Expression] = []
    for node in stmt.find_all(exp.Where, exp.Having):
        if node.this is not None:
            roots.append(node.this)
    for join in stmt.find_all(exp.Join):
        if isinstance(join.this, exp.Lateral):
            continue
        on = join.args.get("on")
        if on is not None:
            roots.append(on)
    return roots


def check_inference(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    if not policy.block_inference_probe:
        return []

    for root in _predicate_roots(stmt):
        if _scalar_subquery_probe(root) or _constant_exists_probe(root):
            return [
                Violation(
                    code="inference_probe",
                    severity=Severity.MEDIUM,
                    reason="uncorrelated subquery compared to a constant (or constant-truth "
                    "EXISTS) in a row filter is an inferential blind-SQLi oracle, not a "
                    "real WHERE condition",
                    action="block",
                    fix="Remove the constant subquery probe; a WHERE condition must "
                    "reference the row being filtered.",
                )
            ]

    return []
