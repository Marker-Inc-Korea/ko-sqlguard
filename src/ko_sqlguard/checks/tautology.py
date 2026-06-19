"""Heuristic tautology detector for the ToxicSQL `OR 1=1` payload family.

Flags predicates that are constantly true: a bare TRUE, equality between two
identical literals (1=1, 'a'='a'), or an OR with a constant-true branch.
Scans WHERE / HAVING / QUALIFY and JOIN ON predicates.
"""
from __future__ import annotations

import operator

from sqlglot import exp

from ..policy import GuardPolicy
from ..result import Severity, Violation

_CMP = {
    exp.EQ: operator.eq, exp.NEQ: operator.ne,
    exp.GT: operator.gt, exp.GTE: operator.ge,
    exp.LT: operator.lt, exp.LTE: operator.le,
}


def _same_operand(a: exp.Expression, b: exp.Expression) -> bool:
    """True if two operands are the SAME column/expression (e.g. ``id`` and ``id``).

    Compares the rendered SQL after peeling parens. Used to flag self-comparisons
    (``id = id``, ``id <= id``) — a constant-true auth-bypass form — WITHOUT touching
    genuine joins like ``a.id = b.id`` where the two operands differ.
    """
    while isinstance(a, exp.Paren):
        a = a.this
    while isinstance(b, exp.Paren):
        b = b.this
    # Only column-vs-column self-reference is interesting; literal-vs-literal is
    # already handled by _lit, and self-comparison of a volatile call is not const.
    if not (isinstance(a, exp.Column) and isinstance(b, exp.Column)):
        return False
    try:
        return a.sql() == b.sql()
    except Exception:
        return False


_SELF_TRUE = (exp.EQ, exp.GTE, exp.LTE)   # x op x is TRUE for these (x not null)
_SELF_FALSE = (exp.NEQ, exp.GT, exp.LT)   # x op x is FALSE for these


def _is_null_test(node: exp.Expression) -> tuple[exp.Expression, bool] | None:
    """If ``node`` is ``x IS NULL`` / ``x IS NOT NULL`` return (x, negated) else None.

    ``x IS NOT NULL`` parses as ``Not(Is(x, Null))``.
    """
    while isinstance(node, exp.Paren):
        node = node.this
    negated = False
    if isinstance(node, exp.Not):
        negated = True
        node = node.this
        while isinstance(node, exp.Paren):
            node = node.this
    if isinstance(node, exp.Is) and isinstance(node.expression, exp.Null):
        return (node.this, negated)
    return None


def _is_null_complement(a: exp.Expression, b: exp.Expression) -> bool:
    """True for ``x IS NULL`` OR-ed with ``x IS NOT NULL`` over the IDENTICAL ``x``."""
    ta, tb = _is_null_test(a), _is_null_test(b)
    if ta is None or tb is None:
        return False
    (xa, na), (xb, nb) = ta, tb
    if na == nb:  # both IS NULL or both IS NOT NULL — not complementary
        return False
    try:
        return xa.sql() == xb.sql()
    except Exception:
        return False


def _lit(node: exp.Expression) -> tuple[str, object] | None:
    """Paren 을 벗기고 리터럴/불리언이면 (kind, value) 로 정규화. 숫자는 float 로(1=1.0 동치)."""
    while isinstance(node, exp.Paren):
        node = node.this
    if isinstance(node, exp.Boolean):
        return ("b", bool(node.this))
    if isinstance(node, exp.Literal):
        if node.is_string:
            return ("s", node.this)
        try:
            return ("n", float(node.this))
        except ValueError:
            return ("s", node.this)
    return None


# Hard recursion bound. A pathological single-line predicate (e.g. an OR/AND chain
# thousands of conjuncts deep) builds an AST tower that would overflow Python's
# C stack. We cap the constant-folding depth and return None (indeterminate — we
# simply do not claim a tautology) past the limit. The limit is far deeper than any
# human-authored predicate, and a truly hostile blob is already bounded/blocked by
# the parser, so capping here costs no real recall while keeping the check itself
# crash-proof (fail-closed, not fail-crash).
_MAX_CONST_DEPTH = 200


def _const_eval(node: exp.Expression | None, _depth: int = 0) -> bool | None:
    """상수 술어의 진리값. 컬럼 등 판정 불가면 None — '1=1','2>1','(1)=(1)','OR 1',
    'NOT 1=2','1=1.0' 같은 상수-참 우회군을 일관되게 평가한다."""
    if node is None:
        return None
    if _depth >= _MAX_CONST_DEPTH:
        return None
    if isinstance(node, exp.Paren):
        return _const_eval(node.this, _depth + 1)
    if isinstance(node, exp.Not):
        v = _const_eval(node.this, _depth + 1)
        return None if v is None else (not v)
    if isinstance(node, exp.Boolean):
        return bool(node.this)
    if isinstance(node, exp.Literal):
        if node.is_string:
            return None
        try:
            return float(node.this) != 0  # bare truthy 리터럴(OR 1)
        except ValueError:
            return None
    if isinstance(node, exp.Or):
        # `x IS NULL OR x IS NOT NULL` on the same operand spans every row -> True.
        if _is_null_complement(node.this, node.expression):
            return True
        a, b = _const_eval(node.this, _depth + 1), _const_eval(node.expression, _depth + 1)
        if a is True or b is True:
            return True
        if a is False and b is False:
            return False
        return None
    if isinstance(node, exp.And):
        a, b = _const_eval(node.this, _depth + 1), _const_eval(node.expression, _depth + 1)
        if a is False or b is False:
            return False
        if a is True and b is True:
            return True
        return None
    # x op x : self-comparison is constant regardless of x's value (modulo NULL),
    # the classic `WHERE id = id` auth-bypass. Only fires when both operands are the
    # IDENTICAL column, so genuine joins `a.id = b.id` are untouched.
    if isinstance(node, (*_SELF_TRUE, *_SELF_FALSE)) and _same_operand(
        node.this, node.expression
    ):
        return isinstance(node, _SELF_TRUE)
    # `<literal> IN (<list>)` / `<col> IN (<same col>, ...)` — membership that always
    # holds. Only constant when the LHS itself appears in the list.
    if isinstance(node, exp.In):
        items = node.expressions or []
        if items and node.args.get("query") is None:
            lhs = node.this
            lhs_lit = _lit(lhs)
            for item in items:
                if lhs_lit is not None and _lit(item) == lhs_lit:
                    return True
                if lhs_lit is None and _same_operand(lhs, item):
                    return True
        return None
    # `'a' LIKE 'a'` (equal literals, no wildcard) or `x LIKE '%'` (all-wildcard
    # pattern matches any non-null) — constant-true filter bypass.
    if isinstance(node, exp.Like):
        pat = _lit(node.expression)
        if pat is not None and pat[0] == "s":
            patstr = str(pat[1])
            if patstr.replace("%", "") == "" and patstr != "":
                return True  # '%' / '%%' matches everything (non-null)
            left = _lit(node.this)
            if (
                left is not None
                and left[0] == "s"
                and "%" not in patstr
                and "_" not in patstr
                and str(left[1]) == patstr
            ):
                return True
        if _same_operand(node.this, node.expression):
            return True  # `col LIKE col`
        return None
    for cls, op in _CMP.items():
        if isinstance(node, cls):
            lv, rv = _lit(node.this), _lit(node.expression)
            if lv is None or rv is None:
                return None
            (lk, lval), (rk, rval) = lv, rv
            if lk != rk:  # 숫자 vs 문자 등 이종 비교 — EQ=거짓, NEQ=참, 그 외 판정 보류
                if cls is exp.EQ:
                    return False
                if cls is exp.NEQ:
                    return True
                return None
            try:
                return bool(op(lval, rval))  # type: ignore[arg-type]  # same kind → comparable
            except TypeError:
                return None
    return None


def _is_const_true(node: exp.Expression | None) -> bool:
    return _const_eval(node) is True


def _predicate_roots(stmt: exp.Expression) -> list[exp.Expression]:
    roots: list[exp.Expression] = []
    for node in stmt.find_all(exp.Where, exp.Having, exp.Qualify):
        if node.this is not None:
            roots.append(node.this)
    for join in stmt.find_all(exp.Join):
        # LATERAL 조인의 'ON true' 는 PostgreSQL 필수 관용구(상관은 서브쿼리 내부에
        # 있음)라 행 필터 무력화가 아니다 → tautology 검사 제외.
        if isinstance(join.this, exp.Lateral):
            continue
        on = join.args.get("on")
        if on is not None:
            roots.append(on)
    return roots


def check_tautology(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    if not policy.block_tautology:
        return []

    violations: list[Violation] = []
    for root in _predicate_roots(stmt):
        # The whole predicate is constant-true, or any OR-branch within it is.
        hit = _is_const_true(root)
        if not hit:
            for or_node in root.find_all(exp.Or):
                if _is_const_true(or_node.this) or _is_const_true(or_node.expression):
                    hit = True
                    break
        if hit:
            violations.append(
                Violation(
                    code="tautology",
                    severity=Severity.MEDIUM,
                    reason="constant-true predicate (e.g. OR 1=1) defeats row filtering",
                    action="block",
                    fix="Remove the always-true condition.",
                )
            )
            break
    return violations
