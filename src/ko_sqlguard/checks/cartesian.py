"""Detect unconstrained cartesian products at the top level of a read query.

An explicit CROSS JOIN is always flagged (it is a cartesian product by
definition). For implicit comma joins we build a connectivity graph of the
relations: relations linked (transitively) by a cross-table join predicate are
constrained, so legitimate old-style joins (`FROM a, b WHERE a.id = b.id`) pass.
The query is flagged when the relations split into MORE THAN ONE connected
component — i.e. at least one pair of relations has no join condition between
them, so their product is unconstrained. This catches the partial-link bypass
`FROM a, b, c, d WHERE a.id = b.id` (a-b linked; c and d dangle) that a simple
">= 2 qualifiers in WHERE" heuristic missed.
"""
from __future__ import annotations

from sqlglot import exp

from ..policy import GuardPolicy
from ..result import Severity, Violation


def _top_selects(stmt: exp.Expression) -> list[exp.Select]:
    if isinstance(stmt, exp.Select):
        return [stmt]
    if isinstance(stmt, (exp.Union, exp.Intersect, exp.Except)):
        return [s for s in (stmt.this, stmt.expression) if isinstance(s, exp.Select)]
    if isinstance(stmt, exp.Subquery) and isinstance(stmt.this, exp.Select):
        return [stmt.this]
    return []


class _DSU:
    """Tiny union-find over relation labels for connectivity checks."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        self.parent[self.find(a)] = self.find(b)

    def components(self, labels: set[str]) -> int:
        return len({self.find(x) for x in labels})


def _relation_label(rel: exp.Expression) -> str | None:
    """A stable lower-cased label (alias or name) for a FROM/JOIN relation."""
    name = rel.alias_or_name
    return name.lower() if name else None


def _and_equalities(pred: exp.Expression) -> list[exp.EQ]:
    """EQ nodes joined to the predicate root through AND (and Paren) ONLY.

    Only an equality that holds for EVERY row constrains a cartesian product. An
    equality buried under an OR (or NOT) branch does not — rows can satisfy the
    other branch — so ``a.id=b.id OR b.active=1`` must NOT link a↔b (that would let
    a near-cartesian through). We therefore descend only AND/Paren from the root and
    stop at OR/NOT, collecting the top-level conjunct equalities. (Bounded walk.)
    """
    out: list[exp.EQ] = []
    stack = [pred]
    seen = 0
    while stack and seen < 10000:
        n = stack.pop(); seen += 1
        if isinstance(n, exp.Paren):
            stack.append(n.this)
        elif isinstance(n, exp.And):
            stack.append(n.this); stack.append(n.expression)
        elif isinstance(n, exp.EQ):
            out.append(n)
        # OR / NOT / others → do not descend (their equalities don't hold for all rows)
    return out


def _cross_qualifier_edges(pred: exp.Expression | None, dsu: _DSU) -> None:
    """Union DISTINCT table qualifiers compared in a top-level (AND-connected) equality.

    Only equality (a.x = b.y) links relations for join purposes; an inequality or
    single-table predicate does not constrain the product. Crucially, only equalities
    that hold for every row (AND-connected to the root, not under an OR/NOT) count —
    otherwise a spoofed ``a.id=b.id OR b.active=1`` would falsely mark the CROSS as
    constrained and let a near-cartesian through.
    """
    if pred is None:
        return
    for eq in _and_equalities(pred):
        lq = eq.this.table if isinstance(eq.this, exp.Column) else None
        rq = eq.expression.table if isinstance(eq.expression, exp.Column) else None
        if lq and rq and lq.lower() != rq.lower():
            dsu.union(lq.lower(), rq.lower())


def check_cartesian(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    if not policy.block_cartesian:
        return []

    violations: list[Violation] = []
    for select in _top_selects(stmt):
        joins = select.args.get("joins") or []
        if not joins:
            continue

        # --- unconstrained-product candidates (explicit CROSS + implicit comma) ---
        # An explicit CROSS JOIN is NOT blocked unconditionally: `a CROSS JOIN b
        # WHERE a.id = b.id` is constrained (identical to an inner join), so route
        # CROSS through the SAME connectivity graph as comma joins and flag it below
        # only if its relations stay in separate components (no cross-table link).
        # An attack CROSS has no such equality → stays unlinked → still blocked.
        needs_connectivity = False
        for join in joins:
            # CROSS/JOIN LATERAL (...) is a correlated subquery, never an
            # unconstrained product -> skip.
            if isinstance(join.this, exp.Lateral):
                continue
            kind = (join.kind or "").upper()
            side = (join.side or "").upper()
            has_on = join.args.get("on") is not None
            has_using = join.args.get("using") is not None
            # explicit CROSS without ON/USING, or an implicit comma join (no
            # kind/side/on/using): both need a connectivity check.
            if kind == "CROSS" and not has_on and not has_using:
                needs_connectivity = True
            elif not kind and not side and not has_on and not has_using:
                needs_connectivity = True

        # --- connectivity over the unconstrained-product group ------------------
        if not needs_connectivity:
            continue

        from_ = select.args.get("from_")
        base_rel = from_.this if from_ is not None else None
        relations: list[exp.Expression] = []
        if base_rel is not None:
            relations.append(base_rel)
        # all join relations (incl. explicit ON ones) participate in the graph so
        # an explicit join can constrain a comma-joined relation transitively.
        for join in joins:
            if isinstance(join.this, exp.Lateral):
                continue
            relations.append(join.this)

        labels: set[str] = set()
        dsu = _DSU()
        for rel in relations:
            lbl = _relation_label(rel)
            if lbl:
                labels.add(lbl)
                dsu.add(lbl)

        # Need at least two relations to have a product; if we cannot label them
        # all (e.g. a function source), fail-closed and flag.
        if len(labels) < 2:
            # An unlabelable comma relation we cannot reason about -> fail-closed.
            if len(relations) >= 2:
                violations.append(_cartesian_violation())
            continue

        # edges: explicit JOIN ON predicates + WHERE equalities.
        for join in joins:
            _cross_qualifier_edges(join.args.get("on"), dsu)
            for ident in join.args.get("using") or []:
                # USING links the join relation to a prior one; conservatively union
                # the join relation with the base relation's component.
                lbl = _relation_label(join.this)
                base_lbl = _relation_label(base_rel) if base_rel is not None else None
                if lbl and base_lbl:
                    dsu.union(lbl, base_lbl)
        where = select.args.get("where")
        _cross_qualifier_edges(where.this if where is not None else None, dsu)

        # More than one connected component => some relations have no join link =>
        # their cross product is unconstrained.
        if dsu.components(labels) > 1:
            violations.append(_cartesian_violation())
    return violations


def _cartesian_violation() -> Violation:
    return Violation(
        code="cartesian",
        severity=Severity.MEDIUM,
        reason="join without ON/USING produces a cartesian product",
        action="block",
        fix="Add a join condition (ON/USING) or a cross-table WHERE predicate.",
    )
