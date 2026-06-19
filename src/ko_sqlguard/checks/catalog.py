"""System-catalog and sensitive-column gates.

Both checks fire INDEPENDENTLY of the table allowlist (they engage even when
``allowed_tables is None``). They close three exfiltration vectors that the
read-only/LIMIT/allowlist pipeline lets through by default:

  * catalog probes — ``pg_authid`` / ``pg_shadow`` / ``information_schema.*`` /
    ``pg_catalog.*`` leak password hashes, role lists, server config, and the
    full schema of objects that are not in the allowlist.
  * sensitive columns — ``password`` / ``ssn`` / ``credit_card`` / ``주민등록번호``
    etc. are PII/secrets no matter which table they live in, so a bare
    ``SELECT password FROM users`` (or the same inside a UNION) must block.
  * whole-row serialization — ``to_jsonb(u)`` / ``row_to_json(u)`` dumps EVERY
    column of ``u`` as JSON, so if any sensitive column is configured we cannot
    prove the row is safe; block the whole-row form too.
"""
from __future__ import annotations

from sqlglot import exp
from sqlglot.optimizer.scope import build_scope

from ..policy import GuardPolicy
from ..result import Severity, Violation
from ._ast import cte_aliases, real_tables

# json/jsonb extract-by-path function families parsed to exp.Anonymous (sqlglot
# does NOT fold the variadic *_path[_text] forms into typed JSONExtract nodes). The
# LAST string-literal argument is the key being projected; an earlier path arg only
# navigates into the object. Matched on the case-folded function name.
_JSON_EXTRACT_FUNCS: frozenset[str] = frozenset(
    {
        "json_extract_path",
        "json_extract_path_text",
        "jsonb_extract_path",
        "jsonb_extract_path_text",
    }
)

# Functions that serialize an entire row (every column) of their table argument.
# to_jsonb(u)/row_to_json(u)/to_json(u) serialize one row; json_agg(u)/jsonb_agg(u)/
# array_agg(u) aggregate whole rows into an array — both dump EVERY column, so a
# denylisted one cannot be ruled out. (jsonb_build_object(...) takes explicit
# key/value pairs, so it is NOT whole-row and stays allowed.)
_WHOLE_ROW_FUNCS: frozenset[str] = frozenset(
    {
        "to_jsonb",
        "to_json",
        "row_to_json",
        "json_agg",
        "jsonb_agg",
        "array_agg",
    }
)

# sqlglot parses some whole-row aggregates to a TYPED node whose sql_name() is the
# screaming-snake form (json_agg -> JSONArrayAgg -> "J_S_O_N_ARRAY_AGG"), so map the
# class name to the canonical lowercase func name we match on.
_TYPED_FUNC_NAMES: dict[str, str] = {
    "JSONArrayAgg": "json_agg",
    "ArrayAgg": "array_agg",
}


def check_catalog(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    """Block reads of system catalogs / metadata schemas (Gap 1).

    Engages regardless of the table allowlist. A catalog table referenced
    ANYWHERE in the statement (including a UNION arm or subquery) blocks the whole
    query — that also covers ``... UNION SELECT passwd FROM pg_shadow`` (Gap 2).
    """
    if not policy.block_system_catalogs:
        return []

    schemas = policy.normalized_catalog_schemas
    bare = policy.normalized_catalog_tables
    prefixes = policy.normalized_catalog_prefixes
    violations: list[Violation] = []
    seen: set[str] = set()

    for table in real_tables(stmt):
        db = (table.db or "").lower()
        name = (table.name or "").lower()
        label = f"{db}.{name}" if db else name
        if label in seen:
            continue

        hit_schema = db in schemas
        # A bare catalog view is only a probe when it is NOT explicitly schema-
        # qualified to a non-catalog schema (a user table literally named
        # "pg_settings" in schema "app" would be app.pg_settings — different).
        catalog_scoped = not db or db in schemas
        hit_bare = name in bare and catalog_scoped
        # Reserved-prefix backstop: any unqualified (or pg_catalog-qualified) relation
        # named pg_* is a system catalog / statistics / introspection view — closes the
        # whole pg_stat_*/pg_statio_* recon family without enumerating each view. A user
        # table in a non-catalog schema (app.pg_foo) is db="app", so it is NOT scoped.
        hit_prefix = catalog_scoped and bool(name) and name.startswith(prefixes)
        if hit_schema or hit_bare or hit_prefix:
            seen.add(label)
            violations.append(
                Violation(
                    code="system_catalog",
                    severity=Severity.HIGH,
                    reason=f"read of system catalog/metadata relation {label!r} is blocked "
                    "(leaks credentials, roles, server config, or out-of-allowlist schema)",
                    action="block",
                    fix="Query application tables only; system catalogs are off-limits.",
                )
            )
    return violations


def check_sensitive_columns(stmt: exp.Expression, policy: GuardPolicy) -> list[Violation]:
    """Block reads of denylisted sensitive columns and whole-row serialization (Gaps 2/3/4).

    Independent of the table allowlist. Matches the exact, case-folded column NAME
    (never a substring), so ``password_changed_at`` / ``card_type`` do not over-fire.

    LIMITATION (SQL-2): a bare ``SELECT * FROM users`` (or ``u.*``) names no column,
    so the denylist cannot see whether ``users`` actually has ``password``/``ssn``.
    With ``allowed_tables=None`` (no catalog of table -> columns) we therefore CANNOT
    prove a ``*`` is safe OR unsafe, and blanket-blocking every ``*`` would destroy
    recall (``SELECT * FROM orders`` is legitimate). To protect sensitive columns
    against ``SELECT *`` you MUST configure a column allowlist
    (``GuardPolicy.allowed_tables={"users": ["id", "name", ...]}``): the allowlist
    check (checks/allowlist.py) then rejects ``*`` over any column-restricted table.
    Whole-row SERIALIZATION (``to_jsonb(u)``/``json_agg(u)``/derived ``SELECT *``) IS
    blocked here because the function names a concrete row source we can resolve to a
    real table; a plain top-level ``*`` does not.
    """
    deny = policy.normalized_sensitive_columns
    if not deny:
        return []

    violations: list[Violation] = []
    flagged: set[str] = set()

    # Resolve which qualifiers are NOT real-table reads, so a denylisted NAME that
    # is merely a CTE/derived-table output alias does not over-fire (recall-safe):
    #   * CTE alias        -> `cte.ssn` is a CTE column, never the physical ssn.
    #   * derived alias     -> `x.ssn` where x = (SELECT id ... ) x(ssn) actually
    #                          reads `id`; only flag if the inner real column is
    #                          itself denylisted.
    ctes = cte_aliases(stmt)
    derived = _derived_aliases(stmt)
    cte_low = {c.lower() for c in ctes}
    derived_low = {a.lower() for a in derived}
    # Map id(column) -> True if its enclosing scope has a physical-table source. An
    # unqualified sensitive NAME is only a real read when a physical table is in
    # scope; sourced purely from a CTE/derived select (e.g. `SELECT 1 AS ssn`) it is
    # just a label over non-sensitive data. Fail-closed: unknown -> treat as physical.
    phys_scope = _columns_with_physical_scope(stmt)

    for col in stmt.find_all(exp.Column):
        name = (col.name or "").lower()
        if name not in deny:
            continue
        qualifier = (col.table or "").lower()
        if qualifier and qualifier in derived_low:
            # Map the outer alias column to the inner real (table, column) and only
            # flag when that real source column is itself sensitive.
            inner_name = _resolve_inner_name(derived, col.table, col.name)
            if inner_name is None or inner_name.lower() not in deny:
                continue
        elif qualifier and qualifier in cte_low:
            continue  # CTE column with no link to a real sensitive column.
        elif not qualifier and id(col) in phys_scope and not phys_scope[id(col)]:
            continue  # unqualified, scope has no physical table -> CTE/derived label.
        key = f"{qualifier}.{name}" if qualifier else name
        if key in flagged:
            continue
        flagged.add(key)
        label = f"{col.table}.{col.name}" if col.table else col.name
        violations.append(
            Violation(
                code="sensitive_column",
                severity=Severity.HIGH,
                reason=f"column {label!r} is on the sensitive-data denylist "
                "(secret / government ID / payment data)",
                action="block",
                fix="Do not select secret/PII columns; request only non-sensitive fields.",
            )
        )

    # Whole-row serialization dumps every column, so we cannot rule out a denylisted
    # one (Gap 4). Block to_jsonb(t)/row_to_json(t)/to_json(t) and the whole-row
    # aggregates json_agg(t)/jsonb_agg(t)/array_agg(t) whose argument is a real-table
    # reference while a sensitive-column denylist is active.
    real_names: set[str] = set()
    for t in real_tables(stmt):
        if t.name:
            real_names.add(t.name.lower())
        alias = t.alias
        if alias:
            real_names.add(alias.lower())

    # Derived-table aliases whose inner projection is a star (`SELECT * FROM real`):
    #   to_jsonb(s) FROM (SELECT * FROM users) s
    # serializes every column of `users`, so the alias is itself a whole-row source.
    derived_star = _derived_star_aliases(stmt)

    for fn in stmt.find_all(exp.Func):
        if isinstance(fn, exp.Anonymous):
            # to_jsonb/row_to_json/jsonb_agg parse to Anonymous: name in .name, arg
            # in .expressions.
            fname = (fn.name or "").lower()
            args = fn.expressions
            first = args[0] if args else None
        else:
            # json_agg/array_agg parse to TYPED nodes (JSONArrayAgg/ArrayAgg) whose
            # arg sits in .this; map the class name to the canonical func name.
            fname = _TYPED_FUNC_NAMES.get(type(fn).__name__, "")
            if not fname:
                try:
                    fname = (fn.sql_name() or "").lower()
                except Exception:
                    fname = ""
            first = fn.this
        if fname not in _WHOLE_ROW_FUNCS:
            continue
        first = _unwrap_agg_arg(first)
        if not isinstance(first, exp.Column):
            continue
        # Three whole-row shapes resolve to a table/alias name:
        #   to_jsonb(u)   -> bare Column, no qualifier, name == table/alias
        #   to_jsonb(u.*) -> qualified star, .table == table/alias
        #   to_jsonb(s)   -> bare Column whose name is a derived-star alias.
        if isinstance(first.this, exp.Star):
            row_name = (first.table or "").lower()
        elif not first.table:
            row_name = first.name.lower()
        else:
            row_name = ""
        if row_name and (row_name in real_names or row_name in derived_star):
            key = f"wholerow:{row_name}"
            if key not in flagged:
                flagged.add(key)
                violations.append(
                    Violation(
                        code="sensitive_column",
                        severity=Severity.HIGH,
                        reason=f"whole-row serialization {fname}({first.sql()}) dumps every column "
                        "of the row, which may include sensitive-denylisted data",
                        action="block",
                        fix="Serialize an explicit allowlist of non-sensitive columns instead.",
                    )
                )

    # JSON-extract by LITERAL key (Gap: SQL-2 jsonb extract). A sensitive value can
    # hide inside a jsonb/json column and be pulled out by a constant key:
    #   data ->> 'password'          json_extract_path_text(data, 'a', 'password')
    #   data #>> '{a,password}'      jsonb_extract_path_text(data, 'password')
    # The key is a STRING LITERAL the AST sees, not an exp.Column, so the loop above
    # misses it. Block when the literal key (or the LAST element of a multi-key path)
    # case-folds into the sensitive denylist. A DYNAMIC key (a column expression like
    # `data ->> keycol`) is NOT a literal, so it is left to the caller / column
    # allowlist — flagging it here would over-fire on benign dynamic projections.
    for key in _json_literal_keys(stmt):
        if key.lower() not in deny:
            continue
        flag = f"jsonkey:{key.lower()}"
        if flag in flagged:
            continue
        flagged.add(flag)
        violations.append(
            Violation(
                code="sensitive_column",
                severity=Severity.HIGH,
                reason=f"json/jsonb extract pulls sensitive key {key!r}, which is on the "
                "sensitive-data denylist (secret / government ID / payment data)",
                action="block",
                fix="Do not extract secret/PII keys from json/jsonb; request only "
                "non-sensitive keys.",
            )
        )

    return violations


def _pg_array_last_element(text: str) -> str | None:
    """Last element of a PostgreSQL text-path literal ``'{a,b,password}'`` -> 'password'.

    Used for the ``#>`` / ``#>>`` operators whose path arrives as one string literal.
    Pure string work (strip braces, split on ``,``) — NO regex, so it cannot ReDoS.
    Returns None for an empty path or a malformed/non-brace literal (fail-open: a
    weird literal just isn't treated as a recognizable single key).
    """
    s = text.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    inner = s[1:-1].strip()
    if not inner:
        return None
    last = inner.split(",")[-1].strip()
    # PG path elements may be double-quoted: {a,"weird,key"} — strip a simple wrap.
    if len(last) >= 2 and last[0] == '"' and last[-1] == '"':
        last = last[1:-1]
    return last or None


def _json_literal_keys(stmt: exp.Expression) -> list[str]:
    """Literal keys projected by json/jsonb extract operators & path functions.

    Covers the four AST shapes sqlglot produces (see probe in checks tests):
      * ``->`` / ``->>``                 -> JSONExtract / JSONExtractScalar, key is the
                                           last JSONPathKey of a JSONPath expression.
      * ``json_extract_path[_text](d,'k')`` folds into the SAME typed node, so it is
                                           handled by the JSONPath branch.
      * ``#>`` / ``#>>``                 -> JSONBExtract / JSONBExtractScalar, path is a
                                           single ``'{a,b,key}'`` string Literal.
      * ``jsonb_extract_path[_text](d,'a','k')`` stays exp.Anonymous; the key is the
                                           LAST string-literal argument.
    Only a constant key is returned; a dynamic key (``d ->> keycol``) yields nothing.
    """
    keys: list[str] = []
    for node in stmt.find_all(
        exp.JSONExtract, exp.JSONExtractScalar, exp.JSONBExtract, exp.JSONBExtractScalar
    ):
        expr = node.args.get("expression")
        if isinstance(expr, exp.JSONPath):
            path_keys = [p for p in expr.expressions if isinstance(p, exp.JSONPathKey)]
            if path_keys:
                last = path_keys[-1].this
                if isinstance(last, str) and last:
                    keys.append(last)
        elif isinstance(expr, exp.Literal) and expr.is_string:
            last = _pg_array_last_element(expr.this)
            if last:
                keys.append(last)
        # A non-literal `expression` (e.g. a Column for a dynamic key) is skipped:
        # literal-key only, by design (dynamic keys are the allowlist's job).

    for fn in stmt.find_all(exp.Anonymous):
        if (fn.name or "").lower() not in _JSON_EXTRACT_FUNCS:
            continue
        # args[0] is the json column/expr; the remaining string literals are the
        # path. The LAST string literal is the projected key.
        str_args = [
            a.this
            for a in fn.expressions[1:]
            if isinstance(a, exp.Literal) and a.is_string and isinstance(a.this, str)
        ]
        if str_args and str_args[-1]:
            keys.append(str_args[-1])
    return keys


def _columns_with_physical_scope(stmt: exp.Expression) -> dict[int, bool]:
    """For each column node, whether its resolving scope has a physical-table source.

    Used only to spare UNQUALIFIED sensitive names that resolve to a CTE/derived
    select (no physical table) — a recall guard. Fail-open on any analysis error:
    columns absent from the map are treated as physical (flagged), so a parser quirk
    can never silently un-block a real sensitive read.
    """
    out: dict[int, bool] = {}
    try:
        root = build_scope(stmt)
        if root is None:
            return out
        for scope in root.traverse():
            has_phys = any(isinstance(s, exp.Table) for s in scope.sources.values())
            for col in scope.columns:
                # OR-accumulate: the SAME column node can be visited by several
                # scopes (e.g. a sensitive column inside an inner scalar subquery
                # whose FROM-less OUTER scope is visited last). Overwriting would let
                # the phys=False outer scope CLOBBER the inner phys=True attribution
                # and silently un-block a real sensitive read. Once ANY scope sees a
                # physical-table source for the node, that sticks (fail-closed).
                out[id(col)] = out.get(id(col), False) or has_phys
    except Exception:
        return {}
    return out


def _unwrap_agg_arg(node: exp.Expression | None) -> exp.Expression | None:
    """Peel aggregate modifiers (DISTINCT / ORDER BY) off the first argument.

    ``array_agg(DISTINCT u)`` -> Distinct(expressions=[u]); ``json_agg(u ORDER BY u.id)``
    -> Order(this=u). Unwrap both so a whole-row argument is still recognized and an
    attacker cannot dodge the gate by adding a modifier.
    """
    seen = 0
    while node is not None and seen < 10:
        seen += 1
        if isinstance(node, exp.Order):
            node = node.this
        elif isinstance(node, exp.Distinct):
            exprs = node.expressions
            node = exprs[0] if exprs else node.this
        else:
            break
    return node


def _derived_star_aliases(stmt: exp.Expression) -> set[str]:
    """Lower-cased derived-table aliases whose inner SELECT projects a bare ``*``.

    ``to_jsonb(s) FROM (SELECT * FROM users) s`` serializes EVERY column of the inner
    real table, so the outer alias ``s`` is a whole-row source even though no explicit
    column is named. Only a star directly in the derived SELECT's projection list
    counts (a star inside a nested subquery/argument is not the alias's output).
    """
    out: set[str] = set()
    for sub in stmt.find_all(exp.Subquery):
        alias = sub.alias
        inner = sub.this
        if not alias or not isinstance(inner, exp.Select):
            continue
        for proj in inner.expressions:
            target = proj.this if isinstance(proj, exp.Alias) else proj
            # `SELECT *` -> Star ; `SELECT t.*` -> Column(this=Star).
            if isinstance(target, exp.Star) or (
                isinstance(target, exp.Column) and isinstance(target.this, exp.Star)
            ):
                out.add(alias.lower())
                break
    return out


def _derived_aliases(stmt: exp.Expression) -> dict[str, tuple[exp.Select, list[str]]]:
    """Subquery/LATERAL alias -> (inner Select, output column aliases).

    Mirrors checks/allowlist.py so a column qualified by a derived-table alias can
    be reduced to its inner real source before the sensitive-column check fires.
    """
    derived: dict[str, tuple[exp.Select, list[str]]] = {}
    for sub in stmt.find_all(exp.Subquery):
        alias = sub.alias
        if alias and isinstance(sub.this, exp.Select):
            ta = sub.args.get("alias")
            col_aliases = [c.name for c in ta.columns] if ta else []
            derived[alias] = (sub.this, col_aliases)
    for lat in stmt.find_all(exp.Lateral):
        alias = lat.alias
        inner = lat.this.this if isinstance(lat.this, exp.Subquery) else lat.this
        if alias and isinstance(inner, exp.Select):
            ta = lat.args.get("alias")
            col_aliases = [c.name for c in ta.columns] if ta else []
            derived[alias] = (inner, col_aliases)
    return derived


def _resolve_inner_name(
    derived: dict[str, tuple[exp.Select, list[str]]], qualifier: str, name: str
) -> str | None:
    """Real inner column NAME behind a derived-table output column, or None.

    `x.ssn` from `(SELECT id ...) x(ssn)` -> 'id'. A computed/unresolved projection
    returns None (the inner select is checked on its own; the outer name is just a
    label over computed data, not a physical sensitive column).
    """
    entry = derived.get(qualifier)
    if entry is None:
        # case-insensitive fallback
        for k, v in derived.items():
            if k.lower() == qualifier.lower():
                entry = v
                break
    if entry is None:
        return None
    inner, col_aliases = entry
    exprs = inner.expressions
    target: exp.Expression | None = None
    if col_aliases:
        low = [a.lower() for a in col_aliases]
        if name.lower() in low:
            idx = low.index(name.lower())
            if idx < len(exprs):
                target = exprs[idx]
    if target is None:
        for e in exprs:
            out = e.alias_or_name
            if out and out.lower() == name.lower():
                target = e
                break
    if target is None:
        return None
    inner_col = target.this if isinstance(target, exp.Alias) else target
    if isinstance(inner_col, exp.Column):
        return inner_col.name
    return None
