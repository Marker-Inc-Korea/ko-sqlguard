from __future__ import annotations

import pytest

from ko_sqlguard import Guard, GuardPolicy, Verdict


def _guard(**overrides: object) -> Guard:
    values: dict[str, object] = {
        "default_limit": None,
        "pii_columns": {
            "customers": ["주민등록번호", "email"],
        },
    }
    values.update(overrides)
    return Guard(GuardPolicy(**values))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 주민등록번호 FROM customers",
        "SELECT customers.email FROM customers",
        "SELECT c.email FROM customers AS c",
        "SELECT email FROM customers AS c JOIN orders AS o ON c.id = o.customer_id",
        "SELECT md5(email) FROM customers",
        "SELECT id FROM customers JOIN orders USING (email)",
        "SELECT id FROM orders JOIN customers USING (email)",
        "SELECT id FROM customers NATURAL JOIN orders",
        'SELECT "Email" FROM "Customers"',
    ],
)
def test_blocks_table_specific_pii_columns(sql: str):
    result = _guard().check(sql)

    assert result.verdict is Verdict.BLOCK
    assert "pii_column" in {violation.code for violation in result.violations}


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM customers",
        "SELECT c.* FROM customers AS c",
        "SELECT to_jsonb(c) FROM customers AS c",
        "SELECT c FROM customers AS c",
    ],
)
def test_blocks_whole_row_access_when_table_has_pii(sql: str):
    result = _guard().check(sql)

    assert result.verdict is Verdict.BLOCK
    assert "pii_column" in {violation.code for violation in result.violations}


def test_count_star_does_not_expose_pii():
    result = _guard().check("SELECT COUNT(*) FROM customers")

    assert result.verdict is Verdict.PASS


def test_same_column_name_is_allowed_on_unclassified_table():
    result = _guard().check("SELECT email FROM public_directory")

    assert result.verdict is Verdict.PASS


def test_later_classified_join_does_not_taint_earlier_safe_using_clause():
    result = _guard().check(
        "SELECT o.id FROM orders o JOIN directory d USING (email) "
        "JOIN customers c ON c.id = o.id"
    )

    assert result.verdict is Verdict.PASS


def test_safe_derived_projection_does_not_inherit_hidden_pii():
    result = _guard().check(
        "SELECT * FROM (SELECT id, status FROM customers) AS safe_customer"
    )

    assert result.verdict is Verdict.PASS


def test_derived_projection_still_blocks_inner_pii_read():
    result = _guard().check(
        "SELECT value FROM (SELECT email AS value FROM customers) AS customer_email"
    )

    assert result.verdict is Verdict.BLOCK
    assert "pii_column" in {violation.code for violation in result.violations}


def test_cte_safe_projection_does_not_inherit_hidden_pii():
    result = _guard().check(
        "WITH safe_customer AS (SELECT id FROM customers) SELECT * FROM safe_customer"
    )

    assert result.verdict is Verdict.PASS


def test_cte_inner_pii_read_is_blocked():
    result = _guard().check(
        "WITH leaked AS (SELECT email FROM customers) SELECT email FROM leaked"
    )

    assert result.verdict is Verdict.BLOCK


def test_schema_qualified_policy_matches_schema_qualified_table():
    guard = _guard(pii_columns={"private.customers": ["email"]})

    blocked = guard.check("SELECT email FROM private.customers")
    other_schema = guard.check("SELECT email FROM public.customers")

    assert blocked.verdict is Verdict.BLOCK
    assert other_schema.verdict is Verdict.PASS


def test_empty_table_pii_set_adds_no_restriction():
    guard = _guard(pii_columns={"customers": []})

    assert guard.check("SELECT * FROM customers").verdict is Verdict.PASS


def test_policy_normalizes_and_merges_duplicate_table_keys():
    policy = GuardPolicy(
        pii_columns={" Customers ": [" Email "], "customers": ["주민등록번호"]}
    )

    assert policy.normalized_pii_columns == {
        "customers": frozenset({"email", "주민등록번호"})
    }


@pytest.mark.parametrize(
    "pii_columns",
    [
        {"": ["email"]},
        {"customers": [""]},
    ],
)
def test_policy_rejects_empty_identifiers(pii_columns: dict[str, list[str]]):
    with pytest.raises(ValueError):
        GuardPolicy(pii_columns=pii_columns)
