import pytest

from ko_sqlguard import (
    Guard,
    GuardPolicy,
    SchemaPolicyError,
    Verdict,
    compile_schema_policy,
)


def test_catalog_compiles_allowlist_and_pii_columns() -> None:
    policy = compile_schema_policy(
        {
            "public.customers": {
                "columns": [
                    "id",
                    {"name": "성명", "pii": True},
                    {"name": "주민등록번호", "pii_label": "RRN"},
                ]
            }
        },
        base_policy=GuardPolicy(default_limit=None),
    )

    assert policy.allowed_tables == {
        "public.customers": ["id", "성명", "주민등록번호"]
    }
    assert policy.pii_columns == {"public.customers": ["성명", "주민등록번호"]}
    assert Guard(policy).check("SELECT id FROM public.customers").verdict is Verdict.PASS
    assert (
        Guard(policy).check("SELECT 주민등록번호 FROM public.customers").verdict
        is Verdict.BLOCK
    )


def test_empty_catalog_is_explicit_deny_all_policy() -> None:
    policy = compile_schema_policy({})
    assert policy.allowed_tables == {}
    assert Guard(policy).check("SELECT * FROM customers").verdict is Verdict.BLOCK


@pytest.mark.parametrize(
    "catalog",
    [
        {"customers": "id"},
        {"customers": [{"name": "id", "pii": "yes"}]},
        {"customers": ["ID", "id"]},
        {"CUSTOMERS": ["id"], "customers": ["id"]},
        {"customers": {"columns": ["id"], "owner": "app"}},
    ],
)
def test_ambiguous_catalog_is_rejected(catalog: object) -> None:
    with pytest.raises((SchemaPolicyError, TypeError)):
        compile_schema_policy(catalog)  # type: ignore[arg-type]
