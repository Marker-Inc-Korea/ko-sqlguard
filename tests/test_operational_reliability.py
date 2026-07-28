"""Resource bounds, telemetry redaction, and production-policy contract tests."""
from __future__ import annotations

import pytest

import ko_sqlguard.guard as guard_module
from ko_sqlguard import GuardPolicy, Severity, Verdict, check


def _codes(sql: str, policy: GuardPolicy) -> set[str]:
    return {violation.code for violation in check(sql, policy=policy).violations}


def test_character_limit_blocks_before_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = GuardPolicy(
        allowed_tables=None,
        default_limit=None,
        max_query_chars=8,
        max_query_bytes=64,
    )

    def parser_must_not_run(*args: object, **kwargs: object) -> object:
        raise AssertionError("resource-limited input reached the parser")

    monkeypatch.setattr(guard_module, "_parse_with_fallback", parser_must_not_run)
    result = check("SELECT 1 ", policy=policy)

    assert result.verdict is Verdict.BLOCK
    assert result.original_sql == ""
    assert result.violations[0].code == "query_too_many_characters"
    assert result.violations[0].severity is Severity.CRITICAL


def test_character_limit_boundary_passes() -> None:
    policy = GuardPolicy(
        allowed_tables=None,
        default_limit=None,
        max_query_chars=8,
        max_query_bytes=64,
    )

    assert check("SELECT 1", policy=policy).verdict is Verdict.PASS


def test_multibyte_byte_limit_is_independent_of_character_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sql = "SELECT '가'"
    byte_length = len(sql.encode("utf-8"))
    policy = GuardPolicy(
        allowed_tables=None,
        default_limit=None,
        max_query_chars=len(sql),
        max_query_bytes=byte_length,
    )

    assert check(sql, policy=policy).verdict is Verdict.PASS
    byte_limited = policy.model_copy(update={"max_query_bytes": byte_length - 1})

    def parser_must_not_run(*args: object, **kwargs: object) -> object:
        raise AssertionError("resource-limited input reached the parser")

    monkeypatch.setattr(guard_module, "_parse_with_fallback", parser_must_not_run)
    byte_limited_result = check(sql, policy=byte_limited)
    assert {v.code for v in byte_limited_result.violations} == {
        "query_too_many_bytes"
    }
    assert byte_limited_result.original_sql == ""


def test_telemetry_excludes_sql_and_violation_reasons() -> None:
    original = "SELECT pg_sleep(1) -- customer secret"
    result = check(original, policy=GuardPolicy(default_limit=None))
    telemetry = result.to_telemetry()
    encoded = telemetry.model_dump_json()

    assert result.forward_safe is False
    assert telemetry.forward_safe is False
    assert telemetry.violation_codes
    assert original not in encoded
    assert "reason" not in encoded
    assert "sql" not in encoded


def test_forward_safe_requires_executable_sql() -> None:
    result = check("SELECT 1", policy=GuardPolicy(allowed_tables=None, default_limit=None))

    assert result.forward_safe is True
    assert result.to_telemetry().forward_safe is True


def test_production_validation_requires_explicit_allowlist() -> None:
    with pytest.raises(ValueError, match="explicit allowed_tables"):
        GuardPolicy().validate_production()


def test_empty_allowlist_is_a_valid_deny_all_production_policy() -> None:
    policy = GuardPolicy(allowed_tables={})

    assert policy.validate_production() is policy
    assert _codes("SELECT * FROM orders", policy) == {"table_not_allowed"}


def test_production_validation_requires_allowlist_violations_to_block() -> None:
    policy = GuardPolicy(allowed_tables={"orders": []}, min_block_severity=Severity.CRITICAL)

    with pytest.raises(ValueError, match="min_block_severity"):
        policy.validate_production()
