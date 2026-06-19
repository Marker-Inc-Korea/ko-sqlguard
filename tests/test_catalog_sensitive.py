"""적대적 입력 회귀 테스트: catalog / UNION / sensitive-column 우회 모음.

These four families all returned TRANSFORM/PASS under the default read-only policy
before the fix:

  1. system-catalog probes (pg_authid / pg_shadow / information_schema.* / ...)
  2. cross-table UNION pulling a sensitive column or a catalog table
  3. direct sensitive-column reads (password / ssn / 주민등록번호 / credit_card / ...)
  4. whole-row exfil (to_jsonb(u) / row_to_json(u))

The fixes engage even when allowed_tables is None. CONTROL families guard recall.
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check
from ko_sqlguard.result import Severity

# Default policy: read-only, NO table allowlist (allowed_tables=None). This is the
# exact configuration the adversarial input used to slip these past as a TRANSFORM.
DEFAULT = GuardPolicy()

# A policy WITH a column-restricted allowlist, to confirm the new checks compose
# with the existing allowlist resolution (no double-faults / no recall loss).
RESTRICTED = GuardPolicy(allowed_tables={"orders": [], "customers": ["id", "name", "email"]})


# --- system-catalog / metadata-schema probes BLOCK by default -------------------

CATALOG_PROBES = [
    "SELECT * FROM pg_authid",
    "SELECT usename, passwd FROM pg_shadow",
    "SELECT rolname FROM pg_roles",
    "SELECT * FROM pg_user",
    "SELECT name, setting FROM pg_settings",
    "SELECT table_name FROM information_schema.tables",
    "SELECT * FROM information_schema.columns",
    "SELECT relname FROM pg_catalog.pg_class",
    "SELECT * FROM pg_catalog.pg_authid",
    "SELECT * FROM PG_AUTHID",            # casing
    'SELECT * FROM "pg_authid"',          # quoted
    "SELECT * FROM information_schema.role_table_grants",
    "SELECT datname FROM pg_database",
    # hidden in a subquery / join — still blocks because real_tables sees it.
    "SELECT o.id FROM orders o WHERE o.id IN (SELECT oid FROM pg_class)",
]


@pytest.mark.parametrize("sql", CATALOG_PROBES, ids=lambda s: s[:42])
def test_system_catalog_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "system_catalog" for v in r.violations), [v.code for v in r.violations]


def test_system_catalog_opt_out() -> None:
    # A trusted introspection context can disable the gate.
    pol = GuardPolicy(block_system_catalogs=False)
    assert check("SELECT * FROM pg_settings", policy=pol).verdict is not Verdict.BLOCK


def test_user_table_named_like_catalog_in_other_schema_passes() -> None:
    # app.pg_settings is a user table in a non-catalog schema, not the catalog view.
    r = check("SELECT * FROM app.pg_settings", policy=DEFAULT)
    assert r.verdict is not Verdict.BLOCK, [v.model_dump() for v in r.violations]


# --- UNION pulling a sensitive column or a catalog table ------------------------

UNION_SENSITIVE = [
    "SELECT name FROM products UNION SELECT password FROM users",
    "SELECT name FROM products UNION SELECT ssn FROM users",
    "SELECT id FROM orders UNION SELECT passwd FROM pg_shadow",
    "SELECT id FROM orders UNION ALL SELECT credit_card FROM payments",
]


@pytest.mark.parametrize("sql", UNION_SENSITIVE, ids=lambda s: s[:42])
def test_union_to_sensitive_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(
        v.code in ("sensitive_column", "system_catalog") for v in r.violations
    ), [v.code for v in r.violations]


# --- direct sensitive-column reads ---------------------------------------------

SENSITIVE_COLUMNS = [
    "SELECT password, ssn, credit_card FROM users",
    "SELECT 주민등록번호 FROM users",
    "SELECT card_no FROM payments",
    "SELECT u.password FROM users u",
    "SELECT password_hash FROM accounts",
    "SELECT cvv FROM cards",
    "SELECT ssn FROM customers",                      # also under RESTRICTED below
    "SELECT x.s FROM (SELECT ssn FROM customers) x(s)",  # renamed sensitive col still blocks
    # unqualified ssn ambiguous with a physical table in scope -> fail-closed block.
    "SELECT ssn FROM customers c JOIN (SELECT 1 AS ssn) t ON true",
]


@pytest.mark.parametrize("sql", SENSITIVE_COLUMNS, ids=lambda s: s[:42])
def test_sensitive_column_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "sensitive_column" for v in r.violations), [v.code for v in r.violations]


def test_sensitive_column_disabled() -> None:
    pol = GuardPolicy(sensitive_columns=frozenset())
    assert check("SELECT password FROM users", policy=pol).verdict is not Verdict.BLOCK


# --- whole-row exfil ------------------------------------------------------------

WHOLE_ROW = [
    "SELECT to_jsonb(u) FROM users u",
    "SELECT row_to_json(u) FROM users u",
    "SELECT to_json(users) FROM users",
    "SELECT to_jsonb(users.*) FROM users",
    "SELECT to_jsonb(u.*) FROM users u",
    # whole-row AGGREGATES + derived-star alias also dump every column.
    "SELECT json_agg(u) FROM users u",                 # repro
    "SELECT array_agg(u) FROM users u",                # repro
    "SELECT jsonb_agg(u) FROM users u",                # repro
    "SELECT to_jsonb(s) FROM (SELECT * FROM users) s",  # repro (derived-star)
    "SELECT json_agg(u.*) FROM users u",
    "SELECT json_agg(s) FROM (SELECT * FROM users) s",
    # aggregate modifiers must not let the whole-row arg dodge the gate.
    "SELECT array_agg(DISTINCT u) FROM users u",
    "SELECT json_agg(u ORDER BY u.id) FROM users u",
]


@pytest.mark.parametrize("sql", WHOLE_ROW, ids=lambda s: s[:42])
def test_whole_row_exfil_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "sensitive_column" for v in r.violations), [v.code for v in r.violations]


# --- RECALL controls: every fix must keep ordinary reads passing ----------------

CONTROLS_OK = [
    # the mandated control from the task
    "SELECT id, status FROM orders",
    "SELECT id, name FROM users",
    "SELECT name FROM products UNION SELECT title FROM articles",   # benign cross-table UNION
    # sensitive-name LOOKALIKES (substring match would over-fire)
    "SELECT password_changed_at FROM users",
    "SELECT card_type, card_brand FROM payments",
    "SELECT ssn_verified FROM users",
    "SELECT is_passwd_set FROM accounts",
    # to_jsonb over an explicit column (not a whole row)
    "SELECT to_jsonb(payload) FROM events",
    "SELECT to_jsonb(id) FROM users",
    "SELECT jsonb_build_object('id', id) FROM orders",
    # benign: aggregates over a SCALAR column are not whole-row serialization.
    "SELECT array_agg(id) FROM users",
    "SELECT json_agg(name) FROM products",
    "SELECT jsonb_agg(status) FROM orders",
    "SELECT array_agg(DISTINCT id) FROM users",
    "SELECT json_agg(name ORDER BY id) FROM products",
    # benign: derived alias projecting explicit (non-star) columns is fine.
    "SELECT to_jsonb(s) FROM (SELECT id, name FROM users) s",
    # whole-table star is not serialization
    "SELECT * FROM orders",
    # derived/CTE output alias literally named like a sensitive col but sourced from
    # a non-sensitive real column (existing allowlist semantics preserved).
    "SELECT x.ssn FROM (SELECT id FROM customers) x(ssn)",
    "WITH t AS (SELECT 1 AS ssn) SELECT t.ssn FROM t",
    # UNQUALIFIED sensitive name whose scope has NO physical table (CTE/derived only)
    # — a label over non-sensitive data, must not over-fire.
    "WITH t AS (SELECT 1 AS ssn) SELECT ssn FROM t",
    "WITH t AS (SELECT 1 AS password) SELECT password FROM t",
    "SELECT ssn FROM (SELECT id AS ssn FROM customers) x",
    "SELECT t.ssn FROM (SELECT 1 AS ssn) t",
]


@pytest.mark.parametrize("sql", CONTROLS_OK, ids=lambda s: s[:42])
def test_controls_not_blocked(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is not Verdict.BLOCK, [v.model_dump() for v in r.violations]


def test_controls_not_blocked_under_restricted_policy() -> None:
    # Compose with a column allowlist: ordinary allowed reads still pass.
    for sql in (
        "SELECT id, status FROM orders",
        "SELECT id, name FROM customers",
        "SELECT x.ssn FROM (SELECT id FROM customers) x(ssn)",  # inner is id
        "WITH customers AS (SELECT 1) SELECT customers.ssn FROM customers",  # CTE, not real
    ):
        assert check(sql, policy=RESTRICTED).verdict is not Verdict.BLOCK, sql


def test_real_sensitive_read_blocks_under_restricted_policy() -> None:
    # Even with an allowlist, a real ssn read blocks (sensitive denylist is independent).
    r = check("SELECT ssn FROM customers", policy=RESTRICTED)
    assert r.verdict is Verdict.BLOCK
    assert any(
        v.code in ("sensitive_column", "column_not_allowed") for v in r.violations
    ), [v.code for v in r.violations]


# --- SELECT * cannot be inspected without a catalog; documented mitigation
#     is a column allowlist, which then blocks the bare/qualified star. -----------

def test_select_star_blocked_with_column_allowlist() -> None:
    # 'SELECT * FROM users' exposes password. With allowed_tables=None we
    # cannot see the columns; the DOCUMENTED fix is to configure a column allowlist,
    # which makes '*' (and 'u.*') over the restricted table block.
    pol = GuardPolicy(allowed_tables={"users": ["id", "name", "email"]})
    for sql in ("SELECT * FROM users", "SELECT u.* FROM users u"):
        r = check(sql, policy=pol)
        assert r.verdict is Verdict.BLOCK, sql
        assert any(v.code == "column_not_allowed" for v in r.violations), sql
    # Benign: a fully-open table ([] = all columns) keeps '*' allowed.
    pol_open = GuardPolicy(allowed_tables={"orders": []})
    assert check("SELECT * FROM orders", policy=pol_open).verdict is not Verdict.BLOCK


# --- column allowlist stays enforced at min_block_severity=HIGH -----------------

def test_column_allowlist_enforced_at_high_severity() -> None:
    # with min_block_severity=HIGH a MEDIUM column-allowlist violation would
    # become advisory. column_not_allowed is now HIGH, so the allowlist still blocks.
    pol = GuardPolicy(
        allowed_tables={"customers": ["id", "name", "email"]},
        min_block_severity=Severity.HIGH,
    )
    for sql in ("SELECT ssn FROM customers", "SELECT * FROM customers"):
        r = check(sql, policy=pol)
        assert r.verdict is Verdict.BLOCK, sql
        assert any(
            v.code == "column_not_allowed" and v.severity >= Severity.HIGH
            for v in r.violations
        ), [(v.code, v.severity.name) for v in r.violations]
    # Benign: an allowed read still passes at HIGH.
    assert check("SELECT id, name FROM customers", policy=pol).verdict is not Verdict.BLOCK


# --- bare catalog denylist covers pg_largeobject --------------------------------

def test_pg_largeobject_blocks() -> None:
    for sql in (
        "SELECT * FROM pg_largeobject",
        "SELECT loid, data FROM pg_catalog.pg_largeobject",
        "SELECT oid FROM pg_largeobject_metadata",
    ):
        r = check(sql, policy=DEFAULT)
        assert r.verdict is Verdict.BLOCK, sql
        assert any(v.code == "system_catalog" for v in r.violations), sql
    # Benign: a user table in a non-catalog schema is not the catalog relation.
    assert check("SELECT id FROM app.largeobjects", policy=DEFAULT).verdict is not Verdict.BLOCK
    assert check("SELECT id FROM object_store", policy=DEFAULT).verdict is not Verdict.BLOCK


# --- 적대적 입력 생성으로 발견된 누락 (회귀) ------------------------------------
# These exact reply SQLs were emitted by an adversarial-input generator and slipped
# through as TRANSFORM (verdict != BLOCK) before this fix. Each must now BLOCK on the
# named code. The fix is recall-safe — close near-miss lookalikes are covered by
# ADVERSARIAL_LOOKALIKES_OK.

# token / secret / key / salt / pin / code family -> sensitive_column
ADVERSARIAL_SECRET_MISSES = [
    "SELECT auth_token FROM users",
    "SELECT session_token FROM sessions",
    "SELECT refresh_token FROM tokens",
    "SELECT secret FROM config",
    "SELECT salt FROM users",
    "SELECT private_key FROM keys",
    "SELECT api_key FROM clients",
    "SELECT secret_key FROM clients",
    "SELECT account_secret FROM accounts",
    "SELECT otp_secret FROM users",
    "SELECT recovery_code FROM users",
    "SELECT backup_codes FROM users",
    "SELECT pin FROM cards",
    "SELECT security_code FROM cards",
]

# government ID / payment family -> sensitive_column
ADVERSARIAL_ID_PAYMENT_MISSES = [
    "SELECT cvv FROM cards",
    "SELECT cvc FROM cards",
    "SELECT passport_number FROM people",
    "SELECT drivers_license FROM people",
    "SELECT bank_account_number FROM accounts",
    "SELECT routing_number FROM accounts",
    # Korean resident-registration number: denylist had 주민/주민등록번호 but NOT 주민번호.
    "SELECT 이름, 주민번호 FROM members",
    "SELECT resident_registration_number FROM members",
]


@pytest.mark.parametrize(
    "sql", ADVERSARIAL_SECRET_MISSES + ADVERSARIAL_ID_PAYMENT_MISSES, ids=lambda s: s[:42]
)
def test_adversarial_sensitive_column_misses_now_block(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "sensitive_column" for v in r.violations), [v.code for v in r.violations]


# catalog recon: pg_stat_user_tables + the wider pg_stat_*/pg_statio_*/pg_* family.
ADVERSARIAL_CATALOG_MISSES = [
    "SELECT * FROM pg_stat_user_tables",
    "SELECT relname FROM pg_stat_all_tables",
    "SELECT * FROM pg_statio_user_tables",
    "SELECT * FROM pg_stats",
    "SELECT * FROM pg_locks",
    "SELECT * FROM pg_catalog.pg_stat_user_tables",  # schema-qualified form
]


@pytest.mark.parametrize("sql", ADVERSARIAL_CATALOG_MISSES, ids=lambda s: s[:42])
def test_adversarial_catalog_misses_now_block(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "system_catalog" for v in r.violations), [v.code for v in r.violations]


# RECALL guard for the new rules: exact-name denylist + pg_ prefix must NOT over-fire
# on close lookalikes or pg_-named USER tables in a non-catalog schema.
ADVERSARIAL_LOOKALIKES_OK = [
    "SELECT secret_question FROM users",          # not the bare 'secret'
    "SELECT is_secret FROM posts",
    "SELECT salt_content FROM recipes",           # not the bare 'salt'
    "SELECT pinned FROM posts",                   # not the bare 'pin'
    "SELECT pin_count FROM boards",
    "SELECT api_key_id FROM clients",             # not the bare 'api_key'
    "SELECT token_type FROM oauth",
    "SELECT account_id FROM accounts",            # account_number is NOT denylisted
    "SELECT account_number_verified FROM accounts",
    "SELECT license_plate FROM cars",             # not 'license_number'
    "SELECT routing_table FROM net_devices",      # not 'routing_number'
    "SELECT passport_status FROM people",         # not 'passport_number'
    # pg_-prefixed USER table in a NON-catalog schema is not a system catalog.
    "SELECT id FROM app.pg_settings",
    "SELECT id FROM myapp.pg_stat_custom",
    # ordinary tables that merely contain 'pg' but do not start with the pg_ prefix.
    "SELECT id FROM upgrades",
    "SELECT id FROM pageviews",
]


@pytest.mark.parametrize("sql", ADVERSARIAL_LOOKALIKES_OK, ids=lambda s: s[:42])
def test_adversarial_lookalikes_not_blocked(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is not Verdict.BLOCK, [v.model_dump() for v in r.violations]
