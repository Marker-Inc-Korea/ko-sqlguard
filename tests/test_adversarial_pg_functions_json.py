"""적대적 입력 회귀 테스트: pg_* function-prefix gate + json/jsonb literal-key
sensitive-column extraction.

Two adversarial-input misses under the DEFAULT read-only policy (allowed_tables=None):

  1. functions.py guarded by an enumerated denylist only, so WAL/recovery/per-relation
     stat pg_* built-ins (pg_current_wal_lsn / pg_is_in_recovery / pg_stat_get_*)
     PASSED. Fix: a fail-closed pg_*-function prefix gate (symmetric with the pg_*
     table-prefix gate in catalog.py) + enumerated families, with a small benign
     allowlist (pg_typeof / pg_size_pretty / version()).
  2. check_sensitive_columns inspected exp.Column names only, so a sensitive value
     pulled out of a jsonb column by a STRING-LITERAL key (data ->> 'password',
     #>> '{a,password}', json_extract_path_text(data,'password')) only TRANSFORMed.
     Fix: inspect the json/jsonb extract operators + *_path[_text] functions and block
     when the literal key case-folds into policy.normalized_sensitive_columns.

CONTROL families assert recall safety (benign keys + normal pg_* helpers stay
non-BLOCK).
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()


# --- Fix 1: pg_* function prefix gate -------------------------------------------

PG_FUNCTION_RECON = [
    # WAL / recovery position
    "SELECT pg_current_wal_lsn()",
    "SELECT pg_current_wal_insert_lsn()",
    "SELECT pg_walfile_name(pg_current_wal_lsn())",
    "SELECT pg_last_wal_replay_lsn()",
    "SELECT pg_last_xact_replay_timestamp()",
    # recovery / standby status
    "SELECT pg_is_in_recovery()",
    "SELECT pg_is_wal_replay_paused()",
    "SELECT pg_get_wal_replay_pause_state()",
    # per-relation / per-backend C-level statistics accessors
    "SELECT pg_stat_get_tuples_inserted(1)",
    "SELECT pg_stat_get_live_tuples(1)",
    "SELECT pg_stat_get_numscans(1)",
    "SELECT pg_stat_get_db_numbackends(1)",
    # replication slots / start time
    "SELECT pg_get_replication_slots()",
    "SELECT pg_postmaster_start_time()",
    "SELECT pg_conf_load_time()",
    # casing must not smuggle it past (matched on the AST name, case-folded)
    "SELECT PG_IS_IN_RECOVERY()",
    "SELECT Pg_Current_Wal_Lsn()",
    # hidden in a subquery / WHERE — still blocks (whole-tree find_all)
    "SELECT o.id FROM orders o WHERE pg_is_in_recovery()",
    # a pg_* function NOT enumerated in DEFAULT_BLOCKED_FUNCTIONS is still caught by
    # the prefix gate (fail-closed) — that is the whole point of the backstop.
    "SELECT pg_made_up_introspection_fn()",
]


@pytest.mark.parametrize("sql", PG_FUNCTION_RECON, ids=lambda s: s[:48])
def test_pg_function_prefix_gate_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "blocked_function" for v in r.violations), [
        v.code for v in r.violations
    ]


PG_FUNCTION_BENIGN = [
    "SELECT pg_typeof(1)",
    "SELECT pg_size_pretty(1024)",
    "SELECT pg_size_bytes('1 GB')",
    "SELECT pg_backend_pid()",
    "SELECT pg_client_encoding()",
    "SELECT pg_column_size(status) FROM orders",
    "SELECT pg_collation_for('x')",
    # ordinary application query with no pg_* call at all
    "SELECT id, status FROM orders WHERE id = 5",
]


@pytest.mark.parametrize("sql", PG_FUNCTION_BENIGN, ids=lambda s: s[:48])
def test_benign_pg_helpers_not_blocked(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is not Verdict.BLOCK, [v.model_dump() for v in r.violations]
    assert not any(v.code == "blocked_function" for v in r.violations), [
        v.code for v in r.violations
    ]


# Server-info reconnaissance functions (typed Anonymous/Current* nodes, not pg_*)
# are reclassified as blocked — they leak server/session metadata to an attacker.
PG_FUNCTION_RECON_TYPED = [
    "SELECT version()",
    "SELECT current_user",
    "SELECT current_database()",
]


@pytest.mark.parametrize("sql", PG_FUNCTION_RECON_TYPED, ids=lambda s: s[:48])
def test_server_info_recon_blocked(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql


def test_pg_function_prefix_gate_opt_out() -> None:
    # A trusted introspection context can disable the prefix gate; the enumerated
    # denylist still blocks pg_current_wal_lsn (it is now in DEFAULT_BLOCKED_FUNCTIONS)
    # but a NON-enumerated pg_* call would fall through.
    pol = GuardPolicy(block_pg_function_prefix=False)
    r = check("SELECT pg_made_up_introspection_fn()", policy=pol)
    assert not any(v.code == "blocked_function" for v in r.violations), [
        v.code for v in r.violations
    ]
    # still enumerated -> still blocked even with the prefix gate off
    assert check("SELECT pg_is_in_recovery()", policy=pol).verdict is Verdict.BLOCK


# --- Fix 2: json/jsonb literal-key sensitive-column extraction -------------------

JSON_SENSITIVE_KEY = [
    # ->> / -> operators (JSONExtractScalar / JSONExtract + JSONPath)
    "SELECT data ->> 'password' FROM users",
    "SELECT data -> 'password' FROM users",
    "SELECT data ->> 'ssn' FROM users",
    "SELECT data ->> 'credit_card' FROM users",
    "SELECT data ->> '주민등록번호' FROM users",
    # #>> / #> operators (JSONBExtractScalar / JSONBExtract + text-path Literal)
    "SELECT data #>> '{password}' FROM users",
    "SELECT data #>> '{profile,ssn}' FROM users",
    "SELECT data #> '{a,api_key}' FROM users",
    # path functions
    "SELECT json_extract_path_text(data, 'password') FROM users",
    "SELECT json_extract_path(data, 'password') FROM users",
    "SELECT jsonb_extract_path_text(data, 'a', 'password') FROM users",
    "SELECT jsonb_extract_path(data, 'profile', 'ssn') FROM users",
    # casing folds into the denylist
    "SELECT data ->> 'PassWord' FROM users",
    "SELECT json_extract_path_text(data, 'SSN') FROM users",
    # chained extract whose final key is sensitive
    "SELECT (data -> 'profile') ->> 'credit_card' FROM users",
    # double-quoted path element with embedded comma -> last element is the key
    'SELECT data #>> \'{a,"password"}\' FROM users',
    # hidden in a UNION arm — independent of table allowlist, still blocks
    "SELECT name FROM orders UNION SELECT data ->> 'password' FROM users",
]


@pytest.mark.parametrize("sql", JSON_SENSITIVE_KEY, ids=lambda s: s[:52])
def test_json_literal_key_sensitive_blocks(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is Verdict.BLOCK, sql
    assert any(v.code == "sensitive_column" for v in r.violations), [
        v.code for v in r.violations
    ]


JSON_BENIGN_KEY = [
    "SELECT data ->> 'display_name' FROM users",
    "SELECT data ->> 'theme' FROM users",
    "SELECT data -> 'preferences' FROM users",
    "SELECT data #>> '{settings,theme}' FROM users",
    "SELECT data #> '{profile,display_name}' FROM users",
    "SELECT json_extract_path_text(data, 'a', 'theme') FROM users",
    "SELECT jsonb_extract_path_text(data, 'display_name') FROM users",
    # the SENSITIVE token is a non-terminal path element, terminal key is benign:
    # extracting {password,version} ->> projects 'version', not the secret itself.
    "SELECT data #>> '{password,version}' FROM users",
    # DYNAMIC key (a column, not a literal) is left to the column allowlist; the
    # literal-key gate must NOT over-fire on it (recall-safe).
    "SELECT data ->> keycol FROM users",
    "SELECT data #>> path_col FROM users",
]


@pytest.mark.parametrize("sql", JSON_BENIGN_KEY, ids=lambda s: s[:52])
def test_benign_json_keys_not_blocked(sql: str) -> None:
    r = check(sql, policy=DEFAULT)
    assert r.verdict is not Verdict.BLOCK, [v.model_dump() for v in r.violations]
    assert not any(v.code == "sensitive_column" for v in r.violations), [
        v.code for v in r.violations
    ]


def test_json_sensitive_disabled_when_denylist_empty() -> None:
    # Disabling the sensitive-column denylist also disables the json-key gate.
    pol = GuardPolicy(sensitive_columns=frozenset())
    r = check("SELECT data ->> 'password' FROM users", policy=pol)
    assert not any(v.code == "sensitive_column" for v in r.violations), [
        v.code for v in r.violations
    ]
