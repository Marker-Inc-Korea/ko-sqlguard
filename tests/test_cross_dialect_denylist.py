"""Cross-dialect denylist asymmetry — MySQL/MSSQL counterparts to covered PG primitives.

PostgreSQL is the target dialect, but real-world SQLi payloads (and external corpora)
carry MySQL/MSSQL spellings verbatim and parse here as ordinary calls/tables. The PG
side already blocks pg_read_file / dblink / pg_authid, so the equivalent other-engine
forms must be blocked too for symmetry on a MySQL/MSSQL backend or fallback:

  load_file()            ≡ pg_read_file()      (filesystem read)
  OPENQUERY/OPENROWSET   ≡ dblink()            (cross-server / file)
  mysql.user             ≡ pg_authid           (credential store)
  authentication_string  ≡ password_hash       (password column)

CONTROL: ordinary application reads stay non-BLOCK (no benign over-fire).
"""
from __future__ import annotations

import pytest

from ko_sqlguard import GuardPolicy, Verdict, check

DEFAULT = GuardPolicy()

ATTACKS = [
    "SELECT load_file('/etc/passwd')",
    "SELECT * FROM OPENQUERY(linked, 'SELECT 1')",
    "SELECT * FROM OPENDATASOURCE('SQLNCLI','...').db.dbo.t",
    "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')",
    "SELECT 1 UNION SELECT authentication_string FROM mysql.user",
    "SELECT user, host FROM mysql.user",
    "SELECT * FROM mysql.db",
    "SELECT * FROM performance_schema.threads",
]


@pytest.mark.parametrize("q", ATTACKS, ids=lambda s: s[:34])
def test_cross_dialect_attack_blocked(q: str) -> None:
    assert check(q, DEFAULT).verdict is Verdict.BLOCK, q


CONTROL = [
    "SELECT name FROM products WHERE id = 1",
    "SELECT user_id, email FROM users WHERE active = true",
    "SELECT host FROM servers WHERE id = 2",          # 'host' col / 'servers' table OK
    "SELECT load FROM machine_metrics WHERE id = 3",  # 'load' column ≠ load_file()
]


@pytest.mark.parametrize("q", CONTROL, ids=lambda s: s[:34])
def test_benign_not_blocked(q: str) -> None:
    assert check(q, DEFAULT).verdict is not Verdict.BLOCK, q
