"""Reproducible external SQLi eval for ko-sqlguard.

Third-party SQLi corpora via the HF datasets-server REST API (stdlib only — no
`datasets`/`pandas`). Reports attack BLOCK-recall (deduped) and benign reads-only
false-block, the two headline numbers in the README.

    PYTHONPATH=src python eval/external_sqli.py

Datasets (auto-downloaded, cached under eval/_cache/):
  - zrmarine/sql_injection      (Query; Label==1 = injection)            attack
  - Pegasus77/sqli (apache-2.0) (output = the SQLi payload)              attack
  - gretelai/synthetic_text_to_sql (apache-2.0) (sql)                    benign
  - b-mc2/sql-create-context (cc-by-4.0) (answer)                        benign

Benign false-block is reported on the READS-ONLY subset (SELECT/WITH): a read-only
guard SHOULD block write/DDL, so counting those as "false" is wrong (see README).
"""
from __future__ import annotations

import json
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ko_sqlguard import GuardPolicy, Verdict, check  # noqa: E402

CACHE = Path(__file__).resolve().parent / "_cache"
POLICY = GuardPolicy()


def _get(url: str, retries: int = 8) -> dict:
    for i in range(retries):
        try:
            return json.load(urllib.request.urlopen(url, timeout=60))
        except urllib.error.HTTPError as e:  # noqa: PERF203
            if e.code == 429 and i < retries - 1:
                time.sleep(min(2 ** i, 30))
                continue
            raise
    raise RuntimeError("unreachable")


def fetch(dataset: str, column: str, where: tuple[str, str] | None = None, n: int = 2000) -> list[str]:
    CACHE.mkdir(exist_ok=True)
    cf = CACHE / (dataset.replace("/", "_") + f"__{column}.jsonl")
    if cf.exists():
        return [json.loads(line) for line in cf.read_text().splitlines() if line.strip()]
    out: list[str] = []
    off = 0
    ds = urllib.parse.quote(dataset)
    while off < n:
        d = _get(
            f"https://datasets-server.huggingface.co/rows?dataset={ds}"
            f"&config=default&split=train&offset={off}&length=100"
        )
        rows = [r["row"] for r in d.get("rows", [])]
        if not rows:
            break
        for r in rows:
            if where and str(r.get(where[0])) != where[1]:
                continue
            v = r.get(column)
            if isinstance(v, str) and v.strip():
                out.append(v)
        off += len(rows)
        if len(rows) < 100:
            break
    cf.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in out))
    return out


class _Timeout(Exception):
    pass


signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))


def blocks(sql: str) -> bool:
    signal.setitimer(signal.ITIMER_REAL, 4.0)
    try:
        return check(sql, policy=POLICY).verdict is Verdict.BLOCK
    except _Timeout:
        return True  # fail-closed, same contract as parse_error
    except Exception:  # noqa: BLE001
        return True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def _norm(s: str) -> str:
    return " ".join(s.split()).lower()


def _is_read(s: str) -> bool:
    """True only for a SINGLE read-only statement (SELECT/WITH/VALUES).

    Prefix-matching alone counts ``SELECT ...; DROP ...`` (multiple statements) and
    ``WITH x AS (...) INSERT ...`` (a CTE feeding a write) as reads because they begin
    with select/with — but those are correctly BLOCKED writes, not read-only benign, so
    they inflate the reads-only false-block denominator. Parse and exclude them so the
    reported benign-FPR reflects genuine read-only queries (honest denominator).
    """
    if not _norm(s).startswith(("select", "with", "(", "values")):
        return False
    try:
        import sqlglot
        from sqlglot import exp as _e
        stmts = [st for st in sqlglot.parse(s) if st is not None]
    except Exception:
        return True  # unparseable but read-prefixed: keep prior (conservative) behaviour
    if len(stmts) != 1:
        return False  # multiple statements (`SELECT ...; DROP ...`) → not read-only
    # any write/DDL node anywhere (incl. a CTE body `WITH x AS (...) INSERT ...`) → not read
    if stmts[0].find(_e.Insert, _e.Update, _e.Delete, _e.Create, _e.Drop,
                     _e.Alter, _e.Merge, _e.Command):
        return False
    return True


def main() -> None:
    attack = []
    seen: set[str] = set()
    for s in fetch("zrmarine/sql_injection", "Query", where=("Label", "1")) + fetch("Pegasus77/sqli", "output"):
        k = _norm(s)
        if k not in seen:
            seen.add(k)
            attack.append(s)
    blk = sum(blocks(s) for s in attack)
    print(f"ATTACK  deduped BLOCK-recall = {blk}/{len(attack)} = {blk / len(attack):.4f}")

    for ds, col in [("gretelai/synthetic_text_to_sql", "sql"), ("b-mc2/sql-create-context", "answer")]:
        rows = fetch(ds, col)
        reads = [s for s in rows if _is_read(s)]
        fb = sum(blocks(s) for s in reads)
        print(f"BENIGN  {ds:34s} reads={len(reads):4d}  false-block = {fb}/{len(reads)} = {fb / max(len(reads), 1):.4f}")


if __name__ == "__main__":
    main()
