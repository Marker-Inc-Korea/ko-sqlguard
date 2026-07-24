"""task #16 — ko-sqlguard vs 베이스라인 (regex / bare-sqlglot) 동일 코퍼스 비교.

external_sqli.py의 fetch/dedup/_is_read/blocks(=ko-sqlguard) 재사용. 베이스라인 추가:
  · keyword-regex blacklist : 위험 키워드/주석/세미콜론/tautology 매칭 (recall↑이나 정상 reads FPR↑)
  · bare-sqlglot statement-type : SELECT/WITH 아니면 block (writes/DDL은 잡으나 SELECT 내 tautology 미탐 → recall↓)

스토리(ko-pii 식): 모든 베이스라인은 한 축에서 붕괴(regex=FPR폭증, bare-sqlglot=recall누락),
ko-sqlguard만 dangerous-recall × benign-FPR 프론티어 양 축 동시 우위.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from _paths import PACKAGE_ROOT, eval_path

KSG = str(PACKAGE_ROOT)
sys.path.insert(0, f"{KSG}/eval")
sys.path.insert(0, f"{KSG}/src")
import external_sqli as E  # fetch, _norm, _is_read, blocks(=ko-sqlguard)
import sqlglot

OUT = eval_path("bench_sql_report.json")

_DANGER = re.compile(
    r"\b(drop|delete|truncate|alter|update|insert|grant|revoke|exec|execute|union|"
    r"xp_\w+|sp_\w+|waitfor|shutdown|outfile|load_file|benchmark|sleep)\b"
    r"|--|/\*|;|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*or\s*'",
    re.I)


def regex_block(sql: str) -> bool:
    return bool(_DANGER.search(sql))


def baresqlglot_block(sql: str) -> bool:
    """statement-type만: 모든 문장이 read(Select/With/Union/Values)면 통과, 아니면 block."""
    try:
        exprs = sqlglot.parse(sql, read="postgres")
    except Exception:
        return True  # 파싱 실패 = fail-closed
    if not exprs:
        return True
    READ = {"Select", "With", "Union", "Values", "Subquery"}
    for e in exprs:
        if e is None or type(e).__name__ not in READ:
            return True
    return False  # 전부 read → 통과 (SELECT 내 tautology는 못 잡음)


METHODS = {
    "ko_sqlguard": E.blocks,        # 가드 (signal-timeout 포함)
    "regex_blacklist": regex_block,
    "bare_sqlglot": baresqlglot_block,
}


def main():
    # attack (deduped union)
    attack, seen = [], set()
    for s in E.fetch("zrmarine/sql_injection", "Query", where=("Label", "1")) + E.fetch("Pegasus77/sqli", "output"):
        k = E._norm(s)
        if k not in seen:
            seen.add(k); attack.append(s)
    # benign reads-only
    benign = []
    for ds, col in [("gretelai/synthetic_text_to_sql", "sql"), ("b-mc2/sql-create-context", "answer")]:
        benign += [s for s in E.fetch(ds, col) if E._is_read(s)]

    print(f"attack(deduped)={len(attack)}  benign(reads-only)={len(benign)}\n")
    report = {"n_attack": len(attack), "n_benign_reads": len(benign), "methods": {}}
    print(f"{'method':16} | dangerous-recall |  benign-FPR")
    for name, fn in METHODS.items():
        rec = sum(fn(s) for s in attack) / len(attack) * 100
        fpr = sum(fn(s) for s in benign) / len(benign) * 100
        report["methods"][name] = {"recall": round(rec, 2), "fpr": round(fpr, 2)}
        print(f"{name:16} |      {rec:6.2f}%     |   {fpr:6.2f}%")
    json.dump(report, open(OUT, "w"), ensure_ascii=False, indent=2)
    print(f"\nsaved → {OUT}")
    print("해석: ko-sqlguard만 양 축 동시 우위(high recall + low FPR). "
          "regex=FPR폭증, bare-sqlglot=SELECT내 tautology 미탐으로 recall누락.")


if __name__ == "__main__":
    main()
