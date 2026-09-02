# Changelog

이 프로젝트의 사용자 영향 변경을 기록합니다.

## Unreleased

## 1.1.0 - 2026-09-02

### Documentation

- SQL 가드가 필요한 이유, 독립 저장소로 배포하는 이유와 `ko-` 네이밍의 의미를
  명확히 했습니다. 언어 특화 주장 대신 LLM SQL 실행 전 정책 경계로 정의했습니다.
- 소프트웨어 안정성과 고객 스키마 qualification을 분리하고, 운영에 필요한 allowlist,
  최소권한 DB role, timeout·quota와 비보장 범위를 제품 계약으로 추가했습니다.

### Added

- `ko-sqlguard` 단일 CLI를 추가해 파일·stdin SQL을 실행 없이 검사하고 JSON 판정을 반환합니다.
- 신뢰한 오프라인 컬럼 목록과 PII 표기를 allowlist/denylist로 변환하는
  `compile_schema_policy()`를 추가했습니다.
- 명시적 운영 allowlist, 구조 검사와 선택적 EXPLAIN 비용 검사를 통과한 SQL만 DB-API에
  전달하는 `execute_guarded()` 통합 경계를 추가했습니다.
- 파라미터화 쿼리의 비용 검사도 실제 실행과 동일한 DB-API 파라미터를 SQL 문자열과 분리해
  `EXPLAIN`에 전달합니다.
- PostgreSQL 17 서비스에서 실제 `EXPLAIN` 비용 gate를 실행하는 독립 CI job을 추가했습니다.
- 오프라인 schema snapshot에서 받은 `pii_columns`를 테이블별로 집행합니다. 직접 컬럼,
  별칭, CTE·파생테이블 내부, `SELECT *`, whole-row와 암시적 join 접근을 순수 AST 검사로
  차단합니다.

## 1.0.0 - 2026-07-28

### Changed

- 모노레포의 `ko-sqlguard/` 이력을 보존해 독립 저장소로 전환했습니다.
- 패키지 성숙도를 Production/Stable로 승격하고 독립 CI와 통합 릴리스 증거에 연결했습니다.
- 독립 CI, 배포 경계, 보안 신고 및 기여 절차를 추가했습니다.
- parser 전 문자·UTF-8 바이트 상한, 원문 없는 telemetry, 명시적 운영 allowlist 검증을
  추가했습니다.

### Removed

- 중복 임시 분석 파일과 모노레포 전용 서비스 Dockerfile을 제거했습니다.

## 0.2.0

- PostgreSQL-first AST 검사, fail-closed 파싱, allowlist, 민감 컬럼, 위험 함수,
  카탈로그 정찰, tautology, cartesian 및 비용 가드를 포함합니다.
- 이 버전은 독립 저장소의 첫 릴리스 후보이며 stable tag는 별도 승격 gate 통과 후 생성합니다.
