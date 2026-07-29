# Changelog

이 프로젝트의 사용자 영향 변경을 기록합니다.

## Unreleased

### Documentation

- 소프트웨어 안정성과 고객 스키마 qualification을 분리하고, 운영에 필요한 allowlist,
  최소권한 DB role, timeout·quota와 비보장 범위를 제품 계약으로 추가했습니다.

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
