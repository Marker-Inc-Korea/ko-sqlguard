# ko-sqlguard Deployment

이 저장소는 `ko-sqlguard` 패키지, 정책 API와 제품 테스트의 canonical source다. 인증, 감사,
공통 정책 로더와 컨테이너 hardening을 포함한 HTTP 서비스 조립은
[`modak_experiments/deployment`](https://github.com/Marker-Inc-Korea/modak_experiments/tree/main/deployment)
에서 관리한다. 공용 런타임을 제품별로 복제하지 않기 위해 이 저장소에는 서비스 `Dockerfile`을 두지 않는다.

## Package Qualification

```bash
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m mypy
python -m pytest
python -m build --sdist --wheel
```

릴리스 후보는 이 저장소의 clean commit에서 만들어야 하며, wheel 검증과 Python 지원 버전 CI가 모두
통과해야 한다. 패키지 검증은 HTTP 서비스 승격을 대신하지 않는다.

## Service Contract

`POST /v1/check` 요청은 `{"sql":"..."}` 형식이다. PASS/TRANSFORM이면 실행 가능한 `safe_sql`을,
BLOCK이면 `safe_sql=null`과 reason code만 반환한다. 서비스나 감사 로그는 차단된 원 SQL을
재노출하지 않는다.

기본 서비스 정책의 `allowed_tables={}`는 모든 테이블 접근을 차단한다. 실제 배포 전에
애플리케이션별 테이블·컬럼 allowlist를 공용 배포 저장소의 `sql-production.json`에 명시해야 한다.
readiness는 read-only, write 비활성, explicit allowlist, LIMIT, inference/catalog gate와
stacked-query canary를 확인한다. 실제 DB 계정에는 별도로 최소 권한, read-only transaction,
statement timeout과 row-level security를 적용해야 한다.

선택 EXPLAIN 비용 검사는 live PostgreSQL과 권한 경계가 필요한 별도 증거다. 정적 서비스의
배포 통과가 live cost guard 검증을 대신하지 않는다. 통합 저장소는 이미지에 이 저장소의 exact
commit을 기록하고, source digest, SBOM, signature와 preflight 결과를 함께 검증해야 한다.
