# ko-sqlguard Deployment

배포 이미지는 SQL을 실행하지 않고 AST만 검사한다. 기본 서비스 정책의 `allowed_tables={}`는
모든 테이블 접근을 차단한다. 실제 배포 전에 애플리케이션별 테이블·컬럼 allowlist를
`sql-production.json`에 명시해야 한다.

## Build

```bash
docker build -f ko-sqlguard/Dockerfile \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t ko-sqlguard:0.2.0 .
```

## Run

```bash
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8083:8080 \
  -e KO_GUARD_API_TOKEN="$KO_GUARD_API_TOKEN" \
  -e KO_GUARD_AUDIT_HMAC_KEY="$KO_GUARD_AUDIT_HMAC_KEY" \
  -v "$PWD/deployment/policies/sql-production.json:/run/policy.json:ro" \
  -e KO_GUARD_POLICY_FILE=/run/policy.json \
  ko-sqlguard:0.2.0
```

두 secret은 서로 다른 최소 32바이트 값이어야 하며 외부 bind에서는 모두 필수다.

## API

`POST /v1/check` 요청은 `{"sql":"..."}` 형식이다. PASS/TRANSFORM이면 실행 가능한 `safe_sql`을,
BLOCK이면 `safe_sql=null`과 reason code만 반환한다. 서비스나 감사 로그는 차단된 원 SQL을
재노출하지 않는다.

readiness는 read-only, write 비활성, explicit allowlist, LIMIT, inference/catalog gate와
stacked-query canary를 확인한다. 실제 DB 계정에는 별도로 최소 권한, read-only transaction,
statement timeout과 row-level security를 적용해야 한다.

선택 EXPLAIN 비용 검사는 live PostgreSQL과 권한 경계가 필요한 별도 증거다. 정적 서비스의
배포 통과가 live cost guard 검증을 대신하지 않는다. 전체 승격 조건은
[suite deployment contract](../deployment/README.md)를 따른다.
