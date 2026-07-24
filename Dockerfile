FROM python:3.12-alpine3.23@sha256:601d3d3797e90e2534782e69c85fafb7971b43f24c7b1b079b7e48dd435e458d AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY ko-sqlguard /src/ko-sqlguard
RUN python -m pip wheel --wheel-dir /wheels /src/ko-sqlguard


FROM python:3.12-alpine3.23@sha256:601d3d3797e90e2534782e69c85fafb7971b43f24c7b1b079b7e48dd435e458d AS runtime

ARG VCS_REF
LABEL org.opencontainers.image.title="ko-sqlguard" \
      org.opencontainers.image.description="Hardened LLM SQL guard service" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/guard \
    KO_GUARD_HOST=0.0.0.0 \
    KO_GUARD_PORT=8080 \
    KO_GUARD_REQUIRE_PROVENANCE=true \
    KO_GUARD_SOURCE_COMMIT="${VCS_REF}" \
    KO_GUARD_SOURCE_DIRTY=false \
    KO_SQL_REQUIRE_ALLOWLIST=true

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 guard \
    && adduser -S -D -H -u 10001 -G guard \
       -h /home/guard -s /sbin/nologin guard \
    && mkdir -p /home/guard \
    && chown guard:guard /home/guard

COPY --from=builder /wheels /tmp/wheels
RUN python -m pip install --no-cache-dir --no-index \
        --find-links /tmp/wheels ko-sqlguard \
    && rm -rf /tmp/wheels
COPY deployment/guard_service.py /opt/guard-service/guard_service.py

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2)"]
CMD ["python", "/opt/guard-service/guard_service.py", "--kind", "sql"]
