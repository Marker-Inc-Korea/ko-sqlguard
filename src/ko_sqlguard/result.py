"""Verdicts, severities, violations, and the GuardResult returned by every check."""
from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict


class Verdict(str, enum.Enum):
    PASS = "pass"
    TRANSFORM = "transform"
    BLOCK = "block"


# What a check *intends* to do. `block` may be downgraded to an effective warn
# when its severity is below GuardPolicy.min_block_severity; `transform` rewrites
# the query and never blocks; `warn` is purely informational.
Action = Literal["block", "transform", "warn"]


class Severity(enum.IntEnum):
    """Ordered so that comparisons like `severity >= policy.min_block_severity` work."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class Violation(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    severity: Severity
    reason: str
    action: Action = "block"
    fix: str | None = None


class GuardTelemetry(BaseModel):
    """Telemetry safe to forward to logs or metrics without SQL content."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    forward_safe: bool
    violation_codes: tuple[str, ...] = ()
    highest_severity: Severity | None = None


class GuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    sql: str | None
    original_sql: str
    violations: tuple[Violation, ...] = ()

    @property
    def ok(self) -> bool:
        return self.verdict is not Verdict.BLOCK

    @property
    def forward_safe(self) -> bool:
        """Whether ``sql`` is present and may be forwarded to the database."""
        return self.verdict in (Verdict.PASS, Verdict.TRANSFORM) and self.sql is not None

    def to_telemetry(self) -> GuardTelemetry:
        """Return a SQL- and reason-free representation suitable for telemetry."""
        return GuardTelemetry(
            verdict=self.verdict,
            forward_safe=self.forward_safe,
            violation_codes=tuple(violation.code for violation in self.violations),
            highest_severity=max(
                (violation.severity for violation in self.violations), default=None
            ),
        )


class GuardBlocked(Exception):
    """Raised by Guard.enforce() when the query is blocked."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        reasons = "; ".join(f"[{v.code}] {v.reason}" for v in result.violations)
        super().__init__(f"SQL blocked: {reasons or 'unknown reason'}")
