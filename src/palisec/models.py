"""Typed models. Integers are Python ints (wei never passes through a float)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Optional, TypedDict

Decision = Literal["ALLOW", "DENY", "REQUIRES_HUMAN_SIGNATURE"]
OperationState = Literal[
    "authorized",
    "denied",
    "pending_approval",
    "approved",
    "rejected",
    "cancelled",
    "expired",
    "authorization_expired",
    "not_recorded",
]

#: Chains this release accepts: Robinhood Chain (4663, real funds, where the deployment enables it) and
#: Robinhood Chain Testnet (46630). A ps_live_ key is a mainnet agent's; a ps_test_ key, testnet's.
SUPPORTED_CHAINS: tuple[int, ...] = (4663, 46630)
MAINNET = 4663
TESTNET = 46630


@dataclass(frozen=True)
class Intent:
    """A transaction the agent intends to send, described before it is signed.

    ``gas_limit`` is the gas you will send with; Palisec bounds the fee as gas_limit x gas price.
    Default: 21000 for a plain transfer, 250000 otherwise. ``request_id`` is unique per intended
    transaction and doubles as the idempotency key (default: a random UUID).
    """

    to: str
    value: int = 0
    data: str = "0x"
    gas_limit: Optional[int] = None
    request_id: Optional[str] = None
    deadline_seconds: int = 120

    @property
    def gas(self) -> int:
        if self.gas_limit is not None:
            return int(self.gas_limit)
        return 21_000 if self.data in ("", "0x") else 250_000


@dataclass(frozen=True)
class Check:
    id: str
    label: str
    status: Literal["pass", "fail", "review", "skipped"]
    detail: str


@dataclass(frozen=True)
class Operation:
    """A recorded decision. Palisec authorizes; it does not sign or broadcast."""

    operation_id: Optional[str]
    request_id: str
    decision: Decision
    state: OperationState
    reason_code: Optional[str]
    message: str
    retryable: bool
    policy_id: Optional[str]
    policy_version: Optional[int]
    authorization_id: Optional[str]
    expires_at: Optional[datetime]
    checks: tuple[Check, ...] = field(default_factory=tuple)
    dry_run: bool = False
    #: Present when read back from the API: the account, target, value and exposure evaluated.
    details: Optional[dict[str, Any]] = None

    @property
    def allowed(self) -> bool:
        """True when the operation carries a usable authorization (allowed, or approved by a human)."""
        return self.state in ("authorized", "approved") and self.authorization_id is not None

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "Operation":
        expires = raw.get("expires_at")
        return cls(
            operation_id=raw.get("operation_id"),
            request_id=raw.get("request_id", ""),
            decision=raw["decision"],
            state=raw["state"],
            reason_code=raw.get("reason_code"),
            message=raw.get("message", ""),
            retryable=bool(raw.get("retryable", False)),
            policy_id=raw.get("policy_id"),
            policy_version=raw.get("policy_version"),
            authorization_id=raw.get("authorization_id"),
            expires_at=datetime.fromisoformat(expires.replace("Z", "+00:00")) if expires else None,
            checks=tuple(
                Check(id=c.get("id", ""), label=c.get("label", ""), status=c.get("status", "skipped"), detail=c.get("detail", ""))
                for c in raw.get("checks") or []
            ),
            dry_run=bool(raw.get("dry_run", False)),
            details=raw.get("details"),
        )


@dataclass(frozen=True)
class SendResult:
    operation: Operation
    #: The transaction hash, or None when the operation is held for a human approver.
    hash: Optional[str]


class LogEvent(TypedDict, total=False):
    """Structured log event. Never contains the API key, request bodies or calldata."""

    type: Literal["request", "response", "retry", "error"]
    method: str
    path: str
    attempt: int
    status: int
    request_id: Optional[str]
    duration_ms: int
    code: str
