"""Typed errors. Match on ``code``, never on the message."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .models import Operation


class PalisecError(Exception):
    """Every failure carries a stable ``code``: a ``PS_`` reason code or ``PS_SDK_CONFIG``,
    ``PS_SDK_TIMEOUT`` or ``PS_SDK_NETWORK``."""

    def __init__(
        self,
        message: str,
        code: str,
        status: Optional[int] = None,
        request_id: Optional[str] = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.request_id = request_id
        self.retryable = retryable

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, status={self.status!r}, message={self.message!r})"


class PalisecConfigError(PalisecError):
    """The client or wallet is configured in a way that cannot work (bad key, wrong chain, wrong account)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "PS_SDK_CONFIG")


class PalisecDeniedError(PalisecError):
    """The policy denied the operation. Nothing was authorized; do not send the transaction."""

    def __init__(self, operation: "Operation") -> None:
        super().__init__(
            operation.message,
            operation.reason_code or "PS_POLICY_001",
            200,
            operation.request_id,
            operation.retryable,
        )
        self.operation = operation


class PalisecApprovalError(PalisecError):
    """A held operation ended without approval: rejected, expired or withdrawn."""

    def __init__(self, operation: "Operation") -> None:
        code = "PS_HUMAN_001" if operation.state == "rejected" else "PS_REPLAY_001"
        super().__init__(f"Approval ended as {operation.state}", code, 200, operation.request_id, False)
        self.operation = operation


class PalisecTimeoutError(PalisecError):
    """The request or the wait did not finish in time. Retrying ``authorize`` with the same
    request ID is safe: it returns the original decision."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "PS_SDK_TIMEOUT", None, None, True)
