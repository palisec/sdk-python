"""Palisec: your agent asks before every transaction and sends only on ALLOW.

Docs: https://palisec.tech/docs/sdk/python
"""

__version__ = "0.4.10"

from .client import DEFAULT_BASE_URL, Palisec, Sender, Transport, redact, safe_op_typed_data, urllib_transport  # noqa: E402
from .codes import REASON_CODES, RETRYABLE  # noqa: E402
from .errors import (  # noqa: E402
    PalisecApprovalError,
    PalisecConfigError,
    PalisecDeniedError,
    PalisecError,
    PalisecTimeoutError,
)
from .models import SUPPORTED_CHAINS, Check, Intent, LogEvent, Operation, SendResult  # noqa: E402
from . import webhooks  # noqa: E402

__all__ = [
    "DEFAULT_BASE_URL",
    "REASON_CODES",
    "RETRYABLE",
    "SUPPORTED_CHAINS",
    "Check",
    "Intent",
    "LogEvent",
    "Operation",
    "Palisec",
    "PalisecApprovalError",
    "PalisecConfigError",
    "PalisecDeniedError",
    "PalisecError",
    "PalisecTimeoutError",
    "Sender",
    "SendResult",
    "Transport",
    "redact",
    "safe_op_typed_data",
    "urllib_transport",
    "webhooks",
    "__version__",
]
