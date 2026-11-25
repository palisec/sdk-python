"""Verify Palisec webhook deliveries.

``palisec-signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>``. Pass the raw body
exactly as received. Stale timestamps (default 5 minutes) are rejected so a captured delivery cannot
be replayed, and the comparison is constant-time. Deduplicate on ``palisec-event-id``: retries reuse it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Mapping, Optional, Union


class WebhookVerificationError(Exception):
    """The delivery is not authentic, is malformed, or is too old."""


def _header(headers: Mapping[str, Any], name: str) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() == name:
            return v[0] if isinstance(v, (list, tuple)) else v
    return None


def verify(secret: str, raw_body: Union[str, bytes], headers: Mapping[str, Any], *, tolerance: int = 300, now: Optional[int] = None) -> dict:
    """Returns the parsed event if the signature is valid; raises WebhookVerificationError otherwise."""
    body = raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body
    ts = _header(headers, "palisec-timestamp")
    sig = _header(headers, "palisec-signature")
    if not ts or not ts.isdigit() or len(ts) > 12 or not sig or not sig.startswith("v1="):
        raise WebhookVerificationError("Missing or malformed Palisec signature headers")
    current = int(time.time()) if now is None else now
    if abs(current - int(ts)) > tolerance:
        raise WebhookVerificationError("Webhook timestamp is outside the tolerance window")
    expected = hmac.new(secret.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig[3:]):
        raise WebhookVerificationError("Webhook signature does not match")
    return json.loads(body)
