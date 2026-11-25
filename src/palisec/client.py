"""Async client for the Palisec authorization API.

The SDK holds no security logic of its own: every decision is made and recorded server-side.
``send_transaction`` enforces that decision in your process by sending only on ALLOW.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Awaitable, Callable, Optional, Protocol, Tuple, Union

from . import __version__
from .codes import RETRYABLE
from .errors import (
    PalisecApprovalError,
    PalisecConfigError,
    PalisecDeniedError,
    PalisecError,
    PalisecTimeoutError,
)
from .models import SUPPORTED_CHAINS, Intent, LogEvent, Operation, SendResult

_KEY = re.compile(r"^ps_(live|test)_[0-9a-f]{48}$")
_KEY_ANYWHERE = re.compile(r"ps_(?:live|test)_[0-9a-f]{8,}")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX = re.compile(r"^0x([0-9a-fA-F]{2})*$")
_OP_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
_LOCAL = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d+)?/")
_RETRY_STATUS = frozenset({429, 502, 503, 504})
DEFAULT_BASE_URL = "https://palisec.tech/api/v1"

_log = logging.getLogger("palisec")

#: (method, url, headers, body, timeout_seconds) -> (status, text). Raise TimeoutError on timeout
#: and OSError on network failure. The default uses urllib in a worker thread.
Transport = Callable[[str, str, dict, Optional[bytes], float], Awaitable[Tuple[int, str]]]


def redact(text: str) -> str:
    """Masks Palisec API keys anywhere in a string, for logs and error reports."""
    return _KEY_ANYWHERE.sub(lambda m: f"{m.group(0)[:12]}...[redacted]", text)


class Sender(Protocol):
    """What ``send_transaction`` needs from a wallet. ``palisec.web3.Web3Sender`` adapts web3.py.

    ``tx`` has ``to``, ``value`` (int wei), ``data`` (hex), ``gas`` (int) and ``chainId``.
    Returns the transaction hash.
    """

    address: str

    def send_transaction(self, tx: dict) -> Union[str, Awaitable[str]]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Never follow redirects: the Authorization header must not travel to another URL.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_opener = urllib.request.build_opener(_NoRedirect)


async def urllib_transport(method: str, url: str, headers: dict, body: Optional[bytes], timeout: float) -> Tuple[int, str]:
    def go() -> Tuple[int, str]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with _opener.open(req, timeout=timeout) as res:
                return res.status, res.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError) or "timed out" in str(e.reason):
                raise TimeoutError(str(e.reason)) from None
            raise ConnectionError(str(e.reason)) from None

    try:
        return await asyncio.wait_for(asyncio.to_thread(go), timeout + 1)
    except asyncio.TimeoutError:
        raise TimeoutError("request timed out") from None


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class Palisec:
    """Async client. Use as ``async with Palisec(api_key=...) as palisec:`` or call ``aclose`` (a no-op today).

    Keep the API key server-side. ``max_retries`` applies to network errors, 429 and 5xx, and only
    on calls that are safe to repeat.
    """

    def __init__(
        self,
        api_key: str,
        *,
        chain_id: Optional[int] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 15.0,
        max_retries: int = 2,
        logger: Optional[Callable[[LogEvent], None]] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        match = _KEY.match(api_key) if isinstance(api_key, str) else None
        if not match:
            raise PalisecConfigError("api_key must be a Palisec agent key (ps_live_ or ps_test_ followed by 48 hex characters)")
        # The key decides the network, so a mainnet key is never pointed at testnet by accident, or the reverse.
        key_chain = 4663 if match.group(1) == "live" else 46630
        if chain_id is None:
            chain_id = key_chain
        if chain_id not in SUPPORTED_CHAINS:
            raise PalisecConfigError(f"chain_id {chain_id} is not supported; supported: {', '.join(map(str, SUPPORTED_CHAINS))}")
        if chain_id != key_chain:
            kind = "mainnet (ps_live_)" if key_chain == 4663 else "testnet (ps_test_)"
            raise PalisecConfigError(f"This is a {kind} key, so chain_id must be {key_chain}, not {chain_id}")
        base = base_url.rstrip("/")
        if not base.startswith("https://") and not _LOCAL.match(base + "/"):
            raise PalisecConfigError("base_url must use HTTPS (plain HTTP is allowed only for localhost)")
        self.chain_id = chain_id
        self._base = base
        self._key = api_key
        self._timeout = float(timeout)
        self._max_retries = max(0, min(int(max_retries), 5))
        self._logger = logger
        self._transport: Transport = transport or urllib_transport

    def __repr__(self) -> str:
        return f"Palisec(chain_id={self.chain_id}, base_url={self._base!r}, api_key='{self._key[:12]}...')"

    async def __aenter__(self) -> "Palisec":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        return None

    # -- internals -----------------------------------------------------------------------------

    def _emit(self, event: LogEvent) -> None:
        if self._logger:
            self._logger(event)
        elif _log.isEnabledFor(logging.DEBUG):
            _log.debug("palisec %s", dict(event))

    def _body(self, intent: Intent) -> dict:
        if not _ADDRESS.match(intent.to or ""):
            raise PalisecConfigError("to must be a 20-byte hex address")
        data = intent.data or "0x"
        if not _HEX.match(data):
            raise PalisecConfigError("data must be 0x-prefixed hex bytes")
        value = int(intent.value)
        if value < 0:
            raise PalisecConfigError("value must not be negative")
        deadline = int(time.time()) + min(max(int(intent.deadline_seconds), 1), 3600)
        return {
            "request_id": intent.request_id or str(uuid.uuid4()),
            "chain_id": self.chain_id,
            "to": intent.to,
            "value_wei": str(value),
            "data": data,
            "gas_limit": intent.gas,
            "deadline": deadline,
        }

    async def _request(self, method: str, path: str, *, body: Any = None, idempotency_key: Optional[str] = None, retry: bool) -> dict:
        attempts = self._max_retries + 1 if retry else 1
        last: Optional[PalisecError] = None
        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            self._emit({"type": "request", "method": method, "path": path, "attempt": attempt})
            headers = {
                "authorization": f"Bearer {self._key}",
                "accept": "application/json",
                "user-agent": f"palisec-python/{__version__}",
            }
            payload = None
            if body is not None:
                headers["content-type"] = "application/json"
                payload = json.dumps(body).encode()
            if idempotency_key:
                headers["idempotency-key"] = idempotency_key
            try:
                status, text = await self._transport(method, f"{self._base}{path}", headers, payload, self._timeout)
            except TimeoutError:
                last = PalisecTimeoutError(f"{method} {path} timed out after {self._timeout:g} s")
                if not retry:
                    raise last from None
            except OSError:
                last = PalisecError(f"Network error calling {method} {path}", "PS_SDK_NETWORK", None, None, True)
                if not retry:
                    raise last from None
            else:
                try:
                    data = json.loads(text) if text else {}
                except ValueError:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
                err = data.get("error") if isinstance(data.get("error"), dict) else None
                request_id = data.get("request_id")
                event: LogEvent = {
                    "type": "response",
                    "method": method,
                    "path": path,
                    "attempt": attempt,
                    "status": status,
                    "request_id": request_id,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
                if err and err.get("code"):
                    event["code"] = err["code"]
                self._emit(event)
                if 200 <= status < 300:
                    return data
                code = (err or {}).get("code") or ("PS_AUTH_001" if status == 401 else "PS_STATE_001")
                retryable = (err or {}).get("retryable")
                if retryable is None:
                    retryable = RETRYABLE.get(code, status in _RETRY_STATUS)
                last = PalisecError(redact((err or {}).get("message") or f"HTTP {status}"), code, status, request_id, bool(retryable))
                if not (retry and status in _RETRY_STATUS):
                    raise last
            if attempt < attempts:
                wait = min(0.25 * 2 ** (attempt - 1), 4.0) + random.random() / 10
                self._emit({"type": "retry", "method": method, "path": path, "attempt": attempt, "duration_ms": int(wait * 1000)})
                await asyncio.sleep(wait)
        assert last is not None
        self._emit({"type": "error", "method": method, "path": path, "attempt": attempts, "code": last.code})
        raise last

    @staticmethod
    def _intent(intent: Optional[Intent], kwargs: dict) -> Intent:
        if intent is not None and kwargs:
            raise PalisecConfigError("pass an Intent or keyword arguments, not both")
        return intent if intent is not None else Intent(**kwargs)

    # -- API -----------------------------------------------------------------------------------

    async def authorize(self, intent: Optional[Intent] = None, **kwargs: Any) -> Operation:
        """Asks whether this transaction may be sent and records the decision with its budget
        reservation. Returns ALLOW, DENY or REQUIRES_HUMAN_SIGNATURE; does not raise on DENY.

        Safe to retry: the request ID is the idempotency key, so a retry returns the original
        decision instead of a second one.
        """
        body = self._body(self._intent(intent, kwargs))
        raw = await self._request("POST", "/operations", body=body, idempotency_key=body["request_id"], retry=True)
        return Operation.from_api(raw)

    async def evaluate(self, intent: Optional[Intent] = None, **kwargs: Any) -> Operation:
        """Dry run: the same evaluation against live state, reserving and recording nothing."""
        body = self._body(self._intent(intent, kwargs))
        return Operation.from_api(await self._request("POST", "/authorizations/evaluate", body=body, retry=True))

    async def get_operation(self, operation_id: str) -> Operation:
        """Reads one of this agent's operations."""
        if not _OP_ID.match(operation_id or ""):
            raise PalisecConfigError("operation_id must be an operation's id")
        return Operation.from_api(await self._request("GET", f"/operations/{operation_id}", retry=True))

    async def who_am_i(self) -> dict:
        """The integration this key belongs to: agent, protected account, chain, scopes and bound policy."""
        return await self._request("GET", "/integration", retry=True)

    async def get_policy(self) -> dict:
        """The exact active policy version this agent is evaluated against (scope policy:read)."""
        return await self._request("GET", "/integration/policy", retry=True)

    async def list_audit_events(self, *, limit: int = 50, before: Optional[str] = None) -> dict:
        """Audit events this agent caused, newest first (scope audit:read). Returns events and next_before."""
        q = urllib.parse.urlencode({"limit": max(1, min(int(limit), 200)), **({"before": before} if before else {})})
        return await self._request("GET", f"/integration/audit-events?{q}", retry=True)

    async def list_operations(self, *, limit: int = 20, before: Optional[str] = None, decision: Optional[str] = None) -> dict:
        """This agent's own operations, newest first (scope operations:read)."""
        q = urllib.parse.urlencode({"limit": max(1, min(int(limit), 100)), **({"before": before} if before else {}), **({"decision": decision} if decision else {})})
        raw = await self._request("GET", f"/integration/operations?{q}", retry=True)
        return {"operations": [Operation.from_api(o) for o in raw.get("operations", [])], "next_before": raw.get("next_before")}

    @property
    def transactions(self) -> "_Transactions":
        """2.0 naming: `propose` is `authorize` (records a decision), `evaluate` is the dry run."""
        return _Transactions(self)

    async def cancel(self, operation_id: str) -> Operation:
        """Withdraws an operation still waiting for approval. Never retried automatically.
        Authorized operations keep their budget until they expire."""
        if not _OP_ID.match(operation_id or ""):
            raise PalisecConfigError("operation_id must be an operation's id")
        return Operation.from_api(await self._request("POST", f"/operations/{operation_id}/cancel", retry=False))

    async def wait_for_approval(self, operation_id: str, *, timeout: float = 900.0, interval: float = 5.0) -> Operation:
        """Waits for an approver's decision on a held operation. Returns the approved operation
        (now carrying an authorization); raises PalisecApprovalError if it is rejected, expires or
        is withdrawn, and PalisecTimeoutError if ``timeout`` seconds pass first."""
        until = time.monotonic() + timeout
        interval = max(float(interval), 1.0)
        while True:
            op = await self.get_operation(operation_id)
            if op.state == "approved":
                return op
            if op.state != "pending_approval":
                raise PalisecApprovalError(op)
            if time.monotonic() + interval > until:
                raise PalisecTimeoutError(f"No approval decision for {operation_id} within {timeout:g} s")
            await asyncio.sleep(interval)

    async def send_transaction(
        self,
        sender: Sender,
        intent: Optional[Intent] = None,
        *,
        wait_for_approval: bool = False,
        approval_timeout: float = 900.0,
        **kwargs: Any,
    ) -> SendResult:
        """Authorizes, then sends with ``sender`` only if allowed.

        Raises PalisecDeniedError on DENY (nothing is sent). A held operation is awaited when
        ``wait_for_approval`` is true, otherwise returned unsent with ``hash=None``. The sender
        must be the agent's registered account. This enforces the decision in your process only:
        until the on-chain module ships, a key used outside Palisec can still transact.
        """
        it = self._intent(intent, kwargs)
        if it.request_id is None:
            it = Intent(**{**it.__dict__, "request_id": str(uuid.uuid4())})
        op = await self.authorize(it)
        if op.decision == "DENY":
            raise PalisecDeniedError(op)
        if op.state == "pending_approval":
            if not wait_for_approval:
                return SendResult(operation=op, hash=None)
            assert op.operation_id is not None
            op = await self.wait_for_approval(op.operation_id, timeout=approval_timeout)
        if not op.allowed:
            raise PalisecDeniedError(op)
        if op.expires_at is not None and op.expires_at.timestamp() <= time.time():
            raise PalisecTimeoutError("The authorization expired before sending")
        account = (op.details or {}).get("account")
        sender_address = getattr(sender, "address", None)
        if not isinstance(sender_address, str) or not _ADDRESS.match(sender_address):
            raise PalisecConfigError("The sender has no valid address")
        if isinstance(account, str) and account.lower() != sender_address.lower():
            raise PalisecConfigError(f"The sender {sender_address} is not the agent's registered account {account}")
        tx = {"to": it.to, "value": int(it.value), "data": it.data or "0x", "gas": it.gas, "chainId": self.chain_id}
        tx_hash = await _maybe_await(sender.send_transaction(tx))
        return SendResult(operation=op, hash=str(tx_hash))

    # ───────── PALISEC smart accounts: on-chain enforcement ─────────

    async def prepare_execution(self, operation_id: str) -> dict:
        """Builds the one user operation PALISEC will co-sign for an allowed or approved operation.
        Returns ``user_operation``, ``safe_op_hash``, ``max_cost_wei`` and ``valid_until``. Nothing is sent."""
        if not _OP_ID.match(operation_id or ""):
            raise PalisecConfigError("operation_id must be an operation's id")
        return await self._request("POST", f"/operations/{operation_id}/user-operation", retry=True)

    async def submit_execution(self, operation_id: str, signature: str) -> dict:
        """Sends the agent's signature; PALISEC co-signs once and submits through the bundler. Never retried."""
        sig = signature if signature.startswith("0x") else "0x" + signature
        if not re.fullmatch(r"0x[0-9a-fA-F]{130}", sig):
            raise PalisecConfigError("signature must be 65 bytes of hex")
        await self._request("POST", f"/operations/{operation_id}/submit", body={"signature": sig}, retry=False)
        return await self.get_execution(operation_id)

    async def get_execution(self, operation_id: str) -> dict:
        """``status`` is not_prepared, prepared, submitted, executed or reverted, with ``transaction_hash`` once known."""
        return await self._request("GET", f"/operations/{operation_id}/execution", retry=True)

    async def execute_with_smart_account(
        self,
        sign_typed_data: Callable[[dict], Union[str, Awaitable[str]]],
        intent: Optional[Intent] = None,
        *,
        wait_for_approval: bool = False,
        approval_timeout: float = 900.0,
        receipt_timeout: float = 90.0,
        **kwargs: Any,
    ) -> dict:
        """Authorizes, then executes through the agent's PALISEC smart account.

        ``sign_typed_data`` signs EIP-712 data with the agent's key, for example with eth-account::

            acct = Account.from_key(agent_key)
            sign = lambda td: acct.sign_typed_data(full_message=td).signature.hex()

        PALISEC co-signs the same operation and the Safe checks both signatures on chain, so the
        agent's key alone cannot move funds. Raises PalisecDeniedError on DENY. Returns
        ``{"operation": Operation, "execution": dict}``.
        """
        it = self._intent(intent, kwargs)
        if it.request_id is None:
            it = Intent(**{**it.__dict__, "request_id": str(uuid.uuid4())})
        op = await self.authorize(it)
        if op.decision == "DENY":
            raise PalisecDeniedError(op)
        if op.state == "pending_approval":
            if not wait_for_approval:
                return {"operation": op, "execution": {"operation_id": op.operation_id, "status": "not_prepared"}}
            assert op.operation_id is not None
            op = await self.wait_for_approval(op.operation_id, timeout=approval_timeout)
        if not op.allowed or op.operation_id is None:
            raise PalisecDeniedError(op)
        prepared = await self.prepare_execution(op.operation_id)
        signature = await _maybe_await(sign_typed_data(safe_op_typed_data(prepared["user_operation"], self.chain_id)))
        execution = await self.submit_execution(op.operation_id, str(signature))
        until = time.monotonic() + receipt_timeout
        while execution.get("status") == "submitted" and time.monotonic() < until:
            await asyncio.sleep(3.0)
            execution = await self.get_execution(op.operation_id)
        return {"operation": op, "execution": execution}


_SAFE_4337_MODULE = "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226"
_ENTRY_POINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"


def safe_op_typed_data(user_operation: dict, chain_id: int) -> dict:
    """The EIP-712 data the agent signs for a prepared user operation, with integers as ints."""
    u = user_operation
    return {
        "domain": {"chainId": chain_id, "verifyingContract": _SAFE_4337_MODULE},
        "types": {
            "EIP712Domain": [{"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "SafeOp": [
                {"name": "safe", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "initCode", "type": "bytes"},
                {"name": "callData", "type": "bytes"},
                {"name": "verificationGasLimit", "type": "uint128"},
                {"name": "callGasLimit", "type": "uint128"},
                {"name": "preVerificationGas", "type": "uint256"},
                {"name": "maxPriorityFeePerGas", "type": "uint128"},
                {"name": "maxFeePerGas", "type": "uint128"},
                {"name": "paymasterAndData", "type": "bytes"},
                {"name": "validAfter", "type": "uint48"},
                {"name": "validUntil", "type": "uint48"},
                {"name": "entryPoint", "type": "address"},
            ],
        },
        "primaryType": "SafeOp",
        "message": {
            "safe": u["sender"],
            "nonce": int(u["nonce"], 16),
            "initCode": "0x",
            "callData": u["callData"],
            "verificationGasLimit": int(u["verificationGasLimit"], 16),
            "callGasLimit": int(u["callGasLimit"], 16),
            "preVerificationGas": int(u["preVerificationGas"], 16),
            "maxPriorityFeePerGas": int(u["maxPriorityFeePerGas"], 16),
            "maxFeePerGas": int(u["maxFeePerGas"], 16),
            "paymasterAndData": "0x",
            "validAfter": int(u["validAfter"]),
            "validUntil": int(u["validUntil"]),
            "entryPoint": _ENTRY_POINT_V07,
        },
    }


class _Transactions:
    """Aliases grouped under the 2.0 naming. Existing method names keep working."""

    def __init__(self, client: Palisec) -> None:
        self._c = client

    async def evaluate(self, intent: Optional[Intent] = None, **kwargs: Any) -> Operation:
        return await self._c.evaluate(intent, **kwargs)

    async def propose(self, intent: Optional[Intent] = None, **kwargs: Any) -> Operation:
        return await self._c.authorize(intent, **kwargs)

    async def get(self, operation_id: str) -> Operation:
        return await self._c.get_operation(operation_id)

    async def wait_for_approval(self, operation_id: str, **kwargs: Any) -> Operation:
        return await self._c.wait_for_approval(operation_id, **kwargs)

    async def cancel(self, operation_id: str) -> Operation:
        return await self._c.cancel(operation_id)
