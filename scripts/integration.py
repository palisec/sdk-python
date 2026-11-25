"""Runs the served palisec wheel against a live server. Started by integration.mjs, which sets up
the organization, policy, agent and key, and plays the human approver when this prints HELD."""

import asyncio
import json
import os
import sys
from pathlib import Path

# Import from the exact wheel palisec.tech serves (wheels are zip files, importable directly).
WHEEL = Path(__file__).resolve().parents[3] / "apps" / "web" / "public" / "sdk" / "palisec-0.4.1-py3-none-any.whl"
sys.path.insert(0, str(WHEEL))

from palisec import Palisec, PalisecDeniedError, PalisecError  # noqa: E402

BASE = os.environ["BASE_URL"].rstrip("/") + "/api/v1"
KEY = os.environ["PALISEC_KEY"]
TOKEN = os.environ["TOKEN"]
OWNER = os.environ["OWNER"]
AGENT = os.environ["AGENT_ACCOUNT"]

passed = failed = 0


def check(name, ok, detail=None):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok or detail is None else f"  -> {str(detail)[:300]}"), flush=True)


def word(x: int) -> str:
    return format(x, "064x")


def transfer(amount: int) -> str:
    return "0xa9059cbb" + word(int(OWNER, 16)) + word(amount)


APPROVE = "0x095ea7b3" + word(int(OWNER, 16)) + word(1)


class Recorder:
    address = AGENT

    def __init__(self):
        self.sent = []

    async def send_transaction(self, tx):
        self.sent.append(tx)
        return "0x" + "cd" * 32


async def main():
    check("import: the served wheel is what runs", "palisec-0.4.1-py3-none-any.whl" in __import__("palisec").__file__)
    sender = Recorder()
    async with Palisec(KEY, base_url=BASE) as palisec:
        dry = await palisec.evaluate(to=TOKEN, data=transfer(1), gas_limit=90_000)
        check("evaluate: dry run allows and records nothing", dry.decision == "ALLOW" and dry.dry_run and dry.operation_id is None, dry)

        # A true retry sends the same body: pin the clock so both calls compute the same deadline.
        import palisec.client as _pc
        _real_time = _pc.time.time
        _pinned = _real_time()
        _pc.time.time = lambda: _pinned
        try:
            r1 = await palisec.authorize(to=TOKEN, data=transfer(2), gas_limit=90_000, request_id="py-idem-1")
            r2 = await palisec.authorize(to=TOKEN, data=transfer(2), gas_limit=90_000, request_id="py-idem-1")
        finally:
            _pc.time.time = _real_time
        check("authorize: ALLOW with an authorization and expiry", r1.allowed and r1.expires_at is not None, r1)
        check("authorize: retrying the same request returns the same operation", r1.operation_id == r2.operation_id, (r1.operation_id, r2.operation_id))

        ok = await palisec.send_transaction(sender, to=TOKEN, data=transfer(3), gas_limit=90_000)
        check("send_transaction: sends on ALLOW with the bounded gas", ok.hash and len(sender.sent) == 1 and sender.sent[0]["gas"] == 90_000, ok)

        before = len(sender.sent)
        try:
            await palisec.send_transaction(sender, to=OWNER, value=1)
            check("send_transaction: DENY raises", False)
        except PalisecDeniedError as e:
            check("send_transaction: DENY raises a stable code and never sends", e.code == "PS_TARGET_001" and len(sender.sent) == before, e.code)

        held = await palisec.send_transaction(sender, to=TOKEN, data=APPROVE, gas_limit=90_000)
        check("send_transaction: a held operation is returned unsent", held.hash is None and held.operation.state == "pending_approval", held.operation)
        withdrawn = await palisec.cancel(held.operation.operation_id)
        check("cancel: the agent withdraws its pending approval", withdrawn.state == "cancelled", withdrawn.state)

        held2 = await palisec.authorize(to=TOKEN, data=APPROVE, gas_limit=90_000)
        print(f"HELD {held2.operation_id}", flush=True)
        done = await palisec.wait_for_approval(held2.operation_id, timeout=60, interval=1)
        check("wait_for_approval: resolves once approved, with an authorization", done.state == "approved" and done.authorization_id, done)

        me = await palisec.who_am_i()
        check("who_am_i: the key identifies its agent and scopes", me["account"].lower() == AGENT.lower() and "mcp" in me["scopes"], me)
        pol = await palisec.get_policy()
        check("get_policy: the exact active version", pol["version"] == 1 and pol["document"]["schema_version"] == "1.1", pol.get("version"))
        trail = await palisec.list_audit_events(limit=10)
        check("list_audit_events: the agent's own events", any(e["type"].startswith("operation.") for e in trail["events"]), len(trail["events"]))
        prop = await palisec.transactions.propose(to=TOKEN, data=transfer(9), gas_limit=90_000)
        mine = await palisec.list_operations(limit=5)
        check("transactions.propose and list_operations", prop.decision == "ALLOW" and any(o.operation_id == prop.operation_id for o in mine["operations"]), prop.decision)

    async with Palisec("ps_test_" + "0" * 48, base_url=BASE) as bad:
        try:
            await bad.authorize(to=TOKEN)
            check("errors: unknown key raises", False)
        except PalisecError as e:
            check("errors: an unknown key is PS_AUTH_001", e.code == "PS_AUTH_001" and e.status == 401, e)

    print(json.dumps({"passed": passed, "failed": failed}), flush=True)
    sys.exit(1 if failed else 0)


asyncio.run(main())
