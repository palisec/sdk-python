"""Holder mandates: the vote message to sign, and the tally of a vote file.

Votes are gasless EIP-712 signatures; weight is the voter's token balance at the proposal's snapshot
block. This module has no dependencies: sign the typed data with your wallet library (for example
``eth_account.Account.sign_typed_data(key, full_message=vote_typed_data(...))``). Signature recovery and
rebuilding the snapshot from the chain are done by the recount script (``recount-mandate.mjs``).
"""

from __future__ import annotations

from typing import Any

VOTE_CHOICES = ("for", "against", "abstain")


def vote_typed_data(chain_id: int, mandate: str, proposal_id: str, choice: str, snapshot_block: int | str) -> dict[str, Any]:
    """The EIP-712 typed data a holder signs for a vote."""
    if choice not in VOTE_CHOICES:
        raise ValueError("choice must be for, against or abstain")
    return {
        "domain": {"name": "Palisec Mandates", "version": "1", "chainId": chain_id},
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "Vote": [
                {"name": "mandate", "type": "string"},
                {"name": "proposalId", "type": "string"},
                {"name": "choice", "type": "uint8"},
                {"name": "snapshotBlock", "type": "uint256"},
            ],
        },
        "primaryType": "Vote",
        "message": {"mandate": mandate, "proposalId": proposal_id, "choice": VOTE_CHOICES.index(choice), "snapshotBlock": int(snapshot_block)},
    }


def tally(quorum: str | int, pass_bps: int, votes: list[dict[str, Any]]) -> dict[str, Any]:
    """The same deterministic count as Palisec: quorum on all votes cast; passes when for / (for + against) > pass_bps."""
    f = a = ab = 0
    for v in votes:
        w = int(v["weight"])
        if v["choice"] == "for":
            f += w
        elif v["choice"] == "against":
            a += w
        else:
            ab += w
    cast = f + a + ab
    reached = cast >= int(quorum)
    decided = f + a
    passed = reached and decided > 0 and f * 10000 > decided * int(pass_bps)
    return {"for": str(f), "against": str(a), "abstain": str(ab), "cast": str(cast), "quorum": str(int(quorum)), "quorum_reached": reached, "passed": passed}


def tally_vote_file(file: dict[str, Any]) -> dict[str, Any]:
    """Recounts a published vote file from its own weights and checks them against its snapshot table."""
    holders = file["holders_at_snapshot"]
    weights_ok = all(holders.get(v["voter"].lower(), "0") == v["weight"] for v in file["votes"])
    rules = file["mandate"]["rules"]
    t = tally(rules["quorum"], rules["pass_bps"], file["votes"])
    r = file["proposal"].get("result") or {}
    matches = not r or all(r.get(k) == t[k] for k in ("for", "against", "abstain", "passed"))
    return {"tally": t, "weights_match_snapshot": weights_ok, "matches_published_result": matches}
