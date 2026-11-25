"""web3.py adapter for ``Palisec.send_transaction``.

No web3 import: works with ``Web3`` or ``AsyncWeb3`` (v6 or v7) and an ``eth_account`` LocalAccount.

    from web3 import AsyncWeb3, AsyncHTTPProvider
    from eth_account import Account
    from palisec.web3 import Web3Sender

    w3 = AsyncWeb3(AsyncHTTPProvider("https://rpc.testnet.chain.robinhood.com"))
    sender = Web3Sender(w3, Account.from_key(os.environ["AGENT_KEY"]))
    result = await palisec.send_transaction(sender, to=TOKEN, data=calldata, gas_limit=90_000)
"""

from __future__ import annotations

import inspect
from typing import Any

from .errors import PalisecConfigError


async def _v(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class Web3Sender:
    """Signs locally with the account and sends the raw transaction through ``w3``.

    Checks that the RPC is on the chain Palisec authorized before signing, and pays the RPC's
    current gas price, the price Palisec bounded the fee on.
    """

    def __init__(self, w3: Any, account: Any) -> None:
        self._w3 = w3
        self._account = account
        self.address: str = account.address

    async def send_transaction(self, tx: dict) -> str:
        eth = self._w3.eth
        chain_id = int(await _v(eth.chain_id))
        if chain_id != tx["chainId"]:
            raise PalisecConfigError(f"The RPC is on chain {chain_id}, but Palisec authorized chain {tx['chainId']}")
        nonce = await _v(eth.get_transaction_count(self.address, "pending"))
        gas_price = int(await _v(eth.gas_price))
        signed = self._account.sign_transaction(
            {
                "to": tx["to"],
                "value": tx["value"],
                "data": tx["data"],
                "gas": tx["gas"],
                "gasPrice": gas_price,
                "nonce": nonce,
                "chainId": chain_id,
            }
        )
        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        sent = await _v(eth.send_raw_transaction(raw))
        return "0x" + bytes(sent).hex() if not isinstance(sent, str) else sent
