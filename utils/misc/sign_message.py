from eth_account.account import LocalAccount
from eth_account.messages import encode_defunct


def sign_message(account: LocalAccount,
                 message_text: str) -> str:
    return account.sign_message(
        signable_message=encode_defunct(
            text=message_text
        )
    ).signature.hex()
