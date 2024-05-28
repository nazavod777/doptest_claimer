import asyncio

import aiohttp
from eth_abi import encode
from eth_account import Account
from eth_account.account import LocalAccount
from loguru import logger
from pyuseragents import random as random_useragent
from web3.auto import w3
from web3.types import TxParams

from data import config
from utils import loader
from utils.misc import append_file, sign_message


class Claimer:
    def __init__(self,
                 account: LocalAccount,
                 proxy_str: str | None = None) -> None:
        self.account: LocalAccount = account
        self.proxy_str: str | None = proxy_str

    async def do_login(self,
                       client: aiohttp.ClientSession) -> str | None:
        sign_hash: str = sign_message(
            account=self.account,
            message_text=f'weareDOPdev{self.account.address.lower()}weareDOPdev'
        )

        while True:
            response_text: None = None

            try:
                r: aiohttp.ClientResponse = await client.post(
                    url='https://apiclaims.dop.org/auth/signin',
                    json={
                        'sign': sign_hash,
                        'walletAddress': self.account.address.lower()
                    },
                    proxy=self.proxy_str
                )

                response_text: str = await r.text()
                response_json: dict = await r.json(content_type=None)

                if response_json['statusCode'] == 429:
                    logger.info(f'{self.account.key.hex()} | Too Many Requests, sleeping 30 secs.')
                    await asyncio.sleep(delay=30)
                    continue

                if response_json.get('statusCode', 0) != 200 or response_json.get('message', '') != 'Signin Successful':
                    logger.error(f'{self.account.key.hex()} | Wrong Auth Response: {response_text}')

                    async with asyncio.Lock():
                        await append_file(
                            file_path='result/wrong_auth.txt',
                            file_content=f'{self.account.key.hex()}\n'
                        )

                    return

                if response_json['data']['user']['claimed']:
                    logger.error(f'{self.account.key.hex()} | Already Claimed')

                    async with asyncio.Lock():
                        await append_file(
                            file_path='result/already_claimed.txt',
                            file_content=f'{self.account.key.hex()}\n'
                        )

                    return

                if response_json['data']['user']['airdropAmount'] <= 0:
                    logger.error(f'{self.account.key.hex()} | Zero Drop Value')

                    async with asyncio.Lock():
                        await append_file(
                            file_path='result/zero_drop_value.txt',
                            file_content=f'{self.account.key.hex()}\n'
                        )

                    return

                if response_json['data']['user']['kycRequired'] and not response_json['data']['user']['kycVerified']:
                    logger.error(f'{self.account.key.hex()} | KYC Required')

                    async with asyncio.Lock():
                        await append_file(
                            file_path='result/kyc_required.txt',
                            file_content=f'{self.account.key.hex()}\n'
                        )

                    return

                return response_json['data']['accessToken']

            except Exception as error:
                if response_text:
                    logger.error(f'{self.account.key.hex()} | Unexpected Error When Auth: {error}, '
                                 f'response: {response_text}')

                else:
                    logger.error(f'{self.account.key.hex()} | Unexpected Error When Auth: {error}')

    async def get_proof(self,
                        client: aiohttp.ClientSession,
                        access_token: str) -> tuple | None:
        while True:
            response_text: None = None

            try:
                r: aiohttp.ClientResponse = await client.get(
                    url='https://apiclaims.dop.org/claim/proof',
                    headers={
                        'Authorization': f'Bearer {access_token}'
                    },
                    proxy=self.proxy_str
                )

                response_text: str = await r.text()
                response_json: dict = await r.json(content_type=None)

                if response_json['statusCode'] == 429:
                    logger.info(f'{self.account.key.hex()} | Too Many Requests, sleeping 30 secs.')
                    await asyncio.sleep(delay=30)
                    continue

                if response_json['statusCode'] != 200 or response_json['message'] != 'Claimed successfully':
                    logger.error(f'{self.account.key.hex()} | Wrong Response When Getting Proof: {response_text}')

                    async with asyncio.Lock():
                        await append_file(
                            file_path=f'result/wrong_when_getting_proof.txt',
                            file_content=f'{self.account.key.hex()}\n'
                        )

                    return

                return response_json['data']

            except Exception as error:
                if response_text:
                    logger.error(f'{self.account.key.hex()} | Unexpected Error When Getting Proof: {error}, '
                                 f'response: {response_text}')

                else:
                    logger.error(f'{self.account.key.hex()} | Unexpected Error When Getting Proof: {error}')

    async def start_claimer(self) -> None:
        try:
            async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(
                        use_dns_cache=False,
                        ttl_dns_cache=300,
                        verify_ssl=False,
                        ssl=None
                    ),
                    headers={
                        'user-agent': random_useragent(),
                        'accept': 'application/json, text/plain, */*',
                        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
                        'content-type': 'application/json',
                        'origin': 'https://claim.dop.org',
                        'referer': 'https://claim.dop.org'
                    }
            ) as client:
                access_token: str | None = await self.do_login(
                    client=client
                )

                if not access_token:
                    return

                proof_data: dict | None = await self.get_proof(
                    client=client,
                    access_token=access_token
                )

                if not proof_data:
                    return

                tx_data: str = '0x83092e47' + encode(
                    types=['uint256', 'bytes32[]', 'uint256[]', 'uint256[]', 'bool', 'bool', 'uint8', 'bytes32',
                           'bytes32'],
                    args=[int(proof_data['proofData']['amount']),
                          [bytes.fromhex(current_proof[2:] if current_proof.startswith('0x') else current_proof) for
                           current_proof in proof_data['merkleProof']],
                          [],
                          [],
                          False,
                          proof_data['proofData']['isKycRequired'],
                          int(proof_data['sign']['v']),
                          bytes.fromhex(proof_data['sign']['r'][2:] if proof_data['sign']['r'].startswith('0x') else
                                        proof_data['sign']['r']),
                          bytes.fromhex(proof_data['sign']['s'][2:] if proof_data['sign']['s'].startswith('0x') else
                                        proof_data['sign']['s'])]
                ).hex()

                transaction: TxParams = {
                    'chainId': await loader.provider.eth.chain_id,
                    'data': tx_data,
                    'from': self.account.address,
                    'gasPrice': w3.to_wei(
                        number=config.GWEI,
                        unit='GWEI'
                    ) if isinstance(config.GWEI, int) and config.GWEI > 0 else await loader.provider.eth.gas_price,
                    'nonce': await loader.provider.eth.get_transaction_count(
                        self.account.address,
                        'latest'
                    ),
                    'to': '0x35f4817b14718C66DBBdBa085F5F8d2c3A4AA420'
                }

                try:
                    gas: int = await loader.provider.eth.estimate_gas(transaction=transaction)

                except Exception as error:
                    logger.error(f'{self.account.key.hex()} | Error When Simulating Transaction: {error}')

                    async with asyncio.Lock():
                        await append_file(
                            file_path='result/error_simulating_transaction.txt',
                            file_content=f'{self.account.key.hex()}\n'
                        )

                    return

                transaction['gas']: int = gas

                transaction_signed = self.account.sign_transaction(
                    transaction_dict=transaction
                )

                await loader.provider.eth.send_raw_transaction(transaction=transaction_signed.rawTransaction)
                transaction_hash: str = w3.to_hex(w3.keccak(transaction_signed.rawTransaction))

                logger.success(f'{self.account.key.hex()} | Successfully Sending Transaction: {transaction_hash}')

                async with asyncio.Lock():
                    await append_file(
                        file_path=f'result/success.txt',
                        file_content=f'{self.account.key.hex()}\n'
                    )

        except Exception as error:
            logger.error(f'{self.account.key.hex()} | Unexpected Error: {error}')

            async with asyncio.Lock():
                await append_file(
                    file_path='result/unexpected_error.txt',
                    file_content=f'{self.account.key.hex()}\n'
                )


async def start_claimer(
        private_key: str,
        proxy_str: str | None = None
) -> None:
    async with loader.semaphore:
        try:
            account: LocalAccount = Account.from_key(
                private_key=private_key
            )

        except ValueError:
            logger.error(f'{private_key} | Not Private Key')

            async with asyncio.Lock():
                await append_file(
                    file_path='result/wrong_pkey.txt',
                    file_content=f'{private_key}\n'
                )

        else:
            await Claimer(account=account,
                          proxy_str=proxy_str).start_claimer()
