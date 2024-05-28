import asyncio
from itertools import cycle
from os import mkdir
from os.path import exists
from sys import stderr

from better_proxy import Proxy
from loguru import logger
from web3 import Web3
from web3.eth import AsyncEth

from core import start_claimer
from data import config
from utils import loader

logger.remove()
logger.add(stderr, format='<white>{time:HH:mm:ss}</white>'
                          ' | <level>{level: <8}</level>'
                          ' | <cyan>{line}</cyan>'
                          ' - <white>{message}</white>')


async def main():
    loader.semaphore = asyncio.Semaphore(value=threads)
    loader.provider = Web3(Web3.AsyncHTTPProvider(endpoint_uri=config.RPC_URL,
                                                  request_kwargs={'verify_ssl': False}),
                           modules={'eth': (AsyncEth,)},
                           middlewares=[])

    tasks: list[asyncio.Task] = [
        asyncio.create_task(
            coro=start_claimer(
                private_key=current_private_key,
                proxy_str=next(proxy_cycle) if proxy_cycle else None
            )
        )
        for current_private_key in accounts_list
    ]

    await asyncio.gather(*tasks)


if __name__ == '__main__':
    if not exists(path='result'):
        mkdir(path='result')

    with open(
            file='data/accounts.txt',
            mode='r',
            encoding='utf-8-sig'
    ) as file:
        accounts_list: list[str] = [row.strip().split(' ')[0] for row in file]

    with open(
            file='data/proxies.txt',
            mode='r',
            encoding='utf-8-sig'
    ) as file:
        proxy_list: list[str] = [Proxy.from_str(
            proxy=row.strip() if '://' in row.strip() else f'http://{row.strip()}'
        ).as_url for row in file]

    proxy_cycle: cycle | None = cycle(proxy_list) if proxy_list else None

    logger.info(f'Successfully Loaded {len(accounts_list)} Accounts')
    threads: int = int(input('\nThreads: '))
    print()

    asyncio.run(main())

    logger.success('Work Has Been Successfully Finished')
    input('\nPress Enter to Exit..')
