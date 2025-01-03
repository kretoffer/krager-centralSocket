import asyncio

from ..domain.entities.client import Client


async def v(client: Client):
    while not client.validated:
        await asyncio.sleep(1)
    data = client.data
    if not data["validate"]:
        client.writer.close()
        await client.writer.wait_closed()
        print("Bad connect was interrupted")
        return False
    return True
