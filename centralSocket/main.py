import asyncio

from appp import config

from appp.domain.entities.client import Client

from appp.logic import newClient

clients = {}


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    client = Client(reader, writer)
    if await newClient.v(client):
        if client.data["userID"] not in clients:
            clients[client.data["userID"]] = {client.data["deviceID"]: client}
        else:
            clients[client.data["userID"]][str(client.data["deviceID"])] = client


async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', config.CENTRAL_SOCKET_PORT)
    print("Server started, waiting for connections...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
