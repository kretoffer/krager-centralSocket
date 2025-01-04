import asyncio

from appp import config

from appp.domain.entities.client import Client

from appp.logic import newClient

from appp.settings.terminal_func import terminal_func

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
    if config.enable_terminal:
        asyncio.create_task(terminal())
    async with server:
        await server.serve_forever()


async def terminal():
    print("Terminal was started")
    while True:
        command:str = await asyncio.to_thread(input, ">> ")
        if command in terminal_func:
            terminal_func[command]()
        elif command.startswith("python: "):
            exec(command[8:])
        else:
            print("I don't understand you")


if __name__ == "__main__":
    asyncio.run(main())
