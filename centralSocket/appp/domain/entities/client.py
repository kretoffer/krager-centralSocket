import json
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from .base import BaseEntity
from ...repository.base import BaseKafkaRepository
from ...repository.client import ClientRepo
from ...logic.Crypto import CryptoCipher


@dataclass
class Client(BaseEntity):
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    crypto_cipher: Optional[CryptoCipher] = field(default=None, kw_only=True)

    def __post_init__(self):
        super().__post_init__()
        self._validated = False
        asyncio.create_task(self.accept())

    async def accept(self):
        print(f"New connect {self.writer.get_extra_info('peername')}")
        message = await self.reader.read(1024)
        message = message.decode('utf-8')
        data = json.loads(message)
        print(data)
        v = await self.validate(data)
        _validated = True
        if not v:
            self.data = {"validate": False, "userID": None}
            # TODO
            return
        print("good client")
        asyncio.create_task(self.listenStream())

    async def validate(self, data):
        if not self.validateDataAccept(data):
            print("don't valid data type")
            self.writer.write("invalid_data".encode('utf-8'))
            return False
        self.data = data
        self.crypto_cipher = CryptoCipher(*ClientRepo.getUserStaticKeyAndIv(data["id"]), data["publicKey"])
        if not await self.validateConnect():
            print("BAD CONNECT")
            self.writer.write("bad connect, you are not ...".encode('utf-8'))
            return False
        return True

    @classmethod
    def validateDataAccept(cls, data):
        return data["type"] == "accept" and data["subtype"] == "accept to connect" and \
            all([el in data for el in ("type", "subtype", "id", "deviceID", "publicKey")])

    async def validateConnect(self):
        # TODO
        return True

    async def listenStream(self):
        data_handler = DataHandler(self.writer)
        while True:
            data = await self.reader.read(1024)
            if not data:
                break
            message = data.decode('utf-8')
            asyncio.create_task(data_handler(message))
        self.writer.close()
        await self.writer.wait_closed()
        print(f"Connect {self.writer.get_extra_info('peername')} was closed")

    async def sendMessage(self, message: dict | str) -> None:
        if message is dict:
            message = json.dumps(message)
        self.writer.write(message.encode('utf-8'))
        await self.writer.drain()

    @property
    def validated(self):
        return self._validated


class DataHandler:
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer

        self.__dataType = {
            "message": self.messageData,
        }

    async def __call__(self, data: dict):
        if DataType := data["type"] in self.__dataType:
            await self.__dataType[DataType](data)
        else:
            self.writer.write(json.dump({"type": "error"}).encode("utf-8"))
            await self.writer.drain()

    async def messageData(self, data: dict):
        repo = BaseKafkaRepository(topic="message")
        repo.addEvent(data, data["chat"]["id"])
        self.writer.write(json.dump({"all": "good"}).encode("utf-8"))
        await self.writer.drain()
