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
    def validateDataAccept(self, data) -> bool:
        pass

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    crypto_cipher: Optional[CryptoCipher] = field(default=None, kw_only=True)
    __validated: bool = field(default=False, kw_only=True)

    def __post_init__(self):
        super().__post_init__()
        asyncio.create_task(self.accept())

    async def accept(self):
        print(f"New connect {self.writer.get_extra_info('peername')}")
        v = await self.connect()
        self.__validated = True
        self.data["validate"] = True
        print(self.data)
        if not v:
            self.data = {"validate": False, "userID": None}
            # TODO
            return
        print("good client")
        asyncio.create_task(self.listenStream())

    async def connect(self):
        message = await self.reader.read(1024)# ожидание сообщения вида data_1 = {"type": "connect", "publicKey": cipher.public_RSA_key.export_key()}
        message = message.decode('utf-8')
        data = json.loads(message)
        if data["type"] != "connect" or "publicKey" not in data:
            # TODO
            raise Exception("Connect error")
        key = data["publicKey"].encode('utf-8')
        self.crypto_cipher = CryptoCipher(public_RSA_key=CryptoCipher.RSA_key_from_bytes(key))
        message = self.crypto_cipher.encodeRSA(json.dumps({"type": "go connect", "key": self.crypto_cipher.public_RSA_key.export_key().decode('utf-8')}))
        await self.sendMessage(message)
        message = await self.reader.read(1024)# ожидание сообщения с данными о юзере
        message = self.crypto_cipher.decodeRSA(message)
        data = json.loads(message.decode('utf-8'))
        if data["type"] != "connect" or not all([el in data for el in ("userID", "deviceID")]):
            # TODO
            raise Exception("ConnectError")
        self.data = {"userID": data["userID"], "deviceID": data["deviceID"]}
        self.crypto_cipher.static_key, self.crypto_cipher.iv = ClientRepo.getUserStaticKeyAndIv(data["userID"], data["deviceID"])
        parameters = self.crypto_cipher.encodeRSApAES(self.crypto_cipher.parameters_to_bytes(self.crypto_cipher.parameters))
        await self.sendMessage(parameters)
        message = await self.reader.read(1024) #ожидание dh public key
        data = self.crypto_cipher.decodeRSApAES(message)
        message = self.crypto_cipher.encodeRSApAES(self.crypto_cipher.public_key_to_bytes(self.crypto_cipher.my_DH_public_key))
        self.crypto_cipher.DH_public_key = data
        await self.sendMessage(message)
        print(f"all good, key = {self.crypto_cipher._key}")
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

    async def sendMessage(self, message: dict | str | bytes) -> None:
        if message is dict:
            message = json.dumps(message)
        if message is str:
            message = message.encode('utf-8')
        self.writer.write(message)
        await self.writer.drain()

    @property
    def validated(self):
        return self.__validated


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
            self.writer.write(json.dumps({"type": "error"}).encode("utf-8"))
            await self.writer.drain()

    async def messageData(self, data: dict):
        repo = BaseKafkaRepository(topic="message")
        repo.addEvent(data, data["chat"]["id"])
        self.writer.write(json.dumps({"all": "good"}).encode("utf-8"))
        await self.writer.drain()
