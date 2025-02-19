import json
import asyncio
from dataclasses import dataclass, field
from typing import Optional

import loguru

from .base import BaseEntity
from ...repository.base import BaseKafkaRepository
from ...repository.client import ClientRepo
from ...logic.Crypto import CryptoCipher, DartCrypto


@dataclass
class Client(BaseEntity):
    def validateDataAccept(self, data) -> bool:
        pass

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    crypto_cipher: Optional[CryptoCipher] = field(default=None, kw_only=True)
    __validated: bool = field(default=False, kw_only=True)

    def __post_init__(self):
        self._data = None
        self._temp = None
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
        if data["type"] != "connect" or "publicKey" not in data or "connectMode" not in data:
            # TODO
            raise Exception("Connect error")
        key = CryptoCipher.RSA_key_from_bytes(data["publicKey"].encode('utf-8')) if data["connectMode"] == "p" else DartCrypto.dart_bytes_to_public_RSA_key(bytes(data["publicKey"]))
        self.crypto_cipher = CryptoCipher(public_RSA_key=key, connect=data["connectMode"], version=data["version"])
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
        if self.crypto_cipher.connect_type == "d":
            message = self.crypto_cipher.encodeRSApAES(self.crypto_cipher.parameters_to_bytes(self.crypto_cipher.parameters, mode=self.crypto_cipher.connect_type))
        else:
            parameters = self.crypto_cipher.parameters_to_bytes(self.crypto_cipher.parameters, mode=self.crypto_cipher.connect_type)
            message = [self.crypto_cipher.encodeRSApAES(el) for el in parameters]
        await self.sendMessage(message)
        message = await self.reader.read(5120) #ожидание dh public key
        data = self.crypto_cipher.decodeRSApAES(message)
        message = self.crypto_cipher.encodeRSApAES(self.crypto_cipher.public_key_to_bytes(self.crypto_cipher.my_DH_public_key, mode=self.crypto_cipher.connect_type))
        self.crypto_cipher.DH_public_key = data
        await self.sendMessage(message)
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

    async def sendMessage(self, message: dict | str | bytes | list[bytes]) -> None:
        if isinstance(message, list):
            for el in message:
                self.writer.write(el)
                await self.writer.drain()
            return
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
        self.repo = BaseKafkaRepository()

    async def __call__(self, data: dict):
        match data["type"]:
            case "message": await self.messageData(data)
            case "post": await self.postData(data)
            case "profiles": await self.editData(data)

    async def messageData(self, data: dict):
        if data["group"] == "post":
            self.repo.addEvent(data, data["chat"]["id"], topic="messages")
            return 0

    async def postData(self, data: dict):
        if data["group"] == "post":
            self.repo.addEvent(data, data["user"]["id"], topic="posts")
            return 0

    async def editData(self, data: dict):
        if data["group"] == "post":
            self.repo.addEvent(data, data["user"]["id"], topic="edits")
            return 0

