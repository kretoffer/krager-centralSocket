from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

import json


class CryptoCipher:
    def __init__(self, staticKey: bytes, iv: bytes, public_RSA_key: bytes | RSA.RsaKey | None = None, public_DSA_key: DSA.DsaKey | None = None):
        key = RSA.generate(2048)
        self.__my_private_RSA_key = RSA.importKey(key.export_key())
        self.__my_public_RSA_key = RSA.importKey(key.publickey().export_key())
        self.__client_public_RSA_key = RSA.importKey(public_RSA_key) if public_RSA_key is bytes else public_RSA_key
        self.__static_key = staticKey
        self.__iv = iv
        DSA_key = DSA.generate(2048)
        self.__DSA_my_public_key = DSA_key.public_key()
        self.DSA_public_key = public_DSA_key

    def encodeRSA(self, message: str | dict | bytes) -> bytes:
        if not self.client_public_RSA_key:
            raise AttributeError(f"В {__class__} не определен атрибут client_public_key")
        message = message if not isinstance(message, dict) else json.dumps(message)
        message = message if isinstance(message, bytes) else message.encode('utf-8')
        cipher = PKCS1_OAEP.new(self.client_public_RSA_key)
        chunk_size = 210
        if len(message) <= chunk_size:
            return cipher.encrypt(message)
        else:
            chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
            message = b''
            for el in chunks:
                message += cipher.encrypt(el)
            return message

    def decodeRSA(self, message: bytes | bytearray | memoryview) -> bytes:
        cipher = PKCS1_OAEP.new(self.__my_private_RSA_key)
        chunk_size = 256
        if len(message) <= chunk_size:
            return cipher.decrypt(message)
        else:
            chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
            message = b''
            for el in chunks:
                message += cipher.decrypt(el)
            return message

    def encodeAES(self, message: str | dict | bytes) -> bytes:
        message = message if not isinstance(message, dict) else json.dumps(message)
        message = message if isinstance(message, bytes) else message.encode('utf-8')
        reminder = len(message) % 16
        if reminder != 0:
            message += bytes(16-reminder)
        cipher = AES.new(self.__static_key, AES.MODE_CBC, self.__iv)
        return cipher.encrypt(message)

    def decodeAES(self, message: bytes | bytearray | memoryview) -> bytes:
        decipher = AES.new(self.__static_key, AES.MODE_CBC, self.__iv)
        return decipher.decrypt(message).rstrip(b'\x00')

    def encodeRSApAES(self, message: str | dict | bytes) -> bytes:
        encode_message_part = self.encodeAES(message)
        encode_message_full = self.encodeRSA(encode_message_part)
        return encode_message_full

    def decodeRSApAES(self, message: bytes | bytearray | memoryview, to_str: bool = True) -> bytes | str:
        decode_message_part = self.decodeRSA(message)
        decode_message_full = self.decodeAES(decode_message_part)
        return decode_message_full.decode('utf-8') if to_str else decode_message_full

    def encode(self, message: str | dict | bytes) -> bytes: return self.encodeAES(message)
    def decode(self, message: bytes | bytearray | memoryview, to_str: bool = True) -> bytes | str: return self.decodeAES(message).decode('utf-8') if to_str else self.decodeAES(message)

    @classmethod
    def get_key(cls, static_key: bytes, dynamic_key: bytes) -> bytes:
        d_key = dynamic_key.lstrip(b'-----BEGIN PUBLIC KEY-----\n').rstrip(b'\n-----END PUBLIC KEY-----')
        key = d_key[:int(len(d_key)/2)] + static_key + d_key[:int(len(d_key)/2):]
        key_hash = SHA256.new(key).digest()
        return key_hash


    @property
    def client_public_RSA_key(self):
        return self.__client_public_RSA_key

    @client_public_RSA_key.setter
    def client_public_RSA_key(self, key: bytes | RSA.RsaKey):
        if isinstance(key, RSA.RsaKey):
            self.__client_public_RSA_key = key
            return
        try:
            self.__client_public_RSA_key = RSA.importKey(key)
        except ValueError | TypeError:
            raise ValueError("Введеное значение не может быть ключем")

    @property
    def public_RSA_key(self):
        return self.__my_public_RSA_key

    @property
    def DSA_public_key(self):
        return self.__DSA_public_key

    @DSA_public_key.setter
    def DSA_public_key(self, key: DSA.DsaKey):
        if key is None:
            self.__DSA_public_key = None
            return
        if isinstance(key, DSA.DsaKey):
            self.__DSA_public_key = key
            self.__key = self.get_key(self.__static_key, )
        else:
            raise TypeError(f"Сюда должно передаваться DsaKey, not {type(key)}")


