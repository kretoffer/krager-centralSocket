from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import struct

import json
from .xor import xor_bytes


def int_to_bytes(num: int):
    num_bytes = (num.bit_length() + 7) // 8
    return num.to_bytes(num_bytes, byteorder='big')

class DartCrypto:
    @classmethod
    def dart_bytes_to_public_RSA_key(cls, data:bytes) -> RSA.RsaKey:
        modulus_length = struct.unpack('>I', data[:4])[0]
        exponent_length = struct.unpack('>I', data[4:8])[0]

        modulus = int.from_bytes(data[8:8 + modulus_length], byteorder='big')
        exponent = int.from_bytes(data[8 + modulus_length:8 + modulus_length + exponent_length], byteorder='big')

        return RSA.construct((modulus, exponent))

    @classmethod
    def RSA_key_to_dart_bytes(cls, key: RSA.RsaKey) -> bytes:
        return key.export_key(format='DER')

    @classmethod
    def python_dh_parameters_to_dart_bytes(cls, parameters: dh.DHParameters) -> tuple[bytes, bytes]:
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        p_bytes = p.to_bytes((p.bit_length()+7) // 8, byteorder='big')
        g_bytes = g.to_bytes((g.bit_length()+7) // 8, byteorder='big')

        return p_bytes, g_bytes

    @classmethod
    def python_dh_public_key_to_dart_bytes(cls, key: dh.DHPublicKey) -> bytes:
        y = key.public_numbers().y
        return int_to_bytes(y)


    @classmethod
    def dart_bytes_to_python_dh_public_key(cls, public_key_bytes: bytes, parameters: dh.DHParameters) -> dh.DHPublicKey:
        #a = base64.b64decode(public_key_bytes)
        #return serialization.load_pem_public_key(a, backend=default_backend())
        a = dh.DHPublicNumbers(
            int.from_bytes(public_key_bytes, byteorder="big"),
            parameters.parameter_numbers()
        ).public_key(default_backend())
        #return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
        return a


class CryptoCipher:
    def __init__(self, staticKey: bytes = None, iv: bytes = None, public_RSA_key: bytes | RSA.RsaKey | None = None, parameters: dh.DHParameters | bool = None, connect: str = "p", version: str = "0.0.1"):
        self.connect_type = connect
        self.version = version

        key = RSA.generate(2048, e=65537)
        self.__my_private_RSA_key = RSA.importKey(key.export_key())
        self.__my_public_RSA_key = RSA.importKey(key.publickey().export_key())
        self.__client_public_RSA_key = self.RSA_key_from_bytes(public_RSA_key, mode=self.connect_type) if public_RSA_key is bytes else public_RSA_key
        self.static_key = staticKey
        self.iv = iv
        self.__key = self.__static_key
        if parameters is not False:
            self.parameters = parameters if parameters else dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.DH_public_key = None

    def encodeRSA(self, message: str | dict | bytes) -> bytes:
        if not self.client_public_RSA_key:
            raise AttributeError(f"В {__class__} не определен атрибут client_public_key")
        message = message if not isinstance(message, dict) else json.dumps(message)
        message = message if isinstance(message, bytes) else message.encode('utf-8')
        cipher = PKCS1_OAEP.new(self.client_public_RSA_key)
        chunk_size = 214
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
        if reminder != 0 or message[-1] in (0, 255):
            if message[-1] != 0:
                message += bytes(16 - reminder)
            else:
                message += b'\xFF'*(16-reminder)

        cipher = AES.new(self.__key, AES.MODE_CBC, self.__iv)
        return cipher.encrypt(message)

    def decodeAES(self, message: bytes | bytearray | memoryview, key: bytes = None) -> bytes:
        decipher = AES.new(key if key else self.__key, AES.MODE_CBC, self.__iv)
        m = decipher.decrypt(message)
        return m.rstrip(b'\x00') if m[-1] == 0 else m.rstrip(b'\xFF')

    def encodeRSApAES(self, message: str | dict | bytes) -> bytes:
        encode_message_part = self.encodeAES(message)
        encode_message_full = self.encodeRSA(encode_message_part)
        return encode_message_full

    def decodeRSApAES(self, message: bytes | bytearray | memoryview, to_str: bool = False) -> bytes | str:
        decode_message_part = self.decodeRSA(message)
        decode_message_full = self.decodeAES(decode_message_part)
        return decode_message_full.decode('utf-8') if to_str else decode_message_full

    def encode(self, message: str | dict | bytes) -> bytes:
        return self.encodeAES(message)

    def decode(self, message: bytes | bytearray | memoryview, to_str: bool = False) -> bytes | str:
        return self.decodeAES(message).decode('utf-8') if to_str else self.decodeAES(message)

    @classmethod
    def parameters_to_bytes(cls, parameters: dh.DHParameters, mode: str):
        match mode:
            case "d": #p
                return parameters.parameter_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.ParameterFormat.PKCS3
                )
            #case "d":
            #    return DartCrypto.python_dh_parameters_to_dart_bytes(parameters)

    @classmethod
    def public_key_to_bytes(cls, key: dh.DHPublicKey, mode: str):
        match mode:
            case "p":
                return key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            case "d":
                return DartCrypto.python_dh_public_key_to_dart_bytes(key)


    @classmethod
    def RSA_key_from_bytes(cls, key: bytes, mode: str = "p") -> RSA.RsaKey:
        match mode:
            case "p":
                return RSA.import_key(key)
            case "d":
                return DartCrypto.dart_bytes_to_public_RSA_key(key)

    @classmethod
    def get_secret(cls, key: dh.DHPrivateKey, publicKey: dh.DHPublicKey) -> bytes:
        key = key.exchange(publicKey)
        return key

    @classmethod
    def get_key(cls, static_key: bytes, d_key: bytes) -> bytes:
        key = d_key[:int(len(d_key) / 2)] + static_key + d_key[int(len(d_key) / 2):]
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
    def DH_public_key(self):
        return self.__DH_public_key

    def get_dh_public_key(self, key):
        if isinstance(key, dh.DHPublicKey):
            return key
        match self.connect_type:
            case "p": return serialization.load_pem_public_key(key, backend=default_backend())
            case "d": return DartCrypto.dart_bytes_to_python_dh_public_key(key, self.parameters)

    @DH_public_key.setter
    def DH_public_key(self, key: dh.DHPublicKey | bytes | None):
        if key is None:
            self.__DH_public_key = None
            return
        if isinstance(key, (dh.DHPublicKey, bytes)):
            self.__DH_public_key = self.get_dh_public_key(key)
            self.__key = self.get_key(self.__static_key, self.get_secret(self.__DH_private_key, self.DH_public_key))
            t1 = self.__my_DH_public_key.public_numbers().y
            t2 = self.__DH_public_key.public_numbers().y
            self.__iv = xor_bytes(
                int_to_bytes(t1)[:16],
                int_to_bytes(t2)[:16]
            )
            del self.__parameters, self.__my_private_RSA_key, self.__my_public_RSA_key, \
                self.__static_key, self.__DH_public_key
        else:
            raise TypeError(f"Сюда должно передаваться DsaKey, not {type(key)}")

    @property
    def my_DH_public_key(self):
        return self.__my_DH_public_key

    @property
    def _key(self):
        """This property need only for unit-tests"""
        return self.__key

    @property
    def parameters(self):
        return self.__parameters

    @parameters.setter
    def parameters(self, parameters: dh.DHParameters | bytes):
        if not isinstance(parameters, (dh.DHParameters, bytes)):
            raise TypeError(f"parameters can't be a {type(parameters)}")
        self.__parameters = parameters if isinstance(parameters, dh.DHParameters) else serialization.load_pem_parameters(parameters, backend=default_backend())
        self.__DH_private_key = self.parameters.generate_private_key()
        self.__my_DH_public_key = self.__DH_private_key.public_key()

    @property
    def static_key(self):
        return self.__static_key

    @static_key.setter
    def static_key(self, key: bytes):
        if key is None:
            self.__static_key = None
            return
        if not isinstance(key, bytes):
            raise TypeError("key can be only bytes")
        if len(key) != 32:
            raise ValueError("kay may be only 32 bytes length")
        self.__static_key = key
        self.__key = self.__static_key

    @property
    def iv(self):
        return self.__iv

    @iv.setter
    def iv(self, iv: bytes):
        if iv is None:
            self.__iv = None
            return
        if not isinstance(iv, bytes):
            raise TypeError("iv can be only bytes")
        if len(iv) != 16:
            raise ValueError("iv may be only 16 bytes length")
        self.__iv = iv
