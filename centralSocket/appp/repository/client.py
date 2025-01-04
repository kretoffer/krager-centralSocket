from .base import BaseKafkaRepository


class ClientRepo:
    @classmethod
    def getUserStaticKeyAndIv(cls, userID: str, deviceID: int):
        key = b'\xd3\x18\xd0\xa6\xc5\xd7/\t\xe5\x01\x95\x11\xb9\xa8(\x007\xc7\xce\xf4\x1b\xc6\x17\xc3\xb6b\xbc\xde\x12[\xad0'
        iv = b'k\x83si\x93\x1dY$\xa1i\xf4\xb8!l\xf8\xfe'
        return key, iv


class ClientKafkaRepository(BaseKafkaRepository):
    ...

