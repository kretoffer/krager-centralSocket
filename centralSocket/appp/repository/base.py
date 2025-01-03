from typing import Any
from abc import ABC
from kafka import KafkaProducer
import json

from ..domain.singleton import Singleton


kafka_ports = (9092,)
defaultKafkaHosts = tuple([f'localhost:{port}' for port in kafka_ports])


class BaseKafkaRepository(metaclass=Singleton):

    def __init__(self, hosts: list | tuple = defaultKafkaHosts, topic: str = "test"):
        self.hosts = hosts
        self.topic = topic
        self.producer = self.getProducer(self.hosts)

    @classmethod
    def getProducer(cls, hosts: list | tuple) -> KafkaProducer:
        producer = KafkaProducer(
            bootstrap_servers=list(hosts),
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        return producer

    def addEvent(self, data: dict, key: Any = None, topic: str | None = None):
        if not isinstance(data, dict):
            raise TypeError(f"event data must be dict.\n{type(data)} doesn't fit")
        topic = topic if topic else self.topic
        self.producer.send(topic, data, key)

    def __add__(self, other: dict | tuple[dict, Any, str]):
        if isinstance(other, dict):
            self.addEvent(other)
        elif isinstance(other, tuple):
            self.addEvent(other[0], other[1], other[2])
        return self


class BaseHttpRepository(ABC):

    def __init__(self, host: str = 'localhost:5052'):
        self.host = host

    @classmethod
    def getHeaders(cls) -> list:
        """Return default headers for request"""
        return []

    def SendRequest(self, host: str | None = None):
        """Send request and return response"""
        #TODO
        host = host if host is not None else self.host
        return None


class BaseSQLRepository(ABC):

    def __init__(self, host: str = ''):
        self.host = host
