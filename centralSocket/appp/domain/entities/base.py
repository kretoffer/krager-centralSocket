from abc import ABC, abstractmethod
from copy import copy
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


from ..events.base import BaseEvent


@dataclass
class BaseEntity(ABC):
    oid: str = field(
        default=str(uuid4()),
        kw_only=True,
    )
    _events: list[BaseEvent] = field(
        default_factory=list,
        kw_only=True,
    )
    created_at: int = field(
        default=datetime.now().timestamp(),
        kw_only=True,
    )

    def __hash__(self) -> int:
        return hash(self.oid)

    def __eq__(self, other: 'BaseEntity') -> bool:
        return self.oid == other.oid

    def register_event(self, event: BaseEvent) -> None:
        self._events.append(event)

    def pull_events(self, clear=True) -> list[BaseEvent]:
        registered_events = copy(self._events)
        if clear:
            self._events.clear()

        return registered_events
