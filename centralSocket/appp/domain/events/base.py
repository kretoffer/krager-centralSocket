from abc import ABC
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass
class BaseEvent(ABC):
    event_id: str = field(
        default=str(uuid4()),
        kw_only=True,
    )
