from dataclasses import dataclass
from .base import BaseValueObject


@dataclass(frozen=True)
class MessageText(BaseValueObject[str]):
    value: str

    def validate(self):
        if not self.value or self.value is not str or len(self.value) > 500:
            raise Exception("Bad Text")

    def as_generic_type(self) -> str:
        return str(self.value)

    def __str__(self):
        return self.as_generic_type()