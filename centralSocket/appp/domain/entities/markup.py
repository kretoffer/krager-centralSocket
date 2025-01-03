from dataclasses import dataclass

from ..enums.message import MarkupType


@dataclass()
class Markup:
    type: MarkupType

    def to_dict(self) -> dict:
        return {
            "type": self.type.name
        }

    @classmethod
    def dict_to_object(cls, data: dict):
        return Markup(
            MarkupType[data["type"]]
        )