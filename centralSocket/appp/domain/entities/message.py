from dataclasses import dataclass, field
from typing import Optional

from ..enums.message import MessageContentType
from ..value.message import MessageText
from .markup import Markup


@dataclass
class MessageContent:
    content_type: MessageContentType
    text: Optional[MessageText] = field(default=None)
    media: list = field(default_factory=list)
    markup: Optional[Markup] = field(default=None)

    def to_dict(self) -> dict:
        return {
            "content_type": self.content_type.name,
            "text": str(self.text) if isinstance(self.text, MessageText) else None,
            "media": self.media,
            "markup": self.markup.to_dict() if isinstance(self.markup, Markup) else None
        }

    @classmethod
    def dict_to_object(cls, data: dict):
        text = data["text"]
        markup = data["markup"]
        return MessageContent(
            MessageContentType[data["content_type"]],
            MessageText(text) if text is not None else None,
            data["media"],
            Markup.dict_to_object(markup) if markup is not None else None
        )


@dataclass
class Message:
    messageId: str
    sender: str
    content: MessageContent

    def to_dict(self) -> dict:
        return {
            "id": self.messageId,
            "sender": self.sender,
            "content": self.content.to_dict()
        }

    @classmethod
    def dict_to_object(cls, data: dict):
        return Message(
            data["id"],
            data["sender"],
            MessageContent.dict_to_object(data["content"])
        )
