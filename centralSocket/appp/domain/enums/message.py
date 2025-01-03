from enum import Enum


class MessageContentType(Enum):
    text = 0
    image = 1
    video = 2
    emoji = 3
    mediaGroup = 4
    voiceMessage = 5
    videoMessage = 6


class MarkupType(Enum):
    KeyboardMarkup = 0
    ReplyMarkup = 1