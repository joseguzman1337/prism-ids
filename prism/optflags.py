from typing import NamedTuple, Optional
from enum import Enum, auto

from .sticky_buffer import StickyBuffer

__all__ = (
    'TriState',
    'MetaFlags',
    'OptFlags',
)


class TriState(Enum):
    NONE = auto()
    OPTIONAL = auto()
    MANDATORY = auto()


class MetaFlags(NamedTuple):
    required: bool
    multiple: bool


class OptFlags(NamedTuple):
    quotes: TriState
    values: TriState
    negation: bool
    sticky_buffer: Optional[StickyBuffer] = None
    meta: Optional[MetaFlags] = None
    is_content_modifier: bool = False
    is_content_transform: bool = False
    known: bool = True

    @property
    def is_meta(self) -> bool:
        return self.meta is not None
