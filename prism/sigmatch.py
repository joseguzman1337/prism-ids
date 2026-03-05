from __future__ import annotations
from typing import Dict, Type, Optional, Any, TypeVar
from abc import ABC, abstractmethod

from .sticky_buffer import StickyBuffer
from .ruleopt import RuleOpt
from .json import JSONProto, StrValueProto, JScalar
from .loc import Loc
from .errors import SemanticError

__all__ = (
    'UtilMixin',
    'SigMatch',
    'BufferMatch',
    'BufferContentMatch',
    'sigmatch_registry',
)


T = TypeVar('T', bound='SigMatch')


class UtilMixin:
    __slots__ = ()

    @staticmethod
    def _optional_value(val: Optional[StrValueProto]) -> Optional[JScalar]:
        if val is None:
            return None
        return val.value

    @staticmethod
    def _optional_json(val: Optional[JSONProto]) -> Optional[Dict[str, Any]]:
        if val is None:
            return None
        return val.json_dict


class SigMatch(UtilMixin, ABC):
    __slots__ = ()
    opt_name: str = ''

    def __init_subclass__(cls: Type[SigMatch], **kwargs: Any) -> None:
        opt_name = kwargs.pop('opt_name', '')

        if opt_name:
            cls.opt_name = opt_name
            if opt_name in sigmatch_registry:
                raise Exception
            sigmatch_registry[opt_name] = cls

    @classmethod
    @abstractmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> SigMatch: ...

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {'type': self.opt_name, }


class BufferMatch(SigMatch, ABC):
    """
    An option which matches on a particular buffer
    """

    __slots__ = ()

    @property
    @abstractmethod
    def buf(self) -> StickyBuffer: ...

    @property
    def relative(self) -> bool:
        """
        If true then this reads from doe_ptr
        """
        return False

    def reveal_buffer_size(self: T, buffer_size: int) -> T:
        return self

    def as_absolute(self) -> BufferMatch:
        raise SemanticError(
            f'{self.opt_name}: cannot start with a relative match'
        )

    def with_endswith(self: T) -> T:
        return self


class BufferContentMatch(BufferMatch):
    """
    An option which matches on a particular buffer and has the side-effect of
    matching at a specific location (writes to doe_ptr).
    """

    __slots__ = ()


sigmatch_registry: Dict[str, Type[SigMatch]] = {}
