from __future__ import annotations
from typing import NamedTuple, Union, Optional, Dict, Any, NoReturn
import re

from .errors import ParseError, SemanticError
from .loc import Loc


_varname = re.compile(r'[^\s,]+')


__all__ = (
    'LiteralValue',
    'ValueRef',
    'RuleValue',
)


def assert_never(value: NoReturn) -> NoReturn:
    assert False, f'Unhandled value: {value} ({type(value).__name__})'


class LiteralValue(NamedTuple):
    int_val: int


class ValueRef(NamedTuple):
    val_name: str


class RuleValue(NamedTuple):
    ref: Union[LiteralValue, ValueRef]

    def __str__(self) -> str:
        ref = self.ref
        if isinstance(ref, LiteralValue):
            return str(ref.int_val)
        elif isinstance(ref, ValueRef):
            return ref.val_name
        else:
            return assert_never()

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        if isinstance(self.ref, LiteralValue):
            return {'int_val': self.ref.int_val, }
        else:
            return {'val_name': self.ref.val_name, }

    @property
    def value(self) -> Union[int, str]:
        if isinstance(self.ref, LiteralValue):
            return self.ref.int_val
        else:
            return self.ref.val_name

    def has_literal_value(self, val: int) -> bool:
        return self.is_literal and self.literal == val

    @property
    def is_literal(self) -> bool:
        return isinstance(self.ref, LiteralValue)

    @property
    def literal(self) -> int:
        if not isinstance(self.ref, LiteralValue):
            raise SemanticError('Cannot resolve variable at build-time')
        return self.ref.int_val

    @classmethod
    def parse(cls, tok: str, loc: Optional[Loc] = None) -> RuleValue:
        if tok.startswith('-') or tok[:1].isdigit():
            try:
                val = int(tok)
            except ValueError:
                raise ParseError(f'Bad literal value "{tok}"', loc=loc)

            return cls(LiteralValue(val))
        else:
            if _varname.match(tok) is None:
                raise ParseError(f'Bad variable name value "{tok}"', loc=loc)
            return cls(ValueRef(tok))

    @classmethod
    def from_literal(cls, val: int) -> RuleValue:
        return cls(LiteralValue(val))
