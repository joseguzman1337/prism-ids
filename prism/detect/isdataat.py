from __future__ import annotations
from dataclasses import dataclass
import re

from ..sigmatch import BufferMatch, UtilMixin
from ..sticky_buffer import StickyBuffer
from ..ruleopt import RuleOpt
from ..loc import Loc
from ..errors import ParseError
from ..rulevar import RuleValue, LiteralValue

from .size import BufferSize

__all__ = (
    'IsDataAt',
)

_parse = re.compile(
    r'^\s*!?([^\s,]+)\s*(,\s*relative)?\s*$',
)
_endswith = (
    True,
    RuleValue(LiteralValue(1)),
    True,
)


@dataclass(init=False, eq=True)
class IsDataAt(BufferMatch, opt_name='isdataat'):
    __slots__ = (
        'buf',
        'negated',
        'val',
        'relative',
    )

    buf: StickyBuffer
    negated: bool
    val: RuleValue
    relative: bool

    def __init__(self,
                 buf: StickyBuffer,
                 negated: bool,
                 val: RuleValue,
                 relative: bool):
        self.buf = buf
        self.negated = negated
        self.val = val
        self.relative = relative

    def __str__(self) -> str:
        if self.is_endswith:
            return 'endswith'
        neg = '!' if self.negated else ''
        rel = ',relative' if self.relative else ''
        return f'isdataat:{neg}{self.val}{rel}'

    @property
    def json_dict(self) -> dict[str, object]:  # pragma: nocover
        return {
            'type': self.opt_name,
            'negated': self.negated,
            'val': UtilMixin._optional_json(self.val),
            'relative': self.relative,
        }

    @property
    def is_endswith(self) -> bool:
        return (self.negated, self.val, self.relative) == _endswith

    @classmethod
    def from_rule_opt(
        cls,
        opt: RuleOpt,
        buf: StickyBuffer,
        loc: Loc | None = None,
    ) -> IsDataAt | BufferSize:
        assert opt.value is not None, 'Blank "isdataat" value'

        value = opt.value

        if value.startswith('!'):
            value = value.lstrip('!')
            negated = True
        else:
            negated = False

        m = _parse.fullmatch(value)
        if m is None:
            raise ParseError(f'Unable to parse {cls.opt_name} value', loc=loc)

        val = RuleValue.parse(m.group(1), loc=loc)

        relative = m.lastindex == 2

        return cls(buf, negated, val, relative).normalize()

    # doe_ptr is initialized to the start of the buffer, so in that case, we
    # can just convert relative to absolute isdataat trivially
    def as_absolute(self) -> IsDataAt | BufferSize:
        return IsDataAt(
            self.buf,
            self.negated,
            self.val,
            False,
        ).normalize()

    def normalize(self) -> IsDataAt | BufferSize:
        if self.relative or not self.val.is_literal:
            return self

        val = self.val.literal
        if not val:
            return self

        hi = lo = None

        if self.negated:
            hi = val - 1
        else:
            lo = val

        return BufferSize(
            self.buf,
            lo,
            hi,
        )
