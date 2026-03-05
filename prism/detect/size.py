from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, TypeVar
import re

from ..errors import SemanticError
from ..sigmatch import BufferMatch
from ..sticky_buffer import StickyBuffer
from ..ruleopt import RuleOpt
from ..loc import Loc
from ..errors import ParseError

__all__ = (
    'DataSize',
    'BufferSize',
)

_parse = re.compile(
    r'^\s*(<|>)?\s*([0-9]{1,5})\s*(?:(<>)\s*([0-9]{1,5}))?\s*$',
)

_T = TypeVar('_T', bound='_Size')


class _Size:
    opt_name: str

    __slots__ = ()
    size_lo: Optional[int]
    size_hi: Optional[int]

    def __str__(self) -> str:
        size_lo = self.size_lo
        size_hi = self.size_hi
        lo = str(size_lo) if size_lo is not None else ''
        hi = str(size_hi) if size_hi is not None else ''
        return f'{lo}:{hi}'

    def __or__(self: _T, other: object) -> _T:
        if not isinstance(other, type(self)):
            return NotImplemented

        if self == other:
            return self

        raise SemanticError(
            f'Conflicting sizes: {self} / {other}'
        )

    @property
    def lt(self) -> bool:
        return self.size_lo is None

    @property
    def gt(self) -> bool:
        return self.size_hi is None

    @classmethod
    def _parse(cls,
               opt: RuleOpt,
               loc: Optional[Loc] = None,
               ) -> tuple[Optional[int], Optional[int]]:
        assert opt.value is not None, 'Blank "size" value'
        assert not opt.negated, 'Negated size'

        m = _parse.fullmatch(opt.value)
        if m is None:
            raise ParseError(f'Unable to parse {cls.opt_name} value', loc=loc)

        if m.lastindex == 2:
            mode, tok = m.group(1, 2)

            val = int(tok)

            lo: Optional[int]
            hi: Optional[int]

            if not mode:
                lo = hi = val
            elif mode == '<':
                lo = None
                hi = val - 1
            elif mode == '>':
                lo = val + 1
                hi = None
            else:  # pragma: nocover
                raise ParseError(f'Unknown comparison type {mode!r}', loc=loc)
        elif m.lastindex == 4:
            loval, hival = m.group(2, 4)
            lo = int(loval)
            hi = int(hival)
        else:  # pragma: nocover
            raise ParseError(f'Unable to parse {cls.opt_name} value', loc=loc)

        return lo, hi

    @property
    def never_matches(self) -> bool:
        if self.size_hi is None:
            return False
        if self.size_lo is None:
            return False
        return self.size_lo > self.size_hi

    def consistent_with(self, sz: Optional[int]) -> bool:
        if self.never_matches:
            return False

        if sz is None:
            return True

        size_lo = self.size_lo
        if size_lo is not None and size_lo > sz:
            return False

        size_hi = self.size_hi
        if size_hi is not None and size_hi < sz:
            return False

        return True


@dataclass(eq=True)
class BufferSize(BufferMatch, _Size, opt_name='bsize'):
    __slots__ = (
        'buf',
        'size_lo',
        'size_hi',
    )
    buf: StickyBuffer
    size_lo: Optional[int]
    size_hi: Optional[int]

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> BufferSize:
        lo, hi = cls._parse(opt, loc=loc)
        return cls(buf, lo, hi)

    @property
    def json_dict(self) -> dict[str, object]:  # pragma: nocover
        buf = self._optional_value(self.buf)
        return {
            'type': self.opt_name,
            'buf': buf,
            'size_hi': self.size_hi,
            'size_lo': self.size_lo,
        }


@dataclass(eq=True)
class DataSize(BufferMatch, _Size, opt_name='dsize'):
    """
    This should never really be constructed since from_rule_opt() will
    transparently convert all dsize into the appropriate bsize for PKT_DATA.
    """

    __slots__ = (
        'size_lo',
        'size_hi',
    )

    size_lo: Optional[int]
    size_hi: Optional[int]

    def __init__(self,
                 size_hi: Optional[int],
                 size_lo: Optional[int]):
        self.size_lo = size_lo
        self.size_hi = size_hi

    @property
    def buf(self) -> StickyBuffer:
        return StickyBuffer.PKT_DATA

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> BufferSize:
        return BufferSize.from_rule_opt(opt, StickyBuffer.PKT_DATA, loc=loc)

    @property
    def json_dict(self) -> dict[str, object]:  # pragma: nocover
        return {
            'type': self.opt_name,
            'size_hi': self.size_hi,
            'size_lo': self.size_lo,
        }
