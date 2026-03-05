from __future__ import annotations
from typing import Iterable, Optional

from ..sigmatch import BufferMatch
from ..sticky_buffer import StickyBuffer
from ..sigmatch import SigMatch
from ..ruleopt import RuleOpt
from ..loc import Loc

__all__ = (
    'RelChain',
)


class RelChain(BufferMatch):
    __slots__ = (
        '_anchor',
        '_chain',
    )

    _anchor: BufferMatch
    _chain: tuple[BufferMatch, ...]

    def __init__(self,
                 anchor: BufferMatch,
                 chain: Iterable[BufferMatch],
                 ) -> None:
        self._anchor = anchor
        self._chain = tuple(chain)

    @property
    def anchor(self) -> BufferMatch:
        return self._anchor

    @property
    def chain(self) -> tuple[BufferMatch, ...]:
        return self._chain

    @property
    def buf(self) -> StickyBuffer:
        return self._anchor.buf

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> SigMatch:
        raise NotImplementedError

    def __str__(self) -> str:
        return (str(self._anchor)
                + '\n  '
                + '\n  '.join(str(x) for x in self._chain))
