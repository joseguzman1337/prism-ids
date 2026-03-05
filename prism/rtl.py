from __future__ import annotations
from typing import \
    Optional, \
    FrozenSet, \
    Set, \
    Sequence, \
    Tuple, \
    Mapping, \
    Generator
from itertools import chain

from .hyperscan import HsDatabase
from .sticky_buffer import StickyBuffer

__all__ = (
    'RtlNode',

    'RtlFinal',
    'RtlNop',
    'CompleteMatch',
    'PartialMatch',

    'RtlOp',
    'MultiPattern',
    'ComboPatterns',
    'OpSequence',
)


class RtlNode:
    __slots__ = (
        '_name',
    )

    template_name = 'rtl_noop.c'

    _name: str

    def __init__(self, name: str):
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def __repr__(self) -> str:
        return f'{type(self).__name__}(name={self._name})'

    @property
    def children(self) -> Generator[RtlNode, None, None]:
        yield from ()

    def topological(self,
                    done: Optional[Set[str]] = None,
                    ) -> Generator[RtlNode, None, None]:
        name = self.name

        if done is None:
            done = {name}
        elif name in done:
            return
        else:
            done.add(name)

        yield from chain(*(c.topological(done) for c in self.children))
        yield self


class RtlFinal(RtlNode):
    __slots__ = ()
    pass


class RtlNop(RtlFinal):
    __slots__ = ()
    pass


class _RtlSidSet(RtlFinal):
    __slots__ = (
        '_sids',
    )

    _sids: FrozenSet[int]

    def __init__(self, name: str, sids: FrozenSet[int]):
        super().__init__(name)
        self._sids = sids

    @property
    def sids(self) -> FrozenSet[int]:
        return self._sids

    def __repr__(self) -> str:
        rep = ', '.join(map(str, sorted(self._sids)))
        return f'{type(self).__name__}({rep})'


class CompleteMatch(_RtlSidSet):
    template_name = 'rtl_match.c'
    __slots__ = ()
    pass


class PartialMatch(_RtlSidSet):
    template_name = 'rtl_partial.c'
    __slots__ = (
        '_buf',
        '_set_bit',
        '_finals',
    )

    _buf: StickyBuffer
    _set_bit: Optional[int]
    _finals: Mapping[int, Tuple[int, ...]]

    def __init__(self, name: str, buf: StickyBuffer, sids: FrozenSet[int]):
        super().__init__(name, sids)
        self._buf = buf
        self._set_bit = None
        self._finals = {}

    def set_state_bit(self, bit: int) -> None:
        self._set_bit = bit

    def set_finals(self, fmap: Mapping[int, Tuple[int, ...]]) -> None:
        self._finals = fmap

    @property
    def set_bit(self) -> int:
        assert self._set_bit is not None
        return self._set_bit

    @property
    def finals(self) -> Generator[Tuple[int, Tuple[int, ...]], None, None]:
        yield from self._finals.items()

    @property
    def has_partials(self) -> bool:
        return self._set_bit is not None

    @property
    def buf(self) -> StickyBuffer:
        return self._buf

    def __repr__(self) -> str:
        rep = ', '.join(map(str, sorted(self._sids)))
        return f'{type(self).__name__}({self._buf.name}, {rep})'


class RtlOp(RtlNode):
    __slots__ = ()
    pass


class MultiPattern(RtlOp):
    template_name = 'rtl_hsmulti.c'
    __slots__ = (
        '_hsdb',
        '_mapping',
    )

    _hsdb: HsDatabase
    _mapping: Mapping[int, RtlNode]

    def __init__(self,
                 name: str,
                 hsdb: HsDatabase,
                 mapping: Mapping[int, RtlNode]):
        super().__init__(name)
        self._hsdb = hsdb
        self._mapping = mapping

    @property
    def children(self) -> Generator[RtlNode, None, None]:
        yield from self._mapping.values()

    def mapping(self) -> Generator[tuple[int, RtlNode], None, None]:
        yield from sorted(self._mapping.items(), key=lambda x: x[0])

    @property
    def hsdb(self) -> HsDatabase:
        return self._hsdb

    def __repr__(self) -> str:
        return f'{type(self).__name__}(hsdb={self._hsdb.name})'


class ComboPatterns(RtlOp):
    __slots__ = ()
    pass


class OpSequence(RtlOp):
    template_name = 'rtl_seq.c'
    __slots__ = (
        '_steps',
    )

    _steps: Tuple[RtlNode, ...]

    def __init__(self, name: str, steps: Sequence[RtlNode]):
        super().__init__(name)
        self._steps = tuple(steps)

    @property
    def steps(self) -> Sequence[RtlNode]:
        return self._steps

    @property
    def children(self) -> Generator[RtlNode, None, None]:
        yield from self._steps
