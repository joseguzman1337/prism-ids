from __future__ import annotations
from typing import (
    Optional, FrozenSet, Set, Sequence, Tuple, Mapping, Generator,
)
from itertools import chain

from .hyperscan import HsDatabase, HsPattern
from .sticky_buffer import StickyBuffer

__all__ = (
    'RtlNode',

    'RtlFinal',
    'RtlNop',
    'RtlMatch',
    'RtlPat',

    'BufPrefix',
    'BufSuffix',
    'BufExact',

    'SinglePattern',
    'MultiPattern',
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


class RtlMatch(RtlFinal):
    template_name = 'rtl_match.c'

    __slots__ = (
        '_sids',
    )

    _sids: FrozenSet[int]

    def __init__(self,
                 name: str,
                 sids: FrozenSet[int]):
        super().__init__(name)
        self._sids = sids

    @property
    def sids(self) -> FrozenSet[int]:
        return self._sids

    def __repr__(self) -> str:
        rep = ', '.join(map(str, sorted(self._sids)))
        return f'{type(self).__name__}({rep})'


class RtlBuf(RtlNode):
    __slots__ = (
        '_buf',
    )

    _sids: FrozenSet[int]

    def __init__(self,
                 name: str,
                 buf: StickyBuffer):
        super().__init__(name)
        self._buf = buf

    @property
    def buf(self) -> StickyBuffer:
        return self._buf


class RtlPat(RtlBuf):
    __slots__ = (
        '_content',
        '_nxt',
    )

    _content: bytes
    _nxt: RtlNode

    def __init__(self,
                 name: str,
                 buf: StickyBuffer,
                 content: bytes,
                 nxt: RtlNode):
        super().__init__(name, buf)
        self._content = content
        self._nxt = nxt

    @property
    def content(self) -> bytes:
        return self._content

    @property
    def children(self) -> Generator[RtlNode, None, None]:
        yield self._nxt

    @property
    def on_match(self) -> RtlNode:
        return self._nxt


class BufPrefix(RtlPat):
    template_name = 'rtl_bufprefix.c'


class BufSuffix(RtlPat):
    template_name = 'rtl_bufsuffix.c'


class BufExact(RtlPat):
    template_name = 'rtl_bufexact.c'


class SinglePattern(RtlBuf):
    template_name = 'rtl_hs.c'
    __slots__ = (
        '_hsdb',
        '_nxt',
    )

    def __init__(self,
                 name: str,
                 buf: StickyBuffer,
                 hsdb: HsDatabase,
                 nxt: RtlNode):
        assert len(hsdb) == 1
        super().__init__(name, buf)
        self._hsdb = hsdb
        self._nxt = nxt

    @property
    def children(self) -> Generator[RtlNode, None, None]:
        yield self._nxt

    @property
    def hsdb(self) -> HsDatabase:
        return self._hsdb

    @property
    def pattern(self) -> HsPattern:
        pat, = self.hsdb
        return pat

    @property
    def on_match(self) -> RtlNode:
        return self._nxt


class MultiPattern(RtlBuf):
    template_name = 'rtl_hsmulti.c'
    __slots__ = (
        '_hsdb',
        '_mapping',
    )

    _hsdb: HsDatabase
    _mapping: Mapping[int, RtlNode]

    def __init__(self,
                 name: str,
                 buf: StickyBuffer,
                 hsdb: HsDatabase,
                 mapping: Mapping[int, RtlNode]):
        super().__init__(name, buf)
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


class OpSequence(RtlNode):
    template_name = 'rtl_seq.c'
    __slots__ = (
        '_steps',
    )

    _steps: Tuple[RtlNode, ...]

    def __init__(self,
                 name: str,
                 steps: Sequence[RtlNode]):
        super().__init__(name)
        self._steps = tuple(steps)

    @property
    def steps(self) -> Sequence[RtlNode]:
        return self._steps

    @property
    def children(self) -> Generator[RtlNode, None, None]:
        yield from self._steps
