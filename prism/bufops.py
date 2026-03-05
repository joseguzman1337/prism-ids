from __future__ import annotations
from typing import NamedTuple, Optional, Sequence
from functools import reduce
from operator import or_

from .sigmatch import BufferMatch
from .sticky_buffer import StickyBuffer
from .errors import SemanticError
from .partition import copartition
from .irgen import irgen_content, ContentIR
from . import detect

__all__ = (
    'BufOps',
)


class RelBuilder(NamedTuple):
    anchor: BufferMatch
    rels: list[BufferMatch]

    def build(self) -> BufferMatch:
        rels = self.rels
        if not rels:
            return self.anchor

        last = rels.pop()
        if isinstance(last, detect.IsDataAt) and last.is_endswith:
            try:
                prev = rels.pop()
            except IndexError:
                prev = self.anchor
                consume = True
            else:
                consume = False

            try:
                new = prev.with_endswith()
            except SemanticError:
                rels.append(last)
            else:
                if consume:
                    return new

                rels.append(new)
        else:
            rels.append(last)

        if isinstance(self.anchor, detect.Pcre):
            raise SemanticError('Relchain cannot start with PCRE')

        return detect.RelChain(self.anchor, rels)


class BufOps(NamedTuple):
    """
    This is the first level of IR for content/buffer matches. We do all
    syntactic normalization and optimizations here. That means pretty much
    anything that we can figure out just from looking at the attributes of the
    rule options themselves without knowing anything about the actual
    semantics.

    Primarily this means normalizing startswith/endswith idioms, eg.
    - content:"abc"; isdataat:!1,relative; -> content:"abc"; endswith;
    - content:"abc"; offset:0; depth:3; -> content:"abc"; startswith;

    It can also be used to detect rules which are inconsistent with themselves
    and, therefore, can never match: eg.
    - content:"abc"; bsize:2;
    - content:"abc"; endswith; isdataat:1,relative;
    """

    buf: StickyBuffer
    size_constraint: Optional[detect.BufferSize]
    content_opts: tuple[BufferMatch, ...]

    def irgen(self) -> ContentIR:
        return irgen_content(
            self.buf,
            self.size_constraint,
            self.content_opts,
        )

    def print(self) -> None:
        (_, size_constraint, opts) = self
        if size_constraint:
            print(f' size-constraint: {size_constraint}')
        for opt in opts:
            print(f' {type(opt).__name__}: {opt}')

    def _fold_bufsz(self) -> BufOps:
        bufsz = self.size_constraint
        if bufsz is None:
            return self

        # If the size is a range, then we have to deal with it at the semantic
        # level.
        buf_size = bufsz.size_lo
        if bufsz.size_hi != buf_size:
            return self

        assert buf_size is not None

        fixedup = list()
        replace = False
        for sm in self.content_opts:
            new = sm.reveal_buffer_size(buf_size)
            fixedup.append(new)
            if sm is not new:
                replace = True

        if not replace:
            return self

        # If even a single content match is able to be turned in to an exact
        # match, then this buffer-size match is redundant, since if that
        # exact-match matches, then we've also checked the buffer size by
        # implication.

        return BufOps(self.buf, None, tuple(fixedup))

    @staticmethod
    def _fold_relative(v: Sequence[BufferMatch],
                       ) -> Sequence[BufferMatch]:
        prev: int = -1
        rels: dict[int, RelBuilder] = {}

        if not any(x.relative for x in v):
            return v

        for i, opt in enumerate(v):
            if opt.relative:
                try:
                    rels[prev].rels.append(opt)
                    continue
                except KeyError:
                    opt = opt.as_absolute()

            rels[i] = RelBuilder(opt, list())
            prev = i

        return tuple(b.build() for b in rels.values())

    @classmethod
    def _classify(cls,
                  opts: Sequence[BufferMatch],
                  ) -> tuple[Optional[detect.BufferSize],
                             tuple[BufferMatch, ...]]:
        opts, s = copartition(detect.BufferSize, opts)
        if not s:
            buffer_size = None
        else:
            buffer_size = reduce(or_, s)

        opts = cls._fold_relative(opts)

        return buffer_size, tuple(opts)

    @classmethod
    def new(cls, buf: StickyBuffer, opts: Sequence[BufferMatch]) -> BufOps:
        size_constraint, content = cls._classify(opts)
        return cls(buf, size_constraint, content)._fold_bufsz()
