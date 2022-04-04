from __future__ import annotations
from typing import Any, Generator, Mapping, NamedTuple, Iterable, Optional
from collections import defaultdict

from .hook import HookDef, Profile
from .partition import copartition
from .rule import Rule, RuleHead
from .flow import Flow
from .rulemeta import RuleMeta
from .loc import Loc
from .sigmatch import BufferMatch
from .sticky_buffer import StickyBuffer
from .errors import SemanticError
from .sigmatch import SigMatch
from .bufops import BufOps
from .ir import (
    BufOp, BufSize, BufRemaining, MPMPattern, Opcode, PatternChain, Regex,
)
from .irgen import irgen

__all__ = (
    'Program',
)


class FastPattern(NamedTuple):
    buf: StickyBuffer
    pat: MPMPattern


class RuleMatches(NamedTuple):
    bufs: Mapping[StickyBuffer, BufOps]
    extra: tuple[SigMatch, ...]

    @classmethod
    def from_parsed(cls, opts: Iterable[SigMatch]) -> RuleMatches:
        # First partition out buffer matches from the others
        bufopts: list[BufferMatch]
        extra, bufopts = copartition(BufferMatch, opts)  # type: ignore

        # Right now we don't support any extra opts
        if extra:
            unsupp = {type(x) for x in extra}
            err = ','.join(x.__name__ for x in unsupp)
            raise SemanticError(f'{err} not supported')

        # Group the buffer matches up by which buffer they match
        bufs = defaultdict(list)
        for opt in bufopts:
            bufs[opt.buf].append(opt)

        return cls(
            {k: BufOps.new(k, v) for k, v in bufs.items()},
            tuple(extra),
        )

    def print(self, r: Rule) -> None:
        print(r.loc, r.meta.sid, r.meta.msg)
        for (buf, bufops) in sorted(self.bufs.items(),
                                    key=lambda x: x[0].name):
            print(f'Buffer: {buf.name}')
            bufops.print()

        extra = self.extra
        if extra:
            print('Extra matches:')
            for opt in extra:
                print(f' {type(opt).__name__}: {opt}')
        print()

    def irgen(self, r: Rule) -> tuple[FastPattern,
                                      Mapping[StickyBuffer, tuple[BufOp, ...]],
                                      tuple[Opcode, ...]]:
        ir = {k: v.irgen() for k, v in self.bufs.items()}

        fps = {k: v for k, v in ir.items() if v.has_fast_pattern}
        if fps:
            # If a fast-pattern is explicitly selected by the rule author then
            # we use it
            if len(fps) > 1:
                raise SemanticError('Multiple fast-patterns')

            fp_buf, = fps.keys()
            fp_pat = fps[fp_buf].fast_pattern
        else:
            # Otherwise we go through all patterns (and for rel-chains we ask
            # it to nominate the highest scoring pattern)
            def all_pats() -> Generator[tuple[StickyBuffer, MPMPattern],
                                        None, None]:
                for k, v in ir.items():
                    yield from ((k, pat.fast_pattern)
                                for pat in v.mpm_patterns)

            def score(v: Optional[tuple[StickyBuffer, MPMPattern]]) -> int:
                if v is None:
                    return 0
                return v[1].score

            # And then we pick the highest scoring pattern
            fp = max(all_pats(), default=None, key=score)
            if fp is None:
                raise SemanticError('No patterns for fast-pattern')

            # In future we may want to weight different buffers when chosing a
            # fast pattern?

            # Making sure to remember what buffer it matches
            fp_buf, fp_pat = fp

            # Make sure we haven't forgotten to extract the winning pattern out
            # of any rel chains
            assert fp_pat.fast_pattern is fp_pat

            # Then if we can do the fast-pattern entirely in the MPM then
            # remove it from bufs.. No point duplicating effort.
            buf_pats = ir[fp_buf]
            opts = buf_pats.content_opts
            if fp_pat in opts:
                new = buf_pats._replace(
                    content_opts=tuple(x for x in opts if x is not fp_pat),
                )
                if new:
                    ir[fp_buf] = new
                else:
                    del ir[fp_buf]
                stripped = True
            else:
                stripped = False

            debug_fastpat = False
            if debug_fastpat:
                print(f'{"Removing" if stripped else "Duplicated"} fast-pat')
                print(r)
                if fp is not None:
                    print(fp_buf)
                    print(fp_pat)
                print()

        assert fp_pat is not None
        assert isinstance(fp_pat, MPMPattern)

        # Finally we can construct all the stuff we need to generate a Program
        # object for this rule
        return (
            FastPattern(fp_buf, fp_pat),
            {k: v.content_opts for k, v in ir.items()
             if v.content_opts},
            tuple(irgen(opt) for opt in self.extra),
        )


def _print_rule(r: Rule,
                matches: Iterable[SigMatch],
                ) -> None:
    print(r.loc, r.meta.sid, r.meta.msg)
    for opt in matches:
        print(f' {type(opt).__name__}: {opt}')
    print()


class Program:
    __slots__ = (
        '_prefilter',
        '_bufs',
        '_extra',

        '_meta',
        '_head',
        '_flow',

        '_raw',
        '_loc',
    )

    _prefilter: FastPattern
    _bufs: Mapping[StickyBuffer, tuple[BufOp, ...]]
    _extra: tuple[Opcode, ...]

    _meta: RuleMeta
    _head: RuleHead
    _flow: Flow

    _raw: Optional[str]
    _loc: Optional[Loc]

    def __init__(self,
                 prefilter: FastPattern,
                 bufs: Mapping[StickyBuffer, tuple[BufOp, ...]],
                 extra: tuple[Opcode, ...],

                 meta: RuleMeta,
                 head: RuleHead,
                 flow: Flow,

                 raw: Optional[str] = None,
                 loc: Optional[Loc] = None,
                 ) -> None:
        self._prefilter = prefilter
        self._bufs = bufs
        self._extra = extra

        self._meta = meta
        self._head = head
        self._flow = flow

        self._raw = raw
        self._loc = loc

    @property
    def supported(self) -> bool:
        def is_supported(ops: tuple[BufOp, ...]) -> bool:
            if len(ops) > 1:
                raise SemanticError('Multiple BufOps')
            op, = ops
            for x in (Regex, PatternChain, BufSize, BufRemaining):
                if isinstance(op, x):
                    raise SemanticError(
                        '%s not supported in backend' % x.__name__
                    )
            return True

        return all(is_supported(ops) for ops in self._bufs.values())

    @classmethod
    def from_rule(cls,
                  r: Rule,
                  debug_err: bool = False,
                  debug: bool = False,
                  ) -> Program:
        parsed = r.parsed

        if not parsed:
            # These are head-only rules which just match IP addresses, they can
            # probably go to a separate hook for that sort of thing
            # print(f'noop {r.meta.sid} {r.meta.msg}')
            raise SemanticError('noop rules not supported', loc=r.loc)

        if r.alp:
            raise SemanticError('app-layer-proto not supported', loc=r.loc)

        try:
            rm = RuleMatches.from_parsed(parsed)
        except SemanticError as e:
            if debug_err:
                print(e)
                _print_rule(r, parsed)
            e.loc = r.loc
            raise

        try:
            fp, bufs, extra = rm.irgen(r)
        except SemanticError as e:
            if debug_err:
                print(e)
                rm.print(r)
            e.loc = r.loc
            raise

        assert fp is not None

        if debug:
            _print_rule(r, parsed)
            rm.print(r)

        meta = r.meta
        head = r.head
        flow = r.flow

        return cls(
            fp,
            bufs,
            extra,

            meta,
            head,
            flow,

            raw=r.raw,
            loc=r.loc,
        )

    def hooks(self, p: Profile) -> tuple[HookDef, ...]:
        """
        Determine which hooks of a profile this rule needs to be attached to.
        """

        return p.determine(
            self._head.proto,
            self._flow,
            self._bufs.keys() | frozenset({self._prefilter.buf}),
            loc=self._loc,
        )

    @property
    def flow(self) -> Flow:
        return self._flow

    @property
    def head(self) -> RuleHead:
        return self._head

    @property
    def meta(self) -> RuleMeta:
        return self._meta

    @property
    def prefilter(self) -> FastPattern:
        return self._prefilter

    @property
    def bufs(self) -> Mapping[StickyBuffer, tuple[BufOp, ...]]:
        return self._bufs

    @property
    def buf_ops(self) -> Generator[tuple[StickyBuffer, BufOp], None, None]:
        fp = self._prefilter
        bufs = self._bufs

        if fp is not None:
            fp_buf = fp.buf
            yield from ((fp_buf, x) for x in bufs.get(fp_buf, ()))

            bufs = {k: v for (k, v) in bufs.items() if k is not fp_buf}

        for k, v in bufs.items():
            yield from ((k, x) for x in v)

    @property
    def extra(self) -> tuple[Opcode, ...]:
        return self._extra

    @property
    def json_dict(self) -> dict[str, Any]:  # pragma: nocover
        return {
            'meta': self._meta.json_dict,
            'head': self._head.json_dict,
            'flow': self._flow.json_dict,
            'prefilter': {
                'buf': self._prefilter.buf.value,
                'pattern': self._prefilter.pat.json_dict,
            },
            'buffers': {
                buf.value: [op.json_dict for op in ops]
                for buf, ops in self._bufs.items()
            },
            'extra': [op.json_dict for op in self._extra],
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Program):
            return NotImplemented

        return all((
            self._meta == other._meta,
            self._head == other._head,
            self._flow == other._flow,

            self._prefilter == other._prefilter,
            self._bufs == other._bufs,
            self._extra == other._extra,
        ))
