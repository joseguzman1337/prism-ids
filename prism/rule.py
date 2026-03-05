from __future__ import annotations
from typing import (
    Optional, NamedTuple, Generator, Tuple, List, DefaultDict, FrozenSet, Dict,
    Iterable, Any,
)
from collections import defaultdict
from functools import reduce, total_ordering
from enum import Enum
import re
import logging

from .loc import Loc
from .errors import ParseError
from .partition import partition
from .rulemeta import RuleMeta
from .threshold import RuleThreshold
from .flowbits import FlowBitOp
from .ruleopt import RuleOpt
from .optparse import translate, SigMatchUnknown
from .sigmatch import SigMatch
from .sticky_buffer import StickyBuffer
from .flow import Flow, FlowDirection, FlowState
from .detect import Content

__all__ = (
    'Action',
    'Direction',
    'RuleHead',
    'Rule',
)

_log = logging.getLogger('rule')

# Any semicolon not preceeded by a backslash, this looks dumb but it's how
# suricata's rule-parser actually works
_unescaped_semi = re.compile(r'(?<!\\);')

# Options singled out from the list for special treatment
_thresh_opts = frozenset({'threshold', 'detection_filter'})
_alp_opts = frozenset({
    'app-layer-protocol',
    'app-layer-event',
})
_special_opts = frozenset({
    'flow',
    'flowbits',
    'noalert',
}) | _alp_opts | _thresh_opts

# flow options
_cl = frozenset({'to_server', 'from_client'})
_sv = frozenset({'to_client', 'from_server'})
_direction = _cl | _sv

_est = 'established'
_nest = 'not_established'
_stateless = 'stateless'
_state = frozenset({_est, _nest, _stateless})

_ostream = 'only_stream'
_nstream = 'no_stream'
_stream = frozenset({_ostream, _nstream})

_ofrag = 'only_frag'
_nfrag = 'no_frag'
_frag = frozenset({_ofrag, _nfrag})

_all = _direction | _state | _stream | _frag


class AppLayerProto(NamedTuple):
    negated: bool
    name: str

    @classmethod
    def from_opt(
        cls,
        opt: RuleOpt,
    ) -> AppLayerProto:
        assert opt.value is not None
        return cls(
            opt.negated,
            opt.value,
        )


class Action(Enum):
    ALERT = 'alert'
    DROP = 'drop'
    PASS = 'pass'
    REJECT = 'reject'
    REJECTSRC = 'rejectsrc'
    REJECTDST = 'rejectdst'
    REJECTBOTH = 'rejectboth'
    CONFIG = 'config'


class Direction(Enum):
    UNI = '->'
    BI = '<>'


class RuleHead(NamedTuple):
    action: Action
    proto: str
    src: str
    sport: str
    direction: Direction
    dst: str
    dport: str

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'action': self.action.value,
            'proto': self.proto,
            'src': self.src,
            'sport': self.sport,
            'direction': self.direction.value,
            'dst': self.dst,
            'dport': self.dport,
        }


@total_ordering
class Rule:
    __slots__ = (
        'head',
        'flow',
        'flowbits',
        'opts',
        'buffers',
        'thresh',
        'meta',
        'alp',
        'raw',
        'loc',

        '_parsed',
        '_inspects_payload',
        '_unsupported_opts',
    )

    head: RuleHead

    flow: Flow
    flowbits: tuple[FlowBitOp, ...]

    opts: tuple[RuleOpt, ...]
    buffers: tuple[StickyBuffer, ...]

    thresh: tuple[RuleThreshold, ...]
    meta: RuleMeta
    alp: tuple[AppLayerProto, ...]

    raw: Optional[str]
    loc: Optional[Loc]

    _parsed: Optional[tuple[SigMatch, ...]]
    _unsupported_opts: frozenset[str]
    _inspects_payload: bool

    def __init__(self,
                 head: RuleHead,
                 flow: Flow,
                 flowbits: tuple[FlowBitOp, ...],
                 opts: tuple[RuleOpt, ...],
                 buffers: tuple[StickyBuffer, ...],
                 thresh: tuple[RuleThreshold, ...],
                 meta: RuleMeta,
                 alp: tuple[AppLayerProto, ...],
                 raw: Optional[str] = None,
                 loc: Optional[Loc] = None):
        self.head = head
        self.flow = flow
        self.flowbits = flowbits
        self.opts = opts
        self.buffers = buffers
        self.thresh = thresh
        self.meta = meta
        self.alp = alp
        self.raw = raw
        self.loc = loc
        self._parsed = None

    @property
    def parsed(self) -> Tuple[SigMatch, ...]:
        parsed = self._parsed
        if parsed is None:
            parsed = tuple((translate(opt, buf, loc=self.loc)
                            for opt, buf in zip(self.opts, self.buffers)))
            self._parsed = parsed

            raw_buf = StickyBuffer.PKT_DATA
            content = Content
            unknown = SigMatchUnknown

            self._inspects_payload = any(
                ((p.buf is raw_buf) for p in parsed if isinstance(p, content))
            )
            self._unsupported_opts = frozenset(
                (p.name for p in parsed if isinstance(p, unknown))
            )

        return parsed

    @property
    def inspects_payload(self) -> bool:
        try:
            return self._inspects_payload
        except AttributeError:
            _ = self.parsed
            return self._inspects_payload

    @property
    def unsupported_opts(self) -> FrozenSet[str]:
        try:
            return self._unsupported_opts
        except AttributeError:
            _ = self.parsed
            return self._unsupported_opts

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'head': self.head.json_dict,
            'flow': self.flow.json_dict,
            'flowbits': [fb.json_dict for fb in self.flowbits],
            'thresh': [t.json_dict for t in self.thresh],
            'opts': [p.json_dict for p in self.parsed],
            'meta': self.meta.json_dict,
        }

    def __str__(self) -> str:
        raw = self.raw
        if raw is None:
            # TODO: Convert it back
            raise NotImplementedError
        return raw

    @property
    def category(self) -> str:
        loc = self.loc
        if loc is None:
            return ''
        return loc.path.stem

    @staticmethod
    def _parse_opts(tok: str, loc:
                    Optional[Loc] = None,
                    ) -> Generator[RuleOpt, None, None]:
        tok = tok.lstrip(' (').rstrip(' )')

        while tok:
            res = _unescaped_semi.search(tok)
            if res is None:
                raise ParseError('Trailing semi-colon (";") not found',
                                 loc=loc)

            semi, rest = res.span()
            cur_opt = tok[:semi]
            tok = tok[rest:]

            opt_name, *optional = cur_opt.split(':', maxsplit=1)

            opt_name = opt_name.lstrip()

            if not optional:
                opt_val = None
            else:
                opt_val, = optional
                opt_val = opt_val.lstrip()

            yield RuleOpt.from_tokens(opt_name, opt_val, loc=loc)

    @classmethod
    def _fold_content_modifiers(cls,
                                opts: List[RuleOpt],
                                loc: Optional[Loc] = None,
                                ) -> List[RuleOpt]:
        prev: int = -1
        mods: DefaultDict[int, List[RuleOpt]] = defaultdict(list)

        for i, opt in enumerate(opts):
            if opt.name in {'content', 'uricontent'}:
                prev = i
            elif opt.flags.is_content_modifier:
                mods[prev].append(opt)

        if not mods:
            return opts

        if -1 in mods:
            err = ', '.join(x.name for x in mods[-1])
            raise ParseError(f'Unexpected modifiers: {err}', loc=loc)

        def modify(i: int, opt: RuleOpt) -> RuleOpt:
            try:
                mod = mods[i]
            except KeyError:
                return opt

            return opt.with_modifiers(mod)

        ret = [modify(i, opt) for i, opt in enumerate(opts)
               if not opt.flags.is_content_modifier]

        return ret

    @classmethod
    def _fold_content_transforms(cls,
                                 opts: List[RuleOpt],
                                 loc: Optional[Loc] = None,
                                 ) -> Generator[RuleOpt, None, None]:
        xfrm_stk = []
        for opt in opts:
            if opt.flags.is_content_transform:
                xfrm_stk.append(opt)
                continue
            if not xfrm_stk:
                yield opt
                continue

            opt = opt.with_transforms(xfrm_stk)
            xfrm_stk.clear()
            yield opt

        if xfrm_stk:
            err = ', '.join(x.name for x in xfrm_stk)
            raise ParseError(f'Unexpected modifiers: {err}', loc=loc)

    @staticmethod
    def _assign_buffers(opts: List[RuleOpt],
                        loc: Optional[Loc] = None) \
            -> Tuple[List[RuleOpt], List[StickyBuffer]]:
        ret = []
        bufs = []
        cur_buf: StickyBuffer = StickyBuffer.PKT_DATA

        # TODO: Handle buffer-transforms
        # eg. StickyBufferSelect(Buffer.HTTP_CONTENT, [transforms, ...])
        for opt in opts:
            sticky_buffer = opt.flags.sticky_buffer
            if sticky_buffer is None:
                ret.append(opt)
                bufs.append(cur_buf)
            else:
                cur_buf = sticky_buffer

        return ret, bufs

    @classmethod
    def _extract_flow(cls,
                      opts: List[RuleOpt],
                      loc: Optional[Loc] = None,
                      ) -> Tuple[List[RuleOpt], Flow]:
        res, opts = partition(lambda opt: opt.name == 'flow', opts)

        def parse_flags(opt: RuleOpt) -> Generator[str, None, None]:
            if opt.value is None:
                return
            yield from (x.strip() for x in opt.value.split(','))

        init: list[str] = []
        flags: FrozenSet[str] = frozenset(
            reduce(lambda acc, opt: parse_flags(opt) or acc, opts, iter(init)),
        )

        unknown = flags - _all
        if unknown:
            raise ParseError(
                'Unknown flow parameters: {", ".join(sorted(unknown))}'
            )

        cl = FlowDirection.CLIENT if bool(flags & _cl) else 0
        sv = FlowDirection.SERVER if bool(flags & _sv) else 0

        est = FlowState.ESTABLISHED if _est in flags else 0
        nest = FlowState.NOT_ESTABLISHED if _nest in flags else 0
        sless = FlowState.STATELESS if _stateless in flags else 0

        dir_val = cl | sv
        if dir_val:
            direction = FlowDirection(dir_val)
        else:
            direction = FlowDirection.BOTH

        state_val = est | nest | sless
        if state_val:
            state = FlowState(state_val)
        else:
            state = FlowState.STATELESS

        return res, Flow(direction, state)

    @classmethod
    def _extract_thresholds(cls,
                            opts: List[RuleOpt],
                            loc: Optional[Loc] = None,
                            ) -> Tuple[List[RuleOpt],
                                       Tuple[RuleThreshold, ...]]:
        res, opts = partition(lambda opt: opt.name in _thresh_opts, opts)
        thresh = RuleThreshold.from_opts(opts, loc=loc)
        return res, tuple(thresh)

    @classmethod
    def _extract_flowbits(cls,
                          opts: List[RuleOpt],
                          loc: Optional[Loc] = None,
                          ) -> Tuple[List[RuleOpt], Tuple[FlowBitOp, ...]]:
        _flowbits = frozenset((
            'flowbits',
            'noalert',
        ))
        res, opts = partition(lambda opt: opt.name in _flowbits, opts)
        if not opts:
            return res, ()

        def parse(opts: Iterable[RuleOpt]) -> Generator[FlowBitOp, None, None]:
            for opt in opts:
                name = opt.name
                if name == 'flowbits':
                    assert opt.value is not None
                    yield FlowBitOp.parse(opt.value, loc=loc)
                elif name == 'noalert':
                    # noalert == flowbits:noalert;
                    yield FlowBitOp.parse(name, loc=loc)

        return res, tuple(parse(opts))

    @classmethod
    def _extract_app_layer(cls,
                           opts: List[RuleOpt],
                           loc: Optional[Loc] = None,
                           ) -> tuple[list[RuleOpt],
                                      tuple[AppLayerProto, ...]]:
        res, opts = partition(lambda opt: opt.name in _alp_opts, opts)
        alps = sorted(frozenset(AppLayerProto.from_opt(x) for x in opts))

        return res, tuple(alps)

    @classmethod
    def parse(cls, s: str, loc: Optional[Loc] = None) -> Rule:
        (
            action_tok,
            proto,
            src,
            sport,
            direction_tok,
            dst,
            dport,

            opts_tok,
        ) = s.split(None, maxsplit=7)

        try:
            action = Action(action_tok)
        except ValueError:
            raise ParseError(f'Invalid action: "{action_tok}"', loc=loc)

        try:
            direction = Direction(direction_tok)
        except ValueError:
            raise ParseError(f'Invalid direction: "{direction_tok}"', loc=loc)

        head = RuleHead(
            action,
            proto,

            src,
            sport,

            direction,

            dst,
            dport,
        )

        # Parse the basic rule option tokens
        opts = list(cls._parse_opts(opts_tok, loc))

        # Our first transformation is to extract metadata info to a separate
        # structure in the rule
        opts, meta_opts = partition(lambda opt: opt.is_meta, opts)
        meta = RuleMeta.from_opts(meta_opts, loc=loc)

        # Our second transformation is to extract:
        # - flow
        # - flowbits
        # - application-layer-proto
        # - thresholding
        # options in to a separate structure, too. This is because they are
        # either something which applies after a rule has matched or before
        # rule matching can begin (eg. because they help to select which
        # ruleset to run)
        #
        # TODO: optimize this with n-way partition to dict or something
        opts, special = partition(lambda opt: opt.name in _special_opts, opts)
        special, flow = cls._extract_flow(special, loc=loc)
        special, thresh = cls._extract_thresholds(special, loc=loc)
        special, flowbits = cls._extract_flowbits(special, loc=loc)
        special, alp = cls._extract_app_layer(special, loc=loc)
        assert not special  # ok, tyler durden, take your medicine

        # Next transformation is to find content modifier options and fold them
        # in to the content match option that they belong to
        opts = cls._fold_content_modifiers(opts, loc=loc)
        opts = list(cls._fold_content_transforms(opts, loc=loc))

        # extract sticky-buffers and assign buffers to options
        opts, buffers = cls._assign_buffers(opts)

        return cls(
            head,

            flow,
            flowbits,

            tuple(opts),
            tuple(buffers),

            thresh,
            meta,
            alp,

            s,
            loc,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        a = self.meta
        b = other.meta
        return (a.sid, a.rev) == (b.sid, b.rev)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        a = self.meta
        b = other.meta
        return (a.sid, a.rev) < (b.sid, b.rev)
