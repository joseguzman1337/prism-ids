from __future__ import annotations
from dataclasses import dataclass
from typing import (
    Any, ClassVar, Dict, Iterable, List, NamedTuple, Optional, Sequence,
)
from urllib.parse import quote
import re
import logging

from ..sigmatch import BufferContentMatch, UtilMixin
from ..sticky_buffer import StickyBuffer
from ..ruleopt import RuleOpt, RuleOptToken, RuleXfrmToken
from ..rulevar import RuleValue
from ..loc import Loc
from ..errors import ParseError, SemanticError, NeverMatches

__all__ = (
    'Content',
)

_log = logging.getLogger('parse')
_hex_space = re.compile(r'[\s,]*')
_hex_split = re.compile(r'(\|)')
_unescape = re.compile(r'\\([:;\\"])')


class FastPattern(NamedTuple):
    only: bool
    offset: int
    length: int

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'only': self.only,
            'offset': self.offset,
            'length': self.length,
        }

    @property
    def chop(self) -> bool:
        return self.offset >= 0 and self.length >= 0

    @property
    def chop_len(self) -> int:
        assert self.chop
        return self.offset + self.length

    @classmethod
    def parse(cls,
              tok: Optional[str],
              loc: Optional[Loc] = None,
              ) -> FastPattern:
        if not tok:
            return cls(False, -1, -1)

        if tok == 'only':
            return cls(True, -1, -1)

        try:
            offset_tok, length_tok = tok.split(',', maxsplit=1)
        except ValueError:
            raise ParseError('Bad fast_pattern tokens', loc=loc)

        try:
            offset = int(offset_tok) - 1
            length = int(length_tok)
        except ValueError:
            raise ParseError('fast_pattern offset/length not integers',
                             loc=loc)

        if offset < 0 or length < 0:
            raise ParseError('Bad fast_pattern offset/length', loc=loc)

        return cls(False, offset, length)


class ContentModifiers(NamedTuple):
    nocase: bool
    depth: Optional[RuleValue]
    offset: Optional[RuleValue]
    distance: Optional[RuleValue]
    within: Optional[RuleValue]
    startswith: bool
    endswith: bool

    fast_pattern: Optional[FastPattern]

    def with_endswith(self) -> ContentModifiers:
        if self.endswith:
            return self
        if self.relative or self.constrained:
            return self
        return self._replace(endswith=True)

    def as_absolute(self) -> ContentModifiers:
        if self.constrained:
            raise SemanticError('Rule begins with constrained relative match')

        distance = self.distance
        if distance is not None and distance.has_literal_value(0):
            self = self._replace(distance=None)

        within = self.within
        if within is not None and within.is_literal:
            self = self._replace(within=None, depth=within)

        return self

    @property
    def relative(self) -> bool:
        return self.distance is not None or self.within is not None

    @property
    def constrained(self) -> bool:
        return self.depth is not None or self.offset is not None

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        depth = UtilMixin._optional_json(self.depth)
        offset = UtilMixin._optional_json(self.offset)
        distance = UtilMixin._optional_json(self.distance)
        within = UtilMixin._optional_json(self.within)
        fp = UtilMixin._optional_json(self.fast_pattern)

        ret: Dict[str, Any] = {}

        if self.nocase:
            ret['nocase'] = True
        if depth is not None:
            ret['depth'] = depth
        if offset is not None:
            ret['offset'] = offset
        if distance is not None:
            ret['distance'] = distance
        if within is not None:
            ret['within'] = within
        if self.startswith:
            ret['startswith'] = True
        if self.endswith:
            ret['endswith'] = True
        if fp is not None:
            ret['fast_pattern'] = fp

        return ret

    def __str__(self) -> str:
        desc = list()
        if self.relative:
            desc.append('relative')
        if self.constrained:
            desc.append('constrained')
        if self.nocase:
            desc.append('nocase')
        if self.fast_pattern is not None:
            desc.append('fp')

        if self.endswith and self.startswith:
            desc.append('exact')
        elif self.startswith:
            desc.append('startswith')
        elif self.endswith:
            desc.append('endswith')

        return ":".join(sorted(desc))

    @classmethod
    def parse(cls,
              negated: bool,
              content: bytes,
              modifiers: Iterable[RuleOptToken],
              loc: Optional[Loc] = None) -> ContentModifiers:
        mods: Dict[str, RuleOptToken] = {}
        for mod in modifiers:
            name = mod.name
            if name in mods:
                raise ParseError(f'Duplicate "{name}" modifier', loc=loc)
            mods[name] = mod

        _none = RuleOptToken('', False, None)

        # Integers / byte-extract variables
        tok_depth = mods.pop('depth', _none).value
        tok_offset = mods.pop('offset', _none).value
        tok_distance = mods.pop('distance', _none).value
        tok_within = mods.pop('within', _none).value

        # Booleans
        startswith = mods.pop('startswith', None) is not None
        endswith = mods.pop('endswith', None) is not None
        nocase = mods.pop('nocase', None) is not None

        # Fast-pattern is special
        fp_mod = mods.pop('fast_pattern', None)
        if fp_mod is None:
            fp = None
        else:
            fp = FastPattern.parse(fp_mod.value, loc=loc)

        # Check that there's nothing left over
        if mods:
            unknown = ", ".join(mods.keys())
            raise ParseError(f'Unknown content modifiers: {unknown}',
                             loc=loc)

        def var(tok: str) -> RuleValue:
            return RuleValue.parse(tok, loc=loc)

        depth = None if tok_depth is None else var(tok_depth)
        offset = None if tok_offset is None else var(tok_offset)
        distance = None if tok_distance is None else var(tok_distance)
        within = None if tok_within is None else var(tok_within)

        is_relative = (distance is not None) or (within is not None)
        is_constrained = (depth is not None) or (offset is not None)

        # Basic sanity check
        if is_relative and is_constrained:
            raise ParseError("Pattern can't be both absolute and relative",
                             loc=loc)

        # Check the requirements for fast-pattern
        if fp is not None:
            if negated and (is_relative or is_constrained):
                raise ParseError('negated fast_pattern incompatible with '
                                 'depth/offset/distance/within',
                                 loc=loc)
            if fp.only and (negated or is_relative or is_constrained):
                raise ParseError('fast_pattern: only; incompatible with '
                                 'negation/depth/offset/distance/within',
                                 loc=loc)
            if fp.chop:
                if fp.chop_len > len(content):
                    raise ParseError(f'fast_pattern chop spec ({fp.chop_len}) '
                                     f'> content length ({len(content)})',
                                     loc=loc)

        # startswith is shorthand for: content:"GET|20|"; depth:4; offset:0;
        # normalize that out here
        if (not is_relative
                and depth is not None
                and depth.has_literal_value(len(content))
                and (offset is None or offset.has_literal_value(0))):
            startswith = True
            depth = offset = None
            is_constrained = False

        # Check the requirements for startswith
        if startswith:
            if is_relative or is_constrained:
                raise ParseError('startswith incompatible with '
                                 'depth/offset/within/distance',
                                 loc=loc)

        # The requirements in the manual for endswith seem to be all lies...
        if endswith:
            if is_relative or offset is not None:
                # https://redmine.openinfosecfoundation.org/issues/5030
                _log.debug('%s: endswith documentation is incorrect', loc)

        # If we have: content:"abc"; depth:3; [endswith;] then this is
        # startswith.
        if (not is_relative
                and offset is None
                and depth is not None
                and depth.has_literal_value(len(content))):
            depth = None
            startswith = True
            is_constrained = False

        # Finally, validate depth and fix it up to take offset in to account
        if depth is not None:
            if depth.is_literal and depth.literal < len(content):
                raise ParseError(f'depth ({depth}) smaller than '
                                 f'content len ({len(content)})',
                                 loc=loc)
            if offset is not None:
                try:
                    dval = depth.literal
                    oval = offset.literal
                except TypeError:
                    # Not sure if this is right, but at least, we can't do it
                    # here and now anwyay. Let's wait and see if this is a
                    # problem
                    raise ParseError('If specificying depth and offset '
                                     'then neither can be a variable')
                depth = RuleValue.from_literal(dval + oval)

        return cls(
            nocase,
            depth,
            offset,
            distance,
            within,
            startswith,
            endswith,
            fp,
        )


_default_modifiers = ContentModifiers(
    nocase=False,
    depth=None,
    offset=None,
    distance=None,
    within=None,
    endswith=False,
    startswith=False,
    fast_pattern=None,
)


@dataclass(init=False, eq=True)
class Content(BufferContentMatch, opt_name='content'):
    _max_pattern: ClassVar[int] = 0xffff

    __slots__ = (
        'buf',
        'negated',
        'content',
        'modifiers',
        'xfrms',
    )

    buf: StickyBuffer
    negated: bool
    content: bytes
    modifiers: ContentModifiers
    xfrms: Sequence[RuleXfrmToken]

    def __init__(self,
                 buf: StickyBuffer,
                 negated: bool,
                 content: bytes,
                 modifiers: Optional[ContentModifiers] = None,
                 xfrms: Sequence[RuleXfrmToken] = ()):
        self.buf = buf
        self.negated = negated
        self.content = content
        if modifiers is None:
            self.modifiers = _default_modifiers
        else:
            self.modifiers = modifiers
        self.xfrms = xfrms

    def with_mods(self, mods: ContentModifiers) -> Content:
        if mods == self.modifiers:
            return self
        if mods == _default_modifiers:
            mods = _default_modifiers
        return Content(
            self.buf,
            self.negated,
            self.content,
            mods,
            self.xfrms,
        )

    def with_endswith(self) -> Content:
        return self.with_mods(self.modifiers.with_endswith())

    def as_absolute(self) -> Content:
        return self.with_mods(self.modifiers.as_absolute())

    def exact(self) -> Content:
        return self.with_mods(
            self.modifiers._replace(
                startswith=True,
                endswith=True,
            )
        )

    def reveal_buffer_size(self, buffer_size: int) -> Content:
        if self.relative:
            return self

        implied_min_len = len(self.content)

        if buffer_size < implied_min_len:
            raise NeverMatches('Implied minimum length shorter than content')

        if implied_min_len != buffer_size:
            return self

        return self.exact()

    @property
    def relative(self) -> bool:
        return self.modifiers.relative

    @property
    def constrained(self) -> bool:
        return self.modifiers.constrained

    @property
    def transformed(self) -> bool:
        return bool(self.xfrms)

    @property
    def has_default_modifiers(self) -> bool:
        return self.modifiers == _default_modifiers

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        buf = self._optional_value(self.buf)

        mods = self.modifiers
        if mods == _default_modifiers:
            modifiers = None
        else:
            modifiers = mods.json_dict

        return {
            'type': self.opt_name,
            'buf': buf,
            'negated': self.negated,
            'content': quote(self.content),
            'modifiers': modifiers,
        }

    def __str__(self) -> str:
        if self.has_default_modifiers:
            mods = 'default'
        else:
            mods = str(self.modifiers)
            assert mods

        neg = '! ' if self.negated else ''
        return f'{neg}{mods} {self.content!r}'

    @classmethod
    def _parse_content_value(cls, tok: str) -> bytes:
        chunks: List[bytes] = []

        is_hex = False
        for part in _hex_split.split(tok):
            if part == '|':
                is_hex = not is_hex
                continue
            if not part:
                continue

            if is_hex:
                part = _hex_space.sub(r'', part)
                chunk = bytes.fromhex(part)
            else:
                part = _unescape.sub(r'\1', part)
                chunk = part.encode('ascii')

            chunks.append(chunk)

        ret = b''.join(chunks)
        return ret

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> Content:
        assert opt.value is not None, 'Blank "content" value'

        negated = opt.negated
        content = cls._parse_content_value(opt.value)
        modifiers = opt.modifiers
        xfrms = opt.transforms

        if not modifiers:
            mods = None
        else:
            mods = ContentModifiers.parse(negated, content, modifiers, loc=loc)

        max_pat = cls._max_pattern
        if len(content) > max_pat:
            raise ParseError(f'Pattern length ({len(content)}) '
                             f'exceeds max pattern length ({max_pat})',
                             loc=loc)

        return cls(
            buf,
            negated,
            content,
            mods,
            xfrms,
        )
