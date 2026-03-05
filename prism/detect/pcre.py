from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, FrozenSet, Dict, Any
import re

from ..sigmatch import BufferContentMatch
from ..sticky_buffer import StickyBuffer
from ..ruleopt import RuleOpt, RuleXfrmToken
from ..loc import Loc
from ..errors import ParseError

__all__ = (
    'Pcre',
)


_parse = re.compile(r'(?<!\\)/(.*(?<!(?<!\\)\\))/([^"]*)')
_pcre_flags = frozenset('AEGimsx')
_snort_flags = frozenset('BO')
_buf_flags = {
    'U': StickyBuffer.HTTP_URI,
    'V': StickyBuffer.HTTP_USER_AGENT,
    'W': StickyBuffer.HTTP_HOST,
    'Z': StickyBuffer.HTTP_HOST_RAW,
    'H': StickyBuffer.HTTP_HEADER,
    'I': StickyBuffer.HTTP_URI_RAW,
    'D': StickyBuffer.HTTP_HEADER_RAW,
    'M': StickyBuffer.HTTP_METHOD,
    'C': StickyBuffer.HTTP_COOKIE,
    'P': StickyBuffer.HTTP_REQUEST_BODY,
    'Q': StickyBuffer.FILE_DATA,
    'Y': StickyBuffer.HTTP_STAT_MSG,
    'S': StickyBuffer.HTTP_STAT_CODE,
}
_supported_opts = _pcre_flags | _snort_flags | {'R', } | _buf_flags.keys()


@dataclass(init=False, eq=True)
class Pcre(BufferContentMatch, opt_name='pcre'):
    __slots__ = (
        'buf',
        'negated',
        'relative',
        'regex',
        'pcre_flags',
        'snort_flags',
        'xfrms',
    )

    buf: StickyBuffer
    negated: bool
    relative: bool
    regex: str
    pcre_flags: FrozenSet[str]
    snort_flags: FrozenSet[str]
    xfrms: tuple[RuleXfrmToken, ...]

    def __init__(self,
                 buf: StickyBuffer,
                 negated: bool,
                 relative: bool,
                 regex: str,
                 pcre_flags: FrozenSet[str],
                 snort_flags: FrozenSet[str],
                 xfrms: tuple[RuleXfrmToken, ...],
                 ) -> None:
        self.buf = buf
        self.negated = negated
        self.relative = relative
        self.regex = regex
        self.pcre_flags = pcre_flags
        self.snort_flags = snort_flags
        self.xfrms = xfrms

    @property
    def modifier_string(self) -> str:
        return (
            ''.join(sorted(self.pcre_flags))
            + ''.join(sorted(self.snort_flags))
        )

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        buf = self._optional_value(self.buf)
        return {
            'type': self.opt_name,
            'buf': buf,
            'negated': self.negated,
            'relative': self.relative,
            'regex': self.regex,
            'pcre_flags': str(sorted(self.pcre_flags)),
            'snort_flags': str(sorted(self.snort_flags)),
        }

    def __str__(self) -> str:
        neg = '!' if self.negated else ''
        return f'{neg}/{self.regex}/{self.modifier_string}'

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> Pcre:
        assert opt.value is not None, 'Blank "pcre" value'

        if opt.modifiers:
            raise ParseError('Modifiers for "pcre"',
                             loc=loc)

        m = _parse.fullmatch(opt.value)
        if m is None:
            raise ParseError('Unable to parse pcre regex', loc=loc)

        regex, modifiers = m.group(1, 2)

        mod_set = frozenset(modifiers)

        unsupported = mod_set - _supported_opts
        if unsupported:
            bad = ''.join(sorted(unsupported))
            raise ParseError(f'Unsupported pcre modifiers: {bad}', loc=loc)

        pcre_flags = mod_set & _pcre_flags
        snort_flags = mod_set & _snort_flags
        relative = 'R' in mod_set

        buf_flags = mod_set & _buf_flags.keys()
        if len(buf_flags) > 1:
            bad = ''.join(sorted(buf_flags))
            raise ParseError(f'Multiple pcre buffer flags: {bad}', loc=loc)

        if buf_flags:
            bufcode, = buf_flags
            setbuf = _buf_flags[bufcode]
            buf = setbuf

        return cls(
            buf,
            opt.negated,
            relative,
            regex,
            pcre_flags,
            snort_flags,
            opt.transforms,
        )
