from __future__ import annotations
from typing import Optional, Mapping, Sequence, NamedTuple, Tuple
from warnings import warn
from functools import singledispatch
import re

from .sigmatch import SigMatch, BufferMatch
from .sticky_buffer import StickyBuffer
from .ruleopt import RuleXfrmToken
from .errors import NeverMatches, SemanticError
from .ir import (
    BufOp, BufRemaining, BufSize, MPMPattern, Opcode, OptionalDotPrefix,
    Pattern, PatternChain, Regex,
)
from . import detect

__all__ = (
    'irgen',
    'irgen_content',
    'irgen_bufmatch',
    'irgen',
)


_hexchar = re.compile(r'[0-9a-fA-F]{2}')


@singledispatch
def irgen_bufmatch(opt: BufferMatch) -> BufOp:
    raise SemanticError(f'TODO: ir: {type(opt).__name__}')


@irgen_bufmatch.register
def _(opt: detect.Content) -> BufOp:
    if opt.negated:
        raise SemanticError('No negated strings')
    if opt.constrained:
        raise SemanticError('No constrained strings')

    startswith = opt.modifiers.startswith
    endswith = opt.modifiers.endswith

    content = opt.content

    xfrms = opt.xfrms
    if not xfrms:
        cls = Pattern
    elif xfrms == (RuleXfrmToken('dotprefix'),):
        cls = OptionalDotPrefix
    else:
        raise SemanticError('No transformed strings')

    if startswith and endswith:
        return cls.exact(content, opt.modifiers.nocase)
    elif endswith:
        return cls.endswith(content, opt.modifiers.nocase)
    elif startswith:
        return cls.startswith(content, opt.modifiers.nocase)
    else:
        return cls(content, opt.modifiers.nocase)


@irgen_bufmatch.register
def _(opt: detect.Pcre) -> BufOp:
    if opt.negated:
        raise SemanticError('No negated regex')
    if opt.snort_flags:
        raise SemanticError('No snort-flags regex')
    if opt.xfrms:
        raise SemanticError('No transformed regex')
    return Regex(opt.regex, opt.pcre_flags)


@irgen_bufmatch.register
def _(opt: detect.BufferSize) -> BufOp:
    if opt.never_matches:
        raise NeverMatches('%s never matches' % opt)
    return BufSize(
        opt.size_lo,
        opt.size_hi,
    )


@irgen_bufmatch.register
def _(opt: detect.IsDataAt) -> BufOp:
    val = opt.val.literal
    if not opt.relative:
        raise SemanticError('Non-relative isdataat: %s' % opt)
    if not val:
        raise SemanticError(str(opt))

    return BufRemaining.isdataat(opt.negated, val)


@irgen_bufmatch.register
def _(opt: detect.RelChain) -> BufOp:
    anchor = irgen_bufmatch(opt.anchor)
    assert isinstance(anchor, MPMPattern)
    return PatternChain(
        anchor,
        tuple(irgen_bufmatch(x) for x in opt.chain),
    )


@singledispatch
def irgen(opt: SigMatch) -> Opcode:
    raise SemanticError(f'TODO: ir: {type(opt).__name__}')


@irgen.register
def _(opt: BufferMatch) -> Opcode:
    return irgen_bufmatch(opt)


def _content_unhex(content: bytes) -> bytes:
    try:
        s = content.decode()
    except UnicodeDecodeError:
        raise SemanticError(f'{content!r} is not unicode?')

    if ':' in s:
        if s.endswith(':'):
            s = s[:-1]

        chars = s.split(':')

        if not all(_hexchar.fullmatch(x) for x in chars):
            raise NeverMatches(f'{content!r} is not hex?')

        return bytes.fromhex(''.join(chars))

    return bytes.fromhex(s)


def _binhex_pattern(orig: bytes,
                    bufsz: Optional[int],
                    startswith: bool = False,
                    endswith: bool = False,
                    ) -> Pattern:
    content = _content_unhex(orig)

    if bufsz is not None:
        if len(content) > bufsz:
            w = f'{orig!r} bigger than buffer size {bufsz}'
            warn(w)
            raise SemanticError(w)
        if len(content) == bufsz:
            return Pattern.exact(content)
        elif startswith and endswith:
            w = f'{orig!r} exact match wrong size: {len(content)} != {bufsz}'
            warn(w)
            raise SemanticError(w)

    if startswith and endswith:
        return Pattern.exact(content)
    if endswith:
        return Pattern.endswith(content)
    if startswith:
        return Pattern.startswith(content)

    return Pattern(content)


def _convert_binhex(opt: BufferMatch,
                    bufsz: Optional[int],
                    ) -> Pattern:
    if not isinstance(opt, detect.Content):
        raise SemanticError('Binhex not a content match')

    if opt.negated or opt.constrained or opt.transformed or opt.relative:
        raise SemanticError(
            'negated/constrained/transformed/relative '
            'not supported for binhex field'
        )

    startswith = opt.modifiers.startswith
    endswith = opt.modifiers.endswith

    return _binhex_pattern(opt.content, bufsz, startswith, endswith)


_binhex_bufs: Mapping[StickyBuffer, Optional[int]] = {
    StickyBuffer.TLS_CERT_FINGERPRINT: 20,
    StickyBuffer.TLS_CERT_SERIAL: None,
    StickyBuffer.JA3_HASH: 16,
    StickyBuffer.JA3S_HASH: 16,
}


class ContentIR(NamedTuple):
    content_opts: Tuple[BufOp, ...]


def _irgen_binhex(buf: StickyBuffer,
                  sc: Optional[detect.BufferSize],
                  opts: Sequence[BufferMatch],
                  ) -> Optional[ContentIR]:
    try:
        bufsz = _binhex_bufs[buf]
    except KeyError:
        return None

    if sc is not None and not sc.consistent_with(bufsz):
        raise SemanticError(
            f'{buf.name}: buffer size {bufsz} not consistent with {sc}')

    return ContentIR(
        tuple(_convert_binhex(opt, bufsz) for opt in opts),
    )


def irgen_content(buf: StickyBuffer,
                  size_constraint: Optional[detect.BufferSize],
                  opts: Sequence[BufferMatch],
                  ) -> ContentIR:
    if not opts:
        raise SemanticError('No opcode for size constraint only')

    ret = _irgen_binhex(buf, size_constraint, opts)
    if ret is not None:
        return ret

    return ContentIR(
        tuple(irgen_bufmatch(opt) for opt in opts),
    )
