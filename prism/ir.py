from __future__ import annotations
from typing import Any, Dict, FrozenSet, Tuple
from warnings import warn
from dataclasses import dataclass
from urllib.parse import quote

from .hyperscan import HsFlag, HsPattern

__all__ = (
    'Opcode',

    'BufOp',

    'BufSize',
    'BufRemaining',

    'MPMPattern',
    'Pattern',
    'PatternChain',
    'OptionalDotPrefix',

    'Regex',
    'StringSet',
)


class Opcode:
    __slots__ = ()

    def __init__(self) -> None:
        raise NotImplementedError('Subclass me')

    @property
    def opcode_name(self) -> str:
        return type(self).__name__

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opcode_name,
        }


class BufOp(Opcode):
    """
    Any opcode which works on a specific buffer.
    """
    pass


@dataclass(frozen=True, eq=True)
class BufSize(BufOp):
    size_lo: int | None
    size_hi: int | None


@dataclass(frozen=True, eq=True)
class BufRemaining(BufOp):
    remains_lo: int | None
    remains_hi: int | None

    @classmethod
    def isdataat(
        cls,
        negated: bool,
        val: int,
    ) -> BufRemaining:
        if negated:
            return cls(
                None,
                val - 1,
            )
        else:
            return cls(
                val,
                None,
            )


class MPMPattern(BufOp):
    """
    Any BufOp which can be included in a hyperscan database
    """
    @property
    def hyperscan_pattern(self) -> HsPattern:
        raise NotImplementedError


@dataclass(frozen=True, eq=True)
class Pattern(MPMPattern):
    content: bytes
    nocase: bool = False
    start: bool = False
    end: bool = False

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opcode_name,
            'content': quote(self.content),
            'nocase': self.nocase,
            'start': self.start,
            'end': self.end,
        }

    @property
    def pattern(self) -> str:
        regex = HsPattern.encode_literal(self.content)
        s = '^' if self.start else ''
        e = '$' if self.end else ''
        return f'{s}{regex}{e}'

    @property
    def hyperscan_pattern(self) -> HsPattern:
        flg = HsFlag.SINGLEMATCH
        if self.nocase:
            flg |= HsFlag.CASELESS

        return HsPattern(
            self.pattern,
            flg,
        )

    @classmethod
    def startswith(cls, content: bytes, nocase: bool = False) -> Pattern:
        return cls(content, nocase, True, False)

    @classmethod
    def endswith(cls, content: bytes, nocase: bool = False) -> Pattern:
        return cls(content, nocase, False, True)

    @classmethod
    def exact(cls, content: bytes, nocase: bool = False) -> Pattern:
        return cls(content, nocase, True, True)


@dataclass(frozen=True, eq=True)
class PatternChain(MPMPattern):
    anchor: MPMPattern
    chain: Tuple[BufOp, ...]

    @property
    def hyperscan_pattern(self) -> HsPattern:
        return self.anchor.hyperscan_pattern

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opcode_name,
            'anchor': self.anchor.json_dict,
            'chain': [x.json_dict for x in self.chain],
        }


@dataclass(frozen=True, eq=True)
class OptionalDotPrefix(Pattern):
    @property
    def pattern(self) -> str:
        content = self.content
        if not content.startswith(b'.'):
            # in this case dotprefix has no effect
            warn(f'dotprefix: {content!r} does not start with "."')
            return super().pattern

        content = content[1:]
        regex = HsPattern.encode_literal(content)
        s = '^' if self.start else ''
        e = '$' if self.end else ''
        return f'{s}(:?\\.)?{regex}{e}'


@dataclass(frozen=True, eq=True)
class Regex(BufOp):
    regex: str
    modifiers: FrozenSet[str]

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opcode_name,
            'regex': self.regex,
            'modifiers': ''.join(sorted(self.modifiers)),
        }


@dataclass(frozen=True, eq=True)
class StringSet(BufOp):
    content: Tuple[bytes, ...]

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opcode_name,
            'string_set': [quote(s) for s in self.content],
        }

    def remove(self, pat: bytes) -> StringSet:
        cls = type(self)
        content = tuple((x for x in self.content if x != pat))
        return cls(content)
