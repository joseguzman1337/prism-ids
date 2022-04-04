from __future__ import annotations
from typing import Any, Dict, FrozenSet, Generator
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

    @property
    def fast_pattern(self) -> MPMPattern:
        return self

    @property
    def score(self) -> int:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError

    @property
    def len_score(self) -> tuple[int, int]:
        return (len(self), self.score)


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

    def __len__(self) -> int:
        return len(self.content)

    @property
    def score(self) -> int:
        a: set[int] = set()
        score = 0

        # Suricata: 8.10.1.1.1.1. Appendix A - Pattern Strength Algorithm
        for val in self.content:
            if val in a:
                score += 1
            else:
                a.add(val)
                c = chr(val)
                if c.isalpha():
                    score += 3
                elif c.isprintable() or val in {0, 1, 0xff}:
                    score += 4
                else:
                    score += 6

        # Add bonuses for being start/end anchored or exact-match
        if self.end:
            score += 5
        if self.start:
            score += 10
        if self.end and self.start:
            score += 15

        return score

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
    chain: tuple[BufOp, ...]

    @property
    def hyperscan_pattern(self) -> HsPattern:
        return self.anchor.hyperscan_pattern

    @property
    def mpm_patterns(self) -> Generator[MPMPattern, None, None]:
        yield self.anchor
        yield from (x for x in self.chain if isinstance(x, MPMPattern))

    @property
    def fast_pattern(self) -> MPMPattern:
        best = max(
            self.mpm_patterns,
            key=lambda x: x.len_score,
        )
        return best

    def __len__(self) -> int:
        return len(self.fast_pattern)

    @property
    def score(self) -> int:
        return self.fast_pattern.score

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
    patterns: tuple[MPMPattern, ...]

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opcode_name,
            'string_set': [s.hyperscan_pattern for s in self.patterns]
        }
