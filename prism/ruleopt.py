from __future__ import annotations
from typing import NamedTuple, Optional, Tuple, Iterable

from .loc import Loc
from .errors import ParseError
from .optflags import OptFlags, TriState
from .registry import sigmatch_lookup

__all__ = (
    'RuleOpt',
    'RuleOptToken',
)


class RuleOptToken(NamedTuple):
    name: str
    negated: bool
    value: Optional[str]

    def __str__(self) -> str:
        if self.value is None:
            me = f'{self.name};'
        else:
            me = f'{self.name}:{"!" if self.negated else ""}{self.value};'
        return me


class RuleXfrmToken(NamedTuple):
    name: str


class RuleOpt(NamedTuple):
    flags: OptFlags
    name: str
    negated: bool
    value: Optional[str]
    modifiers: Tuple[RuleOptToken, ...] = ()
    transforms: Tuple[RuleXfrmToken, ...] = ()

    @property
    def is_meta(self) -> bool:
        return self.flags.is_meta

    def with_modifiers(self, modifiers: Iterable[RuleOpt]) -> RuleOpt:
        assert not self.modifiers, 'RuleOpt already modified'
        if not modifiers:
            return self
        mods = (RuleOptToken(opt.name, opt.negated, opt.value)
                for opt in modifiers)
        return self._replace(modifiers=tuple(mods))

    def with_transforms(self, transforms: Iterable[RuleOpt]) -> RuleOpt:
        assert not self.transforms, 'RuleOpt already transformed'
        if not transforms:
            return self
        xfrms = (RuleXfrmToken(opt.name) for opt in transforms)
        return self._replace(transforms=tuple(xfrms))

    @staticmethod
    def _strip_quotes(value: str, /, mandatory: bool) -> str:
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        if mandatory:
            raise ValueError('Missing quotes')
        return value

    @classmethod
    def from_tokens(cls,
                    name: str,
                    value: Optional[str],
                    loc: Optional[Loc] = None) -> RuleOpt:

        negated = False

        name, flags = sigmatch_lookup(name)

        if value is not None:
            if flags.negation:
                if value.startswith('!'):
                    value = value[1:]
                    negated = True

            if flags.quotes:
                mandatory = flags.quotes == TriState.MANDATORY
                try:
                    value = cls._strip_quotes(value, mandatory=mandatory)
                except ValueError:
                    raise ParseError(f'Missing quotes for "{name}"', loc=loc)

            if flags.values == TriState.NONE:
                raise ParseError(f'Unexpected value for "{name}"', loc=loc)
        elif flags.values == TriState.MANDATORY:
            raise ParseError(f'Missing value for "{name}"', loc=loc)

        return cls(flags, name, negated, value)

    def __str__(self) -> str:
        name = self.name

        if self.value is None:
            me = f'{name};'
        else:
            negated = self.negated
            value = self.value
            q = '"' if self.flags.quotes == TriState.MANDATORY else ''
            me = f'{name}:{"!" if negated else ""}{q}{value}{q};'

        mods = (str(mod) for mod in self.modifiers)
        return ' '.join((me, *mods))
