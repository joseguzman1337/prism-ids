from __future__ import annotations
from typing import NamedTuple, FrozenSet

from .errors import SemanticError

__all__ = (
    'Pcre2',
)

_pcre2_opts = {
    'A': 'PCRE2_ANCHORED',
    'E': 'PCRE2_DOLLAR_ENDONLY',
    'G': 'PCRE2_UNGREEDY',
    'i': 'PCRE2_CASELESS',
    'm': 'PCRE2_MULTILINE',
    's': 'PCRE2_DOTALL',
    'x': 'PCRE2_EXTENDED',
}


class Pcre2(NamedTuple):
    name: str
    regex: str
    flags: FrozenSet[str]

    @property
    def cvar_code(self) -> str:
        return f'_prism__{self.name}_code'

    @property
    def opts(self) -> str:
        flags = self.flags
        if not flags:
            return '0'

        mapping = _pcre2_opts
        unknown = flags - mapping.keys()
        if unknown:
            raise SemanticError(f'Unknown PCRE2 flags: {"".join(unknown)}')

        vals = frozenset({mapping[x] for x in flags})
        return '|'.join(sorted(vals))
