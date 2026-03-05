from warnings import warn
from typing import Tuple

from .sigmatch_table import \
    sigmatch_table as _sigmatch_table, \
    alias_table as _alias_table
from .optflags import OptFlags, TriState

__all__ = (
    'sigmatch_lookup',
    'all_metas',
    'required_metas',
)

_metas = {name: p.meta for name, p in _sigmatch_table.items()
          if p.meta is not None}

all_metas = frozenset(_metas.keys())
required_metas = frozenset({name for name, meta in _metas.items()
                            if meta.required})

del _metas


_default_optflags = OptFlags(
    quotes=TriState.OPTIONAL,
    values=TriState.OPTIONAL,
    negation=False,
    sticky_buffer=None,
    is_content_modifier=False,
    meta=None,
    known=False,
)


def sigmatch_lookup(name: str) -> Tuple[str, OptFlags]:
    name = name.lower()
    try:
        return name, _sigmatch_table[name]
    except KeyError:
        try:
            name = _alias_table[name]
            return name, _sigmatch_table[name]
        except KeyError:
            warn(f'Unknown option "{name}" - may be parsed incorrectly')
            return name, _default_optflags
