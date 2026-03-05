from __future__ import annotations
from typing import (
    ItemsView, Iterable, Iterator, KeysView, Mapping, NamedTuple, Optional,
    ValuesView,
)
from enum import Enum, Flag
from pathlib import Path

__all__ = (
    'HsMode',
    'HsFlag',
    'HsPattern',
    'HsExt',
    'HsDatabase',
)


class HsMode(Enum):
    BLOCK = 1
    STREAM = 2
    VECTORED = 4


class HsExtFlag(Flag):
    MIN_OFFSET = 1
    MAX_OFFSET = 2
    MIN_LENGTH = 4
    EDIT_DISTANCE = 8
    HAMMING_DISTANCE = 16


class HsExt(NamedTuple):
    min_offset: Optional[int] = None
    max_offset: Optional[int] = None
    min_length: Optional[int] = None
    edit_distance: Optional[int] = None
    hamming_distance: Optional[int] = None

    @property
    def ext_str(self) -> str:
        (
            min_offset,
            max_offset,
            min_length,
            edit_distance,
            hamming_distance,
        ) = self

        exts = []

        if min_offset is not None:
            exts.append(f'min_offset={min_offset}')
        if max_offset is not None:
            exts.append(f'max_offset={max_offset}')
        if min_length is not None:
            exts.append(f'min_length={min_length}')
        if edit_distance is not None:
            exts.append(f'edit_distance={edit_distance}')
        if hamming_distance is not None:
            exts.append(f'hamming_distance={hamming_distance}')

        ret = ",".join(exts)
        return f'{{{ret}}}'

    def __int__(self) -> int:
        ret = 0
        if self.min_offset is not None:
            ret |= HsExtFlag.MIN_OFFSET.value
        if self.max_offset is not None:
            ret |= HsExtFlag.MAX_OFFSET.value
        if self.min_length is not None:
            ret |= HsExtFlag.MIN_LENGTH.value
        if self.edit_distance is not None:
            ret |= HsExtFlag.EDIT_DISTANCE.value
        if self.hamming_distance is not None:
            ret |= HsExtFlag.HAMMING_DISTANCE.value
        return ret

    @property
    def flags(self) -> str:
        flags = [
            f'HS_EXT_FLAG_{attr.upper()}'
            for attr, val in zip(self._fields, self)
            if val is not None
        ]

        if not flags:
            return '0'

        return ' | '.join(flags)

    def __str__(self) -> str:
        flags = (
            (attr, val)
            for attr, val in zip(self._fields, self)
            if val is not None
        )

        fields = (
            ('.flags', self.flags),
            *flags,
        )
        return '\n'.join((
            '\t{',
            *(f'\t\t{k} = {v},' for (k, v) in fields),
            '\t}',
        ))


HsNullExt = HsExt()


class HsFlag(Flag):
    NONE = 0
    CASELESS = 1
    DOTALL = 2
    MULTILINE = 4
    SINGLEMATCH = 8
    ALLOWEMPTY = 16
    UTF8 = 32
    UCP = 64
    PREFILTER = 128
    SOM_LEFTMOST = 256
    COMBINATION = 512
    QUIET = 1024

    @property
    def cstr(self) -> str:
        cls = type(self)
        known_flags = cls.__members__.values()
        flags = sorted(
            (f for f in known_flags if f in self and f.value),
            key=lambda x: x.name if x.name is not None else "",
        )
        if not flags:
            return '0'
        return ' | '.join(f'HS_FLAG_{f.name}' for f in flags)

    def __str__(self) -> str:
        ret = ''

        if self & HsFlag.CASELESS:
            ret += 'i'
        if self & HsFlag.DOTALL:
            ret += 's'
        if self & HsFlag.MULTILINE:
            ret += 'm'
        if self & HsFlag.SINGLEMATCH:
            ret += 'H'
        if self & HsFlag.ALLOWEMPTY:
            ret += 'V'
        if self & HsFlag.UTF8:
            ret += '8'
        if self & HsFlag.UCP:
            ret += 'W'
        if self & HsFlag.PREFILTER:
            ret += 'P'
        if self & HsFlag.SOM_LEFTMOST:
            ret += 'L'
        if self & HsFlag.COMBINATION:
            ret += 'C'
        if self & HsFlag.QUIET:
            ret += 'Q'

        return ret


_regex_literal_chars = frozenset(
    ' !"#%&\',-'
    '0123456789'
    ':;=@'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '_`'
    'abcdefghijklmnopqrstuvwxyz'
    '~'
)
_regex_escape_chars = frozenset(
    r'.*[]^$|\?+()'
)


class HsPattern(NamedTuple):
    pattern: str
    flags: HsFlag
    ext: HsExt = HsNullExt

    @property
    def pattern_cstring(self) -> str:
        return self.pattern.replace('\\', '\\\\').replace('"', r'\"')

    @property
    def has_ext(self) -> bool:
        return self.ext != HsNullExt

    @staticmethod
    def encode_literal(pattern: bytes,
                       allowed: frozenset[str] = _regex_literal_chars,
                       escape: frozenset[str] = _regex_escape_chars,
                       ) -> str:
        def f(x: int) -> str:
            ch = chr(x)
            if ch in allowed:
                return ch
            if ch in escape:
                return f'\\{ch}'
            return f'\\x{x:02x}'
        return ''.join(map(f, pattern))

    @classmethod
    def literal(cls,
                pattern: bytes,
                flags: HsFlag = HsFlag.NONE,
                ext: HsExt = HsNullExt,
                ) -> HsPattern:
        return cls(
            cls.encode_literal(pattern),
            flags,
            ext=ext,
        )

    @classmethod
    def combo(cls,
              items: tuple[int, ...],
              flags: HsFlag = HsFlag.COMBINATION | HsFlag.SINGLEMATCH,
              ext: HsExt = HsNullExt,
              ) -> HsPattern:
        return cls(
            f'({"&".join(str(item) for item in items)})',
            flags,
            ext=ext,
        )

    @property
    def flags_ext_str(self) -> str:
        ret = str(self.flags)
        ext = self.ext
        if ext != HsNullExt:
            ret += ext.ext_str
        return ret


PatternMapping = Mapping[HsPattern, int]


class HsDatabase(PatternMapping):
    __slots__ = (
        '_name',
        '_db',
        '_exts',
        '_extmap',
    )

    _name: str
    _db: dict[HsPattern, int]
    _exts: tuple[HsExt, ...]
    _extmap: Mapping[HsExt, int]

    def __init__(self,
                 name: str,
                 pats: dict[HsPattern, int]) -> None:
        self._name = name
        self._db = pats

        extmap: dict[HsExt, int] = {}
        for pat in self._db.keys():
            ext = pat.ext
            if ext in extmap:
                continue

            ext_idx = len(extmap)
            extmap[ext] = ext_idx

        self._exts = tuple(extmap.keys())
        self._extmap = extmap

    @classmethod
    def from_patterns(cls,
                      name: str,
                      pats: Iterable[HsPattern]) -> 'HsDatabase':
        return cls(
            name,
            {k: i for i, k in enumerate(pats)},
        )

    @property
    def cvar_db(self) -> str:
        return f'{self.name}_db'

    @property
    def cvar_bin(self) -> str:
        return f'{self.name}_buf'

    @property
    def asmvar_end(self) -> str:
        return f'__{self.name}_end'

    @property
    def cvar_size(self) -> str:
        return f'{self.name}_size'

    @property
    def ext_array(self) -> tuple[HsExt, ...]:
        return self._exts

    def get_ext_index(self, ext: HsExt) -> int:
        return self._extmap[ext]

    @property
    def pat_ext_indices(self) -> tuple[int, ...]:
        return tuple((self._extmap[pat.ext] for pat in self._db.keys()))

    def __getitem__(self, k: HsPattern) -> int:
        return self._db[k]

    def __iter__(self) -> Iterator[HsPattern]:
        return iter(self._db)

    def __len__(self) -> int:
        return len(self._db)

    def __contains__(self, k: object) -> bool:
        if not isinstance(k, HsPattern):
            return False
        return k in self._db

    def items(self) -> ItemsView[HsPattern, int]:
        return self._db.items()

    def keys(self) -> KeysView[HsPattern]:
        return self._db.keys()

    def values(self) -> ValuesView[int]:
        return self._db.values()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HsDatabase):
            return False
        return bool(self._cmpkey == other._cmpkey)

    @property
    def _cmpkey(self) -> frozenset[HsPattern]:
        return frozenset(self._db.keys())

    @property
    def name(self) -> str:
        return self._name

    def __repr__(self) -> str:
        return f'{type(self).__name__}({self.name})'

    def write_hsdef(self, p: Path) -> None:
        with p.open('w') as f:
            for pat, pat_id in self._db.items():
                f.write(f'{pat_id}:/{pat.pattern}/{pat.flags_ext_str}\n')
