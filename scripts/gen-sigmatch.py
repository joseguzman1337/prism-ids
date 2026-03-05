from typing import (
    Optional, List, Tuple, Dict, Set, Sequence, NamedTuple, Generator, TextIO
)
from pathlib import Path
from itertools import chain
from enum import IntFlag, Enum, auto
import re


class TriState(Enum):
    NONE = auto()
    OPTIONAL = auto()
    MANDATORY = auto()


class MetaFlags(NamedTuple):
    required: bool
    multiple: bool


meta_opts = frozenset({
    'sid',
    'rev',
    'msg',
    'classtype',
    'metadata',
    'reference',
    'target',
})
meta_multi = frozenset({
    'metadata',
    'reference',
    'target',  # suri allows this, and there are buggy rules
})
meta_required = frozenset({'sid', 'msg'})
content_modifiers = frozenset({
    'depth',
    'distance',
    'endswith',
    'fast_pattern',
    'nocase',
    'offset',
    'startswith',
    'within',
})
_force_sticky = frozenset({
    'file.data',
})

_name_parts = re.compile('[_\\-\\.]')


class SigMatch(IntFlag):
    NONE = 0
    NOOPT = auto()
    IPONLY_COMPAT = auto()
    DEONLY_COMPAT = auto()
    NOT_BUILT = auto()
    OPTIONAL_OPT = auto()
    QUOTES_OPTIONAL = auto()
    QUOTES_MANDATORY = auto()
    HANDLE_NEGATION = auto()
    CONTENT_MODIFIER = auto()
    STICKY_BUFFER = auto()
    DEPRECATED = auto()
    STRICT_PARSING = auto()

    TRANSFORM = auto()


class OptTableEntry(NamedTuple):
    opt: str
    aliases: Tuple[str, ...]
    flags: SigMatch


OptTable = Sequence[OptTableEntry]


def _load_table(p: Path) -> Generator[OptTableEntry, None, None]:
    opt: Optional[str] = None
    aliases: List[str] = []
    flag = SigMatch.NONE

    for line in chain(p.read_text().splitlines(), ('',)):
        if not line:
            assert opt is not None
            yield OptTableEntry(opt, tuple(aliases), flag)
            flag = SigMatch.NONE
        elif not line.startswith(' '):
            opt, *aliases = line.split()
        else:
            flag |= SigMatch[line.lstrip()]


class Mangled(NamedTuple):
    parts: Tuple[str, ...]
    lower: str
    camel: str
    upper: str


def transform_name(s: str) -> Mangled:
    parts = _name_parts.split(s)
    lcase = '_'.join((x.lower() for x in parts))
    camel = ''.join((x.title() for x in parts))
    ucase = '_'.join((x.upper() for x in parts))
    return Mangled(tuple(parts), lcase, camel, ucase)


def do_import(f: TextIO, mod: str, things: Sequence[str]) -> None:
    f.write(f'from {mod} import {", ".join(things)}\n')


def do_export(f: TextIO, things: Sequence[str]) -> None:
    f.write('__all__ = (\n')
    for var in things:
        f.write(f'    {var!r},\n')
    f.write(')\n')


def write_sigmatch_table(f: TextIO, raw_table: OptTable) -> None:
    f.write('\nsigmatch_table = {\n')
    for opt, aliases, flags in raw_table:
        if flags & SigMatch.QUOTES_MANDATORY:
            q = TriState.MANDATORY
        elif flags & SigMatch.QUOTES_OPTIONAL:
            q = TriState.OPTIONAL
        else:
            q = TriState.NONE

        if opt not in meta_opts:
            m = None
        else:
            m = MetaFlags(
                required=opt in meta_required,
                multiple=opt in meta_multi,
            )

        if flags & SigMatch.NOOPT:
            v = TriState.NONE
        elif flags & SigMatch.OPTIONAL_OPT:
            v = TriState.OPTIONAL
        else:
            v = TriState.MANDATORY

        n = True if flags & SigMatch.HANDLE_NEGATION else False
        s = True if flags & SigMatch.STICKY_BUFFER else False

        if not s:
            sbuf = None
        else:
            buf = transform_name(opt)
            sbuf = f'StickyBuffer.{buf.upper}'

        f.write(f"""    {opt!r}: OptFlags(
        quotes={str(q)},
        values={str(v)},
        negation={n!r},
""")

        if sbuf:
            f.write(f'        sticky_buffer={sbuf},\n')
        if m:
            f.write(f'        meta={m!r},\n')
        if opt in content_modifiers:
            f.write('        is_content_modifier=True,\n')
        if flags & SigMatch.TRANSFORM:
            f.write('        is_content_transform=True,\n')

        f.write('    ),\n')

    f.write('}\n\n')


def write_alias_table(f: TextIO, raw_table: OptTable) -> None:
    alias_table: Dict[str, str] = dict()
    canonical_opts: Set[str] = set()

    for opt, aliases, flags in raw_table:
        if opt in canonical_opts:
            raise ValueError(f'Duplicated option: "{opt}"')
        canonical_opts.add(opt)

        for alias in aliases:
            if alias in alias_table:
                raise ValueError(f'Duplicated alias: "{alias}"')
            alias_table[alias] = opt

    dupes = canonical_opts & alias_table.keys()
    if dupes:
        raise ValueError(f'Duplicate names {", ".join(dupes)}')

    f.write('\nalias_table: Dict[str, str] = {\n')
    for alias, opt in alias_table.items():
        f.write(f'    {alias!r}: {opt!r},\n')
    f.write('}\n')


def write_sticky_buffer(f: TextIO, raw_table: OptTable) -> None:
    sticky_buffer: Set[str] = set()

    for opt, aliases, flags in raw_table:
        s = opt in _force_sticky or bool(flags & SigMatch.STICKY_BUFFER)

        if s:
            sticky_buffer.add(opt)

    f.write('\n\nclass StickyBuffer(Enum):\n')
    f.write('    PKT_DATA = \'pkt_data\'\n\n')
    for buf in sorted(sticky_buffer):
        mangled = transform_name(buf)
        f.write(f'    {mangled.upper} = {buf!r}\n')

    f.write('''
    @property
    def buf_name(self) -> str:
        return self.name.lower()

    @property
    def arg_name(self) -> str:
        return self.name.lower().replace('_', '-')
''')


def main() -> None:
    tbl_path = Path('sigmatch_table.txt')
    out_path = Path('prism/sigmatch_table.py')
    buf_path = Path('prism/sticky_buffer.py')

    raw_table = list(_load_table(tbl_path))
    raw_table.sort()

    with buf_path.open('w') as f:
        print(f'Generating: {buf_path}')
        do_import(f, 'enum', ('Enum', ))
        f.write('\n')
        do_export(f, ('StickyBuffer',))
        write_sticky_buffer(f, raw_table)

    with out_path.open('w') as f:
        print(f'Generating: {out_path}')
        do_import(f, 'typing', ('Dict', ))
        f.write('\n')
        do_import(f, '.optflags', ('OptFlags', 'TriState', 'MetaFlags'))
        do_import(f, '.sticky_buffer', ('StickyBuffer', ))
        f.write('\n')

        do_export(f, (
            'sigmatch_table',
            'alias_table',
        ))
        write_sigmatch_table(f, raw_table)
        write_alias_table(f, raw_table)


if __name__ == '__main__':
    main()
