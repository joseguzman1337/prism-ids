from typing import Generator, Tuple, TextIO

from pathlib import Path
import logging

from .loc import Loc
from .rule import Rule

__all__ = (
    'Loader',
)


class Loader:
    __slots__ = (
        '_p',
    )

    _log = logging.getLogger()

    _p: Tuple[Path, ...]

    def __init__(self, *paths: Path):
        self._p = paths

    @staticmethod
    def _rule_file_lines(p: Path,
                         f: TextIO,
                         ) -> Generator[Rule, None, None]:
        parse = Rule.parse
        with p.open('r') as f:
            for idx, line in enumerate(f):
                line = line.rstrip('\r\n')
                if not line:
                    continue
                if line.startswith('#'):
                    continue
                loc = Loc(p, idx + 1)
                yield parse(line, loc)

    def __iter__(self) -> Generator[Rule, None, None]:
        for p in self._p:
            try:
                with p.open('r') as f:
                    yield from self._rule_file_lines(p, f)
            except IsADirectoryError:
                for p in p.glob('*.rules'):
                    with p.open('r') as f:
                        yield from self._rule_file_lines(p, f)
