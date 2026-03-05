from typing import NamedTuple
from pathlib import Path

__all__ = (
    'Loc',
)


class Loc(NamedTuple):
    """
    Location of a rule within a source file
    """

    path: Path
    lineno: int

    def __str__(self) -> str:
        return f'{self.path}:{self.lineno}'
