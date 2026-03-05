from typing import Optional, Any

from .loc import Loc

__all__ = (
    'PrismError',
    'SemanticError',
    'RuleError',
    'ParseError',
    'CompileError',
)


class PrismError(Exception):
    pass


class CompileError(PrismError):
    pass


class RuleError(PrismError):
    loc: Optional[Loc]

    def __init__(self, *args: Any, loc: Optional[Loc] = None):
        super().__init__(*args)
        self.loc = loc

    @property
    def explanation(self) -> str:
        return super().__str__()

    def __str__(self) -> str:
        s = super().__str__()
        loc = self.loc
        if loc is None:
            return s
        else:
            return f'{loc.path}:{loc.lineno}: {s}'


class ParseError(RuleError):
    pass


class SemanticError(RuleError):
    pass


class NeverMatches(SemanticError):
    pass
