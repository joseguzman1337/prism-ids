from typing import Tuple, Optional
from dataclasses import dataclass

from .sigmatch import sigmatch_registry as _registry, SigMatch
from .sticky_buffer import StickyBuffer
from .ruleopt import RuleOpt, RuleOptToken
from .loc import Loc
from . import detect  # noqa

__all__ = (
    'SigMatchUnknown',
    'translate',
)


@dataclass(frozen=True, eq=True)
class SigMatchUnknown(SigMatch):
    name: str
    negated: bool
    val_str: Optional[str]

    modifiers: Tuple[RuleOptToken, ...] = ()

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> SigMatch:
        return cls(opt.name, opt.negated, opt.value, opt.modifiers)


def translate(opt: RuleOpt,
              buf: StickyBuffer,
              loc: Optional[Loc] = None) -> SigMatch:
    t = _registry.get(opt.name, SigMatchUnknown)
    return t.from_rule_opt(opt, buf, loc=loc)
