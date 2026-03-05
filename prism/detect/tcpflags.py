from __future__ import annotations
from typing import Optional, Dict, Any

from ..sigmatch import SigMatch
from ..sticky_buffer import StickyBuffer
from ..ruleopt import RuleOpt
from ..loc import Loc
# from ..errors import ParseError

__all__ = (
    'TcpFlags',
)


class TcpFlags(SigMatch, opt_name='tcp.flags'):
    __slots__ = (
    )

    @classmethod
    def from_rule_opt(cls,
                      opt: RuleOpt,
                      buf: StickyBuffer,
                      loc: Optional[Loc] = None) -> TcpFlags:
        return cls()

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.opt_name,
        }
