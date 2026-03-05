from __future__ import annotations
from typing import NamedTuple, Iterable, Optional, Dict, Any, Generator
import logging

from .loc import Loc
from .ruleopt import RuleOpt
from enum import Enum

__all__ = (
    'RuleThreshold',
)

_log = logging.getLogger('rule')


class ThresholdType(Enum):
    THRESHOLD = 'threshold'
    FILTER = 'detection_filter'


class RuleThreshold(NamedTuple):
    type: ThresholdType
    val: str

    @classmethod
    def from_opts(cls,
                  opts: Iterable[RuleOpt],
                  loc: Optional[Loc] = None,
                  ) -> Generator[RuleThreshold, None, None]:
        for opt in opts:
            ttype = ThresholdType(opt.name)

            # TODO: we should parse the value
            assert opt.value is not None
            val = opt.value

            yield cls(ttype, val)

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'type': self.type.value,
            'val': self.val,
        }
