from __future__ import annotations
from typing import NamedTuple, Optional, Dict, Any

from .loc import Loc
from .errors import ParseError
from enum import Enum

__all__ = (
    'FlowBitOp',
    'FlowBitOpType',
)


class FlowBitOpType(Enum):
    NOALERT = 'noalert'
    SET = 'set'
    UNSET = 'unset'
    ISSET = 'isset'
    ISNOTSET = 'isnotset'


class FlowBitOp(NamedTuple):
    op: FlowBitOpType
    var: Optional[str]

    @classmethod
    def parse(cls, val: str, loc: Optional[Loc] = None) -> FlowBitOp:
        op_name, *opt_var = val.split(',', maxsplit=1)

        if not opt_var:
            var = None
        else:
            var, = opt_var
            var = var.lstrip()

        try:
            op = FlowBitOpType(op_name)
        except KeyError:
            raise ParseError(f'Unknown flowbit op "{op_name}"', loc=loc)

        return cls(op, var)

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'op': self.op.value,
            'var': self.var,
        }
