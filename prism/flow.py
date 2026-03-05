from typing import NamedTuple, Dict, Any
from enum import IntFlag, auto


__all__ = (
    'FlowDirection',
    'FlowState',
    'Flow',
)


class FlowDirection(IntFlag):
    CLIENT = auto()
    SERVER = auto()
    BOTH = CLIENT | SERVER

    @property
    def json_dict(self) -> Dict[str, bool]:  # pragma: nocover
        return {
            'client': bool(FlowDirection.CLIENT & self),
            'server': bool(FlowDirection.SERVER & self),
        }

    def __str__(self) -> str:
        if self == FlowDirection.CLIENT:
            return 'client'
        elif self == FlowDirection.SERVER:
            return 'server'
        elif self == (FlowDirection.CLIENT | FlowDirection.SERVER):
            return 'both'
        else:
            return 'neither'


class FlowState(IntFlag):
    ESTABLISHED = auto()
    NOT_ESTABLISHED = auto()
    STATELESS = ESTABLISHED | NOT_ESTABLISHED

    @property
    def json_dict(self) -> Dict[str, bool]:  # pragma: nocover
        return {
            'established': bool(FlowState.ESTABLISHED & self),
            'not_established': bool(FlowState.NOT_ESTABLISHED & self),
        }


# TODO: handle stream/no_stream/frag/no_frag
class Flow(NamedTuple):
    direction: FlowDirection
    state: FlowState
    # stream: FlowStream
    # frag: FlowFrag

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'direction': self.direction.json_dict,
            'state': self.state.json_dict,
        }
