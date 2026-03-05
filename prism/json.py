from typing import Dict, Any, Union
from typing_extensions import Protocol

__all__ = (
    'JSONProto',
    'StrValueProto',
    'JScalar',
    'JValue',
    'JObject',
)


JScalar = Union[str, int, bool, None]
JValue = Union[JScalar, Dict[str, Any]]
JObject = Dict[str, JValue]


class JSONProto(Protocol):
    @property
    def json_dict(self) -> Dict[str, Any]: ...  # pragma: nocover


class StrValueProto(Protocol):
    @property
    def value(self) -> JScalar: ...  # pragma: nocover
