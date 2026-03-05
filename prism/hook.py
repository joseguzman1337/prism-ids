from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from functools import reduce
from operator import or_
from tomllib import load
from typing import Generator, IO, Iterable, Mapping, NamedTuple, Optional
from warnings import warn

from importlib.resources import files
from importlib.resources.abc import Traversable

from .errors import RuleError
from .flow import Flow, FlowDirection
from .loc import Loc
from .sticky_buffer import StickyBuffer


__all__ = (
    'HookDef',
    'Hook',
)

_empty: frozenset[StickyBuffer] = frozenset({})


class HookDef(NamedTuple):
    name: str
    proto: str
    direction: FlowDirection

    # basically the list of fields for this hook
    bufs: frozenset[StickyBuffer]

    # a subset of fields required to match a rule to this hook, if the rule
    # uses _any_ of these fields then it will match this hook. This for example
    # lets us distinguish between pure app-layer TLS rules and TLS rules which
    # also look at packet content, by having two hooks and setting the later
    # one to have _packet_content as required
    required_bufs: frozenset[StickyBuffer] = _empty

    @property
    def buf_names(self) -> Generator[str, None, None]:
        bufs = sorted(self.bufs, key=lambda x: x.name)
        yield from (buf.name.lower() for buf in bufs)

    @classmethod
    def from_toml(cls, d: dict[str, object]) -> HookDef:
        name = d['name']
        proto = d['proto']
        dstr = d['direction']

        if not isinstance(name, str):
            raise TypeError('Name must be a string')
        if not isinstance(proto, str):
            raise TypeError('Proto must be a string')
        if not isinstance(dstr, str):
            raise TypeError('Direction must be a string')

        direction = FlowDirection[dstr.upper()]

        buf_list = d.get('bufs', [])
        rbuf_list = d.get('required_bufs', [])

        if not isinstance(buf_list, list):
            raise TypeError('Bufs must be a list')

        if not isinstance(rbuf_list, list):
            raise TypeError('Bufs must be a list')

        def map_name(s: object) -> str:
            if not isinstance(s, str):
                raise TypeError('Buffer name must be a string')
            return s.upper().replace('-', '_').replace('.', '_')

        bufs = frozenset(StickyBuffer[map_name(s)] for s in buf_list)
        rbufs = frozenset(StickyBuffer[map_name(s)] for s in rbuf_list)

        return cls(
            name,
            proto,
            direction,
            bufs,
            rbufs,
        )


@dataclass(eq=True, frozen=True, slots=True)
class Profile:
    name: str
    desc: str
    all_hooks: tuple[HookDef, ...]
    proto_map: dict[str, tuple[HookDef, ...]]
    hook_set: frozenset[HookDef]
    hook_names: Mapping[str, HookDef]
    all_buffers: tuple[StickyBuffer, ...]

    @classmethod
    def from_toml(
        cls,
        defn: dict[str, object],
        expected_name: str | None = None,
    ) -> Profile:
        name = defn.get('name', expected_name)
        desc = defn.get('desc')
        hooks_list = defn.get('hooks', ())

        if not isinstance(name, str):
            raise TypeError('Profile name must be a string')
        if not isinstance(desc, str):
            raise TypeError('Profile description must be a string')
        if not isinstance(hooks_list, list):
            raise TypeError('Profile hooks must be a list')

        if expected_name != name:
            warn(f"Profile name {name!r} doesn't match "
                 f'expected {expected_name!r}')

        hooks = list()
        hook_names: set[str] = set()
        for h in hooks_list:
            if not isinstance(h, dict):
                raise TypeError('Hooks must be dicts')
            hook = HookDef.from_toml(h)
            if hook.name in hook_names:
                raise ValueError(f'Hook {hook.name!r} multiply defined')
            hooks.append(hook)
            hook_names.add(hook.name)

        protos = defaultdict(list)
        for hook in hooks:
            protos[hook.proto].append(hook)

        bufs: set[StickyBuffer] = reduce(
            or_,
            (hook.bufs for hook in hooks),
            set(),
        )

        return cls(
            name,
            desc,
            all_hooks=tuple(hooks),
            proto_map={k: tuple(v) for k, v in protos.items()},
            hook_set=frozenset(hooks),
            hook_names={h.name: h for h in hooks},
            all_buffers=tuple(sorted(bufs, key=lambda b: b.name))
        )

    @classmethod
    def load(
        cls,
        f: IO[bytes],
        expected_name: str | None = None,
    ) -> Profile:
        defn = load(f)
        f.close()
        del f

        return cls.from_toml(defn, expected_name=expected_name)

    @classmethod
    def from_file(cls, p: Traversable) -> Profile:
        stem, *_ = p.name.rsplit('.', 1)
        with p.open('rb') as f:
            return cls.load(f, expected_name=stem)

    def __in__(self, other: object) -> bool:
        return other in self.hook_set

    def __getitem__(self, name: str) -> HookDef:
        return self.hook_names[name]

    def determine(
        self,
        proto: str,
        f: Flow,
        bufs: Iterable[StickyBuffer],
        loc: Optional[Loc] = None,
    ) -> tuple[HookDef, ...]:
        bufset = frozenset(bufs)
        d = f.direction

        def matches(h: HookDef) -> bool:
            if h.proto != proto:
                return False

            if not (h.direction & d):
                return False

            required = h.required_bufs
            if required and not bufset & required:
                return False

            if bufset - h.bufs:
                return False

            return True

        hooks = tuple(filter(matches, self.proto_map.get(proto, ())))
        if not hooks:
            bufnames = '/'.join(sorted([b.name for b in bufset]))
            # print('hook?', proto, d, bufnames)
            raise RuleError(
                f'{proto}:{d} hook could not be determined: {bufnames}',
                loc=loc,
            )

        return hooks


def _scan_profiles() -> Generator[Profile, None, None]:
    for p in files(__package__).joinpath('profile').iterdir():
        if p.name.endswith('.toml'):
            yield Profile.from_file(p)


class Hook:
    profiles: dict[str, Profile] = {p.name: p for p in _scan_profiles()}

    def __init__(self) -> None:
        raise NotImplementedError
