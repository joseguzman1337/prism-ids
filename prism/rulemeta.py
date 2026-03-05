from __future__ import annotations
from typing import (
    Any, Mapping, Sequence, NamedTuple, Iterable, Optional, Tuple, Dict,
    DefaultDict, List,
)
from collections import defaultdict
from enum import Enum

from .loc import Loc
from .errors import ParseError
from .ruleopt import RuleOpt
from .partition import partition
from .registry import required_metas

__all__ = (
    'RuleMeta',
)


class Target(Enum):
    NONE = None
    SRC_IP = 'src_ip'
    DEST_IP = 'dest_ip'


class RuleMeta(NamedTuple):
    sid: int
    rev: int
    msg: str
    classtype: Optional[str]
    metadata: Mapping[str, Sequence[str]]
    references: Tuple[str, ...]
    target: Target = Target.NONE

    @classmethod
    def from_opts(cls,
                  opts: Iterable[RuleOpt],
                  loc: Optional[Loc] = None,
                  ) -> RuleMeta:
        def is_multi(opt: RuleOpt) -> bool:
            meta = opt.flags.meta
            assert (meta is not None)
            return meta.multiple

        singles, multis = partition(is_multi, opts)

        sd: Dict[str, str] = {}
        for opt in singles:
            if opt.value is None:
                continue
            if opt.name in sd:
                raise ParseError(f'Duplicated "{opt.name}" keyword', loc=loc)
            sd[opt.name] = opt.value

        md: DefaultDict[str, List[str]] = defaultdict(list)
        for opt in multis:
            if opt.value is None:
                continue
            md[opt.name].append(opt.value)

        missing = required_metas - sd.keys()
        if missing:
            raise ParseError(f'Rule has no {", ".join(missing)} keyword(s)',
                             loc=loc)

        try:
            sid = int(sd['sid'])
            rev = int(sd.get('rev', 0))
        except ValueError:
            raise ParseError('sid/rev must be numeric', loc=loc)

        meta_dict = defaultdict(list)
        for tagset in md.pop('metadata', ()):
            for tag in (t.strip() for t in tagset.split(',')):
                k, v = tag.split(None, maxsplit=1)
                meta_dict[k].append(v)

        targets = frozenset(md.pop('target', ()))
        if len(targets) > 1:
            raise ParseError(
                f'Rule has conflicting targets: {", ".join(sorted(targets))}',
                loc=loc,
            )

        if targets:
            t_str, = tuple(targets)
            try:
                target = Target(t_str)
            except ValueError:
                raise ParseError(
                    f'Unknown target type: {t_str!r}',
                    loc=loc,
                )
        else:
            target = Target.NONE

        return cls(
            sid,
            rev,
            sd['msg'],
            sd.get('classtype'),
            {k: tuple(v) for k, v in meta_dict.items()},
            tuple(md['reference']),
            target,
        )

    @property
    def json_dict(self) -> Dict[str, Any]:  # pragma: nocover
        return {
            'sid': self.sid,
            'rev': self.rev,
            'msg': self.msg,
            'classtype': self.classtype,
            'metadata': self.metadata,
            'references': self.references,
            'target': self.target.value,
        }
