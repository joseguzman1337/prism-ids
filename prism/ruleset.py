from __future__ import annotations
from typing import (
    Mapping, Dict, DefaultDict, Optional, Generator, Set, Iterable, Tuple,
    Iterator,
)
from collections import defaultdict
from pathlib import Path
import logging

from .loader import Loader
from .rule import Rule
from .errors import RuleError

__all__ = (
    'RuleSet',
)


class RuleSet:
    __slots__ = (
        '_rules',

        '_sids',
        '_proto',
        '_category',
        '_dirty',
    )

    _rules: Dict[int, Rule]
    _sids: Set[int]
    _proto: Mapping[str, Set[int]]
    _category: Mapping[str, Set[int]]
    _dirty: bool

    _log = logging.getLogger()

    def __init__(self, d: Dict[int, Rule]) -> None:
        rules = dict(sorted(d.items()))

        self._rules = rules
        self._sids = set(rules.keys())

        self._dirty = True

    def _refresh(self) -> None:
        if not self._dirty:
            return

        proto: DefaultDict[str, Set[int]] = defaultdict(set)
        category: DefaultDict[str, Set[int]] = defaultdict(set)

        rules = self._rules

        for k, v in rules.items():
            proto[v.head.proto].add(k)
            category[v.category].add(k)

        self._proto = dict(proto)
        self._category = dict(category)
        self._dirty = False

    def protocol_summary(self,
                         category: Optional[str] = None,
                         ) -> Tuple[Tuple[int, str], ...]:
        self._refresh()

        if category is None:
            summary = [(len(r), p) for p, r in self._proto.items()]
        else:
            try:
                c = self._category[category]
            except KeyError:
                return ()
            summary = [(len(r & c), p) for p, r in self._proto.items()]
            summary = [(nr, p) for nr, p in summary if nr]
        summary.sort(reverse=True)
        return tuple(summary)

    def category_summary(self,
                         proto: Optional[str] = None,
                         ) -> Tuple[Tuple[int, str], ...]:
        self._refresh()

        if proto is None:
            summary = [(len(r), c) for c, r in self._category.items()]
        else:
            try:
                p = self._proto[proto]
            except KeyError:
                return ()
            summary = [(len(r & p), c) for c, r in self._category.items()]
            summary = [(nr, c) for nr, c in summary if nr]
        summary.sort(reverse=True)
        return tuple(summary)

    def get_category(self, category: str) -> Set[int]:
        self._refresh()
        return self._category.get(category, set())

    def get_proto(self, proto: str) -> Set[int]:
        self._refresh()
        return self._proto.get(proto, set())

    def _get_protos(
        self,
        proto_list: Iterable[str],
    ) -> dict[str, frozenset[int]]:
        self._refresh()

        proto_set = frozenset(proto_list)
        if proto_set:
            return {k: frozenset(v)
                    for k, v in self._proto.items()
                    if k in proto_set}
        else:
            return {k: frozenset(v) for k, v in self._proto.items()}

    def get_protos(
        self,
        proto_list: Iterable[str],
    ) -> dict[str, tuple[Rule, ...]]:
        return {
            k: tuple(sorted(self.get_rules(v)))
            for k, v in self._get_protos(proto_list).items()
        }

    def get_rules(self, sids: Iterable[int]) -> Generator[Rule, None, None]:
        rules = self._rules
        for sid in sids:
            yield rules[sid]

    def __len__(self) -> int:
        return len(self._rules)

    def __getitem__(self, sid: int) -> Rule:
        return self._rules[sid]

    def __iter__(self) -> Iterator[Rule]:
        yield from sorted(self._rules.values())

    def __delitem__(self, sid: int) -> None:
        del self._rules[sid]
        self._sids.remove(sid)
        self._dirty = True

    def remove_rules(self, bitmap: Iterable[int]) -> None:
        self._sids.difference_update(bitmap)

        rules = self._rules
        for sid in bitmap:
            del rules[sid]

        self._dirty = True

    def _write_rules(self, rules: Iterable[Rule], p: Path) -> None:
        with p.open('w') as out:
            for r in sorted(rules):
                out.write(str(r))
                out.write('\n')

    def save(self, p: Path) -> None:
        self._write_rules(self._rules.values(), p)

    def save_subset(self, subset: Iterable[int], p: Path) -> None:
        self._write_rules(self.get_rules(subset), p)

    def save_annotated_subset(
        self,
        rule_comments: Mapping[int, str],
        p: Path,
    ) -> None:
        rules = sorted(self.get_rules(rule_comments.keys()))
        with p.open('w') as out:
            for r in rules:
                comment = rule_comments[r.meta.sid]
                if comment:
                    out.write('# ')
                    out.write(comment)
                    out.write('\n')
                out.write(str(r))
                out.write('\n\n')

    @classmethod
    def load(cls, ldr: Loader) -> RuleSet:
        ruleset: Dict[int, Rule] = dict()

        for rule in ldr:
            sid = rule.meta.sid
            if sid in ruleset:
                raise RuleError(f'Rule {sid} multiply defined', loc=rule.loc)
            ruleset[sid] = rule

        return cls(ruleset)

    @classmethod
    def from_paths(cls, paths: Iterable[Path]) -> RuleSet:
        return cls.load(Loader(*paths))
