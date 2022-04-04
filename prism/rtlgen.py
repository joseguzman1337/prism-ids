from __future__ import annotations
from typing import (
    Optional, Generator, NamedTuple, List, Tuple, Mapping, Type, Set, Dict,
    DefaultDict, Sequence, Iterable,
)
from collections import defaultdict, Counter

from .sticky_buffer import StickyBuffer
from .hook import HookDef, Profile
from .hyperscan import HsPattern, HsDatabase
from .ir import Pattern, BufOp
from .program import Program
from .rtl import (
    RtlNode, RtlNop, RtlMatch,
    RtlPat, BufPrefix, BufSuffix, BufExact,
    OpSequence, MultiPattern,
)

__all__ = (
    'gen_rtl',
    'RtlProgram',
    'RtlObject',
)

PrefilterMap = Mapping[HsPattern, Tuple[Program, ...]]
BufMap = Mapping[
    StickyBuffer,
    PrefilterMap,
]

PrefilterDict = DefaultDict[HsPattern, List[Program]]
BufDict = DefaultDict[
    StickyBuffer,
    PrefilterDict,
]

RtlProgram = Mapping[HookDef, RtlNode]


class RtlCache:
    __slots__ = (
        '_names',
        '_hsdbs',
    )

    _names: Counter[str]
    _hsdbs: Dict[Tuple[HsPattern, ...], HsDatabase]

    def __init__(self) -> None:
        self._names = Counter()
        self._hsdbs = {}

    # name, name_2, name_3, etc..
    def emit_unique(self, name: str) -> str:
        name_cnt = self._names.get(name)
        if name_cnt is None:
            self._names[name] = 2
            return name

        self._names[name] += 1
        return f'{name}_{name_cnt}'

    def hsdb(
        self,
        key: Tuple[HsPattern, ...],
        name: str = 'hsdb',
    ) -> HsDatabase:
        cache = self._hsdbs
        hsdb = cache.get(key)
        if hsdb is not None:
            # print('cache hit: hsdb', hsdb)
            return hsdb

        hsdb = HsDatabase.from_patterns(
            self.emit_unique(name),
            key,
        )

        cache[key] = hsdb

        return hsdb

    @property
    def hyperscan_dbs(self) -> Generator[HsDatabase, None, None]:
        yield from self._hsdbs.values()


class RtlGen:
    _print_rtl: bool = False
    _dump_further: bool = False

    __slots__ = (
        '_hook',
        '_names',
        '_cache',

        '_nr_sids',
        '_entry',
        '_insns',
    )

    _hook: HookDef
    _names: Counter[str]
    _cache: RtlCache

    _nr_sids: int
    _entry: Optional[RtlNode]
    _insns: Mapping[str, RtlNode]

    def __init__(self,
                 hook: HookDef,
                 cache: RtlCache,
                 rules: Iterable[Program]):
        self._hook = hook
        self._names = Counter()
        self._cache = cache

        sid_map = {r.meta.sid: r for r in rules}
        self._nr_sids = len(sid_map)
        if not sid_map:
            entry = RtlNop('nop')
            self._entry = entry
            self._insns = self._layout(entry)
            return

        tree = self._prep_rules(rules)

        debug = False
        if debug:
            print(hook.name)
            for buf, mpm in tree.items():
                if len(mpm) == 1:
                    pat, = mpm.keys()
                    print(f' {buf.name} /{pat.pattern}/')
                else:
                    print(f' {buf.name} {len(mpm)}')
            print()

        def gen_one_tail(program: Program) -> RtlNode:
            sid = program.meta.sid
            tail: RtlNode = RtlMatch(
                self.emit(f'match_{sid}'),
                frozenset({sid, }),
            )

            for buf, pat in program.buf_ops:
                tail = self._rtlgen_buf(buf, pat, tail)

            extra = program.extra
            assert not extra

            return tail

        def gen_tail(programs: Sequence[Program]) -> RtlNode:
            if len(programs) == 1:
                program, = programs
                return gen_one_tail(program)

            tails = tuple(gen_one_tail(p) for p in programs)
            # TODO: group any RtlMatch nodes together

            return OpSequence(
                self.emit('tails'),
                tails,
            )

        def gen_no_mpm(buf: StickyBuffer, mpm: PrefilterMap) -> RtlNode:
            pat, = mpm.keys()
            rset, = mpm.values()
            assert rset
            fp = rset[0].prefilter
            assert fp.buf is buf
            return self._rtlgen_buf(
                fp.buf,
                fp.pat,
                gen_tail(rset),
            )

        def gen_mpm(buf: StickyBuffer, mpm: PrefilterMap) -> RtlNode:
            if len(mpm) == 1:
                return gen_no_mpm(buf, mpm)

            hsdb = cache.hsdb(
                tuple(mpm.keys()),
                f'mpm_{buf.name.lower()}',
            )
            return MultiPattern(
                f'mpm_{buf.name.lower()}',
                buf,
                hsdb,
                {hsdb[k]: gen_tail(v) for k, v in mpm.items()},
            )

        # TODO:
        # - generate a different kind of MPM for sets of exact matches of the
        #   same length
        # - add in tails for tules with no fast-pattern
        if len(tree) == 1:
            buf, = tree.keys()
            mpm = tree[buf]
            root = gen_mpm(buf, mpm)
        else:
            root = OpSequence(
                self.emit('hook_main'),
                tuple(gen_mpm(buf, mpm) for (buf, mpm) in tree.items()),
            )

        # Layout all the nodes
        self._entry = root
        self._insns = self._layout(root)

    def emit(self, name: str) -> str:
        counter = self._names
        cnt = counter[name]
        counter[name] += 1
        if not cnt:
            return name
        else:
            return f'{name}_{cnt}'

    def _rtlgen_pat(self,
                    buf: StickyBuffer,
                    op: Pattern,
                    tail: RtlNode,
                    ) -> RtlNode:
        start = op.start
        end = op.end

        if type(op) is Pattern:
            cls: Optional[Type[RtlPat]] = None
            if start and end:
                cls = BufExact
                name = 'exact'
            elif start:
                cls = BufPrefix
                name = 'startswith'
            elif end:
                cls = BufSuffix
                name = 'endswith'

            if cls is not None:
                return cls(
                    self.emit(f'{buf.name.lower()}_{name}'),
                    buf,
                    op.content,
                    tail,
                )
        pat = op.hyperscan_pattern

        hsdb = self._cache.hsdb(
            (pat, ),
            f'pat_{buf.name.lower()}',
        )

        return MultiPattern(
            self.emit(f'pat_{buf.name.lower()}'),
            buf,
            hsdb,
            {
                hsdb[pat]: tail,
            }
        )

        return tail

    def _rtlgen_buf(self,
                    buf: StickyBuffer,
                    op: BufOp,
                    tail: RtlNode,
                    ) -> RtlNode:
        if isinstance(op, Pattern):
            return self._rtlgen_pat(buf, op, tail)
        else:
            raise NotImplementedError(type(op).__name__)

    @property
    def hook(self) -> HookDef:
        return self._hook

    @property
    def nr_sids(self) -> int:
        return self._nr_sids

    @property
    def root(self) -> RtlNode:
        entry = self._entry
        assert entry is not None
        return entry

    @property
    def code(self) -> Mapping[str, RtlNode]:
        return self._insns

    @staticmethod
    def _layout(entry: RtlNode) -> Mapping[str, RtlNode]:
        tmp: Set[str] = set()
        insns: List[RtlNode] = list(entry.topological(tmp))

        return {insn.name: insn for insn in insns}

    @classmethod
    def _prep_rules(cls, rules: Iterable[Program]) -> BufMap:
        entry: BufDict = defaultdict(
            lambda: defaultdict(list)
        )

        for r in rules:
            buf = r.prefilter.buf
            fp = r.prefilter.pat
            entry[buf][fp.hyperscan_pattern].append(r)

        def freeze_matchdict(d: PrefilterDict) -> PrefilterMap:
            return {k: tuple(v) for k, v in d.items()}

        def freeze_bufdict(d: BufDict) -> BufMap:
            return {k: freeze_matchdict(v) for k, v in d.items()}

        return freeze_bufdict(entry)


class RtlHook(NamedTuple):
    nr_sids: int
    insns: Mapping[str, RtlNode]
    entry: RtlNode

    def dump(self) -> None:
        nr_sids, insns, entry = self

        for name, op in insns.items():
            print(f'insn[{name}] -> {op}')

        print(f'entry: {entry.name} {nr_sids} sids')


class RtlObject(NamedTuple):
    profile: Profile
    hyperscan_dbs: Mapping[str, HsDatabase]
    hooks: Mapping[HookDef, RtlHook]

    def dump(self) -> None:
        _, hyperscan_dbs, hooks = self

        for name, hsdb in hyperscan_dbs.items():
            print(f'hsdb: {name} -> {hsdb}')

        for hook, h in hooks.items():
            print(f'hook: {hook.name}')
            h.dump()

    @classmethod
    def link(cls,
             profile: Profile,
             hsdbs: Iterable[HsDatabase],
             units: Iterable[RtlGen],
             ) -> RtlObject:
        prog = {unit.hook: unit for unit in units}

        return RtlObject(
            profile,
            {db.name: db for db in hsdbs},
            {hook: RtlHook(unit.nr_sids, unit.code, unit.root)
             for hook, unit in prog.items()},
        )


def _partition(
    profile: Profile,
    rules: Iterable[Program],
    summary: bool = False,
) -> Dict[HookDef, Tuple[Program, ...]]:
    hooks: DefaultDict[HookDef, List[Program]] = defaultdict(list)
    for r in rules:
        for h in r.hooks(profile):
            hooks[h].append(r)

    if summary:
        for hook, rules in hooks.items():
            print(hook.name, len(rules))

    return {hook: tuple(hooks.get(hook, ())) for hook in profile.all_hooks}


def gen_rtl(
    profile: Profile,
    sigs: Sequence[Program],
    debug: bool = False,
) -> RtlObject:
    cache = RtlCache()

    units = (RtlGen(hook, cache, r) for (hook, r)
             in _partition(profile, sigs).items())

    obj = RtlObject.link(profile, cache.hyperscan_dbs, units)

    if debug:
        obj.dump()

    return obj
