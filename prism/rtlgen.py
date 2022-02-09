from __future__ import annotations
from typing import (
    Optional, Any, Generator, NamedTuple, FrozenSet, List, Tuple, Mapping,
    Type, Set, Dict, DefaultDict, Sequence, Union, Callable, Iterable, cast
)
from collections import defaultdict, Counter
from math import factorial
from itertools import permutations
from random import shuffle

from .sticky_buffer import StickyBuffer
from .errors import CompileError
from .hook import HookDef, Profile
from .hyperscan import HsPattern, HsFlag, HsDatabase
from .ir import Opcode, Pattern, OptionalDotPrefix, StringSet
from .program import Program
from .rtl import (
    RtlNode, RtlNop, CompleteMatch, OpSequence, PartialMatch, MultiPattern
)

__all__ = (
    'gen_rtl',
    'RtlObject',
)


class MatchAction(NamedTuple):
    complete_sids: FrozenSet[int]
    partial_sids: FrozenSet[int]

    # Any is actually MatchAction, recursive types not allowed...
    further: Tuple[Tuple[Opcode, Any], ...]

    def __bool__(self) -> bool:
        return (
            bool(self.complete_sids)
            or bool(self.partial_sids)
            or bool(self.further)
        )

    @classmethod
    def empty(cls) -> MatchAction:
        return cls(
            frozenset(),
            frozenset(),
            tuple(),
        )

    @classmethod
    def complete(cls, sid: int) -> MatchAction:
        return cls(
            frozenset({sid}),
            frozenset(),
            tuple(),
        )

    @classmethod
    def partial(cls, sid: int) -> MatchAction:
        return cls(
            frozenset(),
            frozenset({sid}),
            tuple(),
        )

    def __or__(self: MatchAction, other: MatchAction) -> MatchAction:
        cls = type(self)
        return cls(
            self.complete_sids | other.complete_sids,
            self.partial_sids | other.partial_sids,
            self.further + other.further,
        )

    def partition_further_by_type(self) -> Dict[Type[Opcode],
                                                Tuple[
                                                      Tuple[Opcode,
                                                            MatchAction],
                                                      ...]]:
        ret: DefaultDict[Type[Opcode],
                         List[Tuple[Opcode, MatchAction]]] = defaultdict(list)
        for op, any_action in self.further:
            action = cast(MatchAction, any_action)
            ret[type(op)].append((op, action))

        return {k: tuple(v) for k, v in ret.items()}

    def unfreeze(self) -> MatchActionBuilder:
        return MatchActionBuilder(
            set(self.complete_sids),
            set(self.partial_sids),
            list(self.further),
        )


class MatchActionBuilder(NamedTuple):
    complete_sids: Set[int]
    partial_sids: Set[int]
    further: List[Tuple[Opcode, MatchAction]]

    @classmethod
    def empty(cls) -> MatchActionBuilder:
        return cls(
            set(),
            set(),
            list()
        )

    def __or__(self,
               other: Union[MatchActionBuilder, MatchAction]
               ) -> MatchActionBuilder:
        cls = type(self)
        return cls(
            self.complete_sids | other.complete_sids,
            self.partial_sids | other.partial_sids,
            self.further + cast(
                # Working around non-recursive types
                List[Tuple[Opcode, MatchAction]],
                other.further,
            ),
        )

    def __ior__(self,
                other: Union[MatchActionBuilder, MatchAction]
                ) -> MatchActionBuilder:
        self.complete_sids.update(other.complete_sids)
        self.partial_sids.update(other.partial_sids)
        self.further.extend(other.further)
        return self

    def freeze(self) -> MatchAction:
        return MatchAction(
            frozenset(self.complete_sids),
            frozenset(self.partial_sids),
            tuple(self.further),
        )


PatternSet = Mapping[HsPattern, MatchAction]

MatchDict = DefaultDict[
    Opcode,
    MatchActionBuilder
]
MatchTypeDict = DefaultDict[
    Type[Opcode],
    MatchDict,
]
BufDict = DefaultDict[
    StickyBuffer,
    MatchTypeDict,
]

MatchMap = Mapping[
    Opcode,
    MatchAction,
]
MatchTypeMap = Mapping[
    Type[Opcode],
    MatchMap
]
BufMap = Mapping[
    StickyBuffer,
    MatchTypeMap,
]

RtlHookProg = Mapping[StickyBuffer, RtlNode]


class PartialMatchPlanNode(NamedTuple):
    state_bit: Optional[int]
    finals: FrozenSet[int]
    intermediates: FrozenSet[int]


class PartialMatchPlan(NamedTuple):
    # The number of bits of state required
    state_bits: int

    # The order in which buffers must be matched. May not be all buffers,
    # because this just includes buffers with partial matches.
    ordering: Tuple[StickyBuffer, ...]

    # From any given partial-match with name == key to:
    # the set of sids for which this is the last match
    # the set of sids for which this is not the last match
    nodes: Mapping[str, PartialMatchPlanNode]

    # From any given sid, the number of bits
    sids: Mapping[int, Tuple[int, ...]]

    def apply(self, insns: Mapping[str, RtlNode]) -> None:
        sids = self.sids
        for node_name, pn in self.nodes.items():
            n = insns[node_name]
            assert isinstance(n, PartialMatch)

            bit_idx = pn.state_bit
            if bit_idx is not None:
                n.set_state_bit(bit_idx)

            finals = pn.finals
            if finals:
                fmap = {sid: sids[sid] for sid in sorted(finals)}
                n.set_finals(fmap)


class RtlCache:
    __slots__ = (
        '_names',
        '_actions',
        '_completes',
        '_partials',
        '_hsdbs',
        '_hsdb_names',
    )

    _names: Counter[str]
    _actions: Dict[Tuple[StickyBuffer, MatchAction], RtlNode]
    _completes: Dict[FrozenSet[int], CompleteMatch]
    _partials: Dict[Tuple[StickyBuffer, FrozenSet[int]], PartialMatch]
    _hsdbs: Dict[Tuple[HsPattern, ...], HsDatabase]

    def __init__(self) -> None:
        self._names = Counter()
        self._actions = {}
        self._completes = {}
        self._partials = {}
        self._hsdbs = {}

    # name_0, name_1, name_2, etc..
    def emit(self, name: str) -> str:
        counter = self._names
        cnt = counter[name]
        counter[name] += 1
        return f'{name}_{cnt}'

    # name, name_2, name_3, etc..
    def emit_unique(self, name: str) -> str:
        name_cnt = self._names.get(name)
        if name_cnt is None:
            self._names[name] = 2
            return name

        self._names[name] += 1
        return f'{name}_{name_cnt}'

    def action(self,
               buf: StickyBuffer,
               a: MatchAction,
               gen: Callable[[StickyBuffer, MatchAction], RtlNode],
               ) -> RtlNode:
        cache = self._actions
        key = (buf, a)
        op = cache.get(key)
        if op is not None:
            # print('cache hit: action', buf, a,  op.name)
            return op

        op = gen(buf, a)
        cache[key] = op
        return op

    def complete(self, sids: FrozenSet[int]) -> CompleteMatch:
        cache = self._completes
        op = cache.get(sids)
        if op is not None:
            # This is not good, it means there are multiple ways to match with
            # the same sid, which means our sidbuffer can overflow
            # print('cache hit: match', sids, op.name)
            return op
        sid_names = "_".join(str(sid) for sid in sorted(sids))
        op = CompleteMatch(
            self.emit_unique(f'match_{sid_names}'),
            sids,
        )
        cache[sids] = op
        return op

    def partial(self,
                buf: StickyBuffer,
                sids: FrozenSet[int],
                ) -> PartialMatch:
        cache = self._partials
        key = (buf, sids)
        op = cache.get(key)
        if op is not None:
            # print('cache hit: partial', buf, sids, op.name)
            return op
        buf_name = buf.name.lower()
        op = PartialMatch(self.emit(f'partial_{buf_name}'), buf, sids)
        cache[key] = op
        return op

    def hsdb(
        self,
        key: tuple[HsPattern, ...],
        name: str = 'hyper',
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
        '_cache',

        '_nr_sids',

        '_entry',
        '_insns',
        '_nr_state_bits',
    )

    _hook: HookDef
    _cache: RtlCache
    _nr_sids: int
    _entry: RtlHookProg
    _insns: Mapping[str, RtlNode]
    _nr_state_bits: int

    def __init__(self,
                 hook: HookDef,
                 cache: RtlCache,
                 rules: Iterable[Program]):
        self._hook = hook
        self._cache = cache

        # Process the actual rules
        sid_map, unit = self._prep_rules(rules)
        self._nr_sids = len(sid_map)

        prog = {buf: self._gen_rtl(buf, tm) for buf, tm in unit.items()}

        # Plan the buffer-match ordering
        plan = self._optimize_partial_matches(hook, prog, sid_map)
        if plan is not None:
            # Extract the buffers which didn't have partial matches so we can
            # add them back to the ordered sequence of the other buffers, which
            # do have partial matches
            add_backs = frozenset(prog.keys()) - frozenset(plan.ordering)

            prog = {k: prog[k] for k in tuple(add_backs) + plan.ordering}
            self._nr_state_bits = plan.state_bits
        else:
            self._nr_state_bits = 0

        # Layout all the nodes
        self._entry = prog
        self._insns = insns = self._layout(prog)

        if plan is not None:
            plan.apply(insns)

    @property
    def hook(self) -> HookDef:
        return self._hook

    @property
    def nr_sids(self) -> int:
        return self._nr_sids

    @property
    def root(self) -> RtlHookProg:
        return self._entry

    @property
    def code(self) -> Mapping[str, RtlNode]:
        return self._insns

    @property
    def nr_state_bits(self) -> int:
        return self._nr_state_bits

    @staticmethod
    def _try_permutation(ordering: Tuple[StickyBuffer, ...],
                         bm: Mapping[StickyBuffer, Tuple[PartialMatch, ...]],
                         rules: Mapping[int, FrozenSet[StickyBuffer]],
                         ) -> PartialMatchPlan:
        state = {k: set(v) for k, v in rules.items()}
        bits: Dict[str, PartialMatchPlanNode] = {}
        bitsets: DefaultDict[int, Dict[StickyBuffer, int]] = defaultdict(dict)
        nr_bits = 0

        for buf, partials in ((b, bm[b]) for b in ordering):
            for node in partials:
                sids = node.sids
                finals = set()
                intermediates = set()
                for sid in sids:
                    st = state[sid]
                    st.remove(buf)
                    if st:
                        intermediates.add(sid)
                    else:
                        finals.add(sid)

                bits[node.name] = PartialMatchPlanNode(
                    None if not intermediates else nr_bits,
                    frozenset(finals),
                    frozenset(intermediates),
                )

                if intermediates:
                    cur_bit = nr_bits
                    nr_bits += 1

                    for sid in intermediates:
                        bitset = bitsets[sid]
                        assert buf not in bitset
                        bitset[buf] = cur_bit

        assert nr_bits == sum(1 for n in bits.values() if len(n.intermediates))
        return PartialMatchPlan(
            nr_bits,
            ordering,
            bits,
            {sid: tuple(sorted(d.values())) for (sid, d) in bitsets.items()},
        )

    @classmethod
    def _optimize_partial_matches(cls,
                                  hook: HookDef,
                                  prog: RtlHookProg,
                                  sid_map: Mapping[int, Program],
                                  max_bufs: int = 7,
                                  ) -> Optional[PartialMatchPlan]:
        def partials(insn: RtlNode) -> Tuple[PartialMatch, ...]:
            return tuple((x for x in insn.topological()
                          if isinstance(x, PartialMatch)))

        def convert(bm: RtlHookProg,
                    ) -> Mapping[StickyBuffer, Tuple[PartialMatch, ...]]:
            ret = {buf: partials(node) for (buf, node) in bm.items()}
            return {k: v for (k, v) in ret.items() if v}

        partials_map: Mapping[
            StickyBuffer,
            Tuple[PartialMatch, ...]
        ] = convert(prog)

        rules: Mapping[
            int,
            FrozenSet[StickyBuffer]
        ] = {
            sid: frozenset(prog.prefilters.keys())
            for (sid, prog) in sid_map.items()
            if len(prog.prefilters) > 1
        }

        if not partials_map:
            return None

        best_plan: Optional[PartialMatchPlan] = None

        nr_bufs = len(partials_map.keys())

        if nr_bufs <= max_bufs:
            # if the number of keys is small enough, exhaustively search all
            # permutations
            for p in permutations(partials_map.keys()):
                plan = cls._try_permutation(p, partials_map, rules)
                if best_plan is None or plan.state_bits < best_plan.state_bits:
                    best_plan = plan
                    # ostr = ' -> '.join((buf.name for buf in p))
                    # print(hook.name, ostr, plan.state_bits)
        else:
            # but if it's to large, do a random search, this can produce pretty
            # near optimal solutions
            keys = list(partials_map.keys())
            for _ in range(factorial(max_bufs)):
                shuffle(keys)
                p = tuple(keys)
                plan = cls._try_permutation(p, partials_map, rules)
                if best_plan is None or plan.state_bits < best_plan.state_bits:
                    best_plan = plan
                    ostr = ' -> '.join((buf.name for buf in p))
                    print(hook.name, ostr, plan.state_bits)

        assert best_plan is not None
        print(f'{hook.name}, {best_plan.state_bits} bits:',
              ' -> '.join(x.value for x in best_plan.ordering))

        return best_plan

    @staticmethod
    def _layout(entry: RtlHookProg) -> Mapping[str, RtlNode]:
        tmp: Set[str] = set()
        insns: List[RtlNode] = list()

        for buf in entry.values():
            insns.extend(buf.topological(tmp))

        return {insn.name: insn for insn in insns}

    @classmethod
    def _prep_rules(cls, rules: Iterable[Program],
                    ) -> Tuple[Mapping[int, Program], BufMap]:
        """
        For each hook:
         For each stickybuffer available in that hook:
          For each Opcode-type in the fast-patterns for that hook,buffer
           There is a dict mapping opcodes to match results

        A MatchResult has a set of sids which are completely matched for this
        operation. And a set of sids of rules which are partly matched by this
        operation.

        In other words, the final dict here is the fast-pattern set for a given
        hook,stickybuf pair.
        """
        sidmap: Dict[int, Program] = {}
        unit: BufDict = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(MatchActionBuilder.empty)
            )
        )

        for r in rules:
            sid = r.meta.sid
            sidmap[sid] = r

            bufs = r.prefilters

            nr_bufs = len(bufs)
            assert nr_bufs

            if nr_bufs == 1:
                action = MatchAction.complete(sid)
            else:
                action = MatchAction.partial(sid)

            for buf, v in bufs.items():
                unit[buf][type(v)][v] |= action

        def freeze_matchdict(d: MatchDict) -> MatchMap:
            return {k: v.freeze() for k, v in d.items()}

        def freeze_typedict(d: MatchTypeDict) -> MatchTypeMap:
            return {k: freeze_matchdict(v) for k, v in d.items()}

        def freeze_bufdict(d: BufDict) -> BufMap:
            return {k: freeze_typedict(v) for k, v in d.items()}

        return sidmap, freeze_bufdict(unit)

    def _gen_further(self,
                     buf: StickyBuffer,
                     a: MatchAction,
                     ) -> Generator[RtlNode, None, None]:
        if not a.further:
            return

        further = a.partition_further_by_type()

        if self._dump_further:
            for op_type, opactions in further.items():
                print(op_type)
                for op, _ in opactions:
                    print(' ', op)
                for _, action in opactions:
                    print(' ', action)
            print()

        string_sets = further.pop(StringSet)

        if further:
            # TODO: if there are any other nodes, then generate them here,
            # and make the child be a sequence
            unsupp_types = ', '.join(t.__name__ for t in further.keys())
            raise NotImplementedError(unsupp_types)

        # De-duplicate any identical string-sets
        sets: DefaultDict[StringSet, MatchActionBuilder] = \
            defaultdict(MatchActionBuilder.empty)

        for op, action in string_sets:
            assert isinstance(op, StringSet)
            sets[op] |= action

        # We're going to de-duplicate any identical patterns
        pats: Dict[bytes, int] = {}

        def register(content: Tuple[bytes, ...],
                     ) -> Generator[int, None, None]:
            for pat in content:
                yield pats.setdefault(pat, len(pats))

        # And remember all combinations of patterns
        combos: Dict[Tuple[int, ...], MatchActionBuilder] = {}

        for k, v in sets.items():
            idxs = tuple(register(k.content))
            combos[idxs] = v

        # All patterns are QUIET unless they, on their own, are a match.
        default_pat_flags = HsFlag.SINGLEMATCH | HsFlag.QUIET
        patflags = {i: default_pat_flags for i in pats.values()}
        for idx in (idx for (idx, *others) in combos.keys() if not others):
            patflags[idx] &= ~HsFlag.QUIET

        # Now we build our pattern set
        hspats: DefaultDict[HsPattern, MatchActionBuilder] = \
            defaultdict(MatchActionBuilder.empty)

        # Start with the actual patterns
        for b, idx in pats.items():
            hspat = HsPattern.literal(b, patflags[idx])
            hspats[hspat] |= combos.get((idx, ), MatchActionBuilder.empty())

        # Then add in the combos
        for combo, actions in combos.items():
            if len(combo) > 1:
                hspats[HsPattern.combo(combo)] |= actions

        hspats_final = {hspat: action.freeze()
                        for hspat, action in hspats.items()}

        yield self._pat_node(buf, hspats_final)

    def _gen_action(self, buf: StickyBuffer, a: MatchAction) -> RtlNode:
        children: List[RtlNode] = []

        if a.complete_sids:
            children.append(self._cache.complete(a.complete_sids))

        if a.partial_sids:
            children.append(self._cache.partial(buf, a.partial_sids))

        children.extend(self._gen_further(buf, a))

        nr_children = len(children)

        if nr_children == 0:
            return RtlNop(self._cache.emit('nop'))
        elif nr_children == 1:
            return children.pop()
        else:
            return OpSequence(self._cache.emit('seq'), tuple(children))

    def _pat_node(self, buf: StickyBuffer, pats: PatternSet) -> MultiPattern:
        hsdb = self._cache.hsdb(
            tuple(pats.keys()),
            buf.value.replace('.', '_'),
        )

        mapping = {hsdb[pat]: self._cache.action(buf, action, self._gen_action)
                   for pat, action in pats.items()
                   if action}

        op = MultiPattern(self._cache.emit('hsmulti'), hsdb, mapping)

        return op

    def _gen_rtl(self, buf: StickyBuffer, tm: MatchTypeMap) -> RtlNode:
        tmp = {k: val for k, val in tm.items()}
        res: DefaultDict[HsPattern, MatchActionBuilder] = \
            defaultdict(MatchActionBuilder.empty)

        # Add all Pattern in to pattern set
        for typ in (Pattern, OptionalDotPrefix):
            cur = tmp.pop(typ, {})
            for p, action in cur.items():
                assert isinstance(p, Pattern)
                res[p.hyperscan_pattern] |= action

        # Make sure we haven't forgotten anything! :)
        if tmp:
            unsupp = ', '.join((t.__name__ for t in tmp.keys()))
            raise CompileError(f'Unsupported match: {unsupp}')
        pat_dict = {pat: ab.freeze() for pat, ab in res.items()}

        if self._print_rtl:
            print(buf)
            for match_type, matches in tm.items():
                print(f' - {match_type.__name__} x {len(matches)}')
            for pat, ab in pat_dict.items():
                print('   -', ab)
            print()

        return self._pat_node(buf, pat_dict)


class RtlHook(NamedTuple):
    nr_sids: int
    insns: Mapping[str, RtlNode]
    bufmap: RtlHookProg
    nr_state_bits: int

    def dump(self) -> None:
        nr_sids, insns, bufmap, nr_state_bits = self

        for name, op in insns.items():
            print(f'insn[{name}] -> {op}')

        for buf, node in bufmap.items():
            print(f' - entries: {buf} -> {node.name}')


class RtlObject(NamedTuple):
    profile: Profile
    hyperscan_dbs: Mapping[str, HsDatabase]
    hooks: Mapping[HookDef, RtlHook]
    nr_sids: Mapping[HookDef, int]
    nr_state_bits: int

    def dump(self) -> None:
        _, hyperscan_dbs, hooks, _, _ = self

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
        hooks = {hook: RtlHook(unit.nr_sids,
                               unit.code,
                               unit.root,
                               unit.nr_state_bits)
                 for hook, unit in prog.items()}

        return RtlObject(
            profile,
            {db.name: db for db in hsdbs},
            hooks,
            {k: v.nr_sids for k, v in hooks.items()},
            max((v.nr_state_bits for v in hooks.values()), default=0),
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
