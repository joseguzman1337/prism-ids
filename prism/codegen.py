from typing import (
    Iterable, NamedTuple, Optional, Mapping, Sequence, Dict, Set, Tuple
)
from pathlib import Path
from importlib.resources import files
from importlib.resources.abc import Traversable
from shutil import rmtree

import builtins
import csv

from jinja2 import (
    Environment, BaseLoader, PackageLoader, StrictUndefined, Template
)

from .hook import Profile
from .rtlgen import RtlObject, RtlHookProg
from .rtl import RtlNode
from .hyperscan import HsDatabase
from .hook import HookDef

__all__ = (
    'CBackend',
)


def _state_bit_isset(x: str) -> str:
    return f'state_bit_isset(st, {x})'


class PrismTemplateEnv(Environment):
    def _prism_register_filters(self) -> None:
        self.undefined = StrictUndefined
        self.filters.update({f: getattr(builtins, f) for f in (
            'len',
            'range',
            'zip',
            'hex',
            'enumerate',
            'sorted',
        )})
        self.filters.update({
            'state_bit_isset': _state_bit_isset
        })


class CTemplateEnv(PrismTemplateEnv):
    def __init__(self, loader: BaseLoader) -> None:
        super().__init__(
            loader=loader,
            line_statement_prefix='//',
            variable_start_string='/*{',
            variable_end_string='}*/',
            keep_trailing_newline=False,
            trim_blocks=True,
            lstrip_blocks=True,
            auto_reload=False,
            autoescape=False,
        )
        self._prism_register_filters()


class CodeTemplates(NamedTuple):
    prism_rules_c: Template
    hs_h: Template
    common_h: Template
    bufentry_c: Template
    abi_h: Template
    test_args_c: Template
    hook_c: Template
    entry_c: Template
    hsdb_S: Template
    main_c: Template
    blacklist_h: Template

    rtl_templates: Dict[str, Template]


class CBackend:
    _template_dir = files(__package__).joinpath('templates/c')
    _template_loader = PackageLoader(f'{__package__}.templates', 'c')
    _env = CTemplateEnv(_template_loader)
    _t: Optional[CodeTemplates] = None

    _obj_dir = 'obj'
    _verbatim_files = (
        'prism_rules.h',
        'hyperc.c',
    )
    _mk_files = (
        'compiler.mk',
        'deps.mk',
        'header.mk',
        'hyperscan.mk',
        'prism.rules.mk',
        'rules.mk',
        'targets.mk',
    )
    _toplevel_files = (
        'Makefile',
    )

    __slots__ = (
        '_name',
        '_unit',
        '_tmpl',
    )

    _name: str
    _unit: RtlObject
    _tmpl: CodeTemplates

    @property
    def profile(self) -> Profile:
        return self._unit.profile

    @property
    def hooks(self) -> tuple[HookDef, ...]:
        return self.profile.all_hooks

    @staticmethod
    def mkdir(p: Path) -> None:
        parts = p.parts

        if not parts or parts in {('.',), ('..',)}:
            raise ValueError('Refusing to delete current or parent dir')

        if (p / '.git').is_dir():
            raise ValueError(f'{p} is a git repo, refusing to delete')

        rmtree(str(p), ignore_errors=True)
        p.mkdir(exist_ok=True)

    def __init__(
        self,
        name: str,
        unit: RtlObject,
        out: Path,
        cert_csv: Optional[Path]
    ):
        cls = type(self)
        if cls._t is None:
            cls._t = cls.load_templates()

        self._name = name
        self._unit = unit
        self._tmpl = cls._t

        mk_dir = out / 'mk'
        src_dir = out / 'src'

        out.mkdir(exist_ok=True)
        self.mkdir(mk_dir)
        self.mkdir(src_dir)

        self._verbatim(out, self._toplevel_files)
        self._verbatim(mk_dir, self._mk_files)
        self._verbatim(src_dir, self._verbatim_files)

        self.write_main_c(src_dir / 'main.c')

        hsdbs = unit.hyperscan_dbs
        hsdb_seq = tuple(hsdbs.values())

        for hsdb in hsdb_seq:
            hsdb.write_hsdef(src_dir / f'{hsdb.name}.hsdef')

        self.write_hsdb_S(src_dir / 'hsdb.S', {
            f'{self._obj_dir}/{hsdb.name}.hsdb': hsdb
            for hsdb in hsdb_seq
        })

        self._write_list_mk(
            src_dir / 'hsdb.list.mk',
            'PRISM_HSDB_OBJ',
            [f'$(OBJ_DIR)/{hsdb.name}.hsdb' for hsdb in hsdb_seq],
        )

        self._write_list_mk(
            src_dir / 'hook.list.mk',
            'PRISM_HOOK_SRC',
            [f'prism_hook_{hook.name}.c' for hook in self.hooks]
        )

        self.write_prism_rules_c(
            src_dir / 'prism_rules.c',
            hsdb_seq,
        )

        for hook, ent in unit.hooks.items():
            self.write_hook(
                src_dir / f'prism_hook_{hook.name}.c',
                hook,
                hsdb_seq,
                ent.insns,
                ent.bufmap,
            )

        self.write_common_h(
            src_dir / 'prism_common.h',
            unit.nr_state_bits,
        )

        self.write_abi_h(src_dir / 'prism_abi.h', unit.nr_sids)
        self.write_hs_h(src_dir / 'prism_hs.h', hsdb_seq)
        self.write_test_args_c(src_dir / 'test_args.c')

        cert_bl = set()
        if cert_csv is not None:
            with cert_csv.open() as cert_file:
                reader = csv.reader(cert_file, delimiter=',')
                for date, *rest in reader:
                    # skip header lines
                    if date.startswith("#"):
                        continue
                    fingerprint = tuple(bytes.fromhex(rest[0]))
                    if len(fingerprint) != 20:
                        raise ValueError("bad cert blacklist")
                    cert_bl.add(fingerprint)

        print(f'Cert blacklist {len(cert_bl)} items')
        self.write_blacklist_h(src_dir / 'blacklist.h', cert_bl)

    def _copy(self, inp: Traversable, out: Path) -> None:
        with inp.open('rb') as inf:
            with out.open('wb') as outf:
                while buf := inf.read():
                    outf.write(buf)

    def _verbatim(self, out: Path, files: Iterable[str]) -> None:
        for filename in files:
            self._copy(
                self._template_dir.joinpath(filename),
                out / filename,
            )

    def write_hs_h(self, p: Path, hsdbs: Sequence[HsDatabase]) -> None:
        code = self._tmpl.hs_h.render(
            hsdbs=hsdbs,
        )

        p.write_text(code)

    def write_common_h(
        self,
        p: Path,
        nr_state_bits: int,
    ) -> None:
        code = self._tmpl.common_h.render(
            state_bitmap_sz=(nr_state_bits + 63) // 64,
        )

        p.write_text(code)

    def write_abi_h(self, p: Path, nr_sids: Mapping[HookDef, int]) -> None:
        all_buffers = tuple(
            buf.name.lower()
            for buf in self.profile.all_buffers
        )
        code = self._tmpl.abi_h.render(
            all_buffers=all_buffers,
            hook_defs=self.hooks,
            nr_sids=nr_sids,
        )

        p.write_text(code)

    def write_test_args_c(self, p: Path) -> None:
        code = self._tmpl.test_args_c.render(
            buffers=self.profile.all_buffers,
            hook_defs=self.hooks,
        )

        p.write_text(code)

    def _get_template(self, key: str) -> Template:
        t = self._tmpl

        try:
            return t.rtl_templates[key]
        except KeyError:
            cls = type(self)
            ret = cls._env.get_template(key)
            t.rtl_templates[key] = ret
            return ret

    def write_prism_rules_c(
        self,
        p: Path,
        hsdbs: Sequence[HsDatabase],
    ) -> None:
        with p.open('w') as f:
            f.write(self._tmpl.prism_rules_c.render(
                hsdbs=hsdbs,
            ))

    def write_hook(
        self,
        p: Path,
        hook: HookDef,
        hsdbs: Sequence[HsDatabase],
        insns: Mapping[str, RtlNode],
        bufmap: RtlHookProg,
    ) -> None:
        with p.open('w') as f:
            f.write(self._tmpl.hook_c.render())

            for name, insn in insns.items():
                tmpl = self._get_template(insn.template_name)
                f.write('\n')
                f.write(tmpl.render(
                    name=name,
                    insn=insn,
                ))

            for buf, insn in bufmap.items():
                assert buf is not None
                f.write('\n')
                f.write(self._tmpl.bufentry_c.render(
                    buf=buf,
                    hook=hook,
                    buf_name=buf.name.lower(),
                    entry=insn,
                ))

            f.write('\n')
            buf_names = tuple((buf.name.lower() for buf in bufmap))
            f.write(self._tmpl.entry_c.render(
                hook=hook,
                buf_names=buf_names,
            ))

    def write_main_c(self, p: Path) -> None:
        code = self._tmpl.main_c.render(
            hook_defs=self.hooks,
        )

        p.write_text(code)

    def write_hsdb_S(self, p: Path, hsdbs: Mapping[str, HsDatabase]) -> None:
        code = self._tmpl.hsdb_S.render(
            hsdbs=hsdbs,
        )

        p.write_text(code)

    def _write_list_mk(
        self,
        p: Path,
        var_name: str,
        items: Sequence[str],
    ) -> None:
        with p.open('w') as f:
            f.write(f'{var_name} :=')
            if not items:
                f.write('\\n')
                return

            *cont, final = items

            f.write(' \\\n')

            for filename in cont:
                f.write(f'\t{filename} \\\n')

            f.write(f'\t{final}\n')

    def write_blacklist_h(self, p: Path,
                          cert_blacklist: Set[Tuple[int, ...]]) -> None:
        code = self._tmpl.blacklist_h.render(
            cert_blacklist=cert_blacklist,
        )

        p.write_text(code)

    @classmethod
    def load_templates(cls) -> CodeTemplates:
        get = cls._env.get_template

        return CodeTemplates(
           prism_rules_c=get('prism_rules.c'),
           hs_h=get('prism_hs.h'),
           common_h=get('prism_common.h'),
           bufentry_c=get('bufentry.c'),
           abi_h=get('abi.h'),
           test_args_c=get('test_args.c'),
           hook_c=get('hook.c'),
           entry_c=get('entry.c'),
           main_c=get('main.c'),
           hsdb_S=get('hsdb.S'),
           blacklist_h=get('blacklist.h'),
           rtl_templates={},
        )
