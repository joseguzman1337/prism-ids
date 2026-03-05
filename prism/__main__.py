from typing import Iterable, Optional
from argparse import ArgumentParser, RawTextHelpFormatter
from collections import defaultdict, Counter
from pathlib import Path
from sys import argv
from orjson import dumps
from itertools import chain
import logging

import prism
from prism import __version__
from . import console  # noqa
from .blacklist import blacklist_rules

_log = logging.getLogger()

__all__ = ()


_refract_failed_rules = 'prism.failed.rules'
_refract_annotated_rules = 'prism.annotated.rules'
_refract_suricata_rules = 'prism.suricata.rules'

_strip_payload_rules = 'prism.payload.rules'
_strip_applayer_rules = 'prism.app-layer.rules'

_ssldecrypt_rules = 'prism.ssldecrypt.rules'
_clear_rules = 'prism.clear.rules'

_noalert_rules = 'prism.noalert.rules'
_alert_rules = 'prism.alert.rules'

_parsed_rules = 'prism.rules.json'
_ir_json = 'prism.ir.json'
_rules_json = 'rules.json'


def _get_cmd_name() -> str:  # pragma: nocover
    p = Path(argv[0])

    cmd = p.name

    if cmd == '__main__.py':
        dir_name = p.parent.name
        if dir_name:
            return dir_name

    return cmd


def _print_rule(r: prism.Rule) -> None:  # pragma: nocover
    _log.info('%d:%d : %s', r.meta.sid, r.meta.rev, r.meta.msg)
    for opt in r.opts:
        _log.info(' - %s', opt)
    _log.info('')


def classify_rules(
    profile: prism.Profile,
    proto: str,
    rules: Iterable[prism.Rule],
    unsupported_opts: Counter[str],
    failed: dict[int, str],
    converted: set[int],
    debug: bool = False,
) -> None:
    orig_len = len(failed)
    for r in rules:
        sid = r.meta.sid

        unsupp = r.unsupported_opts
        if unsupp:
            unsupported_opts.update({k: 1 for k in unsupp})
            reason = f'Unsupported: {", ".join(sorted(unsupp))}'
            failed[sid] = reason
            continue

        try:
            ir = prism.Program.from_rule(r, debug_err=debug)
            ir.hooks(profile)
            ir.supported
        except prism.RuleError as e:
            failed[sid] = e.explanation
            continue

        converted.add(sid)

    if failed:
        _log.warning('Failed to convert %d %s rules',
                     len(failed) - orig_len,
                     proto)


def _cmd_parse(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    p = output_dir / _parsed_rules
    _log.info('Writing %d rules to: %s', len(ruleset), p)
    with p.open('wb') as f:
        for r in ruleset:
            f.write(dumps(r.json_dict))
            f.write(b'\n')


def _cmd_stats(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    _log.info('Breakdown by Category')
    _log.info('-' * 21)
    for nr, category in ruleset.category_summary():
        _log.info('%5d %s', nr, category)
    _log.info('')

    _log.info('Breakdown by Protocol')
    _log.info('-' * 21)
    for nr, proto in ruleset.protocol_summary():
        _log.info('%5d %s', nr, proto)
    _log.info('')


def _find_ssldecrypt(ruleset: prism.RuleSet) -> frozenset[int]:
    def is_ssldecrypt(r: prism.Rule) -> bool:
        deployment = r.meta.metadata.get('deployment', ())
        return 'SSLDecrypt' in deployment

    return frozenset({
        r.meta.sid for r in ruleset if is_ssldecrypt(r)
    })


def _cmd_strip_ssldecrypt(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    ssl_rules = _find_ssldecrypt(ruleset)

    if ssl_rules:
        p = output_dir / _ssldecrypt_rules
        _log.info('Writing %d rules to: %s', len(ssl_rules), p)
        ruleset.save_subset(ssl_rules, p)
        ruleset.remove_rules(ssl_rules)

    p = output_dir / _clear_rules
    _log.info('Writing %d rules to: %s', len(ruleset), p)
    ruleset.save(p)


def _find_noalert(ruleset: prism.RuleSet) -> frozenset[int]:
    def is_noalert(r: prism.Rule) -> bool:
        for fb in r.flowbits:
            if fb.op is prism.FlowBitOpType.NOALERT:
                return True
        return False

    return frozenset({
        r.meta.sid for r in ruleset if is_noalert(r)
    })


def _cmd_strip_noalert(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    ssl_rules = _find_noalert(ruleset)

    if ssl_rules:
        p = output_dir / _noalert_rules
        _log.info('Writing %d rules to: %s', len(ssl_rules), p)
        ruleset.save_subset(ssl_rules, p)
        ruleset.remove_rules(ssl_rules)

    p = output_dir / _alert_rules
    _log.info('Writing %d rules to: %s', len(ruleset), p)
    ruleset.save(p)


def _find_slow(ruleset: prism.RuleSet) -> frozenset[int]:
    return frozenset({
        r.meta.sid for r in ruleset if r.inspects_payload
    })


def _cmd_strip(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    slow_rules = _find_slow(ruleset)

    if slow_rules:
        p = output_dir / _strip_payload_rules
        _log.info('Writing %d rules to: %s', len(slow_rules), p)
        ruleset.save_subset(slow_rules, p)
        ruleset.remove_rules(slow_rules)

    p = output_dir / _strip_applayer_rules
    _log.info('Writing %d rules to: %s', len(ruleset), p)
    ruleset.save(p)


def _cmd_refract(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    unknown: Counter[str] = Counter()
    failed: dict[int, str] = dict()
    conv: defaultdict[str, set[int]] = defaultdict(set)

    for proto, rules in ruleset.get_protos(protocols).items():
        classify_rules(
            profile,
            proto,
            rules,
            unknown,
            failed,
            conv[proto],
            debug,
        )

    if failed:
        p = output_dir / _refract_failed_rules
        _log.info('Writing %d rules to: %s', len(failed), p)
        ruleset.save_subset(failed.keys(), p)

        p = output_dir / _refract_annotated_rules
        _log.info('Writing %d annotated rules to: %s', len(failed), p)
        ruleset.save_annotated_subset(failed, p)

    for proto, sigs in conv.items():
        p = output_dir / f'prism.refracted.{proto}.rules'
        _log.info('Writing %d rules to: %s', len(sigs), p)
        ruleset.save_subset(sigs, p)
        ruleset.remove_rules(sigs)

    p = output_dir / _refract_suricata_rules
    _log.info('Writing %d rules to: %s', len(ruleset), p)
    ruleset.save(p)

    if unknown:
        _log.warning('Unsupported rule options:')

        for todo, cnt in unknown.most_common():
            _log.warning(' - %d %s', cnt, todo)

    if failed:
        fail_reasons: Counter[str] = Counter()
        for r in failed.values():
            fail_reasons[r] += 1

        _log.warning('Reasons for rule conversion failure:')

        for todo, cnt in fail_reasons.most_common():
            _log.warning(' - %d %s', cnt, todo)


def do_backend(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    do_json: bool = False,
    do_map: bool = False,
    do_backend: bool = False,
) -> None:  # pragma: nocover
    sigs = {
        proto: tuple(prism.Program.from_rule(r) for r in rules)
        for proto, rules in ruleset.get_protos(protocols).items()
    }
    all_rules = tuple(chain(*sigs.values()))

    if do_json:
        p = output_dir / _ir_json
        _log.info('Outputting IR dump to %s', p)
        with p.open('wb') as f:
            for r in all_rules:
                f.write(dumps(r.json_dict))
                f.write(b'\n')
        del p

    if do_map:
        rule_dict = {str(rule.meta.sid): rule.meta.json_dict
                     for rule in ruleset}
        rule_dict.update(blacklist_rules)

        p = output_dir / _rules_json

        _log.info('Outputting rule map to %s', p)
        p.write_bytes(dumps(rule_dict))

        del p
        del rule_dict

    if do_backend:
        unit = prism.gen_rtl(profile, all_rules)

        _log.info('Outputting rules to %s', output_dir)
        prism.CBackend('cloud', unit, output_dir, cert_bl)


def _cmd_translate(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    do_backend(
        profile,
        ruleset,
        output_dir,
        cert_bl,
        protocols,
        do_json=debug,
        do_map=True,
        do_backend=True,
    )


def _cmd_gen_ir(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    do_backend(
        profile,
        ruleset,
        output_dir,
        cert_bl,
        protocols,
        do_json=debug,
        do_map=False,
        do_backend=False,
    )


# Just a convenience for searching for any rules matching some criteria
def _cmd_check(
    profile: prism.Profile,
    ruleset: prism.RuleSet,
    output_dir: Path,
    cert_bl: Optional[Path],
    protocols: Iterable[str],
    debug: bool = False,
) -> None:  # pragma: nocover
    def check(rule: prism.Rule) -> bool:
        for opt in rule.parsed:
            if isinstance(opt, prism.detect.Content):
                fp = opt.modifiers.fast_pattern
                if fp is not None:
                    if fp.chop:
                        return True
        return False

    for rule in ruleset:
        if check(rule):
            print(rule.meta.sid, rule.meta.msg)


_prog_desc = f"""
{__version__.__title__} v{__version__.__version__}

{__version__.__description__}

Given a suricata ruleset, it can separate out those rules which may be
performed in the cloud on extracted application-layer decodes from those which
must be performed on the raw data from captured packets.

{__version__.__url__}
"""


def main() -> None:  # pragma: nocover
    opts = ArgumentParser(prog='prism',
                          formatter_class=RawTextHelpFormatter,
                          description=_prog_desc)

    g = opts.add_mutually_exclusive_group(required=True)
    g.add_argument('--parse',
                   action='store_const',
                   dest='func',
                   const=_cmd_parse,
                   help='Translate rules syntax to JSON')
    g.add_argument('--stats',
                   action='store_const',
                   dest='func',
                   const=_cmd_stats,
                   help='Print stats about ruleset')
    g.add_argument('--strip-ssldecrypt',
                   action='store_const',
                   dest='func',
                   const=_cmd_strip_ssldecrypt,
                   help='Strip out rules which require decrypted SSL')
    g.add_argument('--strip-noalert',
                   action='store_const',
                   dest='func',
                   const=_cmd_strip_noalert,
                   help="Strip out rules which don't alert")
    g.add_argument('--strip',
                   action='store_const',
                   dest='func',
                   const=_cmd_strip,
                   help='Strip slow (payload-inspecting) rules')
    g.add_argument('--refract',
                   action='store_const',
                   dest='func',
                   const=_cmd_refract,
                   help='Split out rules for translation')
    g.add_argument('--gen-ir',
                   action='store_const',
                   dest='func',
                   const=_cmd_gen_ir,
                   help='Translate rule IR to JSON')
    g.add_argument('--translate',
                   action='store_const',
                   dest='func',
                   const=_cmd_translate,
                   help='Translate rules to C')
    g.add_argument('--check',
                   action='store_const',
                   dest='func',
                   const=_cmd_check,
                   help='Check rules')

    opts.add_argument('--debug', '-d',
                      action='store_true',
                      default=False,
                      help='Dump intermediate state in json files')
    opts.add_argument('--cert',
                      type=Path,
                      metavar='CERTS',
                      help='cert fingerprint blacklist')
    opts.add_argument('--protocol', '-p',
                      metavar='PROTO',
                      default=[],
                      action='append',
                      help='app-layer protocols to refract/translate')
    opts.add_argument('--profile', '--target', '-t',
                      type=str,
                      default='all',
                      help='Runtime profile')

    opts.add_argument('-o',
                      type=Path,
                      dest='output_dir',
                      metavar='DIR',
                      default=Path(),
                      help='Output base dir')
    opts.add_argument('rules',
                      type=Path,
                      metavar='PATH',
                      nargs='+',
                      help='Suricata rules')

    args = opts.parse_args()

    cmd = _get_cmd_name()

    cert_bl = args.cert

    try:
        ruleset = prism.RuleSet.from_paths(args.rules)
    except prism.PrismError as e:
        _log.error('%s: %s', cmd, e)
        raise SystemExit(1)

    _log.info('Loaded %d rules from: %s',
              len(ruleset),
              ' '.join((str(p) for p in args.rules)))

    profile = prism.Hook.profiles.get(args.profile)
    if profile is None:
        _log.error('%s: Unknown profile: %r', cmd, args.profile)
        raise SystemExit(1)

    _log.info('Profile: %s - %s', profile.name, profile.desc)

    try:
        args.func(
            profile,
            ruleset,
            args.output_dir,
            cert_bl,
            args.protocol,
            debug=args.debug,
        )
    except (OSError, prism.PrismError) as e:
        _log.error('%s: %s', cmd, e)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
