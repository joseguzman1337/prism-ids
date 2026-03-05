#!/usr/bin/env python3

from typing import Generator, NamedTuple, Any
from collections import defaultdict
from datetime import datetime
from dateutil.parser import isoparse
from argparse import ArgumentParser
from pathlib import Path
from orjson import loads


def load_alerts(p: Path) -> Generator[dict[str, Any], None, None]:
    for line in p.open():
        if not line:
            break
        obj = loads(line)
        try:
            yield obj['alert']
        except KeyError:
            continue


def _file_lines(p: Path) -> Generator[str, None, None]:
    with p.open() as f:
        for line in f:
            if not line:
                break
            line = line.rstrip()
            if not line or line.startswith('#'):
                continue
            yield line


class Ja3Info(NamedTuple):
    first_seen: datetime
    last_seen: datetime
    reason: str


def ja3_blacklist(p: Path) -> dict[bytes, tuple[Ja3Info, ...]]:
    bl = defaultdict(set)
    for line in _file_lines(p):
        h, first, last, reason = line.split(',', maxsplit=3)
        b = bytes.fromhex(h)
        if len(b) != 16:
            raise ValueError(f'{p}: bad ja3 blacklist')
        bl[b].add(Ja3Info(isoparse(first), isoparse(last), reason))

    return {k: tuple(v) for k, v in bl.items()}


class CertInfo(NamedTuple):
    list_date: datetime
    reason: str


def cert_blacklist(p: Path) -> dict[bytes, tuple[CertInfo, ...]]:
    bl = defaultdict(set)
    for line in _file_lines(p):
        list_date, h, reason = line.split(',', maxsplit=2)
        b = bytes.fromhex(h)
        if len(b) != 20:
            raise ValueError(f'{p}: bad cert blacklist')
        bl[b].add(CertInfo(isoparse(list_date), reason))

    return {k: tuple(v) for k, v in bl.items()}


def main() -> None:
    opts = ArgumentParser(prog='check-blacklist-matches')
    opts.add_argument('--ja3',
                      type=Path,
                      metavar='JA3',
                      default='ja3_fingerprints.csv',
                      help='ja3 hash blacklist')
    opts.add_argument('--cert', '--certs',
                      type=Path,
                      metavar='CERTS',
                      default='sslblacklist.csv',
                      help='cert fingerprint blacklist')
    opts.add_argument('alerts',
                      type=Path,
                      metavar='PATH',
                      nargs='+',
                      help='Prism alerts')
    args = opts.parse_args()

    ja3_bl = ja3_blacklist(args.ja3)
    cert_bl = cert_blacklist(args.cert)

    cl_ja3_hashes = set()
    sv_ja3_hashes = set()
    fpr_hashes = set()

    nr_cl_ja3_hits = 0
    nr_sv_ja3_hits = 0
    nr_fpr_hits = 0

    for p in args.alerts:
        for alert in load_alerts(p):
            sid_set = frozenset(alert['sids'])
            if 79000001 in sid_set:  # ja3
                val = alert['client']['ja3']['hash']
                cl_ja3_hashes.add(bytes.fromhex(val))
                nr_cl_ja3_hits += 1
            if 79000002 in sid_set:  # ja3s
                val = alert['server']['ja3']['hash']
                sv_ja3_hashes.add(bytes.fromhex(val))
                nr_sv_ja3_hits += 1
            if 79000003 in sid_set:  # cert
                val = alert['server']['cert']['fingerprint']
                fpr_hashes.add(bytes.fromhex(val))
                nr_fpr_hits += 1

    fail = False
    bad_ja3 = set()
    bad_cert = set()

    print(f'{nr_cl_ja3_hits} client JA3 hits to {len(cl_ja3_hashes)} hashes')
    for h in sorted(cl_ja3_hashes):
        r = ja3_bl.get(h, None)
        if r is None:
            fail = True
            bad_ja3.add(h)
            continue
        print(f' {h.hex()} -> {", ".join((item.reason for item in r))}')
    print()

    print(f'{nr_sv_ja3_hits} server JA3 hits to {len(sv_ja3_hashes)} hashes')
    for h in sorted(sv_ja3_hashes):
        r = ja3_bl.get(h, None)
        if r is None:
            bad_ja3.add(h)
            fail = True
            continue
        print(f' {h.hex()} -> {", ".join((item.reason for item in r))}')
    print()

    print(f'{nr_fpr_hits} cert hits to {len(fpr_hashes)} hashes')
    for h in sorted(fpr_hashes):
        r = cert_bl.get(h, None)
        if r is None:
            bad_cert.add(h)
            fail = True
            continue
        print(f' {h.hex()} -> {", ".join((item.reason for item in r))}')
    print()

    if fail:
        for h in sorted(bad_ja3):
            print(f'bad ja3: {h.hex()}')
        for h in sorted(bad_cert):
            print(f'bad cert: {h.hex()}')
        raise ValueError('Impossible blacklist matches in results')


if __name__ == '__main__':
    main()
