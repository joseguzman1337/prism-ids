import unittest

from prism import Rule, RuleSet
from prism.__main__ import (
    _find_noalert,
    _find_slow,
    _find_ssldecrypt,
)

ssl_rule = Rule.parse(' '.join((
    'alert tcp any any -> any any',
    '(',
    ''.join((
        'sid: 1;',
        'rev: 1;',
        'msg: "1";',
        'metadata: affected_product Internet, deployment SSLDecrypt;',
    )),
    ')',
)))

tls_rule = Rule.parse(' '.join((
    'alert http any any -> any any',
    '(',
    ''.join((
        'sid: 2;',
        'rev: 1;',
        'msg: "2";',
        'metadata: affected_product Internet, deployment TLSDecrypt;',
    )),
    ')',
)))

datacenter_rule = Rule.parse(' '.join((
    'alert tls any any -> any any',
    '(',
    ''.join((
        'sid: 3;',
        'rev: 1;',
        'msg: "3";',
        'metadata: affected_product Internet, deployment Datacenter;',
    )),
    ')',
)))

perimeter_rule = Rule.parse(' '.join((
    'alert ssl any any -> any any',
    '(',
    ''.join((
        'sid: 3;',
        'rev: 1;',
        'msg: "3";',
        'metadata: affected_product Internet, deployment Perimeter;',
    )),
    ')',
)))

slow_rule = Rule.parse(' '.join((
    'alert tls any any -> any any',
    '(',
    ''.join((
        'sid: 4;',
        'rev: 1;',
        'msg: "4";',
        'content: "EVIL";',
        'metadata: affected_product Internet, deployment Perimeter;',
    )),
    ')',
)))

noalert_rule_1 = Rule.parse(' '.join((
    'alert tcp any any -> any any',
    '(',
    ''.join((
        'sid: 5;',
        'rev: 1;',
        'msg: "1";',
        'noalert;',
    )),
    ')',
)))

noalert_rule_2 = Rule.parse(' '.join((
    'alert tcp any any -> any any',
    '(',
    ''.join((
        'sid: 6;',
        'rev: 1;',
        'msg: "1";',
        'flowbits: noalert;',
    )),
    ')',
)))

all_rules = (
    ssl_rule,
    tls_rule,
    datacenter_rule,
    perimeter_rule,
    slow_rule,
    noalert_rule_1,
    noalert_rule_2,
)


class Test_Main(unittest.TestCase):
    def setUp(self):
        self.rset = RuleSet({r.meta.sid: r for r in all_rules})

    def test_strip_ssl(self):
        out = _find_ssldecrypt(self.rset)
        self.assertSetEqual(out, {1})

    def test_slow(self):
        out = _find_slow(self.rset)
        self.assertSetEqual(out, {4})

    def test_noalert(self):
        out = _find_noalert(self.rset)
        self.assertSetEqual(out, {5, 6})
