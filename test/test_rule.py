import unittest

from prism import ParseError, Rule
from prism.detect.content import Content, ContentModifiers, FastPattern
from prism.detect.pcre import Pcre
from prism.optflags import OptFlags, TriState
from prism.rulemeta import RuleMeta, Target
from prism.ruleopt import RuleOpt, RuleOptToken, RuleXfrmToken
from prism.sticky_buffer import StickyBuffer


class BadRuleTest(unittest.TestCase):
    maxDiff = 4096

    _rule_head = 'alert tls any any -> any any'
    _rule_opts = (
        'sid:1;',
        'rev:1;',
        'msg:"rule";',
    )

    @classmethod
    def rule_string(cls) -> str:
        return f'{cls._rule_head} ({" ".join(cls._rule_opts)})'

    @classmethod
    def rule(cls) -> Rule:
        return Rule.parse(cls.rule_string())


class RuleTest(BadRuleTest):
    def setUp(self):
        self.r = self.rule()


class Test_SNI_Rule(RuleTest):
    _rule_opts = (
        'sid:1;',
        'rev:1;',
        'msg:"rule";',
        'flow:established,to_server;',
        'tls.sni;',
        'dotprefix;',
        'content: ".EVIL";',
        'endswith;',
        'fast_pattern;',
    )

    def test_buffers(self):
        self.assertTupleEqual(self.r.buffers, (
            StickyBuffer.TLS_SNI,
        ))

    def test_opts(self):
        self.assertTupleEqual(self.r.opts, (
            RuleOpt(
                flags=OptFlags(
                    quotes=TriState.MANDATORY,
                    values=TriState.MANDATORY,
                    negation=True,
                    known=True,
                ),
                name='content',
                negated=False,
                value='.EVIL',
                modifiers=(
                    RuleOptToken(
                        name='endswith',
                        negated=False,
                        value=None,
                    ),
                    RuleOptToken(
                        name='fast_pattern',
                        negated=False,
                        value=None,
                    ),
                ),
                transforms=(
                    RuleXfrmToken(name='dotprefix'),
                ),
            ),
        ))

    def test_parsed(self):
        self.assertTupleEqual(self.r.parsed, (
            Content(
                buf=StickyBuffer.TLS_SNI,
                negated=False,
                content=b'.EVIL',
                modifiers=ContentModifiers(
                    nocase=False,
                    depth=None,
                    offset=None,
                    distance=None,
                    within=None,
                    startswith=False,
                    endswith=True,
                    fast_pattern=FastPattern(
                        only=False,
                        offset=-1,
                        length=-1,
                    ),
                ),
                xfrms=(
                    RuleXfrmToken(name='dotprefix'),
                ),
            ),
        ))

    def test_target(self):
        self.assertEqual(
            self.r.meta,
            RuleMeta(
                sid=1,
                rev=1,
                msg='rule',
                classtype=None,
                metadata={},
                references=(),
                target=Target.NONE,
            )
        )


class Test_TgtSrcRule(RuleTest):
    _rule_opts = (
        'sid:1;',
        'rev:1;',
        'msg:"rule";',
        'flow:established,to_server;',
        'tls.sni;',
        'dotprefix;',
        'content: ".EVIL";',
        'endswith;',
        'fast_pattern;',
        'target:src_ip;',
        'target:src_ip;',
    )

    def test_target_src(self):
        self.assertEqual(
            self.r.meta,
            RuleMeta(
                sid=1,
                rev=1,
                msg='rule',
                classtype=None,
                metadata={},
                references=(),
                target=Target.SRC_IP,
            )
        )


class Test_TgtBadRule(BadRuleTest):
    _rule_opts = (
        'sid:1;',
        'rev:1;',
        'msg:"rule";',
        'flow:established,to_server;',
        'tls.sni;',
        'dotprefix;',
        'content: ".EVIL";',
        'endswith;',
        'fast_pattern;',
        'target:dst_ip;',
    )

    def test_target_bad(self):
        with self.assertRaises(ParseError):
            self.rule()


class Test_TgtConflictRule(BadRuleTest):
    _rule_opts = (
        'sid:1;',
        'rev:1;',
        'msg:"rule";',
        'flow:established,to_server;',
        'tls.sni;',
        'dotprefix;',
        'content: ".EVIL";',
        'endswith;',
        'fast_pattern;',
        'target:desz_ip;',
        'target:src_ip;',
    )

    def tgt_conflict_rule(self) -> Rule:
        with self.assertRaises(ParseError):
            self.rule()


class Test_BadFlowRule(unittest.TestCase):
    _rule_opts = (
        'sid:1;',
        'rev:1;',
        'msg:"rule";',
        'flow:established,to_srver;',
        'tls.sni;',
        'dotprefix;',
        'content: ".EVIL";',
        'endswith;',
        'fast_pattern;',
    )

    def tgt_conflict_rule(self) -> Rule:
        with self.assertRaises(ParseError):
            self.rule()


class Test_Pcre(RuleTest):
    _regex = (
        r'\x0d\x0a(?:cache\-control|connection|pragma)'
        r'\x0d\x0a(?:cache\-control|connection|pragma)'
        r'\x0d\x0a(?:cache\-control|connection|pragma)'
        r'\x0d\x0a'
    )
    _msg = "ET MALWARE Ponmocup HTTP Request (generic) M1"
    _sid = 2022197
    _rev = 8
    _rule_opts = (
        f'sid:{_sid};',
        f'rev:{_rev};',
        f'msg:"{_msg}";',
        'flow:established,to_server;',
        # 'http.header;',
        # 'header_lowercase;',
        # 'content:"pragma|3a 20|no-cache|0d 0a|";',
        # 'content:"cache-control|3a 20|no-cache|0d 0a|";',
        'http.host;',
        # 'pcre:"/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/";',
        'content:"1";',
        'fast_pattern;',
        'startswith;',
        # 'http.cookie;',
        # 'content:"=";',
        # 'pcre:"/^[a-z0-9_-]{300,}/Ri";',
        # 'http.accept;',
        # 'content:"*/*";',
        # 'startswith;',
        # 'endswith;',
        # 'http.connection;',
        # 'content:"Close";',
        # 'startswith;',
        # 'endswith;',
        'http.header_names;',
        'to_lowercase;',
        f'pcre:"/{_regex}/";',
        # 'content:!"|0d 0a|accept-";',
        # 'content:!"|0d 0a|referer|0d 0a|";',
        # 'threshold:type limit, track by_src, count 1, seconds 600;',
        'classtype:trojan-activity;',
    )

    def test_parsed(self):
        self.assertTupleEqual(self.r.parsed, (
            Content(
                buf=StickyBuffer.HTTP_HOST,
                negated=False,
                content=b'1',
                modifiers=ContentModifiers(
                    nocase=False,
                    depth=None,
                    offset=None,
                    distance=None,
                    within=None,
                    startswith=True,
                    endswith=False,
                    fast_pattern=FastPattern(
                        only=False,
                        offset=-1,
                        length=-1,
                    ),
                ),
            ),
            Pcre(
                buf=StickyBuffer.HTTP_HEADER_NAMES,
                negated=False,
                relative=False,
                regex=self._regex,
                pcre_flags=frozenset(),
                snort_flags=frozenset(),
                xfrms=(
                    RuleXfrmToken(name='to_lowercase'),
                ),
            )
        ))
