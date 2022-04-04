import unittest

from prism import Rule
from prism.errors import SemanticError
from prism.flow import Flow, FlowDirection, FlowState
from prism.ir import BufSize, OptionalDotPrefix, Pattern, PatternChain, Regex
from prism.program import FastPattern, Program
from prism.rule import Action, Direction, RuleHead
from prism.rulemeta import RuleMeta
from prism.sticky_buffer import StickyBuffer


class IrgenTest(unittest.TestCase):
    _rule_head = 'alert tls any any -> any any'
    _rule_opts = (
        'sid:1;',
        'rev:1;',
    )

    maxDiff = 8192

    @classmethod
    def rule_string(cls) -> str:
        return f'{cls._rule_head} ({" ".join(cls._rule_opts)})'

    @classmethod
    def rule(cls) -> Rule:
        return Rule.parse(cls.rule_string())

    @classmethod
    def program(cls) -> Program:
        return Program.from_rule(cls.rule())

    def setUp(self):
        self.p = self.program()


class Test_Irgen(IrgenTest):
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

    def test_meta(self):
        self.assertEqual(self.p.meta, RuleMeta(
            sid=1,
            rev=1,
            msg='rule',
            classtype=None,
            metadata={},
            references=(),
        ))

    def test_head(self):
        self.assertEqual(self.p._head, RuleHead(
            action=Action.ALERT,
            proto='tls',
            src='any',
            sport='any',
            direction=Direction.UNI,
            dst='any',
            dport='any',
        ))

    def test_flow(self):
        self.assertEqual(self.p._flow, Flow(
            direction=FlowDirection.CLIENT,
            state=FlowState.ESTABLISHED,
        ))

    def test_prefilter(self):
        self.assertEqual(
            self.p._prefilter,
            FastPattern(
                buf=StickyBuffer.TLS_SNI,
                pat=OptionalDotPrefix(
                    content=b'.EVIL',
                    nocase=False,
                    start=False,
                    end=True,
                ),
            ),
        )

    def test_bufs(self):
        self.assertDictEqual(self.p._bufs, {})

    def test_extra(self):
        self.assertTupleEqual(self.p._extra, ())


class Test_NoBufs(IrgenTest):
    _msg = 'ET HUNTING Zero Content-Length HTTP POST with data (outbound)'
    _sid = 2011819
    _rev = 6
    _rule_opts = (
        f'sid:{_sid};',
        f'rev:{_rev};',
        f'msg:"{_msg}";',
        'flow:established,to_server;',
        'http.method;',
        'content:"POST";',
        'http.content_len;',
        'content:"0";',
        'bsize:1;',
        'endswith;',
        'http.request_body;',
        'bsize:>0;',
    )

    def setUp(self):
        pass

    def test_fails(self):
        with self.assertRaises(SemanticError):
            self.program()


class Test_TorRule(IrgenTest):
    _rule_head = 'alert tcp [102.130.117.167,102.130.127.117] any -> any any'
    _msg = 'ET TOR Known Tor Exit Node Traffic group 1'
    _sid = 2520000
    _rev = 5595
    _rule_opts = (
        f'sid:{_sid};',
        f'rev:{_rev};',
        f'msg:"{_msg}";',
        'threshold: type limit, track by_src, seconds 60, count 1;'
        'classtype:misc-attack;'
        'flowbits:set,ET.TorIP;'
    )

    def setUp(self):
        pass

    def test_fails(self):
        with self.assertRaises(SemanticError):
            self.program()


class Test_BrokenRelIsDataAt(IrgenTest):
    _msg = ' '.join((
        'ET WEB_SERVER',
        'Possible HP OpenView Network Node Manager',
        'ovalarm.exe CGI Buffer Overflow Attempt',
    ))
    _sid = 2010704
    _rev = 10
    _rule_opts = (
        f'sid:{_sid};',
        f'rev:{_rev};',
        f'msg:"{_msg}";',
        'flow:established,to_server;',
        'http.method;',
        'content:"GET";',
        'nocase;',
        'http.uri;',
        'content:"/OvCgi/ovalarm.exe";',
        'nocase;',
        'fast_pattern;',
        'content:"OVABverbose=";',
        'nocase;',
        'distance:0;',
        'pcre:"/^(1|on|true)/Ri";',
        'http.accept_lang;',
        # XXX: this used to break because it's relative to the previous PCRE,
        # but we've switched stickybuffer... Turns out suricata's behaviour is
        # to match relative to the start of the new buffer (ie. doe_ptr gets
        # initialized to start of the buffer whenever we switch buffers)
        'isdataat:100,relative;',
        'reference:cve,2009-4179;',
        'classtype:web-application-attack;',
    )

    def test_fails(self):
        with self.assertRaisesRegex(SemanticError,
                                    'PatternChain not supported in backend'):
            self.p.supported

    def test_bufs(self):
        # We now, very cleverly, recognize that isdataat:100,relative is
        # relative to the start of the buffer. Convert it to isdataat:100, and
        # then recognize that that is a buffer size test, so convert it to
        # bsize
        self.assertDictEqual(self.p._bufs, {
            StickyBuffer.HTTP_METHOD: (
                Pattern(
                    content=b'GET',
                    nocase=True,
                    start=False,
                    end=False,
                ),
            ),
            StickyBuffer.HTTP_URI: (
                PatternChain(
                    anchor=Pattern(
                        content=b'/OvCgi/ovalarm.exe',
                        nocase=True,
                        start=False,
                        end=False,
                    ),
                    chain=(
                        Pattern(
                            content=b'OVABverbose=',
                            nocase=True,
                            start=False,
                            end=False,
                        ),
                        Regex(
                            regex=r'^(1|on|true)',
                            modifiers=frozenset('i'),
                        ),
                    ),
                ),
            ),
            StickyBuffer.HTTP_ACCEPT_LANG: (
                BufSize(
                    size_lo=100,
                    size_hi=None,
                ),
            )
        })


class Test_RelChain(IrgenTest):
    _msg = 'ET MALWARE CozyDuke APT Possible SSL Cert 2'
    _sid = 2020967
    _rev = 4

    _rule_opts = (
        f'sid:{_sid};',
        f'rev:{_rev};',
        f'msg:"{_msg}";',
        'flow:established,to_client;',
        'tls.cert_subject;',
        'content:"C=--";',
        'startswith;',
        'content:"ST=SomeState";',
        'distance:0;',
        'tls.cert_serial;',
        'content:"65:5d";',
        'depth:5;',
        'fast_pattern;',
        'reference:url,securelist.com/blog/69731/the-cozyduke-apt/;',
        'reference:md5,859f167704b5c138ed9a9d4d3fdc0723;',
        'classtype:targeted-activity;',
    )

    def test_prefilter(self):
        self.assertEqual(
            self.p._prefilter,
            FastPattern(
                buf=StickyBuffer.TLS_CERT_SERIAL,
                pat=Pattern(
                    content=b'\x65\x5d',
                    nocase=False,
                    start=True,
                    end=False,
                ),
            ),
        )

    def test_bufs(self):
        self.assertDictEqual(self.p._bufs, {
            StickyBuffer.TLS_CERT_SUBJECT: (
                PatternChain(
                    anchor=Pattern(
                        content=b'C=--',
                        nocase=False,
                        start=True,
                        end=False,
                    ),
                    chain=(
                        Pattern(
                            content=b'ST=SomeState',
                            nocase=False,
                            start=False,
                            end=False,
                        ),
                    ),
                ),
            ),
        })


class Test_StringSet(IrgenTest):
    _msg = 'ET MALWARE Fake Virtually SSL Cert APT1'
    _sid = 2016462
    _rev = 4
    _rule_opts = (
        f'sid:{_sid};',
        f'rev:{_rev};',
        f'msg:"{_msg}";',
        'flow:established,to_client;',
        'tls.cert_issuer;',
        'content:"O=www.virtuallythere.com";',
        'content:"OU=new";',
        'content:"CN=new";',
        'tls.cert_subject;',
        'content:"O=www.virtuallythere.com";',
        'fast_pattern;',
        'content:"OU=new";',
        'content:"CN=new";',
        'reference:url,www.mandiant.com/apt1;',
        'classtype:targeted-activity;',
    )

    def test_meta(self):
        self.assertEqual(self.p.meta, RuleMeta(
            sid=2016462,
            rev=4,
            msg='ET MALWARE Fake Virtually SSL Cert APT1',
            classtype='targeted-activity',
            metadata={},
            references=(
                'url,www.mandiant.com/apt1',
            ),
        ))

    def test_head(self):
        self.assertEqual(self.p._head, RuleHead(
            action=Action.ALERT,
            proto='tls',
            src='any',
            sport='any',
            direction=Direction.UNI,
            dst='any',
            dport='any',
        ))

    def test_flow(self):
        self.assertEqual(self.p._flow, Flow(
            direction=FlowDirection.SERVER,
            state=FlowState.ESTABLISHED,
        ))

    def test_prefilter(self):
        self.assertEqual(
            self.p._prefilter,
            FastPattern(
                buf=StickyBuffer.TLS_CERT_SUBJECT,
                pat=Pattern(
                    content=b'O=www.virtuallythere.com',
                    nocase=False,
                ),
            ),
        )

    def test_bufs(self):
        self.assertDictEqual(self.p._bufs, {
            StickyBuffer.TLS_CERT_ISSUER: (
                Pattern(
                    content=b'O=www.virtuallythere.com',
                    nocase=False,
                ),
                Pattern(
                    content=b'OU=new',
                    nocase=False,
                ),
                Pattern(
                    content=b'CN=new',
                    nocase=False,
                ),
            ),
            StickyBuffer.TLS_CERT_SUBJECT: (
                Pattern(
                    content=b'OU=new',
                    nocase=False,
                ),
                Pattern(
                    content=b'CN=new',
                    nocase=False,
                ),
            ),
        })

    def test_extra(self):
        self.assertTupleEqual(self.p._extra, ())


class Test_Pcre(IrgenTest):
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

    def _test_bufs(self):
        self.assertDictEqual(self.p._bufs, {
            StickyBuffer.HTTP_HOST: Pattern(
                pattern=r'^1',
                nocase=False,
            ),
            StickyBuffer.HTTP_HEADER_NAMES: Regex(
                regex=self._regex,
                modifiers=frozenset(),
            ),
        })
