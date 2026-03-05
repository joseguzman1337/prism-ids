from typing import Generator

import unittest

from prism import Rule, gen_rtl
from prism.hook import Hook, Profile
from prism.program import Program


class RtlGenTest(unittest.TestCase):
    maxDiff = 4096

    @staticmethod
    def programs(profile: Profile) -> Generator[Program, None, None]:
        raise NotImplementedError
        yield

    def setUp(self):
        self.profile = Hook.profiles['all']
        self.rtl = gen_rtl(
            self.profile,
            tuple(self.programs(self.profile)),
        )


class Test_RtlGen(RtlGenTest):
    maxDiff = 2048

    @staticmethod
    def programs(profile: Profile) -> Generator[Program, None, None]:
        yield Program.from_rule(
            Rule.parse(' '.join((
                'alert tls any any -> any any',
                '(',
                ''.join((
                    'sid:123;',
                    'rev:22;',
                    'msg:"rule";',
                    'flow:established,to_server;',
                    'tls.sni;',
                    # 'dotprefix;',
                    'content: ".EVIL";',
                    'endswith;',
                    'fast_pattern;',
                )),
                ')',
            )))
        )

    def test_state_bits(self):
        self.assertEqual(self.rtl.nr_state_bits, 0)

    def test_hooks(self):
        hook = self.profile['tls_client']
        self.assertIn(hook, self.rtl.hooks)
        # bm = self.rtl.entries[hook]
        # for buf, insn in bm.items():
        #     print(buf, insn.name)

    def test_insns(self):
        # print(self.rtl.insns)
        # print(self.rtl.hyperscan_dbs)
        pass
