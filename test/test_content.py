import unittest

from prism.detect.content import Content, ContentModifiers
from prism.ruleopt import RuleOpt, RuleOptToken
from prism.sigmatch_table import sigmatch_table
from prism.sticky_buffer import StickyBuffer

_content_opt_flags = sigmatch_table['content']


class Test_Content(unittest.TestCase):
    def test_startswith1(self) -> None:
        c = Content.from_rule_opt(
            RuleOpt(
                flags=_content_opt_flags,
                name='content',
                negated=False,
                value='abc',
                modifiers=(
                    RuleOptToken('depth', False, '3'),
                )
            ),
            StickyBuffer.PKT_DATA,
        )
        self.assertEqual(
            c.modifiers,
            ContentModifiers(
                nocase=False,
                depth=None,
                offset=None,
                distance=None,
                within=None,
                startswith=True,
                endswith=False,
                fast_pattern=None,
            )
        )

    def test_startswith2(self) -> None:
        c = Content.from_rule_opt(
            RuleOpt(
                flags=_content_opt_flags,
                name='content',
                negated=False,
                value='abc',
                modifiers=(
                    RuleOptToken('depth', False, '3'),
                    RuleOptToken('offset', False, '0'),
                )
            ),
            StickyBuffer.PKT_DATA,
        )
        self.assertEqual(
            c.modifiers,
            ContentModifiers(
                nocase=False,
                depth=None,
                offset=None,
                distance=None,
                within=None,
                startswith=True,
                endswith=False,
                fast_pattern=None,
            )
        )

    def test_exact1(self) -> None:
        c = Content.from_rule_opt(
            RuleOpt(
                flags=_content_opt_flags,
                name='content',
                negated=False,
                value='abc',
                modifiers=(
                    RuleOptToken('depth', False, '3'),
                    RuleOptToken('endswith', False, None),
                )
            ),
            StickyBuffer.PKT_DATA,
        )
        self.assertEqual(
            c.modifiers,
            ContentModifiers(
                nocase=False,
                depth=None,
                offset=None,
                distance=None,
                within=None,
                startswith=True,
                endswith=True,
                fast_pattern=None,
            )
        )
