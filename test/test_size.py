import unittest

from prism.detect.size import BufferSize
from prism.errors import ParseError
from prism.ruleopt import RuleOpt
from prism.sigmatch_table import sigmatch_table
from prism.sticky_buffer import StickyBuffer

_bsize_opt_flags = sigmatch_table['bsize']


class Test_Content(unittest.TestCase):
    def test_eq1(self) -> None:
        bsz = BufferSize.from_rule_opt(
            RuleOpt(
                flags=_bsize_opt_flags,
                name='bsize',
                negated=False,
                value='1',
                modifiers=()
            ),
            StickyBuffer.PKT_DATA,
        )

        self.assertEqual(bsz, BufferSize(
            StickyBuffer.PKT_DATA,
            1,
            1,
        ))

        self.assertFalse(bsz.lt)
        self.assertFalse(bsz.gt)
        self.assertFalse(bsz.never_matches)
        self.assertTrue(bsz.consistent_with(None))
        self.assertFalse(bsz.consistent_with(0))
        self.assertTrue(bsz.consistent_with(1))
        self.assertFalse(bsz.consistent_with(2))

    def test_gt1(self) -> None:
        bsz = BufferSize.from_rule_opt(
            RuleOpt(
                flags=_bsize_opt_flags,
                name='bsize',
                negated=False,
                value='>1',
                modifiers=()
            ),
            StickyBuffer.PKT_DATA,
        )

        self.assertEqual(bsz, BufferSize(
            StickyBuffer.PKT_DATA,
            2,
            None,
        ))

        self.assertFalse(bsz.lt)
        self.assertTrue(bsz.gt)
        self.assertFalse(bsz.never_matches)
        self.assertTrue(bsz.consistent_with(None))
        self.assertFalse(bsz.consistent_with(0))
        self.assertFalse(bsz.consistent_with(1))
        self.assertTrue(bsz.consistent_with(2))

    def test_lt1(self) -> None:
        bsz = BufferSize.from_rule_opt(
            RuleOpt(
                flags=_bsize_opt_flags,
                name='bsize',
                negated=False,
                value='<1',
                modifiers=()
            ),
            StickyBuffer.PKT_DATA,
        )

        self.assertEqual(bsz, BufferSize(
            StickyBuffer.PKT_DATA,
            None,
            0,
        ))

        self.assertTrue(bsz.lt)
        self.assertFalse(bsz.gt)
        self.assertFalse(bsz.never_matches)
        self.assertTrue(bsz.consistent_with(None))

    def test_range(self) -> None:
        bsz = BufferSize.from_rule_opt(
            RuleOpt(
                flags=_bsize_opt_flags,
                name='bsize',
                negated=False,
                value='6<>9',
                modifiers=()
            ),
            StickyBuffer.PKT_DATA,
        )

        self.assertEqual(bsz, BufferSize(
            StickyBuffer.PKT_DATA,
            6,
            9,
        ))

        self.assertFalse(bsz.lt)
        self.assertFalse(bsz.gt)
        self.assertFalse(bsz.never_matches)
        self.assertTrue(bsz.consistent_with(None))
        self.assertFalse(bsz.consistent_with(5))
        self.assertTrue(bsz.consistent_with(6))
        self.assertTrue(bsz.consistent_with(9))
        self.assertFalse(bsz.consistent_with(10))

    def test_bad_range(self) -> None:
        bsz = BufferSize.from_rule_opt(
            RuleOpt(
                flags=_bsize_opt_flags,
                name='bsize',
                negated=False,
                value='9<>8',
                modifiers=()
            ),
            StickyBuffer.PKT_DATA,
        )

        self.assertEqual(bsz, BufferSize(
            StickyBuffer.PKT_DATA,
            9,
            8,
        ))

        self.assertFalse(bsz.lt)
        self.assertFalse(bsz.gt)
        self.assertTrue(bsz.never_matches)
        self.assertFalse(bsz.consistent_with(None))
        self.assertFalse(bsz.consistent_with(8))
        self.assertFalse(bsz.consistent_with(9))

    def test_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            BufferSize.from_rule_opt(
                RuleOpt(
                    flags=_bsize_opt_flags,
                    name='bsize',
                    negated=False,
                    value='flibble',
                    modifiers=()
                ),
                StickyBuffer.PKT_DATA,
            )
