import unittest

from prism.detect.isdataat import IsDataAt
from prism.ir import BufRemaining
from prism.ruleopt import RuleOpt
from prism.rulevar import RuleValue
from prism.sigmatch_table import sigmatch_table
from prism.sticky_buffer import StickyBuffer

_isdataat_opt_flags = sigmatch_table['isdataat']


class Test_IsDataAt(unittest.TestCase):
    def test_isdataat(self) -> None:
        ida = IsDataAt.from_rule_opt(
            RuleOpt(
                flags=_isdataat_opt_flags,
                name='isdataat',
                negated=False,
                value='1,relative',
                modifiers=()
            ),
            StickyBuffer.PKT_DATA,
        )

        self.assertEqual(ida, IsDataAt(
            StickyBuffer.PKT_DATA,
            negated=False,
            val=RuleValue.from_literal(1),
            relative=True,
        ))

    def test_ir_not1(self) -> None:
        """
        isdataat:!1; -> len <= 0
        """

        self.assertEqual(
            BufRemaining.isdataat(True, 1),
            BufRemaining(None, 0),
        )

    def test_ir_1(self) -> None:
        """
        isdataat:1; -> len > 0
        """

        self.assertEqual(
            BufRemaining.isdataat(False, 1),
            BufRemaining(1, None),
        )

    def test_ir_not2(self) -> None:
        """
        isdataat:!2; -> len <= 2
        """

        self.assertEqual(
            BufRemaining.isdataat(True, 2),
            BufRemaining(None, 1),
        )

    def test_ir_2(self) -> None:
        """
        isdataat:2; -> len > 2
        """

        self.assertEqual(
            BufRemaining.isdataat(False, 2),
            BufRemaining(2, None),
        )
