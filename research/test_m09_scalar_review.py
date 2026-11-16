"""Negative controls for the scalar review's actual acceptance boundaries."""

import unittest

from m09_scalar_review import literal, message_fact, scalar_fact, split_operands


def instruction(address, opcode, operands):
    return {"address": format(address, "x"), "opcode": opcode, "operands": operands}


class ScalarReviewBoundaryTests(unittest.TestCase):
    def test_indexed_address_commas_do_not_hide_destination(self):
        self.assertEqual(split_operands("%xmm8,0xd0(%rsp,%rax,2)"),
                         ["%xmm8", "0xd0(%rsp,%rax,2)"])

    def test_previous_copy_mechanism_is_rejected_before_other_layout_checks(self):
        function = {"address": "10", "name": "transform", "instructions": [
            instruction(0x10, "movdqa", "%xmm8,0xd0(%rsp)")]}
        with self.assertRaisesRegex(ValueError, "SIMD"):
            scalar_fact(function, "windows")

    def test_a_scalar_division_is_also_rejected(self):
        function = {"address": "10", "name": "transform", "instructions": [
            instruction(0x10, "div", "%r8d")]}
        with self.assertRaisesRegex(ValueError, "division"):
            scalar_fact(function, "linux")

    def test_distinct_identical_literals_cannot_be_attributed_to_one_site(self):
        function = {"address": "10", "name": "f", "instructions": [
            instruction(0x10, "or", "%r8b,(%rsp)"), instruction(0x20, "or", "%r8b,(%rsp)")]}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            literal(function, "or", "%r8b,(%rsp)")

    def message_function(self, return_before_wipe=False):
        # A toy owner isolates the normal-return erasure gate. This is not
        # emitted-code or path coverage for the cryptographic engine.
        rows = [instruction(0x10, "or", "%r8b,0x20(%rsp,%rsi,1)")]
        if return_before_wipe:
            rows.append(instruction(0x11, "ret", ""))
        rows.extend(instruction(0x20 + byte, "movb", "$0x0," + hex(0x20 + byte) + "(%rsp)")
                    for byte in range(32))
        if not return_before_wipe:
            rows.append(instruction(0x60, "ret", ""))
        return {"address": "10", "name": "decapsulate", "instructions": rows}

    def test_wipes_after_the_return_are_not_credited(self):
        with self.assertRaisesRegex(ValueError, "normal-return"):
            message_fact(self.message_function(True), "linux")

    def test_missing_owner_byte_is_not_credited(self):
        function = self.message_function()
        function["instructions"].pop(8)
        with self.assertRaisesRegex(ValueError, "absent"):
            message_fact(function, "linux")

    def test_normal_return_control_preserves_thirty_two_distinct_witnesses(self):
        result = message_fact(self.message_function(), "linux")
        self.assertEqual(len(result["normal_return_32_literal_byte_wipes"]), 32)
        self.assertIn("Other temporaries", result["scope"])


if __name__ == "__main__":
    unittest.main()
