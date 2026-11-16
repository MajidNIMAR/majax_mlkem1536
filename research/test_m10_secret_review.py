"""Negative controls for byte-accurate, bounded instruction review helpers."""
import unittest

from m10_secret_review import check_collection_scope, direct_overlap_writers, wipe_range


def instruction(opcode, operands, address="100"):
    return {"address": address, "opcode": opcode, "operands": operands}


class M10SecretReviewTests(unittest.TestCase):
    def test_one_collection_cannot_fill_two_distinct_review_slots(self):
        for role in ("baseline", "candidate"):
            for kind, binary in (("cli", "delivered"), ("consumer", "consumer")):
                collection = {"role": role, "binary_kind": binary}
                check_collection_scope(collection, kind, role)
                with self.assertRaisesRegex(ValueError, "declared CLI/consumer"):
                    check_collection_scope(collection, "consumer" if kind == "cli" else "cli", role)
                with self.assertRaisesRegex(ValueError, "declared CLI/consumer"):
                    check_collection_scope(collection, kind, "candidate" if role == "baseline" else "baseline")

    def test_one_byte_wipe_before_an_owner_does_not_erase_that_owner(self):
        # A conservative 16-byte assumption previously confused the cursor
        # wipe immediately below h with a write into h. Keep byte widths exact.
        rows = [instruction("movb", "$0x0,0xf8(%rsp)")]
        self.assertEqual(direct_overlap_writers(rows, 0x100, 201), [])
        self.assertEqual(direct_overlap_writers(rows, 0xf8, 1), rows)

    def test_wide_or_partial_overlap_is_not_silently_ignored(self):
        rows = [instruction("movups", "%xmm0,0xf8(%rsp)"),
                instruction("mov", "%rax,0x1c4(%rsp)", "110")]
        self.assertEqual(direct_overlap_writers(rows, 0x100, 201), rows)
        with self.assertRaises(ValueError):
            direct_overlap_writers([instruction("mov", "$0x0,0x100(%rsp)")], 0x100, 201)

    def test_state_wipe_requires_the_cursor_byte_too(self):
        rows = [instruction("movq", "$0x0," + hex(0x100 + offset) + "(%rsp)", hex(0x1000 + offset))
                for offset in range(0, 200, 8)]
        self.assertEqual(wipe_range(rows, 0x100, 200)["bytes_covered"], 200)
        with self.assertRaisesRegex(ValueError, "range incomplete"):
            wipe_range(rows, 0x100, 201)
        rows.append(instruction("movb", "$0x0,0x1c8(%rsp)", "2000"))
        self.assertEqual(len(wipe_range(rows, 0x100, 201)["stores"]), 26)

    def test_reader_wipe_cannot_stand_for_a_disjoint_original_state(self):
        rows = [instruction("movq", "$0x0," + hex(0x30 + offset) + "(%rsp)")
                for offset in range(0, 200, 8)]
        rows.append(instruction("movb", "$0x0,0xf8(%rsp)"))
        with self.assertRaisesRegex(ValueError, "range incomplete"):
            wipe_range(rows, 0x1c0, 201)
        with self.assertRaisesRegex(ValueError, "range incomplete"):
            wipe_range([instruction("movb", "$0x0,0x280(%rsp)")], 0x280, 32)


if __name__ == "__main__":
    unittest.main()
