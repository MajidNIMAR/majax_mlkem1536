"""Regression checks for address closure and evidence replay, not CT proofs."""

import unittest

from m09_lifecycle_inventory import parse, summarize


class PhysicalClosureTests(unittest.TestCase):
    def test_same_demangled_name_keeps_both_physical_functions(self):
        listing = """00000010 <kem1536::dev_kem::keygen>:
  10: call 30 <same>
  15: ret
00000020 <same>:
  20: ret
00000030 <same>:
  30: mov $0x0,0x8(%rsp)
  38: ret
"""
        result = summarize(listing)
        self.assertEqual(result["duplicate_demangled_names"], {"same": 2})
        self.assertEqual(result["direct_or_relative_slot_reachable"], ["10", "30"])
        self.assertEqual(result["literal_zero_store_witnesses_in_scope"][0]["address"], "30")

    def test_elf_relative_slot_is_bound_to_physical_addend(self):
        listing = """00000010 <kem1536::dev_kem::pke_decrypt_into>:
  10: call *0x112(%rip) # 128 <slot>
  16: ret
00000030 <wipe>:
  30: mov $0x0,(%rax)
  38: ret
"""
        result = summarize(listing, "0000000000000128 000000000008 R_X86_64_RELATIVE 30\n")
        self.assertEqual(result["direct_or_relative_slot_reachable"], ["10", "30"])
        self.assertEqual(result["transfers_in_scope"][0]["resolution"], "ELF-relative-slot")
        self.assertEqual(result["unresolved_or_external_in_scope"], [])

    def test_indirect_unknown_stays_visible(self):
        listing = """00000010 <kem1536::dev_kem::decapsulate>:
  10: call *%rax
  12: jne 10 <kem1536::dev_kem::decapsulate>
  15: div %ecx
  18: ret
"""
        result = summarize(listing)
        self.assertEqual(len(result["unresolved_or_external_in_scope"]), 1)
        self.assertEqual(len(result["conditional_branch_sites_in_scope"]), 1)
        self.assertEqual(len(result["division_sites_in_scope"]), 1)
        self.assertFalse(result["all_PKE_paths_proved_erased"])
        self.assertFalse(result["constant_time_proved"])

    def test_empty_or_nonengine_scope_cannot_be_attributed(self):
        with self.assertRaises(ValueError):
            summarize("00000010 <unrelated>:\n  10: ret\n")
        with self.assertRaises(ValueError):
            parse("")


if __name__ == "__main__":
    unittest.main()
