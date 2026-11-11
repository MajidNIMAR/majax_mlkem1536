"""Pure mutation checks for physical import review; no binary or tool runs."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import review_m08_imports as review


LISTING = """0000000000001000 <m08_import_consumer::import_public_probe>:
    1000: call 2000 <kem1536::dev_kem::validate_vector_encoding>
    1005: ret
0000000000001100 <m08_import_consumer::import_private_probe>:
    1100: call *0x10(%rip) # 5000 <import_slot>
    1106: ret
0000000000002000 <kem1536::dev_kem::validate_vector_encoding>:
    2000: mov %eax,0x24(%rsp)
    2004: mov 0x24(%rsp),%ecx
    2008: jne 2010 <kem1536::dev_kem::validate_vector_encoding+0x10>
    200a: ret
0000000000003000 <Polynomial::fill_with>:
    3000: ret
0000000000003100 <Polynomial::fill_with>:
    3100: ret
"""
# readelf -rW prints a bare hexadecimal addend after the relocation kind.
HEADERS = "0000000000005000 0000000000000008 R_X86_64_RELATIVE 0000000000002000\n"


class M08ImportReviewTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m08-import-review-test-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_keeps_same_demangled_name_at_distinct_addresses(self):
        result = review.function_inventory(LISTING, HEADERS)
        self.assertEqual(result["physical_functions"], 5)
        self.assertEqual(result["duplicate_demangled_names"], {"Polynomial::fill_with": 2})
        self.assertIn("0000000000003000:Polynomial::fill_with", result["functions"])
        self.assertIn("0000000000003100:Polynomial::fill_with", result["functions"])

    def test_resolves_exact_machine_address_and_relative_relocation(self):
        result = review.function_inventory(LISTING, HEADERS)
        self.assertEqual(len(result["reachable_by_resolved_direct_closure"]), 3)
        private = result["functions"][result["retained_import_wrappers"]["private"][0]]
        self.assertEqual(private["calls"][0]["resolution"], "ELF relative relocation")
        unresolved = review.function_inventory(LISTING, "")
        private = unresolved["functions"][unresolved["retained_import_wrappers"]["private"][0]]
        self.assertEqual(len(private["unresolved_indirect_transfers"]), 1)
        self.assertFalse(unresolved["unresolved_indirect_target_set_complete"])

    def test_retained_wrappers_are_required_and_not_aliased(self):
        with self.assertRaisesRegex(ValueError, "retained wrapper"):
            review.function_inventory(LISTING.replace("m08_import_consumer::import_private_probe", "unused_private"), HEADERS)
        duplicated = LISTING + "0000000000004000 <m08_import_consumer::import_private_probe>:\n    4000: ret\n"
        with self.assertRaisesRegex(ValueError, "retained wrapper"):
            review.function_inventory(duplicated, HEADERS)

    def test_stack_operands_are_syntax_not_erasure_or_taint_claim(self):
        result = review.function_inventory(LISTING, HEADERS)
        function = result["functions"]["0000000000002000:kem1536::dev_kem::validate_vector_encoding"]
        self.assertEqual(len(function["explicit_stack_addressing"]), 2)
        self.assertTrue(function["explicit_stack_addressing"][0]["destination_is_stack_syntax"])
        self.assertFalse(function["explicit_stack_addressing"][1]["destination_is_stack_syntax"])
        self.assertFalse(result["all_spills_or_copies_erased_proved"])
        self.assertFalse(result["constant_time_proved"])
        self.assertEqual(review.operands("0x8(%rsp,%rax,2),%edx"), ["0x8(%rsp,%rax,2)", "%edx"])

    def test_objdump_cannot_run_before_acceptance_gate(self):
        output = self.root / "artifacts/generated/not-created"
        with patch.object(review, "tool") as tool, patch.object(review, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "acceptance gate"):
                review.collect(self.root / "artifacts/generated/not-a-run", output)
            tool.assert_not_called()
            self.assertFalse(output.exists())

    def test_default_feature_command_and_instrumentation_are_bound(self):
        entry = {"command": ["cargo", "build", "--manifest-path", "research/m08-import-consumer/Cargo.toml"],
                 "rustc": "host: x86_64-unknown-linux-gnu\nrelease: 1.91.1\n", "emit_stack_metadata": False}
        review.check_consumer_command(entry, "linux")
        for flag in ("--features", "--features=research-vectors", "--all-features"):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "feature override"):
                review.check_consumer_command({**entry, "command": [*entry["command"], flag]}, "linux")
        with self.assertRaisesRegex(ValueError, "instrumentation"):
            review.check_consumer_command({**entry, "emit_stack_metadata": True}, "linux")

    def test_manual_witness_is_bound_to_literal_instruction(self):
        key = "candidate-linux"
        folder = self.root / "audit" / key
        folder.mkdir(parents=True)
        (folder / "disassembly.txt.gz").write_bytes(gzip.compress(LISTING.encode()))
        collection = {"binaries": {key: {"sha256": "a" * 64}}}
        data = {"schema": "m08-import-witnesses-v1", "constant_time_proved": False,
                "all_copies_erased_proved": False, "images": {key: {
                    "binary_sha256": "a" * 64, "bounded_conclusion": "toy fixture only",
                    "witnesses": [{"function": "0000000000002000:kem1536::dev_kem::validate_vector_encoding",
                        "address": "2000", "opcode": "mov", "operands": "%eax,0x24(%rsp)",
                        "purpose": "toy write fixture, no secret classification"}]}}}
        (self.root / "collection.json").write_text(json.dumps(collection))
        (self.root / "witnesses.json").write_text(json.dumps(data))
        self.assertEqual(review.check_witnesses(self.root), 1)
        data["images"][key]["witnesses"][0]["address"] = "2004"
        (self.root / "witnesses.json").write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            review.check_witnesses(self.root)


if __name__ == "__main__":
    unittest.main()
