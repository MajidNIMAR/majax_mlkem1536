"""Guard the M07 measurement barrier and the scope of retained LLVM names."""

from pathlib import Path
import unittest
from unittest.mock import patch

from review_m07_binary import BINARIES, address_bodies, collect, focus, seal, zero_store_loops_m07


class M07BinaryReviewGuards(unittest.TestCase):
    def test_missing_acceptance_marker_prohibits_disassembler_subprocess(self):
        with patch("review_m07_binary.Path.is_file", return_value=False), \
                patch("review_m07_binary.subprocess.run") as subprocess_run, \
                patch("review_m07_binary.Path.mkdir") as mkdir:
            with self.assertRaisesRegex(ValueError, "MEMORY_AND_LATENCY_ACCEPTED"):
                collect(Path("unaccepted-m07-run"), Path("uncreated-m07-review"))
            subprocess_run.assert_not_called()
            mkdir.assert_not_called()

    def test_scope_includes_mangled_pke_and_decoding_paths(self):
        for name in ("kem1536::dev_kem::DecapsulationKey::from_bytes",
                     "kem1536::dev_kem::validate_vector_encoding",
                     "kem1536::dev_kem::decode_polynomial_into",
                     "kem1536::engine_poly::Polynomial::fill_with",
                     "_ZN7kem15367dev_kem16pke_encrypt_into17h1234E.llvm.1234"):
            with self.subTest(name=name):
                self.assertTrue(focus(name))
        for name in ("kem1536::dev_kem::hardening::timing", "std::time::Instant::now", "memcpy"):
            with self.subTest(name=name):
                self.assertFalse(focus(name))

    def test_failed_content_review_does_not_create_a_seal(self):
        observations = "M07 " + " ".join(BINARIES.values())
        with patch("review_m07_binary.Path.read_text", return_value=observations), \
                patch("review_m07_binary.verify_contents", side_effect=ValueError("bad review")), \
                patch("review_m07_binary.save") as save, \
                patch("review_m07_binary.Path.mkdir") as mkdir:
            with self.assertRaisesRegex(ValueError, "bad review"):
                seal(Path("unsealed-m07-review"))
            save.assert_not_called()
            mkdir.assert_not_called()

    def test_distinct_addresses_keep_duplicate_demangled_names(self):
        text = ("100 <kem1536::engine_poly::Polynomial::fill_with>:\n100: ret\n\n"
                "200 <kem1536::engine_poly::Polynomial::fill_with>:\n200: ret\n")
        parsed = address_bodies(text)
        self.assertEqual(len(parsed), 2)
        self.assertEqual({row["address"] for row in parsed.values()}, {"100", "200"})
        self.assertTrue(all("fill_with" in row["body"] for row in parsed.values()))

    def test_wipe_counters_remain_bound_to_their_original_register(self):
        lines = ["100: mov $0xe,%ecx"]
        for index in range(8):
            lines.append(f"{0x110 + index:x}: movw $0x0,0x{0x32 + index * 2:x}(%rsp,%rcx,1)")
        lines += ["120: add $0x10,%rcx", "121: cmp $0x20e,%rcx", "122: jne 110 <wipe>", "130: ret"]
        source = "\n".join(lines)
        loop, = zero_store_loops_m07(source)
        self.assertEqual(loop["counter_register"], "%rcx")
        self.assertEqual(loop["stack_interval_inclusive"], [0x40, 0x23f])
        with_reload = source.replace("110: movw", "105: mov 0x10(%rsp),%r13\n110: movw")
        modified, = zero_store_loops_m07(with_reload)
        self.assertEqual(modified["stack_interval_inclusive"], [0x40, 0x23f])
        self.assertEqual(len(modified["reviewed_independent_prefix_instructions"]), 1)
        with self.assertRaises(ValueError):
            zero_store_loops_m07(source.replace("0x38(%rsp,%rcx", "0x38(%rsp,%rax"))


if __name__ == "__main__":
    unittest.main()
