"""Negative controls for the deliberately narrow M06 binary recognisers."""

import unittest

from review_m06_binary import inverse_copy_contract, zero_store_loops


def wipe_fixture(seed=14, base=0x202):
    lines = [f"100: mov $0x{seed:x},%eax", "101: nopl (%rax)"]
    for index in range(8):
        lines.append(f"{0x110 + index:x}: movw $0x0,0x{base + index * 2:x}(%rsp,%rax,1)")
    lines.extend(["120: add $0x10,%rax", f"121: cmp $0x{seed + 512:x},%rax",
                  "122: jne 110 <wipe>", "130: ret"])
    return "\n".join(lines)


def inverse_fixture(platform):
    if platform == "windows":
        prefix = ["push %rsi", "sub $0x40,%rsp", "movdqa %xmm7,0x30(%rsp)",
                  "mov %rdx,%rsi", "mov %rcx,%rdx", "mov $0x200,%r8d",
                  "mov %rsi,%rcx", "call 200 <memcpy>", "lea 0x20(%rip),%rdx",
                  "mov %rsi,%rcx"]
    else:
        prefix = ["push %rbx", "mov %rsi,%rbx", "mov %rdi,%rsi", "mov $0x200,%edx",
                  "mov %rbx,%rdi", "call *0x100(%rip) # 200 <memcpy@GLIBC_2.14>",
                  "lea 0x20(%rip),%rsi", "mov %rbx,%rdi"]
    prefix.append("call 300 <kem1536::engine_poly::transform>")
    return "\n".join(f"{0x100 + index:x}: {row}" for index, row in enumerate(prefix))


class BinaryReviewTests(unittest.TestCase):
    def test_full_coverage_of_shifted_seed_and_intervals(self):
        for seed in (14, 526):
            loop, = zero_store_loops(wipe_fixture(seed))
            self.assertEqual(loop["stack_interval_inclusive"], [0x202 + seed, 0x202 + seed + 511])
            self.assertEqual(loop["bytes_per_loop_execution"], 512)

    def test_rejects_partial_wipe_and_unmodelled_counter_or_flow(self):
        good = wipe_fixture()
        bad = [good.replace("movw $0x0,0x208", "movw $0x1,0x208"),
               good.replace("0x20e,%rax", "0x1fe,%rax"),
               good.replace("add $0x10,%rax", "add $0x20,%rax"),
               good.replace("jne 110", "jne 111"),
               good.replace("112: movw", "112: xor %eax,%eax\n1133: movw"),
               good.replace("112: movw", "112: call 999 <unknown>\n1133: movw"),
               good.replace("0x210(%rsp", "0x20e(%rsp")]
        for source in bad:
            with self.subTest(source=source), self.assertRaises(ValueError):
                zero_store_loops(source)

    def test_no_claim_for_cleanup_after_first_ret(self):
        self.assertEqual(zero_store_loops("1: ret\n" + wipe_fixture()), [])

    def test_copy_targets_the_owned_destination_in_both_abis(self):
        for platform in ("windows", "linux"):
            result = inverse_copy_contract(inverse_fixture(platform), platform)
            self.assertEqual(result["bytes"], 512)
            self.assertEqual(result["destination"], "borrowed Polynomial owner")
            self.assertIs(result["temporary_polynomial_return"], False)

    def test_copy_direction_size_and_call_state_are_checked(self):
        for platform in ("windows", "linux"):
            source = inverse_fixture(platform)
            bad = [source.replace("$0x200", "$0x100"), source.replace("memcpy", "memmove"),
                   source.replace("100: push", "0: jmp 999 <skip>\n100: push"),
                   source.replace("<kem1536::engine_poly::transform>", "<unknown>")]
            if platform == "windows":
                bad += [source.replace("mov %rsi,%rcx", "mov %rdx,%rcx", 1),
                        source.replace("mov %rsi,%rcx", "mov %rax,%rcx")]
                first, _, last = source.rpartition("mov %rsi,%rcx")
                bad.append(first + "mov %rcx,%rcx" + last)
            else:
                bad += [source.replace("mov %rbx,%rdi", "mov %rsi,%rdi", 1),
                        source.replace("mov %rbx,%rdi", "mov %rax,%rdi")]
                first, _, last = source.rpartition("mov %rbx,%rdi")
                bad.append(first + "mov %rdi,%rdi" + last)
            for broken in bad:
                with self.subTest(platform=platform, source=broken), self.assertRaises(ValueError):
                    inverse_copy_contract(broken, platform)


if __name__ == "__main__":
    unittest.main()
