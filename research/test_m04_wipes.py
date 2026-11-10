import unittest
from review_m04_wipes import wipe_coverage


def fixture():
    lines = []
    for base, address in [(0x12, 0x100), (0x212, 0x200)]:
        lines.append(f"{address:x}: mov $0xe,%eax")
        for index in range(8):
            lines.append(f"{address + 1 + index:x}: movw $0x0,0x{base + 2 * index:x}(%rsp,%rax,1)")
        lines.extend([f"{address+9:x}: add $0x10,%rax", f"{address+10:x}: cmp $0x20e,%rax",
                      f"{address+11:x}: jne {address+1:x} <loop>"])
    return "\n".join(lines) + "\n300:\tret"


class WipeReviewTests(unittest.TestCase):
    def test_exact_coverage_and_missing_store(self):
        source = fixture()
        self.assertEqual([r["bytes"] for r in wipe_coverage(source)], [512, 512])
        for broken in [source.replace("movw $0x0,0x12", "movw $0x1,0x12", 1),
                       source.replace("$0x20e,%rax", "$0x1fe,%rax", 1),
                       source.replace("100: mov $0xe,%eax", "100: mov $0xe,%eax\n1000: jmp 109 <skip>"),
                       source.replace("100: mov $0xe,%eax", "100: mov $0xe,%eax\n1000: xor %eax,%eax")]:
            with self.assertRaises(ValueError):
                wipe_coverage(broken)


if __name__ == "__main__":
    unittest.main()
