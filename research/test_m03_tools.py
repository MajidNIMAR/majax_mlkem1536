import unittest
from inspect_m03_binary import parse_disassembly,inventory
from summarize_m03_bench import summarize

class M03ToolsTests(unittest.TestCase):
    def test_inventory_keeps_indirect_calls_and_division_visible(self):
        text='10 <kem1536::dev_kem::decapsulate>:\n  10: call 30 <helper>\n  15: jne 10 <kem1536::dev_kem::decapsulate>\n30 <helper>:\n  30: divq %rcx\n  33: call *%rax\n'
        result=inventory(parse_disassembly(text))
        self.assertEqual(result['directly_reachable']['functions'],2)
        self.assertEqual(result['directly_reachable']['divisions'],1)
        self.assertEqual(result['directly_reachable']['indirect_transfers'],1)
        self.assertFalse(result['indirect_target_set_proven_complete'])
    def test_summary_uses_every_sample_and_rejects_missing_or_duplicate(self):
        rows=[dict(engine=e,operation=o,series=s,iteration=i,nanoseconds=i+1)
            for e in ('R1','ML-KEM-1024') for o in ('keygen','encaps','decaps') for s in range(5) for i in range(1000)]
        summary=summarize(rows)
        self.assertEqual(summary['panels'][0]['aggregate']['median_ns'],500.5)
        self.assertEqual(summary['panels'][0]['aggregate']['p95_ns'],950)
        with self.assertRaises(ValueError):summarize(rows[:-1])
        with self.assertRaises(ValueError):summarize(rows+[rows[0]])

if __name__=='__main__':unittest.main()
