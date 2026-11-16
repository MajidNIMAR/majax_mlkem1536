"""Reject lost observations and falsely accepted hardening regressions."""
from copy import deepcopy
import unittest
from m10_measure import OPS,ALLOC,MEMORY_OPERATIONS,summarize_latency,memory_budgets


class M10MeasurementTests(unittest.TestCase):
    def rows(self):
        return [{'operation':op,'series':2,'iteration':i,'nanoseconds':1000+i} for op in OPS for i in range(500)]

    def test_full_grid_and_series_are_required(self):
        rows = self.rows()
        self.assertEqual(set(summarize_latency(rows,2)),set(OPS))
        for bad in (rows[:-1],rows[:-1]+[rows[0]],rows[:-1]+[{**rows[-1],'series':3}],
                rows[:-1]+[{**rows[-1],'nanoseconds':True}]):
            with self.assertRaises(ValueError):
                summarize_latency(bad,2)

    def test_stack_boundary_and_every_allocation_budget(self):
        base = {op:{'touched_stack_bytes':{'maximum':8192},'requested_allocation_ranges':{k:[0,1] for k in ALLOC}}
            for op in MEMORY_OPERATIONS[4:]}
        candidate = deepcopy(base)
        candidate['decaps_valid']['touched_stack_bytes']['maximum'] += 1024
        self.assertTrue(all(r['passed'] for r in memory_budgets(base,candidate).values()))
        candidate['decaps_valid']['touched_stack_bytes']['maximum'] += 1
        self.assertFalse(memory_budgets(base,candidate)['decaps_valid']['passed'])
        for field in ALLOC:
            candidate = deepcopy(base)
            candidate['encaps']['requested_allocation_ranges'][field][1] += 1
            self.assertFalse(memory_budgets(base,candidate)['encaps']['passed'])


if __name__=='__main__':
    unittest.main()
