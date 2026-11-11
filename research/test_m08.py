"""Mutation checks for M08 finite measurements; no cryptographic execution."""
from copy import deepcopy
import unittest

from run_m08 import CORE_OPERATIONS, IMPORT_OPERATIONS, MEMORY_OPERATIONS, summarize, validate_memory
from test_verify_m07 import memory_rows


def panel():
    rows = memory_rows()
    template = next(r for r in rows if r["operation"] == "import_public_noncanonical")
    for op in MEMORY_OPERATIONS:
        if any(r["operation"] == op for r in rows):
            continue
        for pattern in (0xa5, 0x5a):
            rows.append(dict(template, operation=op, paint_pattern=pattern))
    return rows


class M08MeasurementTests(unittest.TestCase):
    def test_complete_new_memory_grid_and_import_errors(self):
        result = validate_memory(panel(), 1)
        self.assertEqual(set(result), set(MEMORY_OPERATIONS))
        self.assertEqual(len(result), 18)

    def test_memory_missing_and_duplicate_rejected(self):
        rows = panel()
        for damaged in (rows[:-1], rows + [rows[-1]]):
            with self.assertRaises(ValueError):
                validate_memory(damaged, 1)

    def test_memory_invalid_counters_scope_and_calibration_rejected(self):
        for field, value in (("tracker_overflows", 1), ("allocation_failures", 1), ("nanoseconds", 1),
                             ("sample", True), ("secrets_printed", True), ("saturated", True)):
            rows = panel()
            rows[-1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_memory(rows, 1)
        rows = panel()
        row = next(r for r in rows if r["operation"] == "calibration_8192")
        row["touched_stack_high_water_bytes"] = 8191
        with self.assertRaises(ValueError):
            validate_memory(rows, 1)

    def test_all_latency_grids_keep_extremes_and_reject_mutations(self):
        for operations in (CORE_OPERATIONS, IMPORT_OPERATIONS):
            rows = [dict(version=v, operation=op, series=s, iteration=i, nanoseconds=100+i)
                    for v in ("baseline", "candidate") for op in operations for s in range(2) for i in range(2)]
            if operations == IMPORT_OPERATIONS:
                for row in rows:
                    status = 0 if row["operation"] in ("public_valid", "private_valid") else (3 if row["operation"] == "private_hash_invalid" else 2)
                    row.update(schema=1,profile="KEM1536-DEV-Q7681-R1",status=status,expected_status=status,
                               validation_and_drop_outside_timer=True,secrets_printed=False)
            rows[-1]["nanoseconds"] = 999999
            result = summarize(rows, operations, ("baseline", "candidate"), 2, 2)
            self.assertEqual(result["candidate/"+operations[-1]]["maximum_ns"], 999999)
            for changed in (rows[:-1], rows+[rows[-1]]):
                with self.assertRaises(ValueError):
                    summarize(changed, operations, ("baseline", "candidate"), 2, 2)
            for value in (0, -1, True, 1.2):
                damaged = deepcopy(rows)
                damaged[0]["nanoseconds"] = value
                with self.assertRaises(ValueError):
                    summarize(damaged, operations, ("baseline", "candidate"), 2, 2)

    def test_import_status_and_scope_are_required(self):
        rows = [dict(version="candidate",operation=op,series=0,iteration=0,nanoseconds=100,schema=1,
                     profile="KEM1536-DEV-Q7681-R1",status=(0 if op in ("public_valid","private_valid") else (3 if op=="private_hash_invalid" else 2)),
                     validation_and_drop_outside_timer=True,secrets_printed=False) for op in IMPORT_OPERATIONS]
        for row in rows: row["expected_status"]=row["status"]
        summarize(rows,IMPORT_OPERATIONS,("candidate",),1,1)
        for key,value in (("status",99),("profile","wrong"),("validation_and_drop_outside_timer",False),("secrets_printed",True)):
            changed=deepcopy(rows);changed[0][key]=value
            with self.assertRaises(ValueError):summarize(changed,IMPORT_OPERATIONS,("candidate",),1,1)


if __name__ == "__main__":
    unittest.main()
