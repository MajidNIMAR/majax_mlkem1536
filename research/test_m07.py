"""Fault-oriented tests for M07 quantitative evidence, not synthetic KEM results."""
from copy import deepcopy
import unittest

from run_m07 import MEMORY_OPERATIONS, OPERATIONS, summarize, validate_memory


class M07ObservationTests(unittest.TestCase):
    def panel(self):
        return [dict(version=version, operation=operation, series=series,
                     iteration=iteration, nanoseconds=100 + series * 10 + iteration)
                for version in ("baseline", "candidate") for operation in OPERATIONS
                for series in range(2) for iteration in range(2)]

    def summary(self, rows):
        return summarize(rows, ("baseline", "candidate"), 2, 2)

    def test_complete_panel_recomputes_statistics_without_discarding_extremes(self):
        rows = self.panel()
        rows[0]["nanoseconds"] = 1000000
        result = self.summary(rows)["baseline/keygen"]
        self.assertEqual(result["count"], 4)
        self.assertEqual(result["maximum_ns"], 1000000)
        self.assertEqual(result["observations_excluded"], 0)
        self.assertEqual(result["median_ns"], 110.5)
        self.assertEqual(result["p95_ns"], 1000000)

    def test_missing_duplicate_or_unknown_observations_are_rejected(self):
        good = self.panel()
        for rows in (good[:-1], good + [good[0]], []):
            with self.subTest(size=len(rows)), self.assertRaises(ValueError):
                self.summary(rows)


    def test_unknown_operation_and_invalid_indices_are_rejected(self):
        for field, value in (("version", "unmeasured"), ("operation", "other"),
                             ("series", 2), ("iteration", -1)):
            rows = self.panel()
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.summary(rows)

    def test_nonfinite_boolean_negative_and_wrong_type_times_are_rejected(self):
        for value in (0, -1, True, 1.5, float("inf"), float("nan"), "100"):
            rows = self.panel()
            rows[0]["nanoseconds"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.summary(rows)


class M07MemoryEvidenceTests(unittest.TestCase):
    def panel(self):
        rows = []
        for operation in MEMORY_OPERATIONS:
            for pattern in (0xa5, 0x5a):
                calibration = int(operation.split("_")[1]) + 72 if operation.startswith("calibration_") else 0
                rows.append(dict(schema=1, profile="KEM1536-DEV-Q7681-R1", operation=operation,
                    sample=0, paint_pattern=pattern, native_stack_size_requested=1024 * 1024,
                    paint_top_margin_bytes=512, paint_search_bytes=256 * 1024 - 512,
                    touched_stack_high_water_bytes=max(1024, calibration),
                    known_written_calibration_depth_bytes=calibration, saturated=False,
                    calibration_written_array_bytes=calibration - 72 if calibration else 0,
                    alloc_calls=0, alloc_zeroed_calls=0, realloc_calls=0, dealloc_calls=0,
                    allocation_failures=0, foreign_deallocations=0, tracker_overflows=0,
                    total_requested_bytes=0, retained_requested_bytes_at_api_return=0,
                    peak_live_requested_bytes=0, functional_validation=True, secrets_printed=False))
        return rows

    def test_exact_memory_grid_and_summary(self):
        result = validate_memory(self.panel(), 1)
        self.assertEqual(len(result), len(MEMORY_OPERATIONS))
        self.assertEqual(result["keygen"]["count"], 2)

    def test_missing_duplicate_or_unexpected_fields_rejected(self):
        rows = self.panel()
        for invalid in (rows[:-1], rows + [rows[0]]):
            with self.assertRaises(ValueError):
                validate_memory(invalid, 1)
        rows[0]["unexpected_bytes"] = "must never appear"
        with self.assertRaises(ValueError):
            validate_memory(rows, 1)

    def test_bad_calibration_window_or_accounting_rejected(self):
        for field, value in (("saturated", True), ("functional_validation", False),
                             ("tracker_overflows", 1), ("foreign_deallocations", 1),
                             ("allocation_failures", 1), ("retained_requested_bytes_at_api_return", 1),
                             ("alloc_calls", True), ("paint_search_bytes", 0),
                             ("secrets_printed", True)):
            rows = self.panel()
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_memory(rows, 1)
        rows = self.panel()
        calibration = next(row for row in rows if row["operation"] == "calibration_8192")
        calibration["known_written_calibration_depth_bytes"] = 8191
        with self.assertRaises(ValueError):
            validate_memory(rows, 1)


if __name__ == "__main__":
    unittest.main()
