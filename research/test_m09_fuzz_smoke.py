"""Pure tests of post-INIT accounting; never start a fuzzer."""
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from m09_fuzz_smoke import CPUS, TARGETS, ROOT, cpu_lower, observed_init_cpu_upper, parse_init, scalar_lock


class SmokeAccountingTests(unittest.TestCase):
    def test_log_counters_exclude_initial_corpus_and_keep_repeated_executions(self):
        report = parse_init(b"#57 INITED cov: 16\n#100 NEW cov: 18\nstat::number_of_executed_units: 1003\n")
        self.assertEqual(report, dict(INITED_counter=57, final_executed_units_counter=1003, executions_after_INITED=946))

    def test_missing_duplicate_or_backwards_init_is_rejected(self):
        for raw in (b"stat::number_of_executed_units: 99\n", b"#2 INITED\n",
                    b"#2 INITED\n#3 INITED\nstat::number_of_executed_units: 99\n",
                    b"#99 INITED\nstat::number_of_executed_units: 2\n"):
            with self.assertRaises(ValueError):
                parse_init(raw)

    def test_cpu_lower_subtracts_observed_initialization_and_rounding_uncertainty(self):
        usage = dict(user_seconds=30.21, system_seconds=.03, wall_seconds=31)
        self.assertAlmostEqual(cpu_lower(usage, .20), 30.02)
        self.assertEqual(cpu_lower(usage, None), 0)
        self.assertEqual(cpu_lower(usage, 40), 0)

    def test_cpu_invalid_or_nonfinite_is_rejected(self):
        for bad in (-1, True, float("nan"), float("inf"), "30"):
            with self.assertRaises(ValueError):
                cpu_lower(dict(user_seconds=bad, system_seconds=0, wall_seconds=1), 0)
            with self.assertRaises(ValueError):
                cpu_lower(dict(user_seconds=30, system_seconds=0, wall_seconds=31), bad)

    def test_no_proc_observation_has_no_unearned_cpu_credit(self):
        with patch("m09_fuzz_smoke.Path.read_text", side_effect=FileNotFoundError):
            self.assertIsNone(observed_init_cpu_upper(123))

    def test_four_distinct_declared_affinities(self):
        self.assertEqual(set(CPUS), set(TARGETS))
        self.assertEqual(tuple(CPUS.values()), (8, 12, 14, 6))

    def test_scalar_lock_matches_the_existing_python310_reader(self):
        from verify_m04_distribution import cargo_lock
        path = ROOT/"fuzz/Cargo.lock"
        self.assertEqual(scalar_lock(path.read_text()), cargo_lock(path))
        for invalid in ("", '[[package]]\nname = "x"\n',
                        '[[package]]\nname = "x"\nname = "y"\nversion = "1"\n'):
            with self.assertRaises(ValueError):
                scalar_lock(invalid)


if __name__ == "__main__":
    unittest.main()
