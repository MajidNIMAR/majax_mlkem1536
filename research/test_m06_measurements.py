"""M06 gates reject incomplete/duplicated timings and preserve quantile units."""
import unittest

from run_m06_measurements import dispersion, summarize


class MeasurementTests(unittest.TestCase):
    def sample_rows(self):
        return [dict(version=v, operation=op, series=0, iteration=i, nanoseconds=n)
                for v in ("baseline", "candidate") for op in ("keygen", "encaps", "decaps")
                for i, n in enumerate((1, 2, 3, 40))]

    def test_quantile_and_median_keep_raw_nanoseconds(self):
        result = summarize(self.sample_rows(), samples=4, series=1)
        self.assertEqual(result["candidate/keygen"]["median_ns"], 2.5)
        self.assertEqual(result["candidate/keygen"]["p95_ns"], 40)
        self.assertEqual(result["candidate/keygen"]["count"], 4)

    def test_missing_observation_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            summarize(self.sample_rows()[:-1], samples=4, series=1)

    def test_duplicate_does_not_fill_missing_observation(self):
        rows = self.sample_rows()
        rows[-1] = rows[0]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            summarize(rows, samples=4, series=1)

    def test_zero_or_negative_duration_is_not_silently_discarded(self):
        for invalid in (0, -1):
            rows = self.sample_rows()
            rows[-1]["nanoseconds"] = invalid
            with self.subTest(duration=invalid), self.assertRaisesRegex(ValueError, "invalid"):
                summarize(rows, samples=4, series=1)

    def test_descriptive_tail_count_does_not_replace_raw_statistics(self):
        rows = self.sample_rows()
        result = dispersion(rows)["candidate/keygen"]
        self.assertEqual(result["series_median_ns"], {"0": 2.5})
        self.assertEqual(result["posthoc_Tukey_above_q3_plus_1_5_IQR"], 1)
        self.assertEqual(result["posthoc_Tukey_below_q1_minus_1_5_IQR"], 0)
        self.assertEqual(result["maximum_ns"], 40)
        self.assertEqual(summarize(rows, samples=4, series=1)["candidate/keygen"]["count"], 4)


if __name__ == "__main__":
    unittest.main()
