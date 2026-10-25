"""Regression checks for libm portability without relaxing exact event counts."""
from copy import deepcopy
import math
import unittest
from portable_calibration import calibration_tails_match


class PortableCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.saved = [{"hits_above_margin": 10, "ambiguous": 0,
                       "fraction": 10 / 4096,
                       "normal_zero_mean_baseline_tail": 0.022750131948179216}]

    def test_observed_linux_erfc_rounding_is_accepted(self):
        replay = deepcopy(self.saved)
        replay[0]["normal_zero_mean_baseline_tail"] = 0.02275013194817922
        self.assertTrue(calibration_tails_match(replay, self.saved))

    def test_one_changed_event_or_ambiguity_is_rejected(self):
        for field in ("hits_above_margin", "ambiguous"):
            replay = deepcopy(self.saved)
            replay[0][field] += 1
            self.assertFalse(calibration_tails_match(replay, self.saved))

    def test_material_probability_change_is_rejected(self):
        replay = deepcopy(self.saved)
        replay[0]["normal_zero_mean_baseline_tail"] *= 1.000001
        self.assertFalse(calibration_tails_match(replay, self.saved))

    def test_nonfinite_values_and_structure_changes_are_rejected(self):
        for value in (math.nan, math.inf, -math.inf):
            replay = deepcopy(self.saved)
            replay[0]["fraction"] = value
            self.assertFalse(calibration_tails_match(replay, self.saved))
        replay = deepcopy(self.saved)
        del replay[0]["ambiguous"]
        self.assertFalse(calibration_tails_match(replay, self.saved))


if __name__ == "__main__":
    unittest.main()

