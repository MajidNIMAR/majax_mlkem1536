"""Guard the statistical diagnostic against incomplete/duplicated panels."""
import unittest
from analyze_delivery_timing import CLASSES, analyze, welch


def panel():
    return [{"key": key, "class": label, "round": round_, "nanoseconds": 1000 + round_ % 13}
            for key in range(8) for label in CLASSES for round_ in range(400)]


class DeliveryTimingTests(unittest.TestCase):
    def test_complete_panel_and_duplicate_or_missing(self):
        rows = panel()
        self.assertEqual(analyze(rows)["maximum_absolute_t"], 0)
        for broken in [rows[:-1], rows + [rows[0]]]:
            with self.assertRaises(ValueError):
                analyze(broken)

    def test_injected_class_delay_is_visible_without_filtering(self):
        rows = panel()
        for row in rows:
            if row["class"] == "zero":
                row["nanoseconds"] += 100
        self.assertEqual(analyze(rows)["threshold_crossings"], 8)
        self.assertGreater(welch([20, 21, 22], [10, 11, 12])["t"], 4.5)


if __name__ == "__main__":
    unittest.main()
