import json
import math
import unittest

from cost_serialization import json_safe, log2_record, log2_from_numeric_text


class CostExportTests(unittest.TestCase):
    def test_unbounded_and_large_costs_remain_distinguishable_in_json(self):
        data = {"unbounded": log2_record(float("inf"), math.log),
                "zero_probability": log2_record(0, math.log),
                "finite_large": log2_record(2**20000, math.log),
                "undefined": log2_record(float("nan"), math.log)}
        encoded = json.loads(json.dumps(data, allow_nan=False))
        self.assertEqual(encoded["unbounded"], "+infinity")
        self.assertEqual(encoded["zero_probability"], "-infinity")
        self.assertEqual(encoded["undefined"], "undefined")
        self.assertAlmostEqual(encoded["finite_large"], 20000)
        self.assertEqual(json.loads(json.dumps(json_safe({"rop": float("inf"), "zero": 0.0}),
                                               allow_nan=False)), {"rop": "+infinity", "zero": 0.0})
        self.assertAlmostEqual(log2_from_numeric_text("1e5000"), 5000*math.log2(10))


if __name__ == "__main__":
    unittest.main()
