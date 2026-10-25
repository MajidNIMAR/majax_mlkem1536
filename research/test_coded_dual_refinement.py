"""Search controls: simultaneous moves, explicit boundaries and stop behavior."""

import unittest

from refine_coded_dual import descend, in_domain, neighbors


class RefinementTests(unittest.TestCase):
    def make_evaluator(self, function):
        rows = {}

        def evaluate(point):
            if point not in rows:
                rows[point] = dict(index=len(rows), inputs=dict(zip(("samples", "nenu", "nfft", "kfft"), point)),
                                   status="conditional_model_cost", log2_rop=function(point))
            return rows[point]
        return evaluate

    def test_pair_neighborhood_has_32_distinct_points(self):
        points = neighbors((10, 10, 10, 10), (1, 1, 1, 1), True)
        self.assertEqual(len(points), 32)
        self.assertEqual(len(set(points)), 32)
        self.assertTrue(all(1 <= sum(a != b for a, b in zip(p, (10,) * 4)) <= 2 for p in points))

    def test_two_coordinate_move_escapes_axis_trap(self):
        costs = {(0, 0, 0, 0): 2, (1, 1, 0, 0): 0}
        evaluate = self.make_evaluator(lambda p: costs.get(p, 3))
        valid = lambda p: all(v in (0, 1) for v in p)
        start = evaluate((0, 0, 0, 0))
        axis, _ = descend(start, evaluate, valid, (1, 1, 1, 1))
        pair, trace = descend(start, evaluate, valid, (1, 1, 1, 1), True)
        self.assertEqual(axis["log2_rop"], 2)
        self.assertEqual(pair["log2_rop"], 0)
        self.assertEqual(trace["status"], "stable_in_declared_neighborhood")

    def test_quadratic_descent_and_safety_cap(self):
        evaluate = self.make_evaluator(lambda p: sum((v - 2) ** 2 for v in p))
        start = evaluate((0, 0, 0, 0))
        valid = lambda p: all(0 <= v <= 4 for v in p)
        with self.assertRaises(RuntimeError):
            descend(start, evaluate, valid, (1, 1, 1, 1), True, max_sweeps=1)
        best, trace = descend(start, evaluate, valid, (1, 1, 1, 1), True)
        self.assertEqual(best["log2_rop"], 0)
        self.assertGreater(len(trace["trajectory"]), 1)

    def test_search_domain(self):
        self.assertTrue(in_domain(1536, (1267, 52, 136, 20)))
        for p in ((1792, 52, 136, 20), (1000, 97, 136, 20), (1000, 50, 257, 20), (1000, 50, 136, 136)):
            self.assertFalse(in_domain(1536, p))


if __name__ == "__main__":
    unittest.main()
