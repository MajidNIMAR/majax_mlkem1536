"""Exact full-alphabet tests, torus boundaries, factorization and validation."""

import itertools
import unittest

from block_decoder import decode_line_exhaustive, decode_repetition, make_code, nearest_root


class BlockDecoderTests(unittest.TestCase):
    def test_interval_decoder_against_every_center(self):
        for q in (3, 5, 7):
            for size in (1, 2, 3):
                for values in itertools.product(range(q), repeat=size):
                    expected = decode_line_exhaustive(values, (1,) * size, q)
                    actual = decode_repetition(values, q)
                    self.assertEqual((actual["squared_norm"], actual["label"]), expected)
                    self.assertLessEqual(actual["candidate_scores"], 2 * (size + 1))

    def test_ties_and_wrap(self):
        self.assertEqual(decode_repetition((0, 1), 3)["label"], 0)
        self.assertEqual(decode_repetition((0, 4), 5)["label"], 0)
        self.assertEqual(decode_repetition((4, 4), 5)["label"], 4)

    def test_small_code_factorization(self):
        for family in ("repeated", "radix"):
            code = make_code(5, 4, 2, family)
            words = [(list(labels), code.encode(labels)) for labels in itertools.product(range(5), repeat=2)]
            for values in itertools.product(range(5), repeat=4):
                expected = min((sum(min(abs(x-y), 5-abs(x-y)) ** 2 for x, y in zip(values, word)), labels)
                               for labels, word in words)
                result = code.decode_reference(values)
                self.assertEqual((result["squared_norm"], result["labels"]), expected)

    def test_actual_shape_and_codeword_roundtrip(self):
        for family in ("repeated", "radix"):
            code = make_code(7681, 140, 21, family)
            self.assertEqual(sorted(code.record()["block_sizes"]), [6] * 7 + [7] * 14)
            labels = [(i * 373) % 7681 for i in range(21)]
            encoded = code.encode(labels)
            if family == "repeated":
                result = code.decode_repeated(encoded)
                self.assertEqual(result["labels"], labels)
                self.assertEqual(result["squared_norm"], 0)
            self.assertTrue(all(g[0] == 1 for g in code.generators))

    def test_invalid_formats_and_exact_root_choice(self):
        for args in ((9, 8, 1, "radix"), (7681, 140, 141, "radix"), (7681, 140, 21, "unknown")):
            with self.assertRaises(ValueError):
                make_code(*args)
        code = make_code(7681, 140, 21, "repeated")
        with self.assertRaises(ValueError):
            code.decode_repeated([0] * 139)
        with self.assertRaises(ValueError):
            code.decode_repeated([7681] * 140)
        self.assertEqual(nearest_root(7681, 6), 4)
        self.assertEqual(nearest_root(7681, 7), 4)


if __name__ == "__main__":
    unittest.main()
