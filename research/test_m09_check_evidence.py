"""Reject partial or failed full-suite transcripts even with plausible counts."""
import unittest
from m09_check_evidence import log_result


class M09CheckTranscriptTests(unittest.TestCase):
    def test_accepts_explicit_complete_suite(self):
        self.assertEqual(log_result(b'Ran 400 tests in 2.0s\n\nOK\n'),{'python_tests':400})

    def test_rejects_failure_partial_or_duplicate_suite(self):
        for raw in (b'Ran 400 tests in 2.0s\nFAILED\n', b'Ran 350 tests in 2.0s\nOK\n',
                    b'Ran 400 tests in 2.0s\nOK\nRan 400 tests in 2.0s\nOK\n', b'OK\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                log_result(raw)


if __name__ == '__main__':
    unittest.main()
