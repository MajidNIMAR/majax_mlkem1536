"""Do not credit seed initialization as post-initialization M06 fuzzing."""
import json
from pathlib import Path
import tempfile
import unittest

from run_m06_fuzz import inspect_post_init, TARGETS


class FuzzInitializationTests(unittest.TestCase):
    def panel(self, folder, text):
        results = {}
        for name in TARGETS:
            (folder / name).mkdir()
            (folder / name / "segment-000.log").write_text(text)
            results[name] = {"CPU_seconds": 120, "segments": [{"segment": 0}]}
        (folder / "fuzz-summary.json").write_text(json.dumps({"results": results}))

    def test_cpu_budget_with_only_initialized_seeds_is_insufficient(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            self.panel(folder, "#200 INITED cov: 99 ft: 100\n#200 DONE\nstat::number_of_executed_units: 200\n")
            result = inspect_post_init(folder)
            self.assertFalse(result["all_four_have_post_INITED_execution"])
            self.assertEqual(result["targets"]["api_sequence"]["executions_after_INITED"], 0)

    def test_post_init_counter_is_distinct_from_new_coverage_events(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            # A mutation need not discover coverage: do not require NEW, and
            # do not label all 225 executions as post-initialization work.
            self.panel(folder, "#200 INITED cov: 99 ft: 100\n#225 DONE\nstat::number_of_executed_units: 225\n")
            result = inspect_post_init(folder)
            self.assertTrue(result["all_four_have_post_INITED_execution"])
            target = result["targets"]["api_sequence"]
            self.assertEqual(target["executions_after_INITED"], 25)
            self.assertEqual(target["segments"][0]["new_or_reduced_feature_events_after_INITED"], 0)

    def test_ambiguous_init_or_missing_final_counter_is_not_guessed(self):
        for log in ("#1 INITED\n#2 INITED\nstat::number_of_executed_units: 225\n",
                    "#200 INITED\n#225 NEW\n"):
            with self.subTest(log=log), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                self.panel(folder, log)
                self.assertFalse(inspect_post_init(folder)["all_four_have_post_INITED_execution"])

    def test_separate_supplement_preserves_main_init_only_record(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            self.panel(folder, "#200 INITED\nstat::number_of_executed_units: 200\n")
            supplemental = folder / "supplement-001/api_sequence"
            supplemental.mkdir(parents=True)
            (supplemental / "segment-000.log").write_text("#5 INITED\nstat::number_of_executed_units: 30\n")
            (folder / "supplemental-summary.json").write_text(json.dumps({
                "results": {"api_sequence": {"segments": [{"segment": 0}]}}}))
            result = inspect_post_init(folder)["targets"]["api_sequence"]
            self.assertEqual(result["executions_after_INITED"], 25)
            self.assertEqual([s["origin"] for s in result["segments"]], ["main", "supplement"])
            self.assertEqual([s["executions_after_INITED"] for s in result["segments"]], [0, 25])


if __name__ == "__main__":
    unittest.main()
