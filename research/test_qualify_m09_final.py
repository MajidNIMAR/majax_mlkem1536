"""Pure tests of provenance gates and failure receipts; no native acquisitions."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualify_m09_final import (INPUTS, bind_controls, check_validation_outputs, copy_inputs,
                               execute, historical_inputs, inventory, names_in_capture,
                               sha, write_new)


class QualificationAdapterTests(unittest.TestCase):
    def fixture(self, root):
        out = root / "artifacts/generated/m09-test"
        source = out / "source/research"
        source.mkdir(parents=True)
        live = root / "research"
        live.mkdir()
        control = "CONTROLS=('run_m09_qualification.py',)\n"
        (source / "run_m09_qualification.py").write_text(control)
        (live / "run_m09_qualification.py").write_text(control)
        write_new(out / "source.json", dict(source_sha256=inventory(out / "source")))
        for name in INPUTS:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(b"fixture:"+name.encode())
        first = dict(input_sha256={INPUTS[0]: sha(root / INPUTS[0])},
                     output_sha256={"vectors.jsonl.gz": sha(root / INPUTS[1])})
        (root / INPUTS[2]).write_text(json.dumps(first))
        rejection = dict(input_sha256={INPUTS[0]: sha(root / INPUTS[0]), INPUTS[2]: sha(root / INPUTS[2])},
                         output_sha256={"rejections.jsonl.gz": sha(root / INPUTS[3])})
        (root / INPUTS[4]).write_text(json.dumps(rejection))
        return out

    def test_gate_accepts_exact_capture_and_rejects_live_or_captured_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            self.assertEqual(len(bind_controls(root, out)["controls_sha256"]), 1)
            path = root / "research/run_m09_qualification.py"
            saved = path.read_bytes()
            path.write_bytes(saved+b"# changed\n")
            with self.assertRaisesRegex(ValueError, "live control differs"):
                bind_controls(root, out)
            path.write_bytes(saved)
            (out / "source/research/run_m09_qualification.py").write_bytes(saved+b"# changed\n")
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                bind_controls(root, out)

    def test_static_local_import_closure_must_be_captured(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            text = "CONTROLS=('run_m09_qualification.py',)\nimport extra_helper\n"
            for path in (root / "research/run_m09_qualification.py", out / "source/research/run_m09_qualification.py"):
                path.write_text(text)
            (root / "research/extra_helper.py").write_text("value=1\n")
            source = out / "source.json"
            source.write_text(json.dumps(dict(source_sha256=inventory(out / "source"))))
            with self.assertRaisesRegex(ValueError, "uncaptured local helper"):
                bind_controls(root, out)

    def test_control_name_parser_rejects_ambiguous_unsafe_or_missing_declarations(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "controller.py"
            for text in ("CONTROLS=('../escape.py',)\n", "CONTROLS=('run_m09_qualification.py',)*2\n",
                         "CONTROLS=('run_m09_qualification.py',)\nCONTROLS=()\n", "pass\n"):
                path.write_text(text)
                with self.assertRaises((ValueError, TypeError)):
                    names_in_capture(path)

    def test_input_provenance_chain_and_exact_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            hashes = historical_inputs(root)
            self.assertEqual(copy_inputs(root, out), hashes)
            self.assertEqual(copy_inputs(root, out), hashes)
            target = out / "validation-inputs" / INPUTS[0]
            target.write_bytes(b"altered")
            with self.assertRaisesRegex(ValueError, "copied inputs differ"):
                copy_inputs(root, out)
            (root / INPUTS[1]).write_bytes(b"altered")
            with self.assertRaisesRegex(ValueError, "vector provenance differs"):
                historical_inputs(root)

    def test_nonzero_child_exit_is_retained_with_before_after_and_raw_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            with patch("qualify_m09_final.runtime", return_value=dict(numpy_version="2.3.5")), \
                    patch("qualify_m09_final.subprocess.run") as child:
                child.return_value.returncode = 17
                result = execute(out, "validate", root=root)
            receipt = out / "qualification-adapter/validate-001"
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["child_exit_code"], 17)
            self.assertTrue(result["exit_code_known"])
            self.assertTrue((receipt / "request.json").is_file())
            self.assertTrue((receipt / "before.json").is_file())
            self.assertTrue((receipt / "after.json").is_file())
            self.assertTrue((receipt / "stdout.log").is_file())
            self.assertTrue((receipt / "stderr.log").is_file())

    def test_preflight_failure_never_runs_child_and_leaves_failed_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            (root / "research/run_m09_qualification.py").write_text("# mismatch\n")
            with patch("qualify_m09_final.subprocess.run") as child:
                result = execute(out, "validate", root=root)
            child.assert_not_called()
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["exit_code_known"])
            self.assertIsNone(result["child_exit_code"])
            self.assertTrue((out / "qualification-adapter/validate-001/after.json").is_file())

    def test_mutation_during_failed_child_is_detected_and_exit_kept(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            def mutate(*args, **kwargs):
                (root / "research/run_m09_qualification.py").write_text("# changed during execution\n")
                return type("Result", (), dict(returncode=7))()
            with patch("qualify_m09_final.runtime", return_value={}), \
                    patch("qualify_m09_final.subprocess.run", side_effect=mutate):
                result = execute(out, "validate", root=root)
            self.assertEqual(result["child_exit_code"], 7)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("live control differs", result["postflight_error"]["message"])

    def test_existing_receipts_and_unsafe_output_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            (out / "qualification-adapter/validate-001").mkdir(parents=True)
            with self.assertRaises(FileExistsError):
                execute(out, "validate", root=root)
            with self.assertRaisesRegex(ValueError, "direct generated"):
                execute(root / "elsewhere", "validate", root=root)

    def test_consumer_postchecks_reject_wrong_counts_even_when_native_exit_was_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = self.fixture(root)
            write_new(out / "validation.json", dict(source_manifest_sha256=sha(out / "source.json")))
            smoke = dict(schema=1, profile="KEM1536-DEV-Q7681-R1", fresh_imported_key_round_trips=1,
                         fresh_rejections=1, repeat_rejection_equal=True, secrets_printed=False,
                         cases=[dict(operation=str(i), status=0, expected=0) for i in range(13)])
            exhaustive = dict(schema=1, profile="KEM1536-DEV-Q7681-R1", single_coefficient_value_alignment_cases=65536,
                              boundary_position_cases=23040, total_cases=88576,
                              all_expected_statuses_and_accepted_encodings_match=True,
                              complete_vector_space_exhausted=False, formal_program_verification=False, secrets_printed=False)
            formats = dict(inputs=20000, panics_observed=0, public_key_imports=6667, private_key_imports=6667,
                           ciphertext_imports=6666, wrong_lengths_rejected=17000, exact_length_inputs=3000, accepted_imports=1000)
            for host in ("windows", "linux"):
                folder = out / "validation" / host
                folder.mkdir(parents=True)
                for name, value in (("consumer-smoke", smoke), ("consumer-exhaustive", exhaustive), ("formats", formats)):
                    write_new(folder / (name+".stdout"), value)
            self.assertEqual(check_validation_outputs(out)["linux"]["exhaustive_probes"], 88576)
            exhaustive["total_cases"] = 88575
            (out / "validation/linux/consumer-exhaustive.stdout").write_text(json.dumps(exhaustive))
            with self.assertRaisesRegex(ValueError, "exhaustive counters"):
                check_validation_outputs(out)


if __name__ == "__main__":
    unittest.main()
