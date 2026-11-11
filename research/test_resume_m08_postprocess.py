import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import resume_m08_postprocess as recovery


class RecoveryTests(unittest.TestCase):
    def test_resume_refuses_each_existing_output_before_mutation(self):
        root = recovery.ROOT / "target"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            out = Path(temporary)
            folder = out / "postprocessing"
            folder.mkdir()
            self.assertEqual(recovery.check_resume_destination(out), folder)
            for path in [folder / name for name in ("postprocess.json", "failure.json", "recovery-request.json",
                         "recovery.json", "recovery-adapter.py", "interrupted-oracle-001")] + [out / "oracle-replay.json"]:
                path.write_bytes(b"preserve")
                with self.assertRaises(ValueError):
                    recovery.check_resume_destination(out)
                self.assertEqual(path.read_bytes(), b"preserve")
                path.unlink()

    def test_resume_requires_an_ordinary_postprocessing_directory(self):
        root = recovery.ROOT / "target"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            out = Path(temporary)
            (out / "postprocessing").write_bytes(b"not a directory")
            with self.assertRaises(ValueError):
                recovery.check_resume_destination(out)

    def test_partial_member_names_are_exact(self):
        good = {name: "a" * 64 for name in recovery.PARTIAL}
        recovery.check_partial_members(good)
        for changed in ({**good, "extra": "a" * 64}, {k: v for k, v in good.items() if k != recovery.PARTIAL[0]},
                        {**good, recovery.PARTIAL[0]: "X" * 64}):
            with self.assertRaises(ValueError):
                recovery.check_partial_members(changed)

    def test_command_uses_exact_historical_original_controller_and_binary(self):
        command = recovery.oracle_command({"build_command": ["cargo", "--fuzz-dir", "/mnt/c/p/NIST/artifacts/generated/m08-fuzz-001/source/fuzz"]})
        self.assertEqual(command, [r"C:\p\NIST\.tools\research-venv\Scripts\python.exe", "-B",
                                  r"C:\p\NIST\artifacts\generated\m08-fuzz-001\controls\replay_m08_fuzz_corpus.py",
                                  "run", "--campaign", r"C:\p\NIST\artifacts\generated\m08-fuzz-001", "--linux-binary",
                                  "/mnt/c/p/NIST/artifacts/generated/m08-fuzz-001/bin/m08-replay"])

    def fixture(self, directory):
        out = Path(directory)
        folder = out / "postprocessing"
        partial = folder / "interrupted-oracle-001"
        partial.mkdir(parents=True)
        for name in recovery.PARTIAL:
            (partial / name).write_bytes(b"partial" if name.endswith(".gz") else b"")
        (folder / "recovery-adapter.py").write_bytes(b"controller")
        (out / "oracle-replay.json").write_bytes(b"{}")
        (out / "oracle-replay.log").write_bytes(b"completed")
        config = {"build_command": ["cargo", "--fuzz-dir", "/mnt/c/p/NIST/artifacts/generated/m08-fuzz-001/source/fuzz"]}
        recovery.save(out / "config.json", config)
        request = {"schema": "m08-oracle-recovery-request-v1", "profile": recovery.PROFILE,
                   "interrupted_outputs_sha256": recovery.inventory(partial), "original_postprocess_exit_code_known": False,
                   "campaign_or_coverage_rerun": False, "completed_inputs_sha256": {"f": "a"},
                   "oracle_command": recovery.oracle_command(config), "adapter_sha256": recovery.sha(folder / "recovery-adapter.py")}
        recovery.save(folder / "recovery-request.json", request)
        result = {"schema": "m08-oracle-recovery-result-v1", "request_sha256": recovery.sha(folder / "recovery-request.json"),
                  "exit_code": 0, "oracle_receipt_sha256": recovery.sha(out / "oracle-replay.json"),
                  "oracle_log_sha256": recovery.sha(out / "oracle-replay.log"), "adapter_sha256": request["adapter_sha256"]}
        recovery.save(folder / "recovery.json", result)
        final = {"recovery_receipt_sha256": recovery.sha(folder / "recovery.json"),
                 "oracle_command": request["oracle_command"], "oracle_receipt_sha256": result["oracle_receipt_sha256"]}
        recovery.save(folder / "postprocess.json", final)
        return out

    def test_pure_receipt_replay_and_mutation_guards(self):
        root = recovery.ROOT / "target"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            out = self.fixture(temporary)
            with patch.object(recovery, "bindings", return_value={"f": "a"}), patch.object(recovery.subprocess, "run", side_effect=AssertionError("no execution")):
                self.assertEqual(recovery.verify_recovery(out)["resumed_oracle_exit_code"], 0)
                for name in ("oracle-replay.log", "oracle-replay.json", "postprocessing/recovery-adapter.py",
                             "postprocessing/interrupted-oracle-001/oracle-transcript.jsonl.gz"):
                    path = out / name
                    old = path.read_bytes()
                    path.write_bytes(old + b"changed")
                    with self.assertRaises(ValueError):
                        recovery.verify_recovery(out)
                    path.write_bytes(old)


if __name__ == "__main__":
    unittest.main()
