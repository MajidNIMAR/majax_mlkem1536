"""Run the preserved original M07 CLI on this native host after data replay.

This is a fresh finite integration test, not a new benchmark or binary review.
"""
import json
import os
import platform
import shutil
import subprocess

from archive_m07 import ROOT, read, require, sha, temporary_directory, unpack
from package_m07 import PROFILE, RESEARCH_COMMANDS, verify


def smoke():
    require(platform.machine().casefold() in {"amd64", "x86_64"}, "M07 package requires x86-64")
    require(os.name == "nt" or platform.system() == "Linux", "M07 packages support Windows/Linux")
    host = "windows" if os.name == "nt" else "linux"
    snapshot = ROOT / "results/engine/m07-001"
    record = read(snapshot / "provenance.json")["stages"]["delivery"]
    require(record["archive"] == "delivery.tar.gz", "unexpected package evidence archive")
    with temporary_directory() as temporary:
        delivery = temporary / "delivery"
        unpack(snapshot / record["archive"], record, delivery)
        verify(delivery)
        suffix = ".exe" if host == "windows" else ""
        original = delivery / host / "package/bin" / ("kem1536" + suffix)
        executable = temporary / ("kem1536" + suffix)
        shutil.copyfile(original, executable)
        executable.chmod(0o700)
        expected = read(delivery / "result.json")["platforms"][host]["original_binary_sha256"]
        require(sha(executable) == expected, "native smoke is not the reviewed shipped original")
        result = subprocess.run([str(executable), "dev-self-test"], capture_output=True, check=True, timeout=60)
        test = json.loads(result.stdout)
        require(test["profile"] == PROFILE and test["fresh_round_trips"] == 16
                and test["implicit_rejections_checked"] == 16 and test["secrets_printed"] is False,
                "packaged original self-test differs")
        for command in RESEARCH_COMMANDS:
            run = subprocess.run([str(executable), *command], capture_output=True, timeout=30)
            require(run.returncode == 1 and run.stdout == b"", "packaged original did not reject the command normally")
        return {"host": host, "original_binary_sha256": expected, "self_test": test,
                "research_commands_rejected": len(RESEARCH_COMMANDS), "new_compilation_performed": False}


if __name__ == "__main__":
    print(json.dumps(smoke(), indent=2))
