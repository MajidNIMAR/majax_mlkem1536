"""Negative checks on saved command/payload bindings, with synthetic text only."""
from copy import deepcopy
import unittest

from m10_secret_inventory import check_commands
from m09_lifecycle_inventory import digest


class M10CommandBindingTests(unittest.TestCase):
    def panel(self, host):
        original = "artifacts/generated/m10-test/source-image"
        path = "/mnt/c/work/" + original
        prefix = ["wsl.exe", "-d", "Ubuntu-22.04", "--"]
        payloads = [b"synthetic listing\n", b"synthetic headers\n", b"synthetic version\n",
                    b"synthetic relocs\n" if host == "linux" else b""]
        arguments = [prefix + ["objdump", "-d", "-C", "--no-show-raw-insn", path],
                     prefix + ["objdump", "-x", path], prefix + ["objdump", "--version"]]
        if host == "linux":
            arguments.append(prefix + ["readelf", "-Wr", path])
        commands = [{"argv": argv, "exit_code": 0, "stdout_sha256": digest(payload),
                     "stderr_sha256": digest(b"")}
                    for argv, payload in zip(arguments, payloads)]
        return original, commands, payloads

    def test_saved_panel_replays_both_hosts_without_running_tools(self):
        for host in ("windows", "linux"):
            original, commands, payloads = self.panel(host)
            check_commands(commands, host, original, *payloads)

    def test_each_payload_is_bound_even_if_the_inventory_envelope_were_resealed(self):
        for host in ("windows", "linux"):
            original, commands, payloads = self.panel(host)
            for site in range(len(commands)):
                changed = list(payloads)
                changed[site] += b"changed"
                with self.subTest(host=host, payload=site), self.assertRaisesRegex(ValueError, "stdout link differs"):
                    check_commands(commands, host, original, *changed)

    def test_command_status_tool_and_target_cannot_be_substituted(self):
        for host in ("windows", "linux"):
            original, commands, payloads = self.panel(host)
            for site in range(len(commands)):
                for field, value in (("exit_code", 1), ("stderr_sha256", digest(b"warning")),
                                     ("argv", commands[site]["argv"] + ["--changed"])):
                    changed = deepcopy(commands)
                    changed[site][field] = value
                    with self.subTest(host=host, command=site, field=field), self.assertRaises(ValueError):
                        check_commands(changed, host, original, *payloads)
            with self.assertRaisesRegex(ValueError, "path differs"):
                check_commands(commands, host, original + "-other", *payloads)

    def test_missing_extra_or_reordered_command_panel_is_rejected(self):
        for host in ("windows", "linux"):
            original, commands, payloads = self.panel(host)
            for changed in (commands[:-1], commands + [commands[0]], list(reversed(commands))):
                with self.subTest(host=host), self.assertRaises(ValueError):
                    check_commands(changed, host, original, *payloads)


if __name__ == "__main__":
    unittest.main()
