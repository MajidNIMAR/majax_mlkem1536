"""Physical-address and path boundary checks for M08 machine inventories."""
from pathlib import Path
import unittest

from collect_m08_cli_inventory import address_index, member


class M08CLIInventoryTests(unittest.TestCase):
    def test_duplicate_names_and_address_aliases_are_preserved(self):
        data = address_index("100 <same>:\n 100: ret\n200 <same>:\n 200: ret\n200 <alias>:\n 200: ret\n")
        self.assertEqual(len(data["labels"]), 3)
        self.assertEqual(data["physical_address_count"], 2)
        self.assertEqual(data["duplicate_demangled_names"], {"same": 2})
        self.assertFalse(data["all_secret_owners_erased_proved"])

    def test_empty_listing_is_rejected(self):
        with self.assertRaises(ValueError):
            address_index("not disassembly")

    def test_members_cannot_escape(self):
        root = Path(__file__).resolve().parent
        self.assertEqual(member(root, "sub/file.json"), root / "sub/file.json")
        for name in ("../file", "/absolute", "C:/drive", "a\\b", "a//b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                member(root, name)


if __name__ == "__main__":
    unittest.main()
