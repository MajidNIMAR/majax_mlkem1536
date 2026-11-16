"""Reject false claims in the new hosted native-image receipts."""
from copy import deepcopy
import unittest

from m10_publication import check_smoke, qualified_input_names


class M10HostedReceiptTests(unittest.TestCase):
    def fixture(self):
        value = {'schema':'m10-native-smoke-v1','host':'windows','source_manifest_sha256':'a'*64,
            'original_CLI_sha256':'b'*64,'original_default_consumer_sha256':'c'*64,
            'fresh_round_trips':16,'implicit_rejections':16,'consumer_cases':13,'exhaustive_probes':88576,
            'new_builds':0,'fresh_fuzzing_credit_seconds':0,'constant_time_proved':False,'external_audit':False,
            'checks':[{'operation':'dev-self-test','exit_code':0},
                *[{'operation':args,'exit_code':1} for args in (['dev-vectors','1'],['dev-rejection-vectors'],
                    ['dev-hardening'],['dev-mutations'],['dev-timing'])],
                {'operation':'smoke','exit_code':0},{'operation':'exhaustive','exit_code':0}]}
        config = {'source_manifest_sha256':'a'*64,'images':{'windows':{'CLI':'b'*64,'consumer':'c'*64}}}
        return value, config

    def test_accepts_declared_finite_scope(self):
        value, config = self.fixture()
        check_smoke(value,'windows',config)

    def test_rejects_other_image_or_false_credit_and_guarantees(self):
        value, config = self.fixture()
        for key, bad in (('original_CLI_sha256','d'*64),('original_default_consumer_sha256','d'*64),
                         ('fresh_fuzzing_credit_seconds',7256),('external_audit',True),
                         ('constant_time_proved',True),('new_builds',False),('exhaustive_probes',88575)):
            mutant = deepcopy(value)
            mutant[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_smoke(mutant,'windows',config)

    def test_rejects_enabled_research_command(self):
        value, config = self.fixture()
        value['checks'][1]['exit_code'] = 0
        with self.assertRaises(ValueError):
            check_smoke(value,'windows',config)

    def test_input_scope_includes_consumer_locks_and_detects_added_build_script(self):
        names = {'Cargo.toml','crates/kem1536/src/dev_kem.rs',
            'research/m08-import-consumer/Cargo.lock','research/m08-import-consumer/src/main.rs',
            'research/m08-import-consumer/README.md','vectors/README.md','vectors/nist-acvp/NIST-NOTICE.txt'}
        before = qualified_input_names(names)
        self.assertIn('research/m08-import-consumer/Cargo.lock',before)
        self.assertIn('research/m08-import-consumer/src/main.rs',before)
        self.assertNotIn('research/m08-import-consumer/README.md',before)
        self.assertNotIn('vectors/README.md',before)
        self.assertNotIn('vectors/nist-acvp/NIST-NOTICE.txt',before)
        self.assertNotEqual(before,qualified_input_names(names|{'crates/kem1536/build.rs'}))


if __name__ == '__main__':
    unittest.main()
