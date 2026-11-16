"""The M10 adapter must not permanently change the historical reader."""
import unittest
from unittest.mock import patch
import m10_postprocess as adapter


class InstrumentScopeTests(unittest.TestCase):
    def test_historical_boundaries_are_restored_on_success_and_failure(self):
        original = adapter.instrument.owned,adapter.instrument.verify_campaign
        def check(*args):
            self.assertIs(adapter.instrument.owned,adapter.owned)
            self.assertIs(adapter.instrument.verify_campaign,adapter.verify_campaign)
            return {'scope':'M10'}
        with patch.object(adapter.instrument,'verify',side_effect=check):
            self.assertEqual(adapter.verify(None),{'scope':'M10'})
        self.assertEqual((adapter.instrument.owned,adapter.instrument.verify_campaign),original)
        with patch.object(adapter.instrument,'postprocess',side_effect=ValueError('retained attempt')):
            with self.assertRaises(ValueError):
                adapter.execute(None,None,None)
        self.assertEqual((adapter.instrument.owned,adapter.instrument.verify_campaign),original)


if __name__=='__main__':
    unittest.main()
