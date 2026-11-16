"""Budget/ownership regressions for the new local long campaign."""
from copy import deepcopy
import unittest
from m10_campaign import ROOT,read,check_plan,owned
from m09_fuzz_smoke import cpu_lower,parse_init


class M10CampaignTests(unittest.TestCase):
    def test_declared_post_init_budget_cannot_be_reduced(self):
        plan = read(ROOT/'research/m10-campaign-plan.json')
        self.assertEqual(len(check_plan(plan)),4)
        for field,value in (('post_INITED_CPU_lower_seconds_per_harness',1799),
            ('historical_fuzz_CPU_seconds_credited',7200),('initialization_CPU_credited',1),
            ('segment_wall_seconds_requested',30),('independent_harvested_corpus_oracle_replay_required',False)):
            changed = deepcopy(plan)
            changed[field] = value
            with self.assertRaises(ValueError):
                check_plan(changed)

    def test_initialization_and_rounding_are_excluded(self):
        usage = {'user_seconds':300.0,'system_seconds':1.0,'wall_seconds':302.0}
        self.assertEqual(cpu_lower(usage,None),0)
        self.assertEqual(cpu_lower(usage,2.0),298.98)
        with self.assertRaises(ValueError):
            parse_init(b'#100 INITED\nstat::number_of_executed_units: 99\n')

    def test_ownership_is_restricted_to_direct_m10_children(self):
        parent = ROOT/'artifacts/generated'
        self.assertEqual(owned(parent/'m10-fixture',parent),parent/'m10-fixture')
        for name in ('m09-fixture','m10-fixture/child','../m10-fixture'):
            with self.assertRaises(ValueError):
                owned(parent/name,parent)


if __name__=='__main__':
    unittest.main()
