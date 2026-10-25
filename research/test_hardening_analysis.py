"""Independent analytic and negative controls for M02 diagnostic reporting."""

import math
from pathlib import Path
import tempfile
import unittest

from validate_hardening_m02 import timing_summary,extract_probes


class HardeningAnalysisTests(unittest.TestCase):
    def test_welch_against_two_point_exact_variance(self):
        rows=[]
        for label,offset in [(0,0),(1,1),(2,0)]:
            for i in range(2000):
                rows.append(dict(sequence=len(rows),class_=label,nanoseconds=100+2*(i%2)+offset))
        rows=[dict(sequence=r['sequence'],**{'class':r['class_']},nanoseconds=r['nanoseconds']) for r in rows]
        result=timing_summary(rows)
        # Each sample variance is 2000/1999; the two means differ by exactly 1.
        self.assertAlmostEqual(result['pairs'][0]['welch_t'],-math.sqrt(1999/2))
        self.assertTrue(result['pairs'][0]['signal'])
        self.assertEqual(result['pairs'][1]['welch_t'],0.)
        self.assertFalse(result['constant_time_proven'])
        with self.assertRaises(ValueError):
            timing_summary(rows[:-1])

    def test_assembly_negative_control_rejects_conditional_jump(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'fixture.s'
            body=''
            for name in ('reduce_probe','quotient_probe'):
                body+=f'_ZN_{name}123:\n\tmulq\t%rdx\n\tretq\n.seh_endproc\n'
            source.write_text(body,encoding='utf-8')
            self.assertEqual(len(extract_probes(source)),2)
            source.write_text(body.replace('\tretq','\tjne\tOTHER\n\tretq',1),encoding='utf-8')
            with self.assertRaises(ValueError):
                extract_probes(source)


if __name__=='__main__':
    unittest.main()
