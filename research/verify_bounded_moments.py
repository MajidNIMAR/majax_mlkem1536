"""Replay H13 integer histograms, rational bounds and immutable provenance."""

import hashlib
import json
import math
from pathlib import Path

from run_bounded_moments import calculate,read

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-020'


def verify():
    for name in ('provenance.json','independent-provenance.json'):
        provenance=read(RUN/name)
        for group,base in (('input_sha256',ROOT),('output_sha256',RUN)):
            for name,expected in provenance[group].items():
                if hashlib.sha256((base/name).read_bytes()).hexdigest()!=expected:
                    raise ValueError(f'H13 checksum mismatch: {name}')
    replay=calculate()
    for name,value in replay.items():
        if name!='timings' and value!=read(RUN/f'{name}.json'):
            raise ValueError(f'H13 exact replay differs: {name}')
    times=read(RUN/'timings.json')
    if len(times)!=24 or any(not math.isfinite(t['seconds']) or t['seconds']<0 for t in times):
        raise ValueError('H13 resource timings missing')
    independent=read(RUN/'independent-verification.json')
    if independent['N32_banks_verified']!=24 or independent['H12_banks_verified']!=64 or independent['project_arithmetic_imported']:
        raise ValueError('H13 independent coverage failed')
    return dict(snapshot='run-020',exact_rational_replay=True,**replay['summary'])


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
