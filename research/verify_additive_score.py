"""Replay H11 selection, exact moments, calibrations and new observations."""

import hashlib
import json
import math
from pathlib import Path

from run_additive_score import calculate,read

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-018'


def compare(a,b):
    if isinstance(a,dict):
        if set(a)!=set(b):
            raise ValueError('H11 fields differ')
        for k in a:
            compare(a[k],b[k])
    elif isinstance(a,list):
        if len(a)!=len(b):
            raise ValueError('H11 lengths differ')
        for x,y in zip(a,b):
            compare(x,y)
    elif isinstance(a,float):
        if not math.isfinite(b) or abs(a-b)>1e-10*(1+abs(a)):
            raise ValueError('H11 numeric replay differs')
    elif a!=b:
        raise ValueError('H11 exact replay differs')


def verify():
    for filename in ('provenance.json','independent-provenance.json'):
        p=read(RUN/filename)
        for group,base in (('input_sha256',ROOT),('output_sha256',RUN)):
            for name,expected in p[group].items():
                if hashlib.sha256((base/name).read_bytes()).hexdigest()!=expected:
                    raise ValueError(f'H11 hash failed: {name}')
    replay=calculate()
    for name,value in replay.items():
        saved=read(RUN/f'{name}.json')
        if name=='timings':
            if len(saved)!=16 or any(not math.isfinite(t['seconds']) or t['seconds']<0 for t in saved):
                raise ValueError('H11 resource record missing')
        else:
            compare(value,saved)
    independent=read(RUN/'independent-verification.json')
    if independent['exact_uniform_laws_verified']!=len(replay['geometries']) or independent['unique_phase_identities_verified']!=4194304 or independent['greedy_costs_verified']!=33024 or independent['project_arithmetic_imported']:
        raise ValueError('H11 independent coverage missing')
    return dict(snapshot='run-018',selection_panels=len(replay['panels']),
                distinct_uniform_laws=len(replay['geometries']),distinct_LWE_panels=len(replay['banks']),
                phase_identities=4194304,H10_uniform_calibrations=12,H10_CBD_calibrations=96,
                exact_CBD_fourth_moment_computed=False,attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
