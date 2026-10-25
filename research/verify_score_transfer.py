"""Replay H09 and bind every preserved input/output to its checksum."""

import hashlib
import json
from pathlib import Path

from run_score_transfer import calculate, read

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-016'


def compare(a,b):
    if isinstance(a,dict):
        if set(a)!=set(b):
            raise ValueError('H09 field mismatch')
        for k in a:
            compare(a[k],b[k])
    elif isinstance(a,list):
        if len(a)!=len(b):
            raise ValueError('H09 length mismatch')
        for x,y in zip(a,b):
            compare(x,y)
    elif isinstance(a,float):
        if abs(a-b)>1e-8:
            raise ValueError('H09 numeric mismatch')
    elif a!=b:
        raise ValueError('H09 exact mismatch')


def verify():
    for filename in ('provenance.json','independent-provenance.json'):
        p=read(RUN/filename)
        for group,base in (('input_sha256',ROOT),('output_sha256',RUN)):
            for name,expected in p[group].items():
                if hashlib.sha256((base/name).read_bytes()).hexdigest()!=expected:
                    raise ValueError(f'H09 checksum failed: {name}')
    compare(calculate(),read(RUN/'study.json'))
    independent=read(RUN/'independent-verification.json')
    if independent['points_verified']!=4 or independent['residuals_verified']!=2048 or independent['project_arithmetic_imported']:
        raise ValueError('H09 independent coverage missing')
    return dict(snapshot='run-016',points=4,concrete_sample_panels=8,residuals=2048,
                independent_decimal_digits=90,attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
