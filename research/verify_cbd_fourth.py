"""Replay H12 complete population expansions and frozen H11 sample reuse."""

import hashlib
import json
import math
from pathlib import Path

from run_cbd_fourth import calculate,read

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-019'


def compare(a,b):
    if isinstance(a,dict):
        if set(a)!=set(b):
            raise ValueError('H12 fields differ')
        for key in a:
            compare(a[key],b[key])
    elif isinstance(a,list):
        if len(a)!=len(b):
            raise ValueError('H12 lengths differ')
        for x,y in zip(a,b):
            compare(x,y)
    elif isinstance(a,float):
        if not math.isfinite(b) or abs(a-b)>1e-10*(1+abs(a)):
            raise ValueError('H12 numerical replay differs')
    elif a!=b:
        raise ValueError('H12 exact replay differs')


def verify():
    for name in ('provenance.json','independent-provenance.json'):
        p=read(RUN/name)
        for group,base in (('input_sha256',ROOT),('output_sha256',RUN)):
            for filename,expected in p[group].items():
                if hashlib.sha256((base/filename).read_bytes()).hexdigest()!=expected:
                    raise ValueError(f'H12 hash failed: {filename}')
    replay=calculate()
    for name,value in replay.items():
        saved=read(RUN/f'{name}.json')
        if name=='timings':
            if len(saved)!=len(replay['banks']) or any(not math.isfinite(t['seconds']) or t['seconds']<0 for t in saved):
                raise ValueError('H12 timings missing')
        else:
            compare(value,saved)
    independent=read(RUN/'independent-verification.json')
    if independent['population_moment_records_verified']!=len(replay['banks'])*16 or independent['replayed_phase_identities']!=4194304 or independent['project_arithmetic_imported']:
        raise ValueError('H12 independent coverage missing')
    return dict(snapshot='run-019',selection_panels=len(replay['panels']),CBD_banks=len(replay['banks']),
                population_moment_records=len(replay['banks'])*16,character_evaluation='numeric',
                rare_tail_certified=False,attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
