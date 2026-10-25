"""Replay geometry, complete moments and synthetic events of H10."""

import hashlib
import json
import math
from pathlib import Path

from real_dual import (Q,SIZES,SAMPLES,numpy,matrix_case,offsets,make_bank,kernels,analytic,
                       cbd_samples,observations,array_hash,field_rank,character_checks)
from run_real_dual import read,summary

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-017'


def compare(a,b):
    if isinstance(a,dict):
        if set(a)!=set(b):
            raise ValueError('H10 fields differ')
        for name in a:
            compare(a[name],b[name])
    elif isinstance(a,list):
        if len(a)!=len(b):
            raise ValueError('H10 lengths differ')
        for x,y in zip(a,b):
            compare(x,y)
    elif isinstance(a,float):
        if not math.isfinite(b) or abs(a-b)>1e-10:
            raise ValueError('H10 numerical replay differs')
    elif a!=b:
        raise ValueError('H10 exact replay differs')


def verify():
    np=numpy()
    for filename in ('provenance.json','independent-provenance.json'):
        p=read(RUN/filename)
        for group,base in (('input_sha256',ROOT),('output_sha256',RUN)):
            for name,expected in p[group].items():
                if hashlib.sha256((base/name).read_bytes()).hexdigest()!=expected:
                    raise ValueError(f'H10 checksum mismatch: {name}')
    ds=offsets()
    compare(ds,read(RUN/'offsets.json'))
    cases=read(RUN/'cases.json')
    if len(cases)!=4:
        raise ValueError('four matrices required')
    for i,c in enumerate(cases):
        compare(matrix_case(i),c)
    records=read(RUN/'banks.json')
    if [(r['bank']['identifier'],r['bank']['code']['family']) for r in records]!=[(i,f) for i in range(4) for f in ('repeated','radix')]:
        raise ValueError('bank coverage failed')
    for record in records:
        bank=record['bank']
        compare(make_bank(cases[bank['identifier']],bank['code']['family']),bank)
        states,label=cbd_samples(bank['identifier'])
        if label!=record['CBD_seed_ascii'] or array_hash(states)!=record['CBD_states_sha256']:
            raise ValueError('synthetic CBD stream mismatch')
        k=kernels(bank)
        c=np.asarray([v['c'] for v in bank['vectors']],dtype=np.int64)
        compare([dict(N=N,offset=i,**analytic(k,c,d,N,Q)) for N in SIZES for i,d in enumerate(ds)],record['moments'])
        expected=[]
        for N in SIZES:
            top=float(np.max(k['logs'][:N]))
            bias=(top+math.log(float(np.sum(np.exp(k['logs'][:N]-top)))/N))/math.log(2)
            expected.append(dict(N=N,log2_bias=bias))
        compare(expected,record['true_biases'])
        compare(character_checks(k),record['character_checks'])
        compare(k['underflowed_kernel_entries'],record['numerically_underflowed_kernel_entries'])
        compare(field_rank(c.tolist(),Q),record['code_label_rank'])
        compare([i for i,d in enumerate(ds) if i and np.all((c@np.asarray(d))%Q==0)],record['selected_offsets_aliasing_true'])
        compare(observations(bank,states,ds),record['observations'])
    resources=read(RUN/'resources.json')
    if len(resources['timings'])!=28 or any(not math.isfinite(t['seconds']) or t['seconds']<0 for t in resources['timings']):
        raise ValueError('resource measurements missing')
    expected=[dict(identifier=b['bank']['identifier'],family=b['bank']['code']['family'],
                   listed_array_bytes=b['observations']['listed_array_bytes'],
                   largest_listed_array_bytes=max(b['observations']['listed_array_bytes'].values()),
                   sum_listed_array_bytes=sum(b['observations']['listed_array_bytes'].values())) for b in records]
    compare(expected,resources['arrays'])
    compare(summary(cases,records),read(RUN/'summary.json'))
    independent=read(RUN/'independent-verification.json')
    if independent['phase_identities_verified']!=4194304 or independent['moment_records_verified']!=648 or independent['high_precision_characters']!=64 or independent['project_arithmetic_imported']:
        raise ValueError('independent H10 coverage missing')
    return dict(snapshot='run-017',matrices=4,LLL_certificates=4,banks=8,panels=24,
                moment_records=648,phase_identities=4194304,synthetic_CBD_states=4*SAMPLES,
                all_q21_candidates_tested=False,attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
