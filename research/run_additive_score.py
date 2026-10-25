"""Execute H11 with fixed candidate pools and new synthetic observations."""

import argparse
from datetime import datetime,timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import platform
import time

from additive_score import fingerprint,exact_moments,public_orders,empirical,cbd_states,phase_pool
from real_dual import numpy,array_hash,kernels,analytic,field_rank,statistics
from run_block_decoder import targets

ROOT=Path(__file__).resolve().parents[1]
Q=7681
NS=(32,64,128)
METHODS=('norm','hash','energy')
OFFSETS=(0,1,22,24)
INPUTS=['docs/PROTOCOLE_H11.md','research/additive_score.py','research/run_additive_score.py',
        'research/test_additive_score.py','research/verify_additive_score.py','research/verify_additive_score_independent.py',
        'research/real_dual.py','research/block_decoder.py','research/block_decoder_numpy.py',
        'research/lll_dimensions.py','research/exact_lll.py','research/run_block_decoder.py',
        'research/requirements-cbd-dimensions.txt','results/j2/run-017/cases.json',
        'results/j2/run-017/banks.json','results/j2/run-017/offsets.json','results/j2/run-017/provenance.json']


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def write(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(v,stream,indent=2,allow_nan=False)
        stream.write('\n')


def number(v):
    return v['numerator']/v['denominator']


def summarize(panels,geometries,banks):
    by_g={r['geometry_id']:r for r in geometries}
    by_b={(r['geometry_id'],r['family']):r for r in banks}
    groups=[]
    for method in METHODS:
        for N in NS:
            selected=[p for p in panels if p['method']==method and p['N']==N]
            rows=[by_g[p['geometry_id']] for p in selected]
            families=[]
            for family in ('repeated','radix'):
                bs=[by_b[p['geometry_id'],family] for p in selected]
                families.append(dict(family=family,mean_log2_true_bias=sum(b['log2_true_bias'] for b in bs)/4,
                    mean_true_empirical_kurtosis=sum(b['observations'][0]['empirical']['kurtosis'] for b in bs)/4,
                    true_three_sigma_hits=sum(b['observations'][0]['empirical']['tails'][1]['hits_above_margin'] for b in bs),
                    states=4*4096))
            groups.append(dict(method=method,N=N,mean_exact_kurtosis=sum(number(g['exact']['kurtosis']) for g in rows)/4,
                mean_exact_skewness=sum(g['exact']['skewness'] for g in rows)/4,
                mean_uniform_empirical_kurtosis=sum(g['empirical_uniform']['kurtosis'] for g in rows)/4,
                uniform_three_sigma_hits=sum(g['empirical_uniform']['tails'][1]['hits_above_margin'] for g in rows),
                uniform_samples=4*8192,mean_lattice_squared_norm=sum(g['mean_lattice_squared_norm'] for g in rows)/4,
                LWE=families))
    return dict(protocol_commit='cfc924c',q=Q,matrices=4,pool_size=128,selection_panels=len(panels),
        distinct_geometries=len(geometries),distinct_LWE_panels=len(banks),
        exact_uniform_moment_laws=len(geometries),numerical_CBD_moments=len(banks)*len(OFFSETS),
        fresh_uniform_states=4*8192,fresh_CBD_states=4*4096,unique_full_phase_identities=4*2*4096*128,
        H10_uniform_calibrations=12,H10_CBD_calibrations=96,groups=groups,
        exact_CBD_fourth_moment_computed=False,all_q21_candidates_tested=False,
        attack_costs_updated=False,profile_selected=False,j2_closed=False)


def calculate():
    np=numpy()
    parent=ROOT/'results/j2/run-017'
    cases=read(parent/'cases.json')
    old=read(parent/'banks.json')
    ds=read(parent/'offsets.json')
    cosine=np.cos(2*np.pi*np.arange(Q)/Q)
    orders,panels,geometries,banks,pools,times=[],[],[],[],[],[]
    uniform_calibrations=CBD_calibrations=0
    for case in cases:
        identifier=case['identifier']
        ys=[v['y'] for v in case['vectors']]
        start=time.perf_counter()
        chosen,trace=public_orders(ys,Q,identifier)
        times.append(dict(identifier=identifier,step='all_public_orders',seconds=time.perf_counter()-start))
        orders.append(dict(identifier=identifier,orders=chosen,energy_trace=trace,
                           energy_candidate_evaluations=sum(t['candidate_evaluations'] for t in trace)))
        label=f'nist-j2-additive-v1:uniform:{identifier}'
        U=np.asarray(targets(Q,3,8192,label.encode()),dtype=np.int64)
        phases=U@np.asarray(ys,dtype=np.int64).T%Q
        oldU=np.asarray(targets(Q,3,4096,f'nist-j2-real-dual-v1:uniform:{identifier}'.encode()),dtype=np.int64)
        oldphases=oldU@np.asarray(ys,dtype=np.int64).T%Q
        pools.append(dict(identifier=identifier,kind='uniform',seed_ascii=label,states_sha256=array_hash(U),
                          phases_sha256=array_hash(phases),states_bytes=int(U.nbytes),phases_bytes=int(phases.nbytes)))
        unique={}
        start=time.perf_counter()
        for method in METHODS:
            for N in NS:
                indices=sorted(chosen[method][:N])
                key=fingerprint(dict(identifier=identifier,indices=indices))
                panels.append(dict(identifier=identifier,method=method,N=N,geometry_id=key))
                if key in unique:
                    continue
                row=dict(geometry_id=key,identifier=identifier,N=N,indices=indices,
                         exact=exact_moments([ys[i] for i in indices],Q),
                         empirical_uniform=empirical(np.mean(cosine[phases[:,indices]],axis=1),N),
                         mean_lattice_squared_norm=sum(case['vectors'][i]['squared_norm'] for i in indices)/N,
                         maximum_lattice_squared_norm=max(case['vectors'][i]['squared_norm'] for i in indices))
                unique[key]=row
                geometries.append(row)
                if method=='norm':
                    prior=next(r for r in old if r['bank']['identifier']==identifier and r['bank']['code']['family']=='radix')
                    priorstats=next(r for r in prior['observations']['uniform_null'] if r['N']==N)
                    fresh=statistics(np.mean(cosine[oldphases[:,indices]],axis=1),N)
                    if abs(fresh['mean']-priorstats['mean'])>1e-12 or abs(fresh['variance']-priorstats['variance'])>1e-12 or fresh['tails']!=priorstats['tails']:
                        raise ArithmeticError('H10 uniform calibration failed')
                    uniform_calibrations+=1
        times.append(dict(identifier=identifier,step='exact_uniform_moments_and_new_samples',seconds=time.perf_counter()-start))
        Z,cbd_label=cbd_states(identifier,4096)
        for family in ('repeated','radix'):
            start=time.perf_counter()
            prior=next(r for r in old if r['bank']['identifier']==identifier and r['bank']['code']['family']==family)
            bank=prior['bank']
            phase,C,public,truth=phase_pool(bank,Z)
            k=kernels(bank)
            pools.append(dict(identifier=identifier,kind=family,seed_ascii=cbd_label,states_sha256=array_hash(Z),
                phases_sha256=array_hash(phase),public_sha256=array_hash(public),truth_sha256=array_hash(truth),
                states_bytes=int(Z.nbytes),phases_bytes=int(phase.nbytes),unique_phase_identities=int(phase.size)))
            for key,g in unique.items():
                ix=g['indices']
                N=g['N']
                subset=dict(phis=k['phis'][ix],plus=k['plus'][np.ix_(ix,ix)],minus=k['minus'][np.ix_(ix,ix)])
                top=float(np.max(k['logs'][ix]))
                bias=(top+math.log(float(np.sum(np.exp(k['logs'][ix]-top)))/N))/math.log(2)
                results=[]
                for offset in OFFSETS:
                    delta=ds[offset]
                    moments=analytic(subset,C[ix],delta,N,Q)
                    scores=np.mean(cosine[(phase[:,ix]-(C[ix]@np.asarray(delta))[None,:])%Q],axis=1)
                    results.append(dict(offset=offset,analytic=moments,empirical=empirical(scores,N)))
                    if ix==list(range(N)):
                        expected=next(r for r in prior['moments'] if r['N']==N and r['offset']==offset)
                        if any(abs(moments[name]-expected[name])>2e-12 for name in moments):
                            raise ArithmeticError('H10 CBD moment calibration failed')
                        CBD_calibrations+=1
                banks.append(dict(geometry_id=key,identifier=identifier,family=family,N=N,log2_true_bias=bias,
                    code_label_rank=field_rank(C[ix].tolist(),Q),
                    mean_residual_squared_norm=sum(bank['vectors'][i]['squared_residual_norm'] for i in ix)/N,
                    observations=results))
            times.append(dict(identifier=identifier,family=family,step='full_phases_moments_and_CBD_samples',seconds=time.perf_counter()-start))
        print(f'matrix {identifier}: {len(unique)} distinct geometries, {sum(t["candidate_evaluations"] for t in trace)} greedy costs',flush=True)
    if (uniform_calibrations,CBD_calibrations)!=(12,96):
        raise ArithmeticError('H10 calibration coverage changed')
    return dict(orders=orders,panels=panels,geometries=geometries,banks=banks,pools=pools,timings=times,
                summary=summarize(panels,geometries,banks))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT or output.exists():
        raise ValueError('new directory below NIST required')
    result=calculate()
    output.mkdir(parents=True)
    for name,value in result.items():
        write(output/f'{name}.json',value)
    write(output/'provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
        protocol_commit='cfc924c',python=platform.python_version(),numpy=numpy().__version__,
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in INPUTS},
        output_sha256={f'{n}.json':hashlib.sha256((output/f'{n}.json').read_bytes()).hexdigest() for n in result}))
    print(json.dumps(result['summary'],indent=2))


if __name__=='__main__':
    main()
