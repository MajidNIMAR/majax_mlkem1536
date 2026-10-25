"""Portable replay of H11, preserving the historical runner unchanged.

Calculation copied from run_additive_score.calculate; only tail calibration
comparison changes to finite floating tolerances with exact integer counts.
This module does not generate or replace historical study snapshots.
"""
import math
import time
from run_additive_score import ROOT,Q,NS,METHODS,OFFSETS,read,summarize
from additive_score import fingerprint,exact_moments,public_orders,empirical,cbd_states,phase_pool
from real_dual import numpy,array_hash,kernels,analytic,field_rank,statistics
from run_block_decoder import targets
from portable_calibration import calibration_tails_match

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
                    if abs(fresh['mean']-priorstats['mean'])>1e-12 or abs(fresh['variance']-priorstats['variance'])>1e-12 or not calibration_tails_match(fresh['tails'],priorstats['tails']):
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

