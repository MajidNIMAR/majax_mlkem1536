"""H12 complete population moments, frozen selections and reused H11 states."""

import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import time

from cbd_fourth import population
from additive_score import fingerprint,exact_moments,cbd_states,phase_pool,empirical
from real_dual import numpy,kernels,analytic,array_hash

ROOT=Path(__file__).resolve().parents[1]
NS=(4,8,16)
METHODS=('norm','hash','energy')
OFFSETS=(0,1,22,24)
INPUTS=['docs/PROTOCOLE_H12.md','research/cbd_fourth.py','research/run_cbd_fourth.py',
        'research/test_cbd_fourth.py','research/verify_cbd_fourth.py','research/verify_cbd_fourth_independent.py',
        'research/additive_score.py','research/real_dual.py','research/run_block_decoder.py',
        'research/block_decoder.py','research/block_decoder_numpy.py','research/lll_dimensions.py','research/exact_lll.py',
        'research/requirements-cbd-dimensions.txt','results/j2/run-017/banks.json','results/j2/run-017/offsets.json',
        'results/j2/run-018/orders.json','results/j2/run-018/pools.json','results/j2/run-018/provenance.json']


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def write(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(v,stream,indent=2,allow_nan=False)
        stream.write('\n')


def summarize(panels,geometries,banks):
    by_g={g['geometry_id']:g for g in geometries}
    by_b={(b['geometry_id'],b['family']):b for b in banks}
    groups=[]
    for method in METHODS:
        for N in NS:
            ps=[p for p in panels if p['method']==method and p['N']==N]
            gs=[by_g[p['geometry_id']] for p in ps]
            families=[]
            for family in ('repeated','radix'):
                bs=[by_b[p['geometry_id'],family] for p in ps]
                true=[b['population']['offsets'][0]['central'] for b in bs]
                families.append(dict(family=family,mean_true_kurtosis=sum(r['kurtosis'] for r in true)/4,
                    mean_true_log2_bias=sum(b['population']['offsets'][0]['orders'][0]['correction']['log2_abs'] for b in bs)/4,
                    maximum_absolute_kurtosis_delta=max(abs(r['kurtosis_delta_vs_independent']['value']) for r in true),
                    mean_empirical_true_kurtosis=sum(b['observations'][0]['kurtosis'] for b in bs)/4))
            groups.append(dict(method=method,N=N,
                mean_uniform_kurtosis=sum(g['uniform']['kurtosis']['numerator']/g['uniform']['kurtosis']['denominator'] for g in gs)/4,
                independent_cosine_kurtosis=3-3/(2*N),CBD=families))
    return dict(protocol_commit='8354d10',q=7681,eta=3,matrices=4,selection_panels=len(panels),
        distinct_geometries=len(geometries),distinct_CBD_banks=len(banks),offsets_per_bank=4,
        population_moment_records=len(banks)*4*4,CBD_population_moments_through_order4=True,
        covariance_calibrations=len(banks)*4,reused_CBD_states=4*4096,replayed_full_phase_identities=4194304,
        numerical_character_evaluation=True,full_probability_law_enumerated=False,rare_tail_certified=False,
        groups=groups,attack_costs_updated=False,profile_selected=False,j2_closed=False)


def calculate():
    np=numpy()
    parents=read(ROOT/'results/j2/run-017/banks.json')
    ds=read(ROOT/'results/j2/run-017/offsets.json')
    orders=read(ROOT/'results/j2/run-018/orders.json')
    oldpools=read(ROOT/'results/j2/run-018/pools.json')
    panels,geometries,banks,pools,timings=[],[],[],[],[]
    cosine=np.cos(2*np.pi*np.arange(7681)/7681)
    for identifier in range(4):
        original=next(r['bank'] for r in parents if r['bank']['identifier']==identifier)
        ys=[v['y'] for v in original['vectors']]
        unique={}
        for method in METHODS:
            for N in NS:
                ix=sorted(orders[identifier]['orders'][method][:N])
                key=fingerprint(dict(identifier=identifier,indices=ix))
                panels.append(dict(identifier=identifier,method=method,N=N,geometry_id=key))
                if key not in unique:
                    g=dict(geometry_id=key,identifier=identifier,N=N,indices=ix,
                           uniform=exact_moments([ys[i] for i in ix],7681))
                    unique[key]=g
                    geometries.append(g)
        Z,label=cbd_states(identifier,4096)
        for family in ('repeated','radix'):
            bank=next(r['bank'] for r in parents if r['bank']['identifier']==identifier and r['bank']['code']['family']==family)
            phase,C,public,truth=phase_pool(bank,Z)
            expected=next(r for r in oldpools if r['identifier']==identifier and r['kind']==family)
            if array_hash(Z)!=expected['states_sha256'] or array_hash(phase)!=expected['phases_sha256']:
                raise ArithmeticError('H11 reused samples/phase hashes failed')
            pools.append(dict(identifier=identifier,family=family,seed_ascii=label,states_sha256=array_hash(Z),
                              phases_sha256=array_hash(phase),reused_from_run018=True,
                              phase_identities=int(phase.size),states_bytes=int(Z.nbytes),phases_bytes=int(phase.nbytes)))
            old=kernels(bank)
            for key,g in unique.items():
                ix,N=g['indices'],g['N']
                a=[bank['vectors'][i]['y']+bank['vectors'][i]['x']+bank['vectors'][i]['r'] for i in ix]
                labels=C[ix]
                start=time.perf_counter()
                result=population(a,labels,[ds[d] for d in OFFSETS],7681,3,require_zero_label=True)
                timings.append(dict(identifier=identifier,family=family,geometry_id=key,N=N,
                                    seconds=time.perf_counter()-start))
                subset=dict(phis=old['phis'][ix],plus=old['plus'][np.ix_(ix,ix)],minus=old['minus'][np.ix_(ix,ix)])
                observations=[]
                scale=float(np.mean(old['phis'][ix]))
                for r,d in zip(result['offsets'],OFFSETS):
                    reference=analytic(subset,labels,ds[d],N,7681)
                    if abs(r['central']['mean']-reference['mean'])>scale*1e-9 or abs(r['central']['variance']-reference['variance'])>2e-12:
                        raise ArithmeticError('complete expansion/covariance calibration failed')
                    scores=np.mean(cosine[(phase[:,ix]-(labels@np.asarray(ds[d]))[None,:])%7681],axis=1)
                    observations.append(dict(offset=d,**empirical(scores,N)))
                    r['offset']=d
                banks.append(dict(geometry_id=key,identifier=identifier,family=family,N=N,
                                  population=result,observations=observations,
                                  covariance_calibrations=4,largest_character_batch_coordinates=512*145))
            print(f'matrix {identifier} {family}: {len(unique)} complete CBD expansions',flush=True)
    return dict(panels=panels,geometries=geometries,banks=banks,pools=pools,timings=timings,
                summary=summarize(panels,geometries,banks))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT or output.exists():
        raise ValueError('new output directory below NIST required')
    result=calculate()
    output.mkdir(parents=True)
    for name,value in result.items():
        write(output/f'{name}.json',value)
    write(output/'provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
        protocol_commit='8354d10',python=platform.python_version(),numpy=numpy().__version__,
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in INPUTS},
        output_sha256={f'{n}.json':hashlib.sha256((output/f'{n}.json').read_bytes()).hexdigest() for n in result}))
    print(json.dumps(result['summary'],indent=2))


if __name__=='__main__':
    main()
