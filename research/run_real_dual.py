"""Run preregistered H10 in a new local directory."""

import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import time

from real_dual import (Q,ETA,M,L,NF,KF,SIZES,SAMPLES,numpy,array_hash,matrix_case,offsets,
                       make_bank,kernels,analytic,cbd_samples,observations,field_rank,character_checks)

ROOT=Path(__file__).resolve().parents[1]
INPUTS=['docs/PROTOCOLE_H10.md','research/real_dual.py','research/run_real_dual.py',
        'research/test_real_dual.py','research/verify_real_dual.py','research/verify_real_dual_independent.py',
        'research/block_decoder.py','research/block_decoder_numpy.py','research/lll_dimensions.py',
        'research/exact_lll.py','research/run_block_decoder.py','research/requirements-cbd-dimensions.txt',
        'results/j2/run-016/study.json']


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,indent=2,allow_nan=False)
        stream.write('\n')


def summary(cases,banks):
    groups=[]
    for family in ('repeated','radix'):
        rows=[b for b in banks if b['bank']['code']['family']==family]
        for N in SIZES:
            moments=[next(r for r in b['moments'] if r['N']==N and r['offset']==0) for b in rows]
            empirical=[next(r for r in b['observations']['records'] if r['N']==N and r['offset']==0) for b in rows]
            uniform=[next(r for r in b['observations']['uniform_null'] if r['N']==N) for b in rows]
            ranks=[next(r for r in b['observations']['selected_candidate_ranks'] if r['N']==N) for b in rows]
            groups.append(dict(family=family,N=N,matrices=len(rows),
                mean_true_log2_bias=sum(next(v['log2_bias'] for v in b['true_biases'] if v['N']==N) for b in rows)/len(rows),
                mean_true_variance=sum(r['variance'] for r in moments)/len(rows),
                mean_variance_over_baseline=sum(r['variance_over_uniform_baseline'] for r in moments)/len(rows),
                mean_empirical_true_variance=sum(r['variance'] for r in empirical)/len(rows),
                mean_uniform_variance=sum(r['variance'] for r in uniform)/len(rows),
                mean_uniform_three_sigma_tail=sum(r['tails'][1]['fraction'] for r in uniform)/len(rows),
                mean_LWE_true_three_sigma_tail=sum(r['tails'][1]['fraction'] for r in empirical)/len(rows),
                strict_selected_candidates=sum(r['true_strict_above_margin'] for r in ranks),
                ambiguous_selected_candidates=sum(r['ambiguous'] for r in ranks),total_states=len(rows)*SAMPLES))
    return dict(protocol_commit='6827a5a',q=Q,eta=ETA,matrices=len(cases),network_dimension=M+L,
                code_shape=[NF,KF],banks=len(banks),panels=len(banks)*len(SIZES),offsets=27,
                analytic_moment_records=sum(len(b['moments']) for b in banks),
                synthetic_CBD_states=len(cases)*SAMPLES,CBD_variables_per_state=M+L+NF,
                phase_identities=sum(b['observations']['phase_identities'] for b in banks),
                character_checks=sum(len(b['character_checks']) for b in banks),
                candidate_counts=[c['candidate_count'] for c in cases],groups=groups,
                population_laws_enumerated=False,all_q21_candidates_tested=False,
                attack_costs_updated=False,profile_selected=False,j2_closed=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve()
    if not output.is_relative_to(ROOT) or output==ROOT or output.exists():
        raise ValueError('new directory below NIST required')
    np=numpy()
    output.mkdir(parents=True)
    ds=offsets()
    cases,banks,timings=[],[],[]
    for identifier in range(4):
        start=time.perf_counter()
        case=matrix_case(identifier)
        elapsed=time.perf_counter()-start
        cases.append(case)
        timings.append(dict(identifier=identifier,step='matrix_LLL_box',seconds=elapsed))
        states,label=cbd_samples(identifier)
        for family in ('repeated','radix'):
            start=time.perf_counter()
            bank=make_bank(case,family)
            timings.append(dict(identifier=identifier,family=family,step='warm_tables_and_decode_128',seconds=time.perf_counter()-start))
            start=time.perf_counter()
            k=kernels(bank)
            c=np.asarray([v['c'] for v in bank['vectors']],dtype=np.int64)
            moments=[dict(N=N,offset=i,**analytic(k,c,d,N,Q)) for N in SIZES for i,d in enumerate(ds)]
            biases=[]
            for N in SIZES:
                top=float(np.max(k['logs'][:N]))
                bias=(top+math.log(float(np.sum(np.exp(k['logs'][:N]-top)))/N))/math.log(2)
                biases.append(dict(N=N,log2_bias=bias))
            timings.append(dict(identifier=identifier,family=family,step='kernels_and_moments',seconds=time.perf_counter()-start))
            start=time.perf_counter()
            obs=observations(bank,states,ds)
            timings.append(dict(identifier=identifier,family=family,step='LWE_and_uniform_observations',seconds=time.perf_counter()-start))
            banks.append(dict(bank=bank,CBD_seed_ascii=label,CBD_states_sha256=array_hash(states),
                              code_label_rank=field_rank(c.tolist(),Q),
                              selected_offsets_aliasing_true=[i for i,d in enumerate(ds) if i and np.all((c@np.asarray(d))%Q==0)],
                              moments=moments,true_biases=biases,character_checks=character_checks(k),
                              numerically_underflowed_kernel_entries=k['underflowed_kernel_entries'],
                              observations=obs))
            print(f'matrix {identifier} {family}: 128 vectors, 81 moment records, {obs["phase_identities"]} phase identities',flush=True)
    write(output/'cases.json',cases)
    write(output/'offsets.json',ds)
    write(output/'banks.json',banks)
    write(output/'summary.json',summary(cases,banks))
    write(output/'resources.json',dict(timings=timings,
        arrays=[dict(identifier=b['bank']['identifier'],family=b['bank']['code']['family'],
                     listed_array_bytes=b['observations']['listed_array_bytes'],
                     largest_listed_array_bytes=max(b['observations']['listed_array_bytes'].values()),
                     sum_listed_array_bytes=sum(b['observations']['listed_array_bytes'].values())) for b in banks],
        limits=['listed dense arrays only, not OS RSS or total allocator peak',
                'timings include Python/NumPy on this host; not rop or large-list extrapolation',
                'decoder timing includes table construction when not already cached']))
    names=('cases.json','offsets.json','banks.json','summary.json','resources.json')
    write(output/'provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
        protocol_commit='6827a5a',python=platform.python_version(),numpy=np.__version__,
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in INPUTS},
        output_sha256={n:hashlib.sha256((output/n).read_bytes()).hexdigest() for n in names}))
    print(json.dumps(summary(cases,banks),indent=2))


if __name__=='__main__':
    main()
