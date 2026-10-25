"""H09 Decimal replay: no imports of project arithmetic or attack code."""

import argparse
from datetime import datetime, timezone
from decimal import Decimal as D, localcontext
from functools import cache
import hashlib
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PI=D('3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117068')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def log2(x):
    return x.ln()/D(2).ln()


def exp2(x):
    return (x*D(2).ln()).exp()


def tail(x):
    if x>=12:
        # Integration by parts bounds Q(x): successive Mills truncations
        # bracket the integral. Positive remainder has the next-term bound.
        term=total=D(1)
        for j in range(1,25):
            term *= -D(2*j-1)/(x*x)
            total += term
        other=total+term*(-D(49)/(x*x))
        if abs(log2(total)-log2(other))>D('1e-12'):
            raise ArithmeticError('Mills bracket too wide')
        return (-x*x/2).exp()/(x*(2*PI).sqrt())*(total+other)/2
    # Independently integrate the Taylor series of exp(-t^2/2).
    term=total=x
    for j in range(1,10000):
        term *= -x*x*D(2*j-1)/(D(2*j)*D(2*j+1))
        total += term
        if abs(term)<D('1e-95'):
            return D('.5')-total/(2*PI).sqrt()
    raise ArithmeticError('normal Taylor series did not converge')


def normal(M,N,mu,inflation=D(1)):
    return M+log2(tail((2*exp2(N)*exp2(2*mu)/inflation).sqrt()))


def code_factor(q,eta,n,k):
    if n%2==0:
        gamma=D(math.factorial(n//2))
    else:
        h=(n+1)//2
        gamma=D(math.factorial(2*h))*PI.sqrt()/D(4**h*math.factorial(h))
    radius=(((1-D(k)/n)*D(q).ln()+gamma.ln()/n-PI.ln()/2).exp()*D(n+1)/n)
    c=D(eta)*(PI*radius/q)**2
    # Different expansion from the primary positive incomplete-gamma series.
    power=D(1)
    total=D(1)
    for j in range(1,10000):
        power *= -c/j
        term=power*D(n)/D(n+2*j)
        total+=term
        if j>c and abs(term)<D('1e-95'):
            return log2(total)
    raise ArithmeticError('code integral series did not converge')


@cache
def coordinate(q,eta,r):
    x=PI*abs(r)/q
    term=total=D(1)
    for j in range(1,200):
        term *= -x*x/D((2*j-1)*(2*j))
        total += term
        if abs(term)<D('1e-95'):
            return 2*eta*log2(total)
    raise ArithmeticError('cosine series did not converge')


def replay(run):
    saved=read(run/'study.json')
    parent=read(ROOT/'results/j2/run-009/study.json')['minima']
    residuals=[json.loads(s) for s in (ROOT/'results/j2/run-011/residuals.jsonl').read_text().splitlines()]
    deltas=[]
    def near(actual,expected):
        delta=abs(D(str(actual))-expected)
        deltas.append(float(delta))
        if delta>D('1e-8'):
            raise ValueError(f'independent H09 mismatch: {actual} vs {expected}')
    if saved['protocol_commit']!='a0b9fab' or len(saved['points'])!=4 or any(saved[k] for k in ('attack_costs_updated','profile_selected','j2_closed')):
        raise ValueError('independent H09 scope mismatch')
    rows_verified=0
    for i,(old,new) in enumerate(zip(parent,saved['points'])):
        p=old['inputs']
        q,eta,n,k=p['q'],p['eta'],p['nfft'],p['kfft']
        N,mu=D(str(old['log2_list_size'])),D(str(old['log2_relative_threshold']))
        M=D(str(old['log2_repetitions']))+k*log2(D(q))
        ideal=code_factor(q,eta,n,k)
        if new['inputs']!=p or new['parent_index']!=old['index'] or new['lattice_dimension']!=old['lattice_dimension']:
            raise ValueError('independent parent link failed')
        for name,value in (('log2_list_size',N),('log2_threshold',mu),('log2_candidate_budget',M),
                           ('log2_ideal_code_factor',ideal),('log2_inferred_network_factor',mu-ideal)):
            near(new[name],value)
        if [s['variance_inflation'] for s in new['normal_sensitivity']]!=[1.,1.01,1.1,2.]:
            raise ValueError('independent sensitivity coverage failed')
        for s in new['normal_sensitivity']:
            near(s['log2_union_budget'],normal(M,N,mu,D(str(s['variance_inflation']))))
        near(old['log2_epsilon'],normal(M,N,mu))
        lo,hi=D(1),D(2)
        for _ in range(80):
            mid=(lo+hi)/2
            if normal(M,N,mu,mid)<=log2(D('.05')):
                lo=mid
            else:
                hi=mid
        limit=(lo+hi)/2
        covariance=lambda e: log2(e/(2*(exp2(N)-1)))
        v=new['normal_budget_variance_limit']
        near(v['maximum_inflation'],limit)
        near(v['relative_excess'],limit-1)
        near(v['log2_max_mean_off_diagonal_covariance'],covariance(limit-1))
        if [c['relative_variance_excess'] for c in new['covariance_tolerances']]!=[.01,.1,1.]:
            raise ValueError('independent covariance coverage failed')
        for c in new['covariance_tolerances']:
            near(c['log2_max_mean_off_diagonal_covariance'],covariance(D(str(c['relative_variance_excess']))))
        c=new['moment_only_diagnostic']
        bound=exp2(M)/(1+2*exp2(N+2*mu))
        required=log2((exp2(M)/D('.05')-1)/(2*exp2(2*mu)))
        near(c['log2_unclipped_union_bound'],log2(bound))
        near(c['clipped_union_bound'],min(D(1),bound))
        near(c['log2_sufficient_N_at_fixed_mu'],required)
        near(c['additional_list_bits'],required-N)
        if c['full_wrong_candidate_moments_validated'] or c['assumed_wrong_mean']!=0 or c['assumed_wrong_variance']!='1/(2N)':
            raise ValueError('conditional moment scope failed')
        dimension=old['lattice_dimension']
        sizes=[(dimension*(q-1).bit_length()+7)//8,8*dimension]
        if len(new['storage_models'])!=2:
            raise ValueError('storage coverage failed')
        for model,name,size in zip(new['storage_models'],('dense_mod_q_packed','dense_64_bit_coordinates'),sizes):
            if model['representation']!=name or model['bytes_per_vector']!=size or [b['log2_bytes'] for b in model['illustrative_caps']]!=[40,60,80]:
                raise ValueError('storage model failed')
            near(model['log2_list_bytes'],N+log2(D(size)))
            for cap in model['illustrative_caps']:
                maximum=log2(D((1<<cap['log2_bytes'])//size))
                near(cap['log2_max_vectors'],maximum)
                near(cap['list_excess_bits'],N-maximum)
        if len(new['concrete_sample_diagnostics'])!=2:
            raise ValueError('sample family coverage failed')
        for panel,family in zip(new['concrete_sample_diagnostics'],('repeated','radix')):
            label=f'panel-{i}-{family}'
            rows=[r for r in residuals if r['experiment']==label]
            if panel['experiment']!=label or panel['count']!=len(rows) or len(rows)!=256 or panel['certified_population_mean'] or panel['attack_cost_updated']:
                raise ValueError('sample scope failed')
            exact,gaussian=[],[]
            for r in rows:
                if len(r['residual'])!=n or any(abs(v)>q//2 for v in r['residual']) or sum(v*v for v in r['residual'])!=r['squared_norm']:
                    raise ValueError('independent residual failed')
                exact.append(sum((coordinate(q,eta,v) for v in r['residual']),D(0)))
                gaussian.append(-eta*PI*PI*D(r['squared_norm'])/D(q*q)/D(2).ln())
            weights=[exp2(v) for v in exact]
            total=sum(weights)
            mean=log2(total/len(rows))
            near(panel['log2_mean_CBD'],mean)
            near(panel['log2_mean_Gaussian_upper'],log2(sum(exp2(v) for v in gaussian)/len(rows)))
            near(panel['effective_weighted_sample_count'],total*total/sum(w*w for w in weights))
            near(panel['largest_sample_share'],max(weights)/total)
            near(panel['log2_mean_over_ideal_code'],mean-ideal)
            diagnostic_mu=mu-ideal+mean
            near(panel['log2_diagnostic_full_threshold'],diagnostic_mu)
            near(panel['log2_diagnostic_normal_budget'],normal(M,N,diagnostic_mu))
            rows_verified+=len(rows)
    return dict(project_arithmetic_imported=False,decimal_digits=90,points_verified=4,
                residuals_verified=rows_verified,numeric_fields_verified=len(deltas),
                maximum_absolute_delta=max(deltas),normal_tail_method='Mills brackets and integrated Taylor series',
                code_integral_method='alternating exponential series')


def write(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as f:
        json.dump(value,f,indent=2,allow_nan=False)
        f.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,default=ROOT/'results/j2/run-016')
    run=parser.parse_args().run.resolve()
    if not run.is_relative_to(ROOT) or run==ROOT:
        raise ValueError('run below NIST required')
    with localcontext() as ctx:
        ctx.prec=90
        result=replay(run)
    output=run/'independent-verification.json'
    if output.exists():
        if read(output)!=result:
            raise ValueError('independent H09 replay changed')
    else:
        write(output,result)
        names=['research/verify_score_transfer_independent.py','docs/PROTOCOLE_H09.md',
               'results/j2/run-009/study.json','results/j2/run-011/residuals.jsonl',
               (run/'study.json').relative_to(ROOT).as_posix()]
        write(run/'independent-provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
            input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
            output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
