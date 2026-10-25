"""H13 independent full-coordinate cosine/sign expansion; exact fractions."""

import argparse
from collections import Counter
from datetime import datetime,timezone
from fractions import Fraction as F
import hashlib
import itertools
import json
import math
from pathlib import Path

import numpy as np

ROOT=Path(__file__).resolve().parents[1]


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def r(x):
    return dict(numerator=x.numerator,denominator=x.denominator)


def f(x):
    return F(x['numerator'],x['denominator'])


def centered(N,b):
    a,c,d,e=b
    variance=F(1,2*N)
    fourth=F(3*(2*N-1),8*N**3)
    dv=c+a*a
    df=e+a*(4*d+a*(6*(variance+c)+3*a*a))
    k=F(3*(2*N-1),2*N)
    delta=None if dv>=variance else (df+k*dv*(2*variance+dv))/(variance-dv)**2
    return dict(variance_positive_certified=delta is not None,variance_center=r(variance),
        variance_absolute_error_bound=r(dv),fourth_center=r(fourth),fourth_absolute_error_bound=r(df),
        independent_kurtosis=r(k),kurtosis_absolute_error_bound=None if delta is None else r(delta))


def full_histograms(a,q,cap):
    a=np.asarray(a,dtype=np.int64)%q
    N=len(a)
    output=[]
    evaluations=0
    for p in range(1,5):
        histogram=np.zeros(cap+1,dtype=np.int64)
        total=balanced_mass=zero_mass=0
        iterator=itertools.combinations_with_replacement(range(N),p)
        while batch:=list(itertools.islice(iterator,512)):
            ix=np.asarray(batch,dtype=np.int64)
            weights=np.asarray([math.factorial(p)//math.prod(math.factorial(v) for v in Counter(row).values())
                                for row in batch],dtype=np.int64)
            for signs in itertools.product((-1,1),repeat=p):
                balanced=np.zeros(len(ix),dtype=bool)
                if p==2 and signs[0]==-signs[1]:
                    balanced=ix[:,0]==ix[:,1]
                elif p==4:
                    for pairs in (((0,1),(2,3)),((0,2),(1,3)),((0,3),(1,2))):
                        (i,j),(k,l)=pairs
                        if signs[i]==-signs[j] and signs[k]==-signs[l]:
                            balanced|=(ix[:,i]==ix[:,j])&(ix[:,k]==ix[:,l])
                v=(sum(signs[j]*a[ix[:,j]] for j in range(p))+q//2)%q-q//2
                norms=np.einsum('ij,ij->i',v,v)
                total+=int(weights.sum())
                balanced_mass+=int(weights[balanced].sum())
                zero_mass+=int(weights[(norms==0)&~balanced].sum())
                exponents=np.minimum(cap,(norms*42)//(q*q))
                np.add.at(histogram,exponents[~balanced],weights[~balanced])
                evaluations+=len(batch)
        denominator=(2*N)**p
        if total!=denominator or balanced_mass!={1:0,2:2*N,3:0,4:6*N*(2*N-1)}[p]:
            raise ValueError('independent cosine/sign masses failed')
        # Integer common denominator, different from the primary Fraction sum.
        numerator=sum(int(w)*2**(cap-k) for k,w in enumerate(histogram))
        output.append(dict(order=p,signed_multisets=math.comb(2*N+p-1,p),total_ordered_mass=total,
            balanced_ordered_mass=balanced_mass,unbalanced_zero_coefficient_mass=zero_mass,
            attenuation_histogram={str(k):int(w) for k,w in enumerate(histogram) if w},
            raw_correction_absolute_bound=r(F(numerator,denominator*2**cap)),
            capped_mass_bound=r(F(int(histogram[cap]),denominator*2**cap))))
    return output,evaluations


def audit(run):
    if np.__version__!='2.3.5':
        raise RuntimeError('pinned NumPy 2.3.5 required')
    parents=read(ROOT/'results/j2/run-017/banks.json')
    orders=read(ROOT/'results/j2/run-018/orders.json')
    old_geometry={g['geometry_id']:g for g in read(ROOT/'results/j2/run-019/geometries.json')}
    old_banks=read(ROOT/'results/j2/run-019/banks.json')
    banks=read(run/'banks.json')
    calibrations=read(run/'calibrations.json')
    if [(b['identifier'],b['method'],b['family']) for b in banks]!=list(itertools.product(range(4),('norm','hash','energy'),('repeated','radix'))):
        raise ValueError('independent N32 selection coverage failed')
    if [(b['geometry_id'],b['identifier'],b['family']) for b in calibrations]!=[(b['geometry_id'],b['identifier'],b['family']) for b in old_banks]:
        raise ValueError('independent H12 calibration coverage failed')
    evaluations=0
    for record in banks+calibrations:
        indices=sorted(orders[record['identifier']]['orders'][record['method']][:32]) if 'method' in record else old_geometry[record['geometry_id']]['indices']
        if 'indices' in record and record['indices']!=indices:
            raise ValueError('independent frozen public prefix failed')
        parent=next(x['bank'] for x in parents if x['bank']['identifier']==record['identifier'] and x['bank']['code']['family']==record['family'])
        a=[parent['vectors'][i]['y']+parent['vectors'][i]['x']+parent['vectors'][i]['r'] for i in indices]
        ours,count=full_histograms(a,7681,128)
        evaluations+=count
        certificate=record['certificate']
        if (certificate['N'],certificate['q'],certificate['eta'],certificate['cap'])!=(len(indices),7681,3,128):
            raise ValueError('independent certificate scope failed')
        for x,y in zip(ours,certificate['orders'],strict=True):
            if x!={k:v for k,v in y.items() if k not in ('early_stopped_multisets','coordinates_evaluated')}:
                raise ValueError('independent exact histogram/bound failed')
        if centered(len(indices),[f(x['raw_correction_absolute_bound']) for x in ours])!=certificate['centered']:
            raise ValueError('independent central propagation failed')
    # Reconstruct the two rational premises without project imports.
    lower_pi=16*sum(F((-1)**j,(2*j+1)*5**(2*j+1)) for j in range(4))-F(4,239)
    lower_exp=F(1)+F(7,10)+F(49,200)+F(343,6000)
    if lower_pi<=F(157,50) or lower_exp<=2 or 3*F(157,50)**2<=42*F(7,10):
        raise ValueError('independent analytic constants failed')
    if read(run/'constants.json')!=dict(machin_pi_lower=r(lower_pi),exp_point_seven_lower=r(lower_exp),gaussian_dyadic_factor=42,eta=3):
        raise ValueError('independent constant records failed')
    return dict(project_arithmetic_imported=False,full_coordinates_used=True,N32_banks_verified=len(banks),
        H12_banks_verified=len(calibrations),cosine_sign_evaluations=evaluations,
        histograms_and_rational_bounds_matched=True,rare_tail_certified=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,default=ROOT/'results/j2/run-020')
    run=parser.parse_args().run.resolve()
    if not run.is_relative_to(ROOT) or run==ROOT:
        raise ValueError('run below NIST required')
    result=audit(run)
    output=run/'independent-verification.json'
    def write(path,value):
        with path.open('x',encoding='utf-8',newline='\n') as stream:
            json.dump(value,stream,indent=2,allow_nan=False)
            stream.write('\n')
    if output.exists():
        if read(output)!=result:
            raise ValueError('independent H13 replay differs')
    else:
        write(output,result)
        names=['docs/PROTOCOLE_H13.md','research/verify_bounded_moments_independent.py',
            'research/requirements-cbd-dimensions.txt','results/j2/run-017/banks.json',
            'results/j2/run-018/orders.json','results/j2/run-019/geometries.json','results/j2/run-019/banks.json']
        names += [(run/f'{n}.json').relative_to(ROOT).as_posix() for n in ('constants','banks','calibrations')]
        write(run/'independent-provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
            input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
            output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
