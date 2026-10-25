"""H12 independent cosine-index/sign expansion of CBD population moments.

No project arithmetic imports. Coordinate characters are calculated with
Decimal at 80 digits, then the finite expansions are evaluated numerically.
"""

import argparse
from collections import Counter
from datetime import datetime,timezone
from decimal import Decimal as D,localcontext
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
Q=7681
PI=D('3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117068')
NS=(4,8,16)
METHODS=('norm','hash','energy')
OFFSETS=(0,1,22,24)


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def ah(a):
    h=json.dumps(dict(shape=list(a.shape),dtype='<i8'),sort_keys=True,separators=(',',':')).encode()+b'\n'
    return hashlib.sha256(h+np.asarray(a,dtype='<i8',order='C').tobytes()).hexdigest()


def lookup_tables():
    logs=[]
    cosines=[]
    with localcontext() as ctx:
        ctx.prec=80
        for r in range(Q//2+1):
            x=PI*r/Q
            term=total=D(1)
            for j in range(1,200):
                term *= -x*x/D((2*j-1)*(2*j))
                total += term
                if abs(term)<D('1e-85'):
                    break
            else:
                raise ArithmeticError('Decimal cosine series failed')
            logs.append(float(6*total.ln()))
            cosines.append(float(2*total*total-1))
    return np.asarray(logs),np.asarray(cosines)


def signed_record(pos,neg,denominator):
    # Independent scalar fsum after one common rescaling per sign.
    def total(arrays):
        if not arrays:
            return None
        values=np.concatenate(arrays)
        peak=float(max(values))
        return peak+math.log(math.fsum(math.exp(float(v)-peak) for v in values))-math.log(denominator)
    p,n=total(pos),total(neg)
    with localcontext() as ctx:
        ctx.prec=100
        if p is None and n is None:
            return dict(sign=0,log2_abs=None,log2_positive=None,log2_negative=None,
                        log2_absolute_mass=None,absolute_over_mass=0.,cancellation_sensitive=False)
        peak=max(x for x in (p,n) if x is not None)
        a=D(0) if p is None else (D(str(p))-D(str(peak))).exp()
        b=D(0) if n is None else (D(str(n))-D(str(peak))).exp()
        value=a-b
        mass=a+b
        ln2=D(2).ln()
        ratio=float(abs(value)/mass)
        return dict(sign=0 if not value else 1 if value>0 else -1,
                    log2_abs=None if not value else float((D(str(peak))+abs(value).ln())/ln2),
                    log2_positive=None if p is None else p/math.log(2),
                    log2_negative=None if n is None else n/math.log(2),
                    log2_absolute_mass=float((D(str(peak))+mass.ln())/ln2),
                    absolute_over_mass=ratio,cancellation_sensitive=ratio<1e-10)


def decimal_value(c):
    return D(0) if not c['sign'] else D(c['sign'])*(D(str(c['log2_abs']))*D(2).ln()).exp()


def describe(x):
    return dict(sign=0 if not x else 1 if x>0 else -1,
                log2_abs=None if not x else float(abs(x).ln()/D(2).ln()),value=float(x))


def central(orders,N):
    with localcontext() as ctx:
        ctx.prec=100
        mu,c2,c3,c4=[decimal_value(r['correction']) for r in orders]
        v0=D(1)/(2*N)
        f0=D(3)/(4*N*N)-D(3)/(8*N**3)
        independent=f0/(v0*v0)
        dv=c2-mu*mu
        variance=v0+dv
        third=c3+mu*(2*mu*mu-3*v0-3*c2)
        change4=c4+mu*(-4*c3+mu*(6*v0+6*c2-3*mu*mu))
        fourth=f0+change4
        delta=(c4-4*mu*c3+6*mu**2*(v0+c2)-3*mu**4
               +independent*(2*v0*mu**2-2*v0*c2-c2**2+2*c2*mu**2-mu**4))/variance**2
        base=Fraction(3)-Fraction(3,2*N)
        return dict(mean=float(mu),variance=float(variance),third=describe(third),fourth=float(fourth),
                    skewness=describe(third/variance.sqrt()**3),kurtosis=float(fourth/variance**2),
                    independent_cosine_kurtosis=dict(numerator=base.numerator,denominator=base.denominator),
                    kurtosis_delta_vs_independent=describe(delta),variance_correction=describe(dv),
                    central_fourth_correction=describe(change4))


def expansion(a,c,ds,lookup,cosines):
    a=np.asarray(a,dtype=np.int64)
    c=np.asarray(c,dtype=np.int64)
    ds=np.asarray(ds,dtype=np.int64)
    N=len(a)
    output=[[] for _ in ds]
    counts=[]
    evaluated=0
    for p in range(1,5):
        pos=[[] for _ in ds]
        neg=[[] for _ in ds]
        mass=balanced_mass=zero_mass=underflow_mass=0
        original=itertools.combinations_with_replacement(range(N),p)
        while batch:=list(itertools.islice(original,256)):
            ix=np.asarray(batch,dtype=np.int64)
            weights=np.asarray([math.factorial(p)//math.prod(math.factorial(v) for v in Counter(row).values())
                                for row in batch],dtype=np.int64)
            for signs in itertools.product((-1,1),repeat=p):
                coefficients=sum(s*a[ix[:,j]] for j,s in enumerate(signs))
                residues=(coefficients+Q//2)%Q-Q//2
                labels=sum(s*c[ix[:,j]] for j,s in enumerate(signs))%Q
                balanced=[]
                for row in batch:
                    net=Counter()
                    for i,s in zip(row,signs):
                        net[i]+=s
                    balanced.append(not any(net.values()))
                balanced=np.asarray(balanced,dtype=bool)
                zero=np.all(residues==0,axis=1)
                if np.any(labels[zero]):
                    raise ValueError('independent zero coefficient/code-label identity failed')
                logs=lookup[np.abs(residues)].sum(axis=1)
                mass+=int(weights.sum())
                balanced_mass+=int(weights[balanced].sum())
                zero_mass+=int(weights[zero&~balanced].sum())
                underflow_mass+=int(weights[(np.exp(logs)==0)&~balanced].sum())
                evaluated+=len(batch)
                use=~balanced
                lw=logs[use]+np.log(weights[use])
                phases=(labels[use]@ds.T)%Q
                values=cosines[np.abs((phases+Q//2)%Q-Q//2)]
                for j in range(len(ds)):
                    for sign,acc in ((1,pos),(-1,neg)):
                        keep=sign*values[:,j]>0
                        if np.any(keep):
                            acc[j].append(lw[keep]+np.log(np.abs(values[keep,j])))
        denominator=(2*N)**p
        if mass!=denominator or balanced_mass!={1:0,2:2*N,3:0,4:12*N*N-6*N}[p]:
            raise ValueError('independent cosine/sign expansion mass failed')
        counts.append(dict(order=p,multisets=math.comb(2*N+p-1,p),total_ordered_mass=mass,
                           balanced_ordered_mass=balanced_mass,unbalanced_zero_coefficient_mass=zero_mass,
                           unbalanced_exp_underflow_ordered_mass=underflow_mass))
        for j in range(len(ds)):
            corr=signed_record(pos[j],neg[j],denominator)
            with localcontext() as ctx:
                ctx.prec=100
                raw=D(balanced_mass)/denominator+decimal_value(corr)
            fraction=Fraction(balanced_mass,denominator)
            output[j].append(dict(order=p,normalizer=denominator,balanced_mass=balanced_mass,
                balanced_fraction=dict(numerator=fraction.numerator,denominator=fraction.denominator),
                raw_moment=float(raw),correction=corr))
    return dict(counts=counts,offsets=[dict(index=j,orders=r,central=central(r,N),offset=OFFSETS[j])
                                      for j,r in enumerate(output)]),evaluated


def uniform_moments(ys):
    N=len(ys)
    B=np.asarray([tuple(sign*x%Q for x in y) for y in ys for sign in (1,-1)],dtype=np.int64)
    pairs=(B[:,None,:]+B[None,:,:])%Q
    codes=(pairs[:,:,0]+Q*pairs[:,:,1]+Q**2*pairs[:,:,2]).reshape(-1)
    keys,values=np.unique(codes,return_counts=True)
    P=dict(zip(map(int,keys),map(int,values)))
    triples=sum(P.get(int(b[0]+Q*b[1]+Q**2*b[2]),0) for b in B)
    E=sum(v*v for v in P.values())
    var=Fraction(1,2*N)
    third=Fraction(triples,(2*N)**3)
    fourth=Fraction(E,(2*N)**4)
    kurt=fourth/var**2
    r=lambda x:dict(numerator=Fraction(x).numerator,denominator=Fraction(x).denominator)
    return dict(N=N,mean=r(0),variance=r(var),third=r(third),fourth=r(fourth),
        ordered_signed_triples=triples,ordered_signed_quadruples=E,independent_quadruples=12*N*N-6*N,
        extra_quadruples=E-(12*N*N-6*N),pair_support=len(P),pair_spectrum_sha256=digest(sorted(P.items())),
        skewness=float(third)/float(var)**1.5,kurtosis=r(kurt),independent_cosine_kurtosis=r(3-Fraction(3,2*N)),
        fourth_moment_three_sigma_upper=r(min(Fraction(1),kurt/81)))


def stats(values,N):
    mean=math.fsum(map(float,values))/len(values)
    centered=values-mean
    var=float(np.sum(centered**2)/len(values))
    tails=[]
    for threshold in (math.sqrt(2/N),3/math.sqrt(2*N),.5):
        hits=int(np.count_nonzero(values>threshold+1e-12))
        ambiguous=int(np.count_nonzero(np.abs(values-threshold)<=1e-12))
        p=hits/len(values)
        z=1.959963984540054
        den=1+z*z/len(values)
        middle=(p+z*z/(2*len(values)))/den
        radius=z*math.sqrt((p*(1-p)+z*z/(4*len(values)))/len(values))/den
        tails.append(dict(threshold=threshold,hits_above_margin=hits,ambiguous=ambiguous,fraction=p,
                          wilson95_approx_iid=[max(0.,middle-radius),min(1.,middle+radius)],
                          normal_zero_mean_baseline_tail=math.erfc(threshold*math.sqrt(N))/2))
    return dict(samples=len(values),mean=mean,variance=var,tails=tails,
                raw_third=float(np.sum(values**3)/len(values)),raw_fourth=float(np.sum(values**4)/len(values)),
                skewness=float(np.sum(centered**3)/len(values))/var**1.5,
                kurtosis=float(np.sum(centered**4)/len(values))/var**2)


def audit(run):
    if np.__version__!='2.3.5':
        raise RuntimeError('pinned NumPy 2.3.5 required')
    parents=read(ROOT/'results/j2/run-017/banks.json')
    ds=read(ROOT/'results/j2/run-017/offsets.json')
    orders=read(ROOT/'results/j2/run-018/orders.json')
    oldpools=read(ROOT/'results/j2/run-018/pools.json')
    panels=read(run/'panels.json')
    geometries=read(run/'geometries.json')
    records=read(run/'banks.json')
    pools=read(run/'pools.json')
    expected_panels=[]
    used=set()
    maximum=normalized_error=0.
    evaluated=phase_count=0
    def compare(a,b,path=()):
        nonlocal maximum
        if isinstance(a,dict):
            if set(a)!=set(b):
                raise ValueError(f'independent H12 fields differ: {path}')
            for k in a:
                compare(a[k],b[k],path+(k,))
        elif isinstance(a,list):
            if len(a)!=len(b):
                raise ValueError('independent H12 lengths differ')
            for i,(x,y) in enumerate(zip(a,b)):
                compare(x,y,path+(i,))
        elif isinstance(a,float):
            delta=abs(a-b)
            maximum=max(delta,maximum)
            tolerance=1e-7 if path and str(path[-1]).startswith('log2_') else 1e-10*(1+abs(a))
            if not math.isfinite(b) or delta>tolerance:
                raise ValueError(f'independent H12 numeric mismatch {path}: {a} / {b}')
        elif a!=b:
            raise ValueError(f'independent H12 exact mismatch {path}: {a} / {b}')
    if len(panels)!=36 or len(pools)!=8:
        raise ValueError('independent H12 coverage failed')
    by_g={g['geometry_id']:g for g in geometries}
    by_b={(b['geometry_id'],b['family']):b for b in records}
    lookup,phase_cos=lookup_tables()
    score_cos=np.asarray([math.cos(2*math.pi*j/Q) for j in range(Q)])
    for identifier in range(4):
        template=next(r['bank'] for r in parents if r['bank']['identifier']==identifier)
        ys=[v['y'] for v in template['vectors']]
        keys=set()
        for method in METHODS:
            for N in NS:
                ix=sorted(orders[identifier]['orders'][method][:N])
                key=digest(dict(identifier=identifier,indices=ix))
                expected_panels.append(dict(identifier=identifier,method=method,N=N,geometry_id=key))
                g=by_g[key]
                compare(dict(geometry_id=key,identifier=identifier,N=N,indices=ix,
                             uniform=uniform_moments([ys[i] for i in ix])),g)
                keys.add(key)
                used.add(key)
        label=f'nist-j2-additive-v1:CBD:{identifier}'
        raw=np.frombuffer(hashlib.shake_256(label.encode()).digest(4096*145),dtype=np.uint8)
        bits=np.unpackbits(raw[:,None],axis=1,bitorder='little').astype(np.int64)
        Z=(bits[:,:3].sum(axis=1)-bits[:,3:6].sum(axis=1)).reshape(4096,145)
        E,S=Z[:,:3],Z[:,3:]
        for family in ('repeated','radix'):
            bank=next(r['bank'] for r in parents if r['bank']['identifier']==identifier and r['bank']['code']['family']==family)
            vs=bank['vectors']
            A=np.asarray(bank['A'],dtype=np.int64)
            Y=np.asarray([v['y'] for v in vs],dtype=np.int64)
            X=np.asarray([v['x'] for v in vs],dtype=np.int64)
            R=np.asarray([v['r'] for v in vs],dtype=np.int64)
            C=np.asarray([v['c'] for v in vs],dtype=np.int64)
            public=(E+sum(S[:,j,None]*A[:,j][None,:] for j in range(142)))%Q
            truth=[]
            pos=2
            for gen in bank['code']['generators']:
                truth.append(sum(S[:,pos+j]*v for j,v in enumerate(gen))%Q)
                pos+=len(gen)
            truth=np.asarray(truth,dtype=np.int64).T.copy()
            lhs=(public@Y.T-truth@C.T)%Q
            rhs=(E@Y.T+S[:,:2]@X.T+S[:,2:]@R.T)%Q
            if not np.array_equal(lhs,rhs):
                raise ValueError('independent reused phase identity failed')
            phase_count+=lhs.size
            old=next(p for p in oldpools if p['identifier']==identifier and p['kind']==family)
            if ah(Z)!=old['states_sha256'] or ah(rhs)!=old['phases_sha256']:
                raise ValueError('independent H11 reused pool mismatch')
            pool=next(p for p in pools if p['identifier']==identifier and p['family']==family)
            compare(dict(identifier=identifier,family=family,seed_ascii=label,states_sha256=ah(Z),phases_sha256=ah(rhs),
                         reused_from_run018=True,phase_identities=int(rhs.size),states_bytes=int(Z.nbytes),phases_bytes=int(rhs.nbytes)),pool)
            for key in sorted(keys):
                g=by_g[key]
                ix,N=g['indices'],g['N']
                rec=by_b[key,family]
                a=[vs[i]['y']+vs[i]['x']+vs[i]['r'] for i in ix]
                result,count=expansion(a,C[ix],[ds[d] for d in OFFSETS],lookup,phase_cos)
                evaluated+=count
                compare(result,rec['population'])
                for ours,saved in zip(result['offsets'],rec['population']['offsets']):
                    for x,y in zip(ours['orders'],saved['orders']):
                        a0,b0=x['correction'],y['correction']
                        l1=[v for v in (a0['log2_absolute_mass'],b0['log2_absolute_mass']) if v is not None]
                        if l1:
                            peak=max(l1)
                            v=lambda r:0. if not r['sign'] else r['sign']*2**(r['log2_abs']-peak)
                            error=abs(v(a0)-v(b0))
                            normalized_error=max(error,normalized_error)
                            if error>1e-9:
                                raise ValueError('independent correction lost precision relative to mass')
                observations=[]
                for d in OFFSETS:
                    delta=np.asarray([sum(x*y for x,y in zip(vs[i]['c'],ds[d])) for i in ix],dtype=np.int64)
                    values=np.sum(score_cos[(rhs[:,ix]-delta[None,:])%Q],axis=1)/N
                    observations.append(dict(offset=d,**stats(values,N)))
                compare(observations,rec['observations'])
                if (rec['identifier'],rec['family'],rec['N'],rec['covariance_calibrations'],rec['largest_character_batch_coordinates'])!=(identifier,family,N,4,512*145):
                    raise ValueError('independent bank metadata failed')
    compare(expected_panels,panels)
    if used!=set(by_g) or len(records)!=2*len(geometries) or len(by_b)!=len(records):
        raise ValueError('independent H12 duplicate or missing bank')
    summary=read(run/'summary.json')
    if summary['protocol_commit']!='8354d10' or summary['population_moment_records']!=len(records)*16 or not summary['CBD_population_moments_through_order4'] or any(summary[k] for k in ('full_probability_law_enumerated','rare_tail_certified','attack_costs_updated','profile_selected','j2_closed')):
        raise ValueError('independent H12 summary scope failed')
    return dict(project_arithmetic_imported=False,numpy=np.__version__,coordinate_table_decimal_digits=80,
                distinct_geometries_verified=len(geometries),CBD_banks_verified=len(records),
                population_moment_records_verified=len(records)*16,cosine_sign_evaluations=evaluated,
                replayed_phase_identities=int(phase_count),all_multiplicities_and_sample_events_matched=True,
                maximum_absolute_numeric_delta=maximum,maximum_correction_error_over_absolute_mass=normalized_error)


def write(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(v,stream,indent=2,allow_nan=False)
        stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,default=ROOT/'results/j2/run-019')
    run=parser.parse_args().run.resolve()
    if not run.is_relative_to(ROOT) or run==ROOT:
        raise ValueError('run below NIST required')
    result=audit(run)
    output=run/'independent-verification.json'
    if output.exists():
        previous=read(output)
        ignore=('maximum_absolute_numeric_delta','maximum_correction_error_over_absolute_mass')
        if {k:v for k,v in previous.items() if k not in ignore}!={k:v for k,v in result.items() if k not in ignore}:
            raise ValueError('independent H12 replay changed')
    else:
        write(output,result)
        names=['research/verify_cbd_fourth_independent.py','docs/PROTOCOLE_H12.md',
               'research/requirements-cbd-dimensions.txt','results/j2/run-017/banks.json',
               'results/j2/run-017/offsets.json','results/j2/run-018/orders.json','results/j2/run-018/pools.json']
        names += [(run/f'{n}.json').relative_to(ROOT).as_posix() for n in ('panels','geometries','banks','pools','summary')]
        write(run/'independent-provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
            input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
            output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
