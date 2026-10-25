"""Independent H11 pair convolutions, closed-form greedy increments and scores.

No project arithmetic imports. Exact uniform moments; CBD moments numeric.
"""

import argparse
from datetime import datetime,timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
Q=7681
NS=(32,64,128)
METHODS=('norm','hash','energy')
OFFSETS=(0,1,22,24)


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def ah(a):
    h=json.dumps(dict(shape=list(a.shape),dtype='<i8'),sort_keys=True,separators=(',',':')).encode()+b'\n'
    return hashlib.sha256(h+np.asarray(a,dtype='<i8',order='C').tobytes()).hexdigest()


def uniform(n,count,label):
    values=[]
    k=0
    while len(values)<n*count:
        raw=hashlib.shake_256(label.encode()+k.to_bytes(8,'little')).digest(4096)
        k+=1
        for j in range(0,len(raw),2):
            v=raw[j]+256*raw[j+1]
            if v<65536//Q*Q:
                values.append(v%Q)
                if len(values)==n*count:
                    break
    return np.asarray(values,dtype=np.int64).reshape(count,n)


def pack(v):
    return sum((int(x)%Q)*Q**j for j,x in enumerate(v))


def vector_add(a,b):
    return tuple((int(x)+int(y))%Q for x,y in zip(a,b))


def convolution(B):
    if not B:
        return {}
    a=np.asarray(B,dtype=np.int64)
    pairs=(a[:,None,:]+a[None,:,:])%Q
    keys=sum(pairs[:,:,j]*Q**j for j in range(a.shape[1])).reshape(-1)
    unique,counts=np.unique(keys,return_counts=True)
    return dict(zip(map(int,unique),map(int,counts)))


def rational(x):
    x=Fraction(x)
    return dict(numerator=x.numerator,denominator=x.denominator)


def uniform_moments(ys):
    N=len(ys)
    B=[tuple(sign*x%Q for x in y) for y in ys for sign in (1,-1)]
    if len(set(B))!=2*N or (0,0,0) in B:
        raise ValueError('independent orthogonality hypotheses failed')
    P=convolution(B)
    triple=sum(P.get(pack(b),0) for b in B)
    energy=sum(v*v for v in P.values())
    var=Fraction(1,2*N)
    third=Fraction(triple,(2*N)**3)
    fourth=Fraction(energy,(2*N)**4)
    kurt=fourth/var**2
    return dict(N=N,mean=rational(0),variance=rational(var),third=rational(third),fourth=rational(fourth),
                ordered_signed_triples=triple,ordered_signed_quadruples=energy,
                independent_quadruples=12*N*N-6*N,extra_quadruples=energy-(12*N*N-6*N),
                pair_support=len(P),pair_spectrum_sha256=digest(sorted(P.items())),
                skewness=float(third)/float(var)**1.5,kurtosis=rational(kurt),
                independent_cosine_kurtosis=rational(3-Fraction(3,2*N)),
                fourth_moment_three_sigma_upper=rational(min(Fraction(1),kurt/81)))


def check_order(record,ys):
    B=[]
    P={}
    energy=0
    order=[]
    total=0
    for row in record['energy_trace']:
        Bset=set(B)
        costs=[]
        for i,y0 in enumerate(ys):
            if i in order:
                continue
            y=tuple(x%Q for x in y0)
            two=tuple(2*x%Q for x in y)
            three=tuple(3*x%Q for x in y)
            # Closed form from expanding ||P+2(1_B shifted by ±y)
            # +2*delta_0+delta_2y+delta_-2y||_2^2. Primary uses a delta Counter.
            term=sum(P.get(pack(vector_add(b,y)),0) for b in B)
            overlap=sum(vector_add(b,two) in Bset for b in B)
            increment=(8*term+4*P.get(0,0)+4*P.get(pack(two),0)
                       +8*len(B)+8*overlap+8*int(three in Bset)+6)
            costs.append((i,energy+increment))
        i,value=min(costs,key=lambda v:(v[1],v[0]))
        if row!=dict(selected=i,energy=value,candidate_evaluations=len(costs),candidate_costs_sha256=digest(costs)):
            raise ValueError('independent greedy choice/cost trace failed')
        order.append(i)
        B.extend([tuple(x%Q for x in ys[i]),tuple(-x%Q for x in ys[i])])
        P=convolution(B)  # full rebuild at every step, no incremental update
        energy=sum(v*v for v in P.values())
        if value!=energy:
            raise ValueError('closed-form increment/full convolution mismatch')
        total+=len(costs)
    expected=dict(norm=list(range(128)),
                  hash=sorted(range(128),key=lambda i:(hashlib.sha256(f"nist-j2-additive-v1:hash:{record['identifier']}:{i}".encode()).digest(),i)),
                  energy=order)
    if len(order)!=128 or record['orders']!=expected or record['energy_candidate_evaluations']!=total:
        raise ValueError('independent public orders failed')
    return total


def stats(values,N):
    mean=math.fsum(map(float,values))/len(values)
    centered=values-mean
    var=float(np.sum(centered**2)/len(values))
    tails=[]
    for t in (math.sqrt(2/N),3/math.sqrt(2*N),.5):
        hits=int(np.count_nonzero(values>t+1e-12))
        ambiguous=int(np.count_nonzero(np.abs(values-t)<=1e-12))
        p=hits/len(values)
        z=1.959963984540054
        div=1+z*z/len(values)
        middle=(p+z*z/(2*len(values)))/div
        radius=z*math.sqrt((p*(1-p)+z*z/(4*len(values)))/len(values))/div
        tails.append(dict(threshold=t,hits_above_margin=hits,ambiguous=ambiguous,fraction=p,
                          wilson95_approx_iid=[max(0.,middle-radius),min(1.,middle+radius)],
                          normal_zero_mean_baseline_tail=math.erfc(t*math.sqrt(N))/2))
    return dict(samples=len(values),mean=mean,variance=var,tails=tails,
                raw_third=float(np.sum(values**3)/len(values)),raw_fourth=float(np.sum(values**4)/len(values)),
                skewness=float(np.sum(centered**3)/len(values))/var**1.5 if var else None,
                kurtosis=float(np.sum(centered**4)/len(values))/var**2 if var else None)


def rank(rows):
    a=[list(map(int,row)) for row in zip(*rows)]
    r=0
    for j in range(len(a[0])):
        p=next((i for i in range(r,len(a)) if a[i][j]%Q),None)
        if p is None:
            continue
        a[p],a[r]=a[r],a[p]
        inv=pow(a[r][j],-1,Q)
        a[r]=[x*inv%Q for x in a[r]]
        for i in range(len(a)):
            if i!=r:
                v=a[i][j]
                a[i]=[(x-v*y)%Q for x,y in zip(a[i],a[r])]
        r+=1
        if r==len(a):
            break
    return r


def audit(run):
    if np.__version__!='2.3.5':
        raise RuntimeError('pinned NumPy 2.3.5 required')
    parent=ROOT/'results/j2/run-017'
    cases=read(parent/'cases.json')
    old=read(parent/'banks.json')
    ds=read(parent/'offsets.json')
    orders=read(run/'orders.json')
    panels=read(run/'panels.json')
    geometries=read(run/'geometries.json')
    banks=read(run/'banks.json')
    pools=read(run/'pools.json')
    maximum=normalized_mean_error=0.
    def compare(a,b):
        nonlocal maximum
        if isinstance(a,dict):
            if set(a)!=set(b):
                raise ValueError('independent H11 fields differ')
            for k in a:
                compare(a[k],b[k])
        elif isinstance(a,list):
            if len(a)!=len(b):
                raise ValueError('independent H11 lengths differ')
            for x,y in zip(a,b):
                compare(x,y)
        elif isinstance(a,float):
            delta=abs(a-b)
            maximum=max(maximum,delta)
            if not math.isfinite(b) or delta>1e-9*(1+abs(a)):
                raise ValueError(f'independent H11 numeric mismatch: {a} / {b}')
        elif a!=b:
            raise ValueError(f'independent H11 exact mismatch: {a} / {b}')
    if len(orders)!=4 or len(panels)!=36 or len(pools)!=12:
        raise ValueError('independent H11 panel coverage failed')
    costs=0
    expected_panels=[]
    by_g={g['geometry_id']:g for g in geometries}
    used=set()
    uniform_calibs=CBD_calibs=phase_count=0
    cosine=np.asarray([math.cos(2*math.pi*j/Q) for j in range(Q)])
    lookup=[6*math.log(math.cos(math.pi*j/Q)) for j in range(Q//2+1)]
    for identifier,case in enumerate(cases):
        record=orders[identifier]
        if record['identifier']!=identifier:
            raise ValueError('order matrix link failed')
        ys=[v['y'] for v in case['vectors']]
        costs+=check_order(record,ys)
        keys=set()
        for method in METHODS:
            for N in NS:
                ix=sorted(record['orders'][method][:N])
                key=digest(dict(identifier=identifier,indices=ix))
                expected_panels.append(dict(identifier=identifier,method=method,N=N,geometry_id=key))
                g=by_g[key]
                if (g['identifier'],g['N'],g['indices'])!=(identifier,N,ix):
                    raise ValueError('independent geometry sharing failed')
                keys.add(key)
        U=uniform(3,8192,f'nist-j2-additive-v1:uniform:{identifier}')
        uphases=sum(U[:,j,None]*np.asarray(ys,dtype=np.int64)[:,j][None,:] for j in range(3))%Q
        pool=next(p for p in pools if p['identifier']==identifier and p['kind']=='uniform')
        compare(dict(identifier=identifier,kind='uniform',seed_ascii=f'nist-j2-additive-v1:uniform:{identifier}',
                     states_sha256=ah(U),phases_sha256=ah(uphases),states_bytes=int(U.nbytes),phases_bytes=int(uphases.nbytes)),pool)
        oldU=uniform(3,4096,f'nist-j2-real-dual-v1:uniform:{identifier}')
        oldphase=oldU@np.asarray(ys,dtype=np.int64).T%Q
        for key in keys:
            g=by_g[key]
            ix,N=g['indices'],g['N']
            compare(uniform_moments([ys[i] for i in ix]),g['exact'])
            compare(stats(np.sum(cosine[uphases[:,ix]],axis=1)/N,N),g['empirical_uniform'])
            compare(sum(case['vectors'][i]['squared_norm'] for i in ix)/N,g['mean_lattice_squared_norm'])
            compare(max(case['vectors'][i]['squared_norm'] for i in ix),g['maximum_lattice_squared_norm'])
            used.add(key)
            if ix==list(range(N)):
                prior=next(r for r in old if r['bank']['identifier']==identifier and r['bank']['code']['family']=='radix')
                expected=next(r for r in prior['observations']['uniform_null'] if r['N']==N)
                current=stats(np.sum(cosine[oldphase[:,ix]],axis=1)/N,N)
                for field in ('mean','variance','tails'):
                    compare(current[field],expected[field])
                uniform_calibs+=1
        label=f'nist-j2-additive-v1:CBD:{identifier}'
        raw=np.frombuffer(hashlib.shake_256(label.encode()).digest(4096*145),dtype=np.uint8)
        bits=np.unpackbits(raw[:,None],axis=1,bitorder='little').astype(np.int64)
        Z=(bits[:,:3].sum(axis=1)-bits[:,3:6].sum(axis=1)).reshape(4096,145)
        E,S=Z[:,:3],Z[:,3:]
        for family in ('repeated','radix'):
            prior=next(r for r in old if r['bank']['identifier']==identifier and r['bank']['code']['family']==family)
            bank=prior['bank']
            vs=bank['vectors']
            Y=np.asarray([v['y'] for v in vs],dtype=np.int64)
            X=np.asarray([v['x'] for v in vs],dtype=np.int64)
            R=np.asarray([v['r'] for v in vs],dtype=np.int64)
            C=np.asarray([v['c'] for v in vs],dtype=np.int64)
            A=np.asarray(bank['A'],dtype=np.int64)
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
                raise ValueError('independent new full phase identity failed')
            phase_count+=lhs.size
            pool=next(p for p in pools if p['identifier']==identifier and p['kind']==family)
            compare(dict(identifier=identifier,kind=family,seed_ascii=label,states_sha256=ah(Z),phases_sha256=ah(rhs),
                         public_sha256=ah(public),truth_sha256=ah(truth),states_bytes=int(Z.nbytes),
                         phases_bytes=int(rhs.nbytes),unique_phase_identities=int(rhs.size)),pool)
            coefficients=[v['y']+v['x']+v['r'] for v in vs]
            lf=lambda a:math.fsum(lookup[abs((int(x)+Q//2)%Q-Q//2)] for x in a)
            logs=[lf(a) for a in coefficients]
            phis=[math.exp(x) for x in logs]
            plus=np.zeros((128,128))
            minus=np.zeros((128,128))
            for j in range(128):
                for k in range(j,128):
                    plus[j,k]=plus[k,j]=math.exp(lf([x+y for x,y in zip(coefficients[j],coefficients[k])]))
                    minus[j,k]=minus[k,j]=math.exp(lf([x-y for x,y in zip(coefficients[j],coefficients[k])]))
            for key in keys:
                g=by_g[key]
                ix,N=g['indices'],g['N']
                out=next(r for r in banks if r['geometry_id']==key and r['family']==family)
                if (out['identifier'],out['N'])!=(identifier,N):
                    raise ValueError('independent LWE link failed')
                top=max(logs[i] for i in ix)
                bias=(top+math.log(math.fsum(math.exp(logs[i]-top) for i in ix)/N))/math.log(2)
                compare(bias,out['log2_true_bias'])
                compare(rank(C[ix].tolist()),out['code_label_rank'])
                compare(sum(vs[i]['squared_residual_norm'] for i in ix)/N,out['mean_residual_squared_norm'])
                if [r['offset'] for r in out['observations']]!=list(OFFSETS):
                    raise ValueError('independent selected offset coverage failed')
                for result in out['observations']:
                    d=result['offset']
                    angles=[2*math.pi*(sum(x*y for x,y in zip(vs[i]['c'],ds[d]))%Q)/Q for i in ix]
                    means=[phis[i]*math.cos(t) for i,t in zip(ix,angles)]
                    mean=math.fsum(means)/N
                    variance=math.fsum((minus[i,j]*math.cos(angles[a]-angles[b])+plus[i,j]*math.cos(angles[a]+angles[b]))/2
                                       for a,i in enumerate(ix) for b,j in enumerate(ix))/N**2-mean*mean
                    diagonal=math.fsum((minus[i,i]+plus[i,i]*math.cos(2*angles[a]))/2-means[a]**2 for a,i in enumerate(ix))/N**2
                    theory=dict(mean=mean,variance=variance,diagonal_variance=diagonal,
                                off_diagonal_variance=variance-diagonal,variance_over_uniform_baseline=variance*2*N)
                    compare(theory,result['analytic'])
                    error=abs(mean-result['analytic']['mean'])/(math.fsum(phis[i] for i in ix)/N)
                    normalized_mean_error=max(error,normalized_mean_error)
                    if error>1e-9:
                        raise ValueError('independent tiny CBD mean lost precision')
                    phase=(rhs[:,ix]-np.asarray([sum(x*y for x,y in zip(vs[i]['c'],ds[d])) for i in ix])[None,:])%Q
                    compare(stats(np.sum(cosine[phase],axis=1)/N,N),result['empirical'])
                    if ix==list(range(N)):
                        expected=next(r for r in prior['moments'] if r['N']==N and r['offset']==d)
                        compare(theory,{name:expected[name] for name in theory})
                        CBD_calibs+=1
    compare(expected_panels,panels)
    if used!=set(by_g) or len(by_g)!=len(geometries) or len(banks)!=2*len(geometries) or (uniform_calibs,CBD_calibs)!=(12,96):
        raise ValueError('independent deduplication/calibration coverage failed')
    summary=read(run/'summary.json')
    if summary['protocol_commit']!='cfc924c' or summary['distinct_geometries']!=len(geometries) or summary['unique_full_phase_identities']!=phase_count or any(summary[k] for k in ('exact_CBD_fourth_moment_computed','all_q21_candidates_tested','attack_costs_updated','profile_selected','j2_closed')):
        raise ValueError('independent H11 summary scope mismatch')
    return dict(project_arithmetic_imported=False,numpy=np.__version__,matrices=4,greedy_costs_verified=costs,
                exact_uniform_laws_verified=len(geometries),LWE_panels_verified=len(banks),
                numerical_CBD_moments_verified=len(banks)*4,unique_phase_identities_verified=int(phase_count),
                H10_uniform_calibrations=uniform_calibs,H10_CBD_calibrations=CBD_calibs,
                all_selected_sample_events_and_hashes_matched=True,maximum_absolute_numeric_delta=maximum,
                maximum_mean_error_over_true_bias_scale=normalized_mean_error)


def write(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(v,stream,indent=2,allow_nan=False)
        stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,default=ROOT/'results/j2/run-018')
    run=parser.parse_args().run.resolve()
    if not run.is_relative_to(ROOT) or run==ROOT:
        raise ValueError('run below NIST required')
    result=audit(run)
    output=run/'independent-verification.json'
    if output.exists():
        ignore=('maximum_absolute_numeric_delta','maximum_mean_error_over_true_bias_scale')
        previous=read(output)
        if {k:v for k,v in previous.items() if k not in ignore}!={k:v for k,v in result.items() if k not in ignore}:
            raise ValueError('independent H11 replay changed')
    else:
        write(output,result)
        names=['research/verify_additive_score_independent.py','docs/PROTOCOLE_H11.md',
               'research/requirements-cbd-dimensions.txt','results/j2/run-017/cases.json',
               'results/j2/run-017/banks.json','results/j2/run-017/offsets.json']
        names += [(run/f'{n}.json').relative_to(ROOT).as_posix() for n in ('orders','panels','geometries','banks','pools','summary')]
        write(run/'independent-provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
            input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
            output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
