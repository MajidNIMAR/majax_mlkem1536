"""H10 independent geometry, full coefficients and synthetic score replay.

No project arithmetic imports. Decimal characters, scalar covariance sums,
different bit extraction and modular distances; same pinned array runtime.
"""

import argparse
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
Q,M,L,NF,KF,SAMPLES=7681,3,2,140,21,4096
NS=(32,64,128)
PI=D('3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117068')
TOL=1e-12


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def ah(a):
    head=json.dumps(dict(shape=list(a.shape),dtype='<i8'),sort_keys=True,separators=(',',':')).encode()+b'\n'
    return hashlib.sha256(head+np.asarray(a,dtype='<i8').tobytes(order='C')).hexdigest()


def uniform(n,count,label):
    values=[]
    counter=0
    while len(values)<n*count:
        raw=hashlib.shake_256(label.encode()+counter.to_bytes(8,'little')).digest(4096)
        counter+=1
        for j in range(0,len(raw),2):
            v=raw[j]+256*raw[j+1]
            if v<65536//Q*Q:
                values.append(v%Q)
                if len(values)==n*count:
                    break
    return np.asarray(values,dtype=np.int64).reshape(count,n)


def det(B):
    n=len(B)
    return sum((-1)**sum(p[i]>p[j] for i in range(n) for j in range(i+1,n))
               *math.prod(B[i][p[i]] for i in range(n)) for p in itertools.permutations(range(n)))


def case_check(c):
    A=uniform(L+NF,M,f"nist-j2-real-dual-v1:matrix:{c['identifier']}").tolist()
    if c['A']!=A or c['q']!=Q or (c['m'],c['l'])!=(M,L):
        raise ValueError('independent public matrix failed')
    r=c['reduction']
    B,R,U=r['original'],r['reduced'],r['unimodular']
    expected=[[int(i==j) for j in range(M)]+A[i][:L] for i in range(M)]
    expected += [[0]*M+[Q*int(i==j) for j in range(L)] for i in range(L)]
    if B!=expected or abs(det(U))!=1 or abs(det(R))!=Q**L or (np.asarray(U,dtype=np.int64)@np.asarray(B,dtype=np.int64)).tolist()!=R:
        raise ValueError('independent lattice certificate failed')
    replay=[row[:] for row in B]
    for op in r['trace']:
        if op[0]=='reduce':
            _,i,j,a=op
            replay[i]=[x-a*y for x,y in zip(replay[i],replay[j])]
        elif op[0]=='swap':
            i=op[1]
            replay[i],replay[i-1]=replay[i-1],replay[i]
        else:
            raise ValueError('invalid trace operation')
    if replay!=R or r['delta']!='3/4' or r['dimension']!=5:
        raise ValueError('independent trace failed')
    gram=[[sum(a*b for a,b in zip(v,w)) for w in R] for v in R]
    mu=[[Fraction(0)]*5 for _ in range(5)]
    norms=[]
    for i in range(5):
        for j in range(i):
            mu[i][j]=(Fraction(gram[i][j])-sum(mu[i][k]*mu[j][k]*norms[k] for k in range(j)))/norms[j]
            if abs(mu[i][j])>Fraction(1,2):
                raise ValueError('independent size reduction failed')
        norms.append(Fraction(gram[i][i])-sum(mu[i][j]**2*norms[j] for j in range(i)))
    if any(norms[i]<(Fraction(3,4)-mu[i][i-1]**2)*norms[i-1] for i in range(1,5)):
        raise ValueError('independent Lovasz condition failed')
    coeff=np.asarray(list(itertools.product(range(-2,3),repeat=5)),dtype=np.int64)
    values=(coeff@np.asarray(R,dtype=np.int64)+Q//2)%Q-Q//2
    found={}
    for v,a in zip(values.tolist(),coeff.tolist()):
        first=next((x for x in v[:M] if x),0)
        if first:
            sign=1 if first>0 else -1
            v=tuple(sign*x for x in v)
            found.setdefault(v,dict(y=list(v[:M]),x=list(v[M:]),squared_norm=sum(x*x for x in v),
                                    coefficients=[sign*x for x in a]))
    ordered=sorted(found.values(),key=lambda v:(v['squared_norm'],v['y'],v['x']))
    if c['candidate_count']!=len(ordered) or c['vectors']!=ordered[:128]:
        raise ValueError('independent bounded-list selection failed')


def check_code(bank,case):
    code=bank['code']
    family=code['family']
    generators=[]
    sizes=[NF//KF+(j<NF%KF) for j in range(KF)]
    for size in sizes:
        root=1
        while (root+1)**size<=Q:
            root+=1
        base=1 if family=='repeated' else root if (2*root+1)**size>=Q*2**size else root+1
        generators.append([base**j%Q for j in range(size)])
    if code['generators']!=generators or (code['q'],code['n'],code['k'])!=(Q,NF,KF):
        raise ValueError('independent code generators failed')
    terms=0
    for v,selected in zip(bank['vectors'],case['vectors']):
        if v['y']!=selected['y'] or v['x']!=selected['x'] or v['squared_lattice_norm']!=selected['squared_norm']:
            raise ValueError('independent bank/list link failed')
        y=np.asarray(v['y'],dtype=np.int64)
        t=(y@np.asarray(case['A'],dtype=np.int64)[:,L:])%Q
        if v['t']!=t.tolist():
            raise ValueError('independent code target failed')
        labels=[]
        residuals=[]
        pos=0
        for g in generators:
            errors=(t[pos:pos+len(g)][None,:]-np.arange(Q,dtype=np.int64)[:,None]*np.asarray(g)[None,:]+Q//2)%Q-Q//2
            distances=np.einsum('ij,ij->i',errors,errors)
            label=int(np.argmin(distances))
            labels.append(label)
            residuals.extend(errors[label].tolist())
            terms+=Q*len(g)
            pos+=len(g)
        if labels!=v['c'] or residuals!=v['r'] or sum(x*x for x in residuals)!=v['squared_residual_norm']:
            raise ValueError('independent exhaustive decoder failed')
    return terms


def decimal_table():
    values=[]
    for r in range(Q//2+1):
        x=PI*r/Q
        term=total=D(1)
        for j in range(1,200):
            term *= -x*x/D((2*j-1)*(2*j))
            total += term
            if abs(term)<D('1e-85'):
                break
        else:
            raise ArithmeticError('Decimal cosine did not converge')
        values.append(6*total.ln())
    return values


def stats(values,N):
    mean=float(sum(values)/len(values))
    variance=float(np.sum((values-mean)**2)/len(values))
    tails=[]
    for threshold in (math.sqrt(2/N),3/math.sqrt(2*N),.5):
        hits=sum(int(x>threshold+TOL) for x in values)
        ambiguous=sum(int(abs(x-threshold)<=TOL) for x in values)
        p=hits/len(values)
        z=1.959963984540054
        div=1+z*z/len(values)
        center=(p+z*z/(2*len(values)))/div
        half=z*math.sqrt((p*(1-p)+z*z/(4*len(values)))/len(values))/div
        tails.append(dict(threshold=threshold,hits_above_margin=hits,ambiguous=ambiguous,fraction=p,
                          wilson95_approx_iid=[max(0.,center-half),min(1.,center+half)],
                          normal_zero_mean_baseline_tail=math.erfc(threshold*math.sqrt(N))/2))
    return dict(samples=len(values),mean=mean,variance=variance,tails=tails)


def field_rank(C):
    a=[list(row) for row in zip(*C)]
    r=0
    for j in range(len(a[0])):
        pivot=next((i for i in range(r,len(a)) if a[i][j]%Q),None)
        if pivot is None:
            continue
        a[r],a[pivot]=a[pivot],a[r]
        a[r]=[(x*pow(a[r][j],-1,Q))%Q for x in a[r]]
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
    cases=read(run/'cases.json')
    records=read(run/'banks.json')
    ds=read(run/'offsets.json')
    expected=[[0]*KF]+[[int(i==j) for i in range(KF)] for j in range(KF)]
    expected += [[1]*KF,[1 if j%2==0 else Q-1 for j in range(KF)]]
    expected += uniform(KF,3,'nist-j2-real-dual-v1:offsets').tolist()
    if ds!=expected or len(cases)!=4 or [(b['bank']['identifier'],b['bank']['code']['family']) for b in records]!=[(i,f) for i in range(4) for f in ('repeated','radix')]:
        raise ValueError('independent experiment coverage failed')
    for i,c in enumerate(cases):
        if c['identifier']!=i:
            raise ValueError('matrix order failed')
        case_check(c)
    table=decimal_table()
    lookup=[float(x) for x in table]
    max_delta=0.
    count=phases_checked=decoder_terms=characters=0
    def compare(a,b):
        nonlocal max_delta
        if isinstance(a,dict):
            if set(a)!=set(b):
                raise ValueError('independent field mismatch')
            for name in a:
                compare(a[name],b[name])
        elif isinstance(a,list):
            if len(a)!=len(b):
                raise ValueError('independent length mismatch')
            for x,y in zip(a,b):
                compare(x,y)
        elif isinstance(a,float):
            delta=abs(a-b)
            max_delta=max(delta,max_delta)
            if not math.isfinite(b) or delta>1e-8:
                raise ValueError(f'independent numeric mismatch: {a}, {b}')
        elif a!=b:
            raise ValueError(f'independent exact mismatch: {a}, {b}')
    for rec in records:
        bank=rec['bank']
        i=bank['identifier']
        decoder_terms+=check_code(bank,cases[i])
        vs=bank['vectors']
        a=[v['y']+v['x']+v['r'] for v in vs]
        Y=np.asarray([v['y'] for v in vs],dtype=np.int64)
        X=np.asarray([v['x'] for v in vs],dtype=np.int64)
        R=np.asarray([v['r'] for v in vs],dtype=np.int64)
        C=np.asarray([v['c'] for v in vs],dtype=np.int64)
        center=lambda x:(int(x)+Q//2)%Q-Q//2
        lf=lambda v:math.fsum(lookup[abs(center(x))] for x in v)
        logs=[lf(v) for v in a]
        plus=np.zeros((128,128))
        minus=np.zeros((128,128))
        underflow=0
        for j in range(128):
            for k in range(j,128):
                p=math.exp(lf([x+y for x,y in zip(a[j],a[k])]))
                m=math.exp(lf([x-y for x,y in zip(a[j],a[k])]))
                plus[j,k]=plus[k,j]=p
                minus[j,k]=minus[k,j]=m
                underflow+=(1 if j==k else 2)*(int(p==0)+int(m==0))
        compare(underflow,rec['numerically_underflowed_kernel_entries'])
        phis=[math.exp(x) for x in logs]
        moments=[]
        for N in NS:
            top=max(logs[:N])
            compare(dict(N=N,log2_bias=(top+math.log(math.fsum(math.exp(x-top) for x in logs[:N])/N))/math.log(2)),
                    next(r for r in rec['true_biases'] if r['N']==N))
            for d,delta in enumerate(ds):
                angles=[2*math.pi*(sum(x*y for x,y in zip(v['c'],delta))%Q)/Q for v in vs[:N]]
                means=[p*math.cos(t) for p,t in zip(phis[:N],angles)]
                mean=math.fsum(means)/N
                diag=math.fsum((minus[j,j]+plus[j,j]*math.cos(2*angles[j]))/2-means[j]**2 for j in range(N))/N**2
                raw=math.fsum((minus[j,k]*math.cos(angles[j]-angles[k])+plus[j,k]*math.cos(angles[j]+angles[k]))/2
                              for j in range(N) for k in range(N))/N**2
                variance=raw-mean*mean
                moments.append(dict(N=N,offset=d,mean=mean,variance=variance,diagonal_variance=diag,
                                    off_diagonal_variance=variance-diag,variance_over_uniform_baseline=variance*(2*N)))
        compare(moments,rec['moments'])
        count+=len(moments)
        expressions=[('a0',a[0]),('a127',a[127]),('a0+a1',[x+y for x,y in zip(a[0],a[1])]),
                     ('a0-a1',[x-y for x,y in zip(a[0],a[1])]),('a0+a127',[x+y for x,y in zip(a[0],a[127])]),
                     ('a0-a127',[x-y for x,y in zip(a[0],a[127])]),('a63+a127',[x+y for x,y in zip(a[63],a[127])]),
                     ('a63-a127',[x-y for x,y in zip(a[63],a[127])])]
        compare([dict(expression=name,log2_phi=float(sum((table[abs(center(x))] for x in v),D(0))/D(2).ln()))
                 for name,v in expressions],rec['character_checks'])
        characters+=len(expressions)
        label=f'nist-j2-real-dual-v1:CBD:{i}'
        raw=np.frombuffer(hashlib.shake_256(label.encode()).digest(SAMPLES*(M+L+NF)),dtype=np.uint8)
        bits=np.unpackbits(raw[:,None],axis=1,bitorder='little').astype(np.int64)
        Z=(bits[:,:3].sum(axis=1)-bits[:,3:6].sum(axis=1)).reshape(SAMPLES,M+L+NF)
        if rec['CBD_seed_ascii']!=label or ah(Z)!=rec['CBD_states_sha256']:
            raise ValueError('independent CBD bits failed')
        E,S=Z[:,:M],Z[:,M:]
        A=np.asarray(bank['A'],dtype=np.int64)
        public=(E+sum(S[:,j,None]*A[:,j][None,:] for j in range(L+NF)))%Q
        truth=[]
        pos=L
        for g in bank['code']['generators']:
            truth.append(sum(S[:,pos+j]*v for j,v in enumerate(g))%Q)
            pos+=len(g)
        truth=np.asarray(truth,dtype=np.int64).T.copy()
        lhs=(public@Y.T-truth@C.T)%Q
        rhs=(E@Y.T+S[:,:L]@X.T+S[:,L:]@R.T)%Q
        if not np.array_equal(lhs,rhs):
            raise ValueError('independent complete phase identity failed')
        phases_checked+=lhs.size
        uniform_label=f'nist-j2-real-dual-v1:uniform:{i}'
        U=uniform(M,SAMPLES,uniform_label)
        uphase=sum(U[:,j,None]*Y[:,j][None,:] for j in range(M))%Q
        arrays=dict(states=Z,public_b=public,true_symbols=truth,public_phases=lhs,direct_phases=rhs,
                    uniform_b=U,uniform_phases=uphase,coefficients=np.asarray(a,dtype=np.int64),code_labels=C)
        obs=rec['observations']
        compare({name:ah(value) for name,value in arrays.items()},obs['integer_array_hashes'])
        compare({name:int(value.nbytes) for name,value in arrays.items()},obs['listed_array_bytes'])
        compare(uniform_label,obs['uniform_seed_ascii'])
        compare(lhs.size,obs['phase_identities'])
        compare(field_rank(C.tolist()),rec['code_label_rank'])
        compare([j for j,d in enumerate(ds) if j and not np.any(C@np.asarray(d)%Q)],rec['selected_offsets_aliasing_true'])
        cosine=np.asarray([math.cos(2*math.pi*j/Q) for j in range(Q)])
        seen={}
        for N in NS:
            candidates=[]
            for d,delta in enumerate(ds):
                shifts=np.asarray([sum(x*y for x,y in zip(row,delta)) for row in C[:N]],dtype=np.int64)
                score=np.sum(cosine[(rhs[:,:N]-shifts[None,:])%Q],axis=1)/N
                compare(dict(N=N,offset=d,**stats(score,N)),next(r for r in obs['records'] if r['N']==N and r['offset']==d))
                candidates.append(score)
            seen[N]=candidates
            difference=candidates[0]-np.max(np.asarray(candidates[1:]),axis=0)
            maximum=np.max(np.asarray(candidates[1:]),axis=0)
            rank=dict(N=N,selected_false_candidates=26,true_strict_above_margin=int(np.count_nonzero(difference>TOL)),
                      false_strict_above_margin=int(np.count_nonzero(difference<-TOL)),
                      ambiguous=int(np.count_nonzero(np.abs(difference)<=TOL)),
                      minimum_absolute_gap=float(min(abs(x) for x in difference)),maximum_selected_false=stats(maximum,N))
            compare(rank,next(r for r in obs['selected_candidate_ranks'] if r['N']==N))
            compare(dict(N=N,exact_uniform_mean=0,exact_uniform_variance=1/(2*N),
                         **stats(np.sum(cosine[uphase[:,:N]],axis=1)/N,N)),next(r for r in obs['uniform_null'] if r['N']==N))
    s=read(run/'summary.json')
    if s['protocol_commit']!='6827a5a' or s['phase_identities']!=phases_checked or s['analytic_moment_records']!=count or s['character_checks']!=characters or any(s[k] for k in ('population_laws_enumerated','all_q21_candidates_tested','attack_costs_updated','profile_selected','j2_closed')):
        raise ValueError('independent summary scope mismatch')
    return dict(project_arithmetic_imported=False,numpy=np.__version__,decimal_digits=80,
                matrices_verified=4,LLL_certificates_verified=4,complete_banks_verified=8,
                moment_records_verified=count,phase_identities_verified=int(phases_checked),
                exhaustive_decoder_coordinate_terms=decoder_terms,high_precision_characters=characters,
                all_sample_events_and_integer_hashes_matched=True,maximum_absolute_numeric_delta=max_delta)


def write(p,value):
    with p.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(value,stream,indent=2,allow_nan=False)
        stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,default=ROOT/'results/j2/run-017')
    run=parser.parse_args().run.resolve()
    if not run.is_relative_to(ROOT) or run==ROOT:
        raise ValueError('run below NIST required')
    with localcontext() as ctx:
        ctx.prec=80
        result=audit(run)
    output=run/'independent-verification.json'
    if output.exists():
        previous=read(output)
        if {k:v for k,v in previous.items() if k!='maximum_absolute_numeric_delta'}!={k:v for k,v in result.items() if k!='maximum_absolute_numeric_delta'}:
            raise ValueError('independent H10 replay changed')
    else:
        write(output,result)
        names=['research/verify_real_dual_independent.py','docs/PROTOCOLE_H10.md',
               'research/requirements-cbd-dimensions.txt']
        names += [(run/n).relative_to(ROOT).as_posix() for n in ('cases.json','offsets.json','banks.json','summary.json')]
        write(run/'independent-provenance.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),
            input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
            output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
