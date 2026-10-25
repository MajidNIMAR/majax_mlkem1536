"""Independent H08 bit-layer laws, integer score arrays and LLL certificates.

No project arithmetic imports. Uses pinned NumPy with different recurrences
and phase construction; it does not enumerate up to 2^54 bit configurations.
"""

from fractions import Fraction
from datetime import datetime,timezone
import hashlib
import itertools
import json
import math
from pathlib import Path

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/j2/run-015'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def array_digest(a):
    dtype='|u1' if a.dtype==np.uint8 else '<i8'
    header=json.dumps(dict(shape=list(a.shape),dtype=dtype),sort_keys=True,separators=(',',':')).encode()+b'\n'
    return hashlib.sha256(header+a.astype(dtype).tobytes(order='C')).hexdigest()


def matrix(case):
    q,m,l,i=17,case['m'],case['l'],case['identifier']
    label=(f'nist-j2-full-dual-v1:17:{i}' if m==2 else f'nist-j2-cbd-dimension-v1:17:3:2:{i}').encode()
    values=[]
    counter=0
    while len(values)<m*(l+4):
        raw=hashlib.shake_256(label+counter.to_bytes(8,'little')).digest(4096)
        counter+=1
        for j in range(0,len(raw),2):
            v=int.from_bytes(raw[j:j+2],'little')
            if v<65536//q*q:
                values.append(v%q)
                if len(values)==m*(l+4):
                    break
    return [values[j*(l+4):(j+1)*(l+4)] for j in range(m)]


def det(B):
    n=len(B)
    return sum((-1)**sum(p[i]>p[j] for i in range(n) for j in range(i+1,n))*math.prod(B[i][p[i]] for i in range(n))
               for p in itertools.permutations(range(n)))


def verify_case(c):
    q,m,l,A=17,c['m'],c['l'],c['A']
    if A!=matrix(c):
        raise ValueError('independent public matrix failed')
    r=c['reduction']
    B,R,U=r['original'],r['reduced'],r['unimodular']
    n=m+l
    expected=[[int(i==j) for j in range(m)]+A[i][:l] for i in range(m)]+[[0]*m+[17*int(i==j) for j in range(l)] for i in range(l)]
    if B!=expected or abs(det(U))!=1 or abs(det(R))!=17**l:
        raise ValueError('independent determinant certificate failed')
    if [[sum(U[i][k]*B[k][j] for k in range(n)) for j in range(n)] for i in range(n)]!=R:
        raise ValueError('independent unimodular transform failed')
    replay=[row[:] for row in B]
    for op in r['trace']:
        if op[0]=='reduce':
            _,i,j,a=op
            replay[i]=[x-a*y for x,y in zip(replay[i],replay[j])]
        elif op[0]=='swap':
            i=op[1]
            replay[i],replay[i-1]=replay[i-1],replay[i]
        else:
            raise ValueError('invalid trace')
    if replay!=R:
        raise ValueError('independent trace failed')
    gram=[[sum(a*b for a,b in zip(v,w)) for w in R] for v in R]
    mu=[[Fraction(0)]*n for _ in range(n)]
    norms=[]
    for i in range(n):
        for j in range(i):
            mu[i][j]=(Fraction(gram[i][j])-sum(mu[i][k]*mu[j][k]*norms[k] for k in range(j)))/norms[j]
            if abs(mu[i][j])>Fraction(1,2):
                raise ValueError('independent size reduction failed')
        norms.append(Fraction(gram[i][i])-sum(mu[i][j]**2*norms[j] for j in range(i)))
    if any(norms[i]<(Fraction(3,4)-mu[i][i-1]**2)*norms[i-1] for i in range(1,n)):
        raise ValueError('independent Lovasz check failed')
    center=lambda x:(x+8)%17-8
    reference=[]
    for y in itertools.product(range(-8,9),repeat=m):
        if next((v for v in y if v),0)<=0:
            continue
        x=[center(sum(a*line[j] for a,line in zip(y,A))) for j in range(l)]
        reference.append(dict(y=list(y),x=x,squared_norm=sum(v*v for v in list(y)+x)))
    reduced={}
    for coefficients in itertools.product(range(-2,3),repeat=n):
        v=[center(sum(a*R[i][j] for i,a in enumerate(coefficients))) for j in range(n)]
        first=next((a for a in v[:m] if a),0)
        if not first:
            continue
        sign=1 if first>0 else -1
        v=tuple(sign*a for a in v)
        reduced.setdefault(v,dict(y=list(v[:m]),x=list(v[m:]),squared_norm=sum(a*a for a in v),coefficients=[sign*a for a in coefficients]))
    order=lambda v:(v['squared_norm'],v['y'],v['x'])
    if sorted(reference,key=order)!=c['reference'] or sorted(reduced.values(),key=order)!=c['lll_box']:
        raise ValueError('independent quotient lists failed')


def bit_laws(A,g):
    m=len(A)
    l=len(A[0])-4
    shape=(17,)*(m+1)
    coords=np.array(list(itertools.product(range(17),repeat=m+1)),dtype=np.int64)
    strides=np.array([17**i for i in range(m,-1,-1)],dtype=np.int64)
    # Secrets first, errors last; each bit is a separate Bernoulli transition.
    cols=[[row[j] for row in A]+[0 if j<l else g[j-l]] for j in range(l+4)]
    cols += [[int(i==j) for i in range(m)]+[0] for j in range(m)]
    permutations=[(((coords-c)%17)@strides,((coords+c)%17)@strides) for c in map(np.asarray,cols)]
    results={}
    for eta in (1,2,3):
        a=np.zeros(len(coords),dtype=np.int64)
        a[0]=1
        steps=0
        for positive,negative in permutations:
            for _ in range(eta):
                a=a+a[positive]
                steps+=1
            for _ in range(eta):
                a=a+a[negative]
                steps+=1
        if int(a.sum())!=1<<steps or bool(np.any(a<0)):
            raise ArithmeticError('independent Bernoulli mass failed')
        results[eta]=a.reshape(shape)
    return results


def pcheck(record,p):
    if Fraction(record['numerator'],record['denominator'])!=p:
        raise ValueError('independent event probability failed')


def score_arrays(bank,table):
    m,N=bank['m'],bank['N']
    bs=np.array(list(itertools.product(range(17),repeat=m)),dtype=np.int64)
    ys=np.array([v['y'] for v in bank['vectors']],dtype=np.int64)
    cs=np.array([v['c'] for v in bank['vectors']],dtype=np.int64)
    dot=bs@ys.T
    phases=(dot[:,None,:]-np.arange(17)[None,:,None]*cs[None,None,:])%17
    folds=np.empty((len(bs),17,9),dtype=np.uint8)
    for d in range(9):
        folds[:,:,d]=np.sum((phases==d)|(phases==(17-d)%17),axis=2)
    integers=np.sum(folds.astype(np.int64)*np.array(table['cosine_weights']),axis=2)
    order=np.argsort(integers,axis=1,kind='stable')
    sorted_t=np.take_along_axis(integers,order,axis=1)
    rows,j=np.nonzero(np.diff(sorted_t,axis=1)<N)
    if bool(np.any(folds[rows,order[rows,j]]!=folds[rows,order[rows,j+1]])):
        raise ValueError('independent ranking certificate unresolved')
    for boundary in (0,N//2*(1<<48)):
        if bool(np.any((integers<boundary)&(integers+N>boundary))):
            raise ValueError('independent threshold unresolved')
    values=np.sum(folds*np.array([math.cos(2*math.pi*d/17) for d in range(9)]),axis=2)/N
    return folds,integers,values


def audit_events(result,weights,T,V,N):
    W=weights.reshape(-1,17)
    den=result['denominator']
    strict=member=0
    tied=Fraction(0)
    counts=[[0]*17 for _ in range(2)]
    unions=[0,0]
    for u in range(17):
        w=W[:,u]
        wrong=np.max(np.delete(T,u,axis=1),axis=1)
        strict+=int(np.sum(w*(T[:,u]>wrong)))
        member+=int(np.sum(w*(T[:,u]>=wrong)))
        ties=np.sum(T==T[:,u,None],axis=1)
        for k in range(1,18):
            tied+=Fraction(int(np.sum(w*((T[:,u]>=wrong)&(ties==k)))),k)
        for j,boundary in enumerate((0,N//2*(1<<48))):
            unions[j]+=int(np.sum(w*(wrong>=boundary)))
            for d in range(17):
                counts[j][d]+=int(np.sum(w*(T[:,(u+d)%17]>=boundary)))
    pcheck(result['strict_success'],Fraction(strict,den))
    pcheck(result['true_in_argmax'],Fraction(member,den))
    pcheck(result['uniform_tie_success'],tied/den)
    for j,tail in enumerate(result['tails']):
        ps=[Fraction(c,den) for c in counts[j][1:]]
        pcheck(tail['true_pass'],Fraction(counts[j][0],den))
        pcheck(tail['any_false_pass'],Fraction(unions[j],den))
        for p,record in zip(ps,tail['false_offset_pass']):
            pcheck(record,p)
        pcheck(tail['independence_prediction'],1-math.prod(1-p for p in ps))
        pcheck(tail['exact_union_bound'],min(Fraction(1),sum(ps)))
    delta=0.0
    for d,r in enumerate(result['offset_moments']):
        sums=second=0.0
        for u in range(17):
            v=V[:,(u+d)%17]
            sums+=float(np.sum(W[:,u]*v))
            second+=float(np.sum(W[:,u]*v*v))
        mean=sums/den
        variance=second/den-mean*mean
        delta=max(delta,abs(mean-r['mean']),abs(variance-r['variance']))
    if delta>2e-12:
        raise ValueError('independent score moments failed')
    for j,tail in enumerate(result['uniform_null']['tails']):
        boundary=(0,N//2*(1<<48))[j]
        per=[Fraction(int(np.sum(T[:,u]>=boundary)),len(T)) for u in range(17)]
        pcheck(tail['fixed_guess_pass'],per[0])
        pcheck(tail['any_guess_pass'],Fraction(int(np.sum(np.max(T,axis=1)>=boundary)),len(T)))
        pcheck(tail['independence_prediction'],1-math.prod(1-p for p in per))
    return delta


def replay():
    if np.__version__!='2.3.5':
        raise RuntimeError('pinned NumPy required')
    cases=read(RUN/'cases.json')
    panels=read(RUN/'panels.json')
    records=[json.loads(s) for s in (RUN/'banks.jsonl').read_text().splitlines()]
    tables=next(t for t in read(ROOT/'results/j2/run-013/transcendental-tables.json') if t['q']==17)
    by_case={c['case']:c for c in cases}
    expected={(m,l,i) for m,l in ((2,1),(3,2)) for i in range(8)}
    if len(cases)!=16 or {(c['m'],c['l'],c['identifier']) for c in cases}!=expected or len(panels)!=1152:
        raise ValueError('H08 case coverage failed')
    laws={}
    for c in cases:
        verify_case(c)
        for g in ((1,1,1,1),(1,2,4,8)):
            for eta,a in bit_laws(c['A'],g).items():
                laws[c['case'],g,eta]=a
    supplied_laws=read(RUN/'laws.json')
    if len(supplied_laws)!=96:
        raise ValueError('96 exact laws required')
    for r in supplied_laws:
        a=laws[r['case'],tuple(r['g']),r['eta']]
        if array_digest(a)!=r['sha256'] or list(a.shape)!=r['shape'] or int(a.sum())!=r['denominator']:
            raise ValueError('independent bit-layer law failed')
    by_bank={r['bank_id']:r for r in records}
    used={}
    expected_panels={(c['case'],source,N,family,metric,eta) for c in cases for source in ('reference','lll_box')
                     for N in (4,8,12) for family in ('repeated','radix') for metric in ('euclidean','cbd') for eta in (1,2,3)}
    if {(p['case'],p['source'],p['N'],p['family'],p['metric'],p['eta']) for p in panels}!=expected_panels:
        raise ValueError('independent panel coverage failed')
    links={(p['case'],p['source'],p['N'],p['family'],p['metric']):p['bank_id'] for p in panels if p['eta']==1}
    if any(p['bank_id']!=links[p['case'],p['source'],p['N'],p['family'],p['metric']] for p in panels):
        raise ValueError('independent eta/geometry sharing failed')
    for p in panels:
        if p['eta']!=1:
            continue
        c=by_case[p['case']]
        A,m,l=c['A'],c['m'],c['l']
        g=[1]*4 if p['family']=='repeated' else [1,2,4,8]
        vectors=[]
        center=lambda x:(x+8)%17-8
        for v in c[p['source']][:p['N']]:
            target=[sum(a*row[j] for a,row in zip(v['y'],A))%17 for j in range(l,l+4)]
            errors=[[center(x-symbol*a) for x,a in zip(target,g)] for symbol in range(17)]
            costs=[sum(x*x for x in r) if p['metric']=='euclidean' else sum(tables['cbd_weights'][abs(x)] for x in r) for r in errors]
            symbol=min(range(17),key=lambda j:(costs[j],j))
            r=errors[symbol]
            vectors.append(dict(y=v['y'],x=v['x'],c=symbol,r=r,coefficient=v['y']+v['x']+r))
        bank=dict(q=17,m=m,l=l,A=A,g=g,N=p['N'],vectors=vectors)
        if digest(bank)!=p['bank_id'] or by_bank[p['bank_id']]['bank']!=bank:
            raise ValueError('independent geometry/decoder identity failed')
        used[p['bank_id']]=(p['case'],tuple(g))
    if set(used)!=set(by_bank):
        raise ValueError('independent missing or extra bank')
    max_delta=0.0
    scores=0
    for key,(case,g) in used.items():
        record=by_bank[key]
        bank=record['bank']
        folds,T,V=score_arrays(bank,tables)
        if {'folds':array_digest(folds),'integer_scores':array_digest(T)}!=record['score_hashes']:
            raise ValueError('independent complete phase/score arrays failed')
        scores+=T.size
        for eta in (1,2,3):
            a=laws[case,g,eta]
            result=record['results'][str(eta)]
            if array_digest(a)!=result['law_sha256']:
                raise ValueError('independent bank law link failed')
            max_delta=max(max_delta,audit_events(result,a,T,V,bank['N']))
    return dict(project_arithmetic_imported=False,matrices=16,LLL_certificates=16,panels=1152,
                exact_laws_verified=96,maximum_Bernoulli_layers=54,total_Bernoulli_layers=3072,
                distinct_score_banks=len(records),complete_guess_scores=int(scores),
                exact_hashes_and_events_matched=True,maximum_absolute_moment_delta=max_delta)


def main():
    result=replay()
    output=RUN/'independent-verification.json'
    if output.exists():
        old=read(output)
        if {k:v for k,v in old.items() if k!='maximum_absolute_moment_delta'}!={k:v for k,v in result.items() if k!='maximum_absolute_moment_delta'}:
            raise ValueError('independent replay changed')
    else:
        with output.open('x',encoding='utf-8',newline='\n') as stream:
            json.dump(result,stream,indent=2)
            stream.write('\n')
        names=['research/verify_higher_cbd_independent.py','research/requirements-cbd-dimensions.txt','results/j2/run-013/transcendental-tables.json']
        names += [(RUN/n).relative_to(ROOT).as_posix() for n in ('cases.json','panels.json','laws.json','banks.jsonl')]
        provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),
                        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                        output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()})
        with (RUN/'independent-provenance.json').open('x',encoding='utf-8',newline='\n') as stream:
            json.dump(provenance,stream,indent=2)
            stream.write('\n')
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':
    main()
