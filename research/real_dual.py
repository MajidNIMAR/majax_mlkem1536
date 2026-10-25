"""H10 complete finite-list scores at the real modulus; no attack cost."""

import hashlib
import itertools
import json
import math

from block_decoder import centered, make_code
from block_decoder_numpy import decode, warm_tables
from lll_dimensions import reduce
from run_block_decoder import targets

Q, ETA, M, L, NF, KF = 7681, 3, 3, 2, 140, 21
SIZES = (32, 64, 128)
SAMPLES = 4096
TOL = 1e-12


def numpy():
    import numpy as np
    if np.__version__ != '2.3.5':
        raise RuntimeError('local pinned NumPy 2.3.5 required')
    return np


def array_hash(a):
    np=numpy()
    header=json.dumps(dict(shape=list(a.shape),dtype='<i8'),sort_keys=True,separators=(',',':')).encode()+b'\n'
    return hashlib.sha256(header+np.asarray(a,dtype='<i8',order='C').tobytes()).hexdigest()


def matrix_case(identifier):
    if type(identifier) is not int or identifier not in range(4):
        raise ValueError('preregistered matrix identifier required')
    label=f'nist-j2-real-dual-v1:matrix:{identifier}'
    A=targets(Q,L+NF,M,label.encode())
    B=[[int(i==j) for j in range(M)]+A[i][:L] for i in range(M)]
    B += [[0]*M+[Q*int(i==j) for j in range(L)] for i in range(L)]
    certificate=reduce(B)
    found={}
    for coefficients in itertools.product(range(-2,3),repeat=M+L):
        v=[centered(sum(a*row[j] for a,row in zip(coefficients,certificate['reduced'])),Q) for j in range(M+L)]
        first=next((a for a in v[:M] if a),0)
        if not first:
            continue
        sign=1 if first>0 else -1
        v=tuple(sign*a for a in v)
        found.setdefault(v,dict(y=list(v[:M]),x=list(v[M:]),squared_norm=sum(a*a for a in v),
                                coefficients=[sign*a for a in coefficients]))
    vectors=sorted(found.values(),key=lambda v:(v['squared_norm'],v['y'],v['x']))
    if len(vectors)<max(SIZES):
        raise ArithmeticError('enumeration did not supply the preregistered list')
    return dict(identifier=identifier,q=Q,m=M,l=L,A=A,seed_ascii=label,reduction=certificate,
                candidate_count=len(vectors),selection='centered quotient; nonzero y; one representative per sign; sorted norm,y,x',
                vectors=vectors[:max(SIZES)])


def offsets():
    rows=[[0]*KF]+[[int(i==j) for i in range(KF)] for j in range(KF)]
    rows += [[1]*KF,[1 if j%2==0 else Q-1 for j in range(KF)]]
    rows += targets(Q,KF,3,b'nist-j2-real-dual-v1:offsets')
    if len(rows)!=27 or len({tuple(r) for r in rows})!=27:
        raise ArithmeticError('offset coverage failed')
    return rows


def make_bank(case,family):
    q,m,l,A=case['q'],case['m'],case['l'],case['A']
    code=make_code(q,NF,KF,family)
    warm_tables(code)
    vectors=[]
    for v in case['vectors']:
        y,x=v['y'],v['x']
        t=[sum(y[i]*A[i][j] for i in range(m))%q for j in range(l,l+NF)]
        result=code.decode_repeated(t) if family=='repeated' else decode(code,t)
        c=result['labels']
        r=[centered(a-b,q) for a,b in zip(t,code.encode(c))]
        if sum(a*a for a in r)!=result['squared_norm']:
            raise ArithmeticError('decoded norm mismatch')
        vectors.append(dict(y=y,x=x,t=t,c=c,r=r,squared_lattice_norm=v['squared_norm'],
                            squared_residual_norm=result['squared_norm']))
    bank=dict(identifier=case['identifier'],q=q,eta=ETA,m=m,l=l,A=A,code=code.record(),vectors=vectors)
    validate_bank(bank)
    return bank


def validate_bank(bank):
    q,m,l=bank['q'],bank['m'],bank['l']
    A=bank['A']
    seen=set()
    for v in bank['vectors']:
        y,x,c,r,t=v['y'],v['x'],v['c'],v['r'],v['t']
        if len(y)!=m or len(x)!=l or len(c)!=bank['code']['k'] or len(r)!=bank['code']['n']:
            raise ValueError('full coefficient dimensions failed')
        if any(type(a) is not int or abs(a)>q//2 for a in y+x+r) or any(type(a) is not int or not 0<=a<q for a in c):
            raise ValueError('canonical integer coefficients required')
        if next((a for a in y if a),0)<=0 or tuple(y) in seen:
            raise ValueError('distinct signed nonzero y required for uniform-null orthogonality')
        seen.add(tuple(y))
        if x!=[centered(sum(y[i]*A[i][j] for i in range(m)),q) for j in range(l)]:
            raise ValueError('lattice congruence failed')
        expected=[sum(y[i]*A[i][j] for i in range(m))%q for j in range(l,len(A[0]))]
        word=[a*g%q for a,block in zip(c,bank['code']['generators']) for g in block]
        if t!=expected or r!=[centered(a-b,q) for a,b in zip(t,word)]:
            raise ValueError('code congruence failed')
    return True


def field_rank(rows,q):
    a=[[(int(x)%q) for x in row] for row in rows]
    rank=0
    for j in range(len(a[0])):
        pivot=next((i for i in range(rank,len(a)) if a[i][j]),None)
        if pivot is None:
            continue
        a[rank],a[pivot]=a[pivot],a[rank]
        inv=pow(a[rank][j],-1,q)
        a[rank]=[x*inv%q for x in a[rank]]
        for i in range(rank+1,len(a)):
            factor=a[i][j]
            a[i]=[(x-factor*y)%q for x,y in zip(a[i],a[rank])]
        rank+=1
        if rank==len(a):
            break
    return rank


def cbd_samples(identifier):
    np=numpy()
    label=f'nist-j2-real-dual-v1:CBD:{identifier}'
    raw=np.frombuffer(hashlib.shake_256(label.encode()).digest(SAMPLES*(M+L+NF)),dtype=np.uint8)
    lookup=np.asarray([(v&7).bit_count()-((v>>3)&7).bit_count() for v in range(256)],dtype=np.int64)
    return lookup[raw].reshape(SAMPLES,M+L+NF),label


def kernels(bank):
    np=numpy()
    q,eta=bank['q'],bank['eta']
    a=np.asarray([v['y']+v['x']+v['r'] for v in bank['vectors']],dtype=np.int64)
    lookup=2*eta*np.log(np.cos(np.pi*np.arange(q//2+1)/q))
    def logphi(v):
        residues=(v+q//2)%q-q//2
        return np.sum(lookup[np.abs(residues)],axis=-1)
    logs=logphi(a)
    plus=np.asarray([logphi(a+row) for row in a])
    minus=np.asarray([logphi(a-row) for row in a])
    return dict(coefficients=a,logs=logs,log_plus=plus,log_minus=minus,
                phis=np.exp(logs),plus=np.exp(plus),minus=np.exp(minus),
                underflowed_kernel_entries=int(np.sum(np.exp(plus)==0)+np.sum(np.exp(minus)==0)))


def analytic(k,c,delta,N,q):
    np=numpy()
    theta=2*np.pi*((c[:N]@np.asarray(delta,dtype=np.int64))%q)/q
    individual=k['phis'][:N]*np.cos(theta)
    cross=(k['minus'][:N,:N]*np.cos(theta[:,None]-theta[None,:])
           +k['plus'][:N,:N]*np.cos(theta[:,None]+theta[None,:]))/2
    mean=float(np.sum(individual)/N)
    variance=float(np.sum(cross)/N**2-mean*mean)
    diagonal=float(np.sum(np.diag(cross)-individual**2)/N**2)
    if variance < -1e-14:
        raise ArithmeticError('negative analytic variance')
    return dict(mean=mean,variance=variance,diagonal_variance=diagonal,
                off_diagonal_variance=variance-diagonal,variance_over_uniform_baseline=variance*(2*N))


def wilson(hits,total):
    z=1.959963984540054
    p=hits/total
    denominator=1+z*z/total
    center=(p+z*z/(2*total))/denominator
    radius=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denominator
    return [max(0.,center-radius),min(1.,center+radius)]


def statistics(values,N):
    np=numpy()
    thresholds=(2/math.sqrt(2*N),3/math.sqrt(2*N),.5)
    tails=[]
    for threshold in thresholds:
        hits=int(np.sum(values>threshold+TOL))
        ambiguous=int(np.sum(np.abs(values-threshold)<=TOL))
        tails.append(dict(threshold=threshold,hits_above_margin=hits,ambiguous=ambiguous,
                          fraction=hits/len(values),wilson95_approx_iid=wilson(hits,len(values)),
                          normal_zero_mean_baseline_tail=math.erfc(threshold*math.sqrt(N))/2))
    return dict(samples=len(values),mean=float(np.mean(values)),variance=float(np.var(values)),tails=tails)


def observations(bank,states,ds):
    np=numpy()
    q,m,l,Nmax=bank['q'],bank['m'],bank['l'],len(bank['vectors'])
    A=np.asarray(bank['A'],dtype=np.int64)
    Y=np.asarray([v['y'] for v in bank['vectors']],dtype=np.int64)
    C=np.asarray([v['c'] for v in bank['vectors']],dtype=np.int64)
    coeff=np.asarray([v['y']+v['x']+v['r'] for v in bank['vectors']],dtype=np.int64)
    public=(states[:,m:]@A.T+states[:,:m])%q
    truth=np.zeros((len(states),bank['code']['k']),dtype=np.int64)
    start=m+l
    for j,g in enumerate(bank['code']['generators']):
        truth[:,j]=(states[:,start:start+len(g)]@np.asarray(g,dtype=np.int64))%q
        start+=len(g)
    phases=(public@Y.T-truth@C.T)%q
    direct=(states@coeff.T)%q
    if not np.array_equal(phases,direct):
        raise ArithmeticError('complete LWE phase identity failed')
    cosine=np.cos(2*np.pi*np.arange(q)/q)
    true_values={N:np.mean(cosine[phases[:,:N]],axis=1) for N in SIZES}
    maxima={N:np.full(len(states),-np.inf) for N in SIZES}
    records=[]
    for d,delta in enumerate(ds):
        shifted=(phases-(C@np.asarray(delta,dtype=np.int64))[None,:])%q
        values=cosine[shifted]
        for N in SIZES:
            score=np.mean(values[:,:N],axis=1)
            records.append(dict(N=N,offset=d,**statistics(score,N)))
            if d:
                maxima[N]=np.maximum(maxima[N],score)
    ranks=[]
    for N in SIZES:
        gap=true_values[N]-maxima[N]
        ranks.append(dict(N=N,selected_false_candidates=len(ds)-1,
                          true_strict_above_margin=int(np.sum(gap>TOL)),
                          false_strict_above_margin=int(np.sum(gap<-TOL)),
                          ambiguous=int(np.sum(np.abs(gap)<=TOL)),
                          minimum_absolute_gap=float(np.min(np.abs(gap))),
                          maximum_selected_false=statistics(maxima[N],N)))
    uniform_label=f"nist-j2-real-dual-v1:uniform:{bank['identifier']}"
    uniform=np.asarray(targets(q,m,len(states),uniform_label.encode()),dtype=np.int64)
    uniform_phases=(uniform@Y.T)%q
    null=[dict(N=N,exact_uniform_mean=0,exact_uniform_variance=1/(2*N),
               **statistics(np.mean(cosine[uniform_phases[:,:N]],axis=1),N)) for N in SIZES]
    arrays=dict(states=states,public_b=public,true_symbols=truth,public_phases=phases,
                direct_phases=direct,uniform_b=uniform,uniform_phases=uniform_phases,
                coefficients=coeff,code_labels=C)
    return dict(records=records,selected_candidate_ranks=ranks,uniform_null=null,
                phase_identities=len(states)*Nmax,
                integer_array_hashes={n:array_hash(a) for n,a in arrays.items()},
                listed_array_bytes={n:int(a.nbytes) for n,a in arrays.items()},
                uniform_seed_ascii=uniform_label)


def character_checks(k):
    ln2=math.log(2)
    return [dict(expression=name,log2_phi=float(value/ln2)) for name,value in (
        ('a0',k['logs'][0]),('a127',k['logs'][127]),
        ('a0+a1',k['log_plus'][0,1]),('a0-a1',k['log_minus'][0,1]),
        ('a0+a127',k['log_plus'][0,127]),('a0-a127',k['log_minus'][0,127]),
        ('a63+a127',k['log_plus'][63,127]),('a63-a127',k['log_minus'][63,127]))]
