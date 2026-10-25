"""H11 exact uniform moments and public selection from a fixed dual pool."""

from collections import Counter
from fractions import Fraction
import hashlib
import json
import math

from real_dual import numpy,statistics


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def plus(a,b,q):
    return tuple((x+y)%q for x,y in zip(a,b))


def signed(ys,q):
    if q<3 or q%2==0 or not ys or any(len(y)!=len(ys[0]) for y in ys):
        raise ValueError('nonempty equal-dimensional vectors and odd modulus required')
    rows=[tuple(s*x%q for x in y) for y in ys for s in (1,-1)]
    if any(not any(y) for y in rows) or len(set(rows))!=len(rows):
        raise ValueError('nonzero frequencies distinct up to sign required')
    return rows


def pair_counts(ys,q):
    B=signed(ys,q)
    return Counter(plus(a,b,q) for a in B for b in B)


def rational(v):
    v=Fraction(v)
    return dict(numerator=v.numerator,denominator=v.denominator)


def exact_moments(ys,q):
    B=signed(ys,q)
    N=len(ys)
    P=pair_counts(ys,q)
    triple=sum(P[y] for y in B)
    energy=sum(x*x for x in P.values())
    independent=12*N*N-6*N
    if sum(P.values())!=(2*N)**2 or energy<independent:
        raise ArithmeticError('uniform pair-count invariant failed')
    spectrum=sorted((sum(x*q**j for j,x in enumerate(z)),v) for z,v in P.items())
    variance=Fraction(1,2*N)
    third=Fraction(triple,(2*N)**3)
    fourth=Fraction(energy,(2*N)**4)
    kurtosis=fourth/variance**2
    return dict(N=N,mean=rational(0),variance=rational(variance),third=rational(third),fourth=rational(fourth),
                ordered_signed_triples=triple,ordered_signed_quadruples=energy,
                independent_quadruples=independent,extra_quadruples=energy-independent,
                pair_support=len(P),pair_spectrum_sha256=fingerprint(spectrum),
                skewness=float(third)/float(variance)**1.5,kurtosis=rational(kurtosis),
                independent_cosine_kurtosis=rational(Fraction(3)-Fraction(3,2*N)),
                fourth_moment_three_sigma_upper=rational(min(Fraction(1),kurtosis/81)))


def delta_pairs(B,y,q):
    y=tuple(x%q for x in y)
    negative=tuple(-x%q for x in y)
    delta=Counter()
    for b in B:
        delta[plus(b,y,q)]+=2
        delta[plus(b,negative,q)]+=2
    delta[plus(y,y,q)]+=1
    delta[plus(negative,negative,q)]+=1
    delta[(0,)*len(y)]+=2
    return delta


def greedy_order(ys,q):
    # Only frequencies and their original public norm order enter selection.
    P=Counter()
    B=[]
    remaining=set(range(len(ys)))
    energy=0
    order,trace=[],[]
    while remaining:
        costs=[]
        for i in sorted(remaining):
            delta=delta_pairs(B,ys[i],q)
            value=energy+sum(2*P[z]*v+v*v for z,v in delta.items())
            costs.append((i,value))
        i,value=min(costs,key=lambda t:(t[1],t[0]))
        P.update(delta_pairs(B,ys[i],q))
        B.extend([tuple(x%q for x in ys[i]),tuple(-x%q for x in ys[i])])
        if value!=sum(v*v for v in P.values()) or sum(P.values())!=len(B)**2:
            raise ArithmeticError('incremental energy mismatch')
        energy=value
        order.append(i)
        remaining.remove(i)
        trace.append(dict(selected=i,energy=energy,candidate_evaluations=len(costs),
                          candidate_costs_sha256=fingerprint(costs)))
    return order,trace


def public_orders(ys,q,identifier):
    signed(ys,q)
    normal=list(range(len(ys)))
    hashed=sorted(normal,key=lambda i:(hashlib.sha256(f'nist-j2-additive-v1:hash:{identifier}:{i}'.encode()).digest(),i))
    energy,trace=greedy_order(ys,q)
    return dict(norm=normal,hash=hashed,energy=energy),trace


def empirical(values,N):
    np=numpy()
    result=statistics(values,N)
    centered=values-result['mean']
    var=result['variance']
    result.update(raw_third=float(np.mean(values**3)),raw_fourth=float(np.mean(values**4)),
                  skewness=float(np.mean(centered**3))/var**1.5 if var else None,
                  kurtosis=float(np.mean(centered**4))/var**2 if var else None)
    return result


def cbd_states(identifier,count):
    np=numpy()
    label=f'nist-j2-additive-v1:CBD:{identifier}'
    raw=np.frombuffer(hashlib.shake_256(label.encode()).digest(count*145),dtype=np.uint8)
    lookup=np.asarray([(v&7).bit_count()-((v>>3)&7).bit_count() for v in range(256)],dtype=np.int64)
    return lookup[raw].reshape(count,145),label


def phase_pool(bank,states):
    np=numpy()
    q,m,l=bank['q'],bank['m'],bank['l']
    A=np.asarray(bank['A'],dtype=np.int64)
    Y=np.asarray([v['y'] for v in bank['vectors']],dtype=np.int64)
    C=np.asarray([v['c'] for v in bank['vectors']],dtype=np.int64)
    coeff=np.asarray([v['y']+v['x']+v['r'] for v in bank['vectors']],dtype=np.int64)
    public=(states[:,m:]@A.T+states[:,:m])%q
    truth=np.zeros((len(states),21),dtype=np.int64)
    pos=m+l
    for j,g in enumerate(bank['code']['generators']):
        truth[:,j]=states[:,pos:pos+len(g)]@np.asarray(g,dtype=np.int64)%q
        pos+=len(g)
    lhs=(public@Y.T-truth@C.T)%q
    rhs=states@coeff.T%q
    if not np.array_equal(lhs,rhs):
        raise ArithmeticError('new-state full phase identity failed')
    return lhs,C,public,truth
