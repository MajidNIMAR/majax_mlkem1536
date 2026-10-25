"""Population CBD moments by complete signed-multiset expansion through four.

Algebraic expansion and multiplicities are exact; characters are numeric.
Balanced contributions are separated so tiny corrections remain visible.
"""

from collections import Counter
from decimal import Decimal as D,localcontext
from fractions import Fraction
import itertools
import math

from real_dual import numpy


def log_add(a,b):
    if a is None:
        return b
    if b is None:
        return a
    peak=max(a,b)
    return peak+math.log1p(math.exp(min(a,b)-peak))


def correction(positive,negative,normalizer):
    shift=math.log(normalizer)
    p=None if positive is None else positive-shift
    n=None if negative is None else negative-shift
    absolute=log_add(p,n)
    if p==n:
        sign,logabs=0,None
    elif n is None or (p is not None and p>n):
        sign=1
        logabs=p if n is None else p+math.log(-math.expm1(n-p))
    else:
        sign=-1
        logabs=n if p is None else n+math.log(-math.expm1(p-n))
    ratio=0. if logabs is None else math.exp(logabs-absolute)
    ln2=math.log(2)
    return dict(sign=sign,log2_abs=None if logabs is None else logabs/ln2,
                log2_positive=None if p is None else p/ln2,log2_negative=None if n is None else n/ln2,
                log2_absolute_mass=None if absolute is None else absolute/ln2,
                absolute_over_mass=ratio,cancellation_sensitive=absolute is not None and ratio<1e-10)


def value_decimal(record):
    if not record['sign']:
        return D(0)
    return D(record['sign'])*(D(str(record['log2_abs']))*D(2).ln()).exp()


def describe_decimal(x):
    return dict(sign=0 if not x else 1 if x>0 else -1,
                log2_abs=None if not x else float(abs(x).ln()/D(2).ln()),value=float(x))


def centered_moments(orders,N):
    with localcontext() as ctx:
        ctx.prec=100
        c=[value_decimal(r['correction']) for r in orders]
        mu=c[0]
        v0=D(1)/(2*N)
        f0=D(3)/(4*N*N)-D(3)/(8*N**3)
        dv=c[1]-mu*mu
        variance=v0+dv
        if variance<=0:
            raise ArithmeticError('nonpositive full population variance')
        m2=v0+c[1]
        third=c[2]-3*mu*m2+2*mu**3
        dfourth=c[3]-4*mu*c[2]+6*mu*mu*m2-3*mu**4
        fourth=f0+dfourth
        independent=f0/v0**2
        delta=(dfourth-independent*(2*v0*dv+dv**2))/variance**2
        return dict(mean=float(mu),variance=float(variance),third=describe_decimal(third),
                    fourth=float(fourth),skewness=describe_decimal(third/variance.sqrt()**3),
                    kurtosis=float(fourth/variance**2),
                    independent_cosine_kurtosis=dict(numerator=(Fraction(3)-Fraction(3,2*N)).numerator,
                                                    denominator=(Fraction(3)-Fraction(3,2*N)).denominator),
                    kurtosis_delta_vs_independent=describe_decimal(delta),
                    variance_correction=describe_decimal(dv),central_fourth_correction=describe_decimal(dfourth))


def terms(N,p):
    factorial=math.factorial(p)
    for indices in itertools.combinations_with_replacement(range(2*N),p):
        counts=Counter(indices)
        multiplicity=factorial//math.prod(math.factorial(v) for v in counts.values())
        signs=Counter()
        for i in indices:
            signs[i//2]+=1 if i%2==0 else -1
        yield indices,multiplicity,not any(signs.values())


def population(a,c,deltas,q,eta,require_zero_label=False):
    np=numpy()
    if any(np.asarray(v).dtype.kind not in 'iu' for v in (a,c,deltas)) or type(q) is not int or type(eta) is not int:
        raise ValueError('integer coefficients, modulus and CBD parameter required')
    a=np.asarray(a,dtype=np.int64)
    c=np.asarray(c,dtype=np.int64)
    deltas=np.asarray(deltas,dtype=np.int64)
    N=a.shape[0]
    if a.ndim!=2 or c.ndim!=2 or c.shape[0]!=N or deltas.ndim!=2 or deltas.shape[1]!=c.shape[1] or not 1<=N<=16 or q<3 or q%2==0 or eta<1:
        raise ValueError('compatible fixed coefficients, offsets and N<=16 required')
    signed_a=np.stack((a,-a),axis=1).reshape(2*N,-1)
    signed_c=np.stack((c,-c),axis=1).reshape(2*N,-1)
    lookup=2*eta*np.log(np.cos(np.pi*np.arange(q//2+1)/q))
    cosine=np.cos(2*np.pi*np.arange(q)/q)
    results=[[] for _ in deltas]
    counts=[]
    for p in range(1,5):
        positive=[None]*len(deltas)
        negative=[None]*len(deltas)
        stats=dict(order=p,multisets=0,total_ordered_mass=0,balanced_ordered_mass=0,
                   unbalanced_zero_coefficient_mass=0,unbalanced_exp_underflow_ordered_mass=0)
        iterator=terms(N,p)
        while batch:=list(itertools.islice(iterator,512)):
            indices=np.asarray([r[0] for r in batch],dtype=np.int64)
            weights=np.asarray([r[1] for r in batch],dtype=np.int64)
            balanced=np.asarray([r[2] for r in batch],dtype=bool)
            coefficients=(signed_a[indices].sum(axis=1)+q//2)%q-q//2
            labels=signed_c[indices].sum(axis=1)%q
            zero=np.all(coefficients==0,axis=1)
            if require_zero_label and np.any(labels[zero]%q):
                raise ArithmeticError('zero full coefficient has a nonzero code label')
            logs=np.sum(lookup[np.abs(coefficients)],axis=1)
            stats['multisets']+=len(batch)
            stats['total_ordered_mass']+=int(weights.sum())
            stats['balanced_ordered_mass']+=int(weights[balanced].sum())
            stats['unbalanced_zero_coefficient_mass']+=int(weights[zero&~balanced].sum())
            stats['unbalanced_exp_underflow_ordered_mass']+=int(weights[(np.exp(logs)==0)&~balanced].sum())
            mask=~balanced
            lw=logs[mask]+np.log(weights[mask])
            angles=(labels[mask]@deltas.T)%q
            phases=cosine[angles]
            for j in range(len(deltas)):
                for sign,acc in ((1,positive),(-1,negative)):
                    chosen=sign*phases[:,j]>0
                    if np.any(chosen):
                        values=lw[chosen]+np.log(np.abs(phases[chosen,j]))
                        peak=float(np.max(values))
                        total=peak+math.log(float(np.sum(np.exp(values-peak))))
                        acc[j]=log_add(acc[j],total)
        expected_balanced={1:0,2:2*N,3:0,4:12*N*N-6*N}[p]
        normalizer=(2*N)**p
        if stats['total_ordered_mass']!=normalizer or stats['balanced_ordered_mass']!=expected_balanced or stats['multisets']!=math.comb(2*N+p-1,p):
            raise ArithmeticError('signed expansion multiplicity invariant failed')
        counts.append(stats)
        for j in range(len(deltas)):
            corr=correction(positive[j],negative[j],normalizer)
            with localcontext() as ctx:
                ctx.prec=100
                raw=D(expected_balanced)/normalizer+value_decimal(corr)
            results[j].append(dict(order=p,normalizer=normalizer,balanced_mass=expected_balanced,
                                   balanced_fraction=dict(numerator=Fraction(expected_balanced,normalizer).numerator,
                                                          denominator=Fraction(expected_balanced,normalizer).denominator),
                                   raw_moment=float(raw),correction=corr))
    return dict(counts=counts,offsets=[dict(index=i,orders=orders,central=centered_moments(orders,N))
                                      for i,orders in enumerate(results)])
