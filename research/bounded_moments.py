"""Exact rational majorants for CBD(3) score moments; no character rounding."""

from fractions import Fraction as F
import itertools
import math

def numpy():
    import numpy as np
    if np.__version__!='2.3.5':
        raise RuntimeError('pinned NumPy 2.3.5 required')
    return np


def rational(value):
    return dict(numerator=value.numerator,denominator=value.denominator)


def fraction(value):
    return F(value['numerator'],value['denominator'])


def constant_certificate():
    x=F(1,5)
    pi_lower=16*(x-x**3/3+x**5/5-x**7/7)-4*F(1,239)
    exp_lower=sum(F(7,10)**j/math.factorial(j) for j in range(4))
    assert pi_lower>F(157,50) and exp_lower>2
    assert 3*F(157,50)**2>42*F(7,10)
    return dict(machin_pi_lower=rational(pi_lower),exp_point_seven_lower=rational(exp_lower),
                gaussian_dyadic_factor=42,eta=3)


def multiplicities_and_balance(ix):
    np=numpy()
    p=ix.shape[1]
    divisor=np.ones(len(ix),dtype=np.int64)
    for j in range(1,p):
        divisor*=1+np.sum(ix[:,j,None]==ix[:,:j],axis=1)
    weights=math.factorial(p)//divisor
    if p%2:
        balanced=np.zeros(len(ix),dtype=bool)
    elif p==2:
        balanced=(ix[:,0]^1)==ix[:,1]
    else:
        balanced=(((ix[:,0]^1)==ix[:,1])&((ix[:,2]^1)==ix[:,3])
                 |((ix[:,0]^1)==ix[:,2])&((ix[:,1]^1)==ix[:,3])
                 |((ix[:,0]^1)==ix[:,3])&((ix[:,1]^1)==ix[:,2]))
    return weights,balanced


def enclose(N,bounds):
    b1,b2,b3,b4=bounds
    v0=F(1,2*N)
    f0=F(3,4*N*N)-F(3,8*N**3)
    dv=b2+b1*b1
    change4=b4+4*b1*b3+6*b1*b1*(v0+b2)+3*b1**4
    base=3-F(3,2*N)
    positive=v0>dv
    delta=None if not positive else (change4+base*(2*v0*dv+dv*dv))/(v0-dv)**2
    return dict(variance_positive_certified=positive,variance_center=rational(v0),
                variance_absolute_error_bound=rational(dv),
                fourth_center=rational(f0),fourth_absolute_error_bound=rational(change4),
                independent_kurtosis=rational(base),
                kurtosis_absolute_error_bound=None if delta is None else rational(delta))


def certify(a,q,cap=128,chunk=32,batch_size=2048):
    np=numpy()
    a=np.asarray(a)
    if a.ndim!=2 or a.dtype.kind not in 'iu' or not 1<=len(a)<=32 or not 1<=a.shape[1]<=145:
        raise ValueError('integer matrix with 1..32 vectors and 1..145 coordinates required')
    if type(q) is not int or not 3<=q<=7681 or q%2==0 or not 1<=cap<=256 or chunk<1 or batch_size<1:
        raise ValueError('bounded odd modulus and positive resource limits required')
    a=((a%q).astype(np.int64)+q//2)%q-q//2
    N,D=a.shape
    signed=np.stack((a,-a),axis=1).reshape(2*N,D)
    orders=[]
    for p in range(1,5):
        histogram=np.zeros(cap+1,dtype=np.int64)
        total=balanced_mass=zero_mass=multisets=early=coordinates=0
        original=itertools.combinations_with_replacement(range(2*N),p)
        while batch:=list(itertools.islice(original,batch_size)):
            ix=np.asarray(batch,dtype=np.int64)
            weights,balanced=multiplicities_and_balance(ix)
            multisets+=len(batch)
            total+=int(weights.sum())
            balanced_mass+=int(weights[balanced].sum())
            ix,weights=ix[~balanced],weights[~balanced]
            norms=np.zeros(len(ix),dtype=np.int64)
            for start in range(0,D,chunk):
                if not len(ix):
                    break
                end=min(D,start+chunk)
                v=(signed[ix,start:end].sum(axis=1)+q//2)%q-q//2
                coordinates+=len(ix)*(end-start)
                norms+=np.sum(v*v,axis=1)
                if end<D:
                    stop=42*norms>=cap*q*q
                    histogram[cap]+=int(weights[stop].sum())
                    early+=int(stop.sum())
                    ix,weights,norms=ix[~stop],weights[~stop],norms[~stop]
            if len(ix):
                exponents=np.minimum(cap,42*norms//(q*q))
                np.add.at(histogram,exponents,weights)
                zero_mass+=int(weights[norms==0].sum())
        expected={1:0,2:2*N,3:0,4:12*N*N-6*N}[p]
        denominator=(2*N)**p
        if total!=denominator or balanced_mass!=expected or int(histogram.sum())!=total-balanced_mass:
            raise ArithmeticError('signed mass accounting failed')
        bound=sum((F(int(w),2**k) for k,w in enumerate(histogram) if w),F(0))/denominator
        orders.append(dict(order=p,signed_multisets=multisets,total_ordered_mass=total,
            balanced_ordered_mass=balanced_mass,unbalanced_zero_coefficient_mass=zero_mass,
            attenuation_histogram={str(k):int(w) for k,w in enumerate(histogram) if w},
            raw_correction_absolute_bound=rational(bound),
            capped_mass_bound=rational(F(int(histogram[cap]),denominator*2**cap)),
            early_stopped_multisets=early,coordinates_evaluated=coordinates))
    return dict(N=N,q=q,eta=3,cap=cap,orders=orders,
                centered=enclose(N,[fraction(r['raw_correction_absolute_bound']) for r in orders]))
