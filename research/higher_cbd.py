"""Exact finite-group CBD laws and full dual scores in dimensions 3/5.

Integer laws and decisions use pinned NumPy; displayed moments are numeric.
No large-parameter attack cost, MLWE rotations or KEM implementation.
"""

from fractions import Fraction
from functools import cache
import hashlib
import json
import math

from block_decoder import centered,make_code
from cbd_decoder import decode_scalar
from full_dual_toy import probability
from lll_dimensions import candidates
from run_block_decoder import targets

Q=17
SIZES=(4,8,12)


def numpy():
    import numpy as np
    if np.__version__!="2.3.5":
        raise RuntimeError("pinned NumPy 2.3.5 required; use the local research environment")
    return np


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def array_hash(a):
    np=numpy()
    dtype="|u1" if a.dtype==np.uint8 else "<i8"
    header=json.dumps(dict(shape=list(a.shape),dtype=dtype),sort_keys=True,separators=(",",":")).encode()+b"\n"
    return hashlib.sha256(header+np.asarray(a,dtype=dtype,order="C").tobytes()).hexdigest()


@cache
def coordinates(q,m):
    np=numpy()
    values=np.indices((q,)*m,dtype=np.int64).reshape(m,-1).T.copy()
    values.setflags(write=False)
    return values


def case_data(m,l,identifier):
    if (m,l) not in ((2,1),(3,2)) or not 0<=identifier<8:
        raise ValueError("preregistered architecture and identifier required")
    label=(f"nist-j2-full-dual-v1:17:{identifier}" if m==2 else
           f"nist-j2-cbd-dimension-v1:17:3:2:{identifier}").encode()
    A=targets(Q,l+4,m,label)
    reduction,reference,reduced=candidates(A,Q,m,l)
    return dict(case=f"d{m+l}-matrix{identifier}",q=Q,m=m,l=l,dimension=m+l,identifier=identifier,
                A=A,seed_ascii=label.decode(),reduction=reduction,reference=reference,lll_box=reduced)


def columns(A,g):
    m=len(A)
    n=len(A[0])
    l=n-len(g)
    if m<1 or l<1 or any(len(row)!=n for row in A):
        raise ValueError("rectangular public matrix and nonempty lattice secret required")
    return [[int(i==j) for i in range(m)]+[0] for j in range(m)]+[
        [row[j] for row in A]+[0 if j<l else g[j-l]] for j in range(n)]


def law(A,g,eta,q=Q):
    np=numpy()
    cs=columns(A,g)
    if eta not in (1,2,3) or 2*eta*len(cs)>62:
        raise ValueError("CBD support or exact int64 mass budget exceeded")
    shape=(q,)*len(cs[0])
    weights=np.zeros(shape,dtype=np.int64)
    weights[(0,)*len(shape)]=1
    axes=tuple(range(len(shape)))
    for i,column in enumerate(cs):
        updated=np.zeros_like(weights)
        for value in range(-eta,eta+1):
            multiplicity=math.comb(2*eta,eta+value)
            updated+=multiplicity*np.roll(weights,tuple(value*c for c in column),axis=axes)
        weights=updated
        if int(weights.sum())!=1<<(2*eta*(i+1)) or bool(np.any(weights<0)):
            raise ArithmeticError("exact CBD convolution mass/overflow check failed")
    return weights


def make_bank(case,source,N,family,metric,costs):
    if source not in ("reference","lll_box") or N not in SIZES:
        raise ValueError("fixed source and list size required")
    q,A,m,l=case["q"],case["A"],case["m"],case["l"]
    code=make_code(q,4,1,family)
    vectors=[]
    for vector in case[source][:N]:
        y,x=vector["y"],vector["x"]
        t=[sum(y[i]*A[i][j] for i in range(m))%q for j in range(l,l+4)]
        decoded=decode_scalar(code,t,costs,metric)
        c=decoded["labels"][0]
        r=[centered(a-b,q) for a,b in zip(t,code.encode([c]))]
        vectors.append(dict(y=y,x=x,c=c,r=r,coefficient=y+x+r))
    return dict(q=q,m=m,l=l,A=A,g=code.record()["generators"][0],N=N,vectors=vectors)


def score_data(bank,cosine_weights):
    np=numpy()
    q,m,N=bank["q"],bank["m"],bank["N"]
    bs=coordinates(q,m)
    us=np.arange(q,dtype=np.int64)
    folds=np.zeros((len(bs),q,q//2+1),dtype=np.uint8)
    bins=np.zeros((len(bs),q),dtype=np.complex128)
    for v in bank["vectors"]:
        public=sum(bs[:,i]*v["y"][i] for i in range(m))%q
        phase=(public[:,None]-v["c"]*us[None,:])%q
        absolute=np.minimum(phase,q-phase)
        for d in range(q//2+1):
            folds[:,:,d]+=(absolute==d)
        bins[:,v["c"]]+=np.exp(2j*np.pi*public/q)
    integers=np.sum(folds.astype(np.int64)*np.asarray(cosine_weights,dtype=np.int64),axis=2,dtype=np.int64)
    order=np.argsort(integers,axis=1,kind="stable")
    sorted_t=np.take_along_axis(integers,order,axis=1)
    rows,adjacent=np.nonzero(np.diff(sorted_t,axis=1)<N)
    if len(rows) and bool(np.any(folds[rows,order[rows,adjacent]]!=folds[rows,order[rows,adjacent+1]])):
        raise ArithmeticError("unresolved exact score ordering")
    for boundary in (0,N//2*(1<<48)):
        if bool(np.any((integers<boundary)&(integers+N>boundary))):
            raise ArithmeticError("unresolved exact score threshold")
    cosines=np.cos(2*np.pi*np.arange(q//2+1)/q)
    values=np.sum(folds*cosines,axis=2)/N
    fourier=np.exp(-2j*np.pi*us[:,None]*us[None,:]/q)
    dft=(bins@fourier).real/N
    delta=float(np.max(np.abs(values-dft)))
    if delta>1e-12:
        raise ArithmeticError("direct DFT disagrees with phase scores")
    best=integers==np.max(integers,axis=1,keepdims=True)
    return dict(folds=folds,integers=integers,values=values,best=best,
                hashes=dict(folds=array_hash(folds),integer_scores=array_hash(integers)),DFT_delta=delta)


def moments(bank,eta):
    np=numpy()
    q,N=bank["q"],bank["N"]
    vs=bank["vectors"]
    phi=lambda a:math.prod(math.cos(math.pi*centered(v,q)/q)**(2*eta) for v in a)
    coefficients=[v["coefficient"] for v in vs]
    phis=np.array([phi(a) for a in coefficients])
    plus=np.array([[phi([x+y for x,y in zip(a,b)]) for b in coefficients] for a in coefficients])
    minus=np.array([[phi([x-y for x,y in zip(a,b)]) for b in coefficients] for a in coefficients])
    labels=np.array([v["c"] for v in vs])
    records=[]
    for d in range(q):
        angles=2*np.pi*labels*d/q
        means=phis*np.cos(angles)
        cross=(minus*np.cos(angles[:,None]-angles[None,:])+plus*np.cos(angles[:,None]+angles[None,:]))/2
        covariance=cross-means[:,None]*means[None,:]
        records.append(dict(offset=d,mean=float(means.sum()/N),variance=float(covariance.sum()/N**2),
                            diagonal_variance=float(np.trace(covariance)/N**2)))
    return records


def evaluate(bank,weights,data,eta):
    np=numpy()
    q,N=bank["q"],bank["N"]
    denominator=1<<(2*eta*(bank["m"]+bank["l"]+4))
    W=weights.reshape(-1,q)
    if int(W.sum())!=denominator:
        raise ArithmeticError("law denominator failed")
    best=data["best"]
    ties=best.sum(axis=1)
    strict=int(np.sum(W*(best&(ties[:,None]==1))))
    member=int(np.sum(W*best))
    tie_success=sum((Fraction(int(np.sum(W*(best&(ties[:,None]==k)))),k) for k in range(1,q+1)),Fraction(0))/denominator
    records=moments(bank,eta)
    probabilities=W.astype(np.float64)/denominator
    for d,record in enumerate(records):
        values=np.roll(data["values"],-d,axis=1)
        mean=float(np.sum(probabilities*values))
        variance=float(np.sum(probabilities*(values-mean)**2))
        if max(abs(mean-record["mean"]),abs(variance-record["variance"]))>2e-12:
            raise ArithmeticError("full-law moments disagree with CBD characteristic")
        record.update(enumerated_mean=mean,enumerated_variance=variance)
    tails=[]
    null=[]
    for boundary,name in ((0,"0"),(N//2*(1<<48),"1/2")):
        mask=data["integers"]>=boundary
        counts=[int(np.sum(W*np.roll(mask,-d,axis=1))) for d in range(q)]
        any_false=(mask.sum(axis=1)[:,None]-mask.astype(np.int64))>0
        joint=int(np.sum(W*any_false))
        ps=[Fraction(c,denominator) for c in counts[1:]]
        tails.append(dict(threshold=name,true_pass=probability(counts[0],denominator),
                          false_offset_pass=[probability(p) for p in ps],any_false_pass=probability(joint,denominator),
                          independence_prediction=probability(1-math.prod(1-p for p in ps)),
                          exact_union_bound=probability(min(Fraction(1),sum(ps)))))
        rows=len(mask)
        per=[Fraction(int(mask[:,u].sum()),rows) for u in range(q)]
        null.append(dict(threshold=name,fixed_guess_pass=probability(per[0]),
                         any_guess_pass=probability(int(np.any(mask,axis=1).sum()),rows),
                         independence_prediction=probability(1-math.prod(1-p for p in per)),
                         Gaussian_fixed_guess_tail=math.erfc((0 if name=="0" else .5)*math.sqrt(N))/2))
    uniform=data["values"][:,0]
    null_mean=float(np.mean(uniform))
    null_variance=float(np.mean((uniform-null_mean)**2))
    if abs(null_mean)>2e-12 or abs(null_variance-1/(2*N))>2e-12:
        raise ArithmeticError("uniform null identity failed")
    return dict(eta=eta,denominator=denominator,law_sha256=array_hash(weights),
                strict_success=probability(strict,denominator),true_in_argmax=probability(member,denominator),
                uniform_tie_success=probability(tie_success),offset_moments=records,tails=tails,
                uniform_null=dict(mean=null_mean,variance=null_variance,tails=null))
