"""Deterministic rational LLL and bounded quotient enumeration in dimension 3.

Research construction only. No floating-point Gram-Schmidt, BKZ or sampler.
"""

from fractions import Fraction
import itertools


def determinant(B):
    return (B[0][0]*(B[1][1]*B[2][2]-B[1][2]*B[2][1])
            -B[0][1]*(B[1][0]*B[2][2]-B[1][2]*B[2][0])
            +B[0][2]*(B[1][0]*B[2][1]-B[1][1]*B[2][0]))


def gram_schmidt(B):
    stars=[]
    mu=[[Fraction(0) for _ in B] for _ in B]
    norms=[]
    for i,row in enumerate(B):
        star=list(map(Fraction,row))
        for j,previous in enumerate(stars):
            mu[i][j]=sum(Fraction(a)*b for a,b in zip(row,previous))/norms[j]
            star=[a-mu[i][j]*b for a,b in zip(star,previous)]
        norm=sum(a*a for a in star)
        if norm<=0:
            raise ValueError("full-rank basis required")
        stars.append(star)
        norms.append(norm)
    return mu,norms


def multiply(A,B):
    return [[sum(a*b for a,b in zip(row,column)) for column in zip(*B)] for row in A]


def verify_reduction(record):
    original,reduced,U=record["original"],record["reduced"],record["unimodular"]
    if any(len(B)!=3 or any(len(row)!=3 or any(type(x) is not int for x in row) for row in B)
           for B in (original,reduced,U)):
        raise ValueError("integer three-dimensional bases required")
    if abs(determinant(U))!=1 or multiply(U,original)!=reduced or abs(determinant(original))!=abs(determinant(reduced)):
        raise ValueError("unimodular reduction certificate failed")
    replay=[row[:] for row in original]
    for step in record["trace"]:
        if step[0]=="reduce":
            _,k,j,m=step
            if not 0<=j<k<3 or type(m) is not int:
                raise ValueError("invalid reduction trace")
            replay[k]=[a-m*b for a,b in zip(replay[k],replay[j])]
        elif step[0]=="swap":
            _,k=step
            if k not in (1,2):
                raise ValueError("invalid swap trace")
            replay[k],replay[k-1]=replay[k-1],replay[k]
        else:
            raise ValueError("unknown reduction operation")
    if replay!=reduced:
        raise ValueError("reduction trace did not replay")
    mu,norms=gram_schmidt(reduced)
    if any(abs(mu[i][j])>Fraction(1,2) for i in range(3) for j in range(i)):
        raise ValueError("basis is not size reduced")
    if any(norms[k]<(Fraction(3,4)-mu[k][k-1]**2)*norms[k-1] for k in (1,2)):
        raise ValueError("Lovasz condition failed")
    if not 1<=record["iterations"]<=10000:
        raise ValueError("invalid LLL iteration budget")
    return True


def reduce_basis(B):
    original=[list(row) for row in B]
    if len(original)!=3 or any(len(row)!=3 or any(type(x) is not int for x in row) for row in original):
        raise ValueError("integer 3x3 basis required")
    if determinant(original)==0:
        raise ValueError("full-rank basis required")
    R=[row[:] for row in original]
    U=[[int(i==j) for j in range(3)] for i in range(3)]
    trace=[]
    k,iterations=1,0
    while k<3:
        iterations+=1
        if iterations>10000:
            raise ArithmeticError("LLL iteration budget exhausted")
        for j in range(k-1,-1,-1):
            mu,_=gram_schmidt(R)
            value=mu[k][j]
            nearest=(2*value.numerator+value.denominator)//(2*value.denominator)
            if nearest:
                R[k]=[a-nearest*b for a,b in zip(R[k],R[j])]
                U[k]=[a-nearest*b for a,b in zip(U[k],U[j])]
                trace.append(["reduce",k,j,nearest])
        mu,norms=gram_schmidt(R)
        if norms[k]>=(Fraction(3,4)-mu[k][k-1]**2)*norms[k-1]:
            k+=1
        else:
            R[k],R[k-1]=R[k-1],R[k]
            U[k],U[k-1]=U[k-1],U[k]
            trace.append(["swap",k])
            k=max(1,k-1)
    record=dict(original=original,reduced=R,unimodular=U,trace=trace,iterations=iterations,
                delta="3/4",dimension=3,arithmetic="exact rational Gram-Schmidt")
    verify_reduction(record)
    return record


def quotient_candidates(A,q):
    half=q//2
    rows=[]
    for a,b in itertools.product(range(-half,half+1),repeat=2):
        if next((v for v in (a,b) if v),0)<=0:
            continue
        x=(a*A[0][0]+b*A[1][0]+half)%q-half
        rows.append(dict(y=[a,b],x=x,squared_norm=a*a+b*b+x*x))
    return sorted(rows,key=lambda r:(r["squared_norm"],r["y"],r["x"]))


def reduced_candidates(A,q,reduction,bound=2):
    verify_reduction(reduction)
    if reduction["original"]!=[[1,0,A[0][0]],[0,1,A[1][0]],[0,0,q]] or bound!=2:
        raise ValueError("expected dual basis and fixed coefficient box required")
    half=q//2
    candidates={}
    for coefficients in itertools.product(range(-bound,bound+1),repeat=3):
        raw=[sum(c*row[i] for c,row in zip(coefficients,reduction["reduced"])) for i in range(3)]
        v=[(x+half)%q-half for x in raw]
        first=next((x for x in v[:2] if x),0)
        if first==0:
            continue
        sign=1 if first>0 else -1
        v=tuple(sign*x for x in v)
        witness=[sign*c for c in coefficients]
        if (v[0]*A[0][0]+v[1]*A[1][0]-v[2])%q:
            raise ArithmeticError("projected vector left the dual relation")
        candidates.setdefault(v,dict(y=list(v[:2]),x=v[2],squared_norm=sum(x*x for x in v),coefficients=witness))
    return sorted(candidates.values(),key=lambda r:(r["squared_norm"],r["y"],r["x"]))
