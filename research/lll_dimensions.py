"""Exact rational LLL in dimensions 2..8; separate from frozen H07."""

from fractions import Fraction
import itertools

from exact_lll import gram_schmidt,multiply


def determinant(B):
    R=[list(map(Fraction,row)) for row in B]
    result=Fraction(1)
    for i in range(len(R)):
        pivot=next((j for j in range(i,len(R)) if R[j][i]),None)
        if pivot is None:
            return 0
        if pivot!=i:
            R[pivot],R[i]=R[i],R[pivot]
            result=-result
        p=R[i][i]
        result*=p
        for j in range(i+1,len(R)):
            factor=R[j][i]/p
            R[j]=[a-factor*b for a,b in zip(R[j],R[i])]
    if result.denominator!=1:
        raise ArithmeticError("nonintegral determinant")
    return result.numerator


def verify(record):
    B,R,U=record["original"],record["reduced"],record["unimodular"]
    n=len(B)
    if not 2<=n<=8 or any(len(C)!=n or any(len(row)!=n or any(type(x) is not int for x in row) for row in C) for C in (B,R,U)):
        raise ValueError("integer square basis dimension 2..8 required")
    if abs(determinant(U))!=1 or multiply(U,B)!=R or abs(determinant(B))!=abs(determinant(R)):
        raise ValueError("invalid basis transformation")
    replay=[row[:] for row in B]
    for step in record["trace"]:
        if step[0]=="reduce":
            _,k,j,c=step
            if not 0<=j<k<n or type(c) is not int:
                raise ValueError("invalid size reduction")
            replay[k]=[a-c*b for a,b in zip(replay[k],replay[j])]
        elif step[0]=="swap":
            k=step[1]
            if not 1<=k<n:
                raise ValueError("invalid swap")
            replay[k],replay[k-1]=replay[k-1],replay[k]
        else:
            raise ValueError("unknown reduction operation")
    if replay!=R or record["dimension"]!=n or record["delta"]!="3/4" or not 1<=record["iterations"]<=10000:
        raise ValueError("trace or reduction metadata failed")
    mu,norms=gram_schmidt(R)
    if any(abs(mu[i][j])>Fraction(1,2) for i in range(n) for j in range(i)) or any(norms[k]<(Fraction(3,4)-mu[k][k-1]**2)*norms[k-1] for k in range(1,n)):
        raise ValueError("LLL conditions failed")
    return True


def reduce(B):
    R=[list(row) for row in B]
    n=len(R)
    if not 2<=n<=8 or any(len(row)!=n or any(type(x) is not int for x in row) for row in R) or determinant(R)==0:
        raise ValueError("full-rank integer basis dimension 2..8 required")
    U=[[int(i==j) for j in range(n)] for i in range(n)]
    trace=[]
    k,iterations=1,0
    while k<n:
        iterations+=1
        if iterations>10000:
            raise ArithmeticError("LLL budget exhausted")
        for j in range(k-1,-1,-1):
            mu,_=gram_schmidt(R)
            v=mu[k][j]
            c=(2*v.numerator+v.denominator)//(2*v.denominator)
            if c:
                R[k]=[a-c*b for a,b in zip(R[k],R[j])]
                U[k]=[a-c*b for a,b in zip(U[k],U[j])]
                trace.append(["reduce",k,j,c])
        mu,norms=gram_schmidt(R)
        if norms[k]>=(Fraction(3,4)-mu[k][k-1]**2)*norms[k-1]:
            k+=1
        else:
            R[k],R[k-1]=R[k-1],R[k]
            U[k],U[k-1]=U[k-1],U[k]
            trace.append(["swap",k])
            k=max(1,k-1)
    record=dict(original=B,reduced=R,unimodular=U,trace=trace,iterations=iterations,dimension=n,delta="3/4")
    verify(record)
    return record


def candidates(A,q,m,l):
    B=[[int(i==j) for j in range(m)]+A[i][:l] for i in range(m)]
    B+=[[0]*m+[q*int(i==j) for j in range(l)] for i in range(l)]
    reduction=reduce(B)
    center=lambda x:(x+q//2)%q-q//2
    reference=[]
    for y in itertools.product(range(-q//2+1,q//2+1),repeat=m):
        if next((v for v in y if v),0)<=0:
            continue
        x=[center(sum(y[i]*A[i][j] for i in range(m))) for j in range(l)]
        reference.append(dict(y=list(y),x=x,squared_norm=sum(v*v for v in list(y)+x)))
    reduced={}
    for c in itertools.product(range(-2,3),repeat=m+l):
        v=[center(sum(a*row[j] for a,row in zip(c,reduction["reduced"]))) for j in range(m+l)]
        first=next((a for a in v[:m] if a),0)
        if not first:
            continue
        sign=1 if first>0 else -1
        v=tuple(sign*a for a in v)
        reduced.setdefault(v,dict(y=list(v[:m]),x=list(v[m:]),squared_norm=sum(a*a for a in v),coefficients=[sign*a for a in c]))
    order=lambda v:(v["squared_norm"],v["y"],v["x"])
    reference=sorted(reference,key=order)
    reduced=sorted(reduced.values(),key=order)
    if len(reduced)<12 or any(a["squared_norm"]>b["squared_norm"] for a,b in zip(reference,reduced)):
        raise ArithmeticError("list capacity or reference norm order failed")
    return reduction,reference,reduced
