"""Finite LWE coded-dual score with exact phase laws and certified decisions.

No BKZ, MLWE rotations, full-size attack, KEM implementation or security cost.
All randomness in the LWE experiment is enumerated with exact CBD1 weights.
"""

from collections import Counter
from fractions import Fraction
import cmath
import itertools
import math

from block_decoder import centered,make_code
from cbd_decoder import decode_scalar
from run_block_decoder import targets

COS_SCALE=1<<48
DENOMINATOR=4**7


def probability(value,denominator=1):
    value=Fraction(value,denominator)
    return dict(numerator=value.numerator,denominator=value.denominator,value=float(value))


def matrix(q,identifier):
    return targets(q,5,2,f"nist-j2-full-dual-v1:{q}:{identifier}".encode("ascii"))


def dual_list(A,q,size,family,metric,weights):
    code=make_code(q,4,1,family)
    candidates=[]
    for y in itertools.product(range(-q//2+1,q//2+1),repeat=2):
        if next((v for v in y if v),0)<=0:
            continue
        x=centered(sum(y[i]*A[i][0] for i in range(2)),q)
        candidates.append((sum(v*v for v in y)+x*x,y,x))
    candidates.sort()
    if len(candidates)<size:
        raise ValueError("not enough distinct signed dual representatives")
    rows=[]
    for squared,y,x in candidates[:size]:
        t=[sum(y[i]*A[i][j] for i in range(2))%q for j in range(1,5)]
        result=decode_scalar(code,t,weights,metric)
        c=result["labels"][0]
        r=[centered(a-b,q) for a,b in zip(t,code.encode([c]))]
        rows.append(dict(y=list(y),x=x,t=t,c=c,r=r,coefficient=list(y)+[x]+r,
                         squared_lattice_norm=squared,certificates=result["certificates"]))
    return dict(q=q,A=A,code=code.record(),size=size,metric=metric,vectors=rows,
                selection="shortest centered representatives in enumerated nonzero dual quotient, one per sign pair")


def lwe_law(A,generator,q):
    law=Counter()
    for state in itertools.product((-1,0,1),repeat=7):
        e,s=state[:2],state[2:]
        weight=2**state.count(0)
        b=tuple((sum(a*v for a,v in zip(row,s))+error)%q for row,error in zip(A,e))
        truth=sum(g*v for g,v in zip(generator,s[1:]))%q
        law[b+(truth,)]+=weight
    if sum(law.values())!=DENOMINATOR:
        raise ArithmeticError("CBD state weights do not normalize")
    return [dict(b=list(key[:2]),truth=key[2],weight=weight) for key,weight in sorted(law.items())]


def folded(phases,q):
    counts=[0]*(q//2+1)
    for p in phases:
        p%=q
        counts[min(p,q-p)]+=1
    return counts


def integer_score(hist,cosine_weights):
    return sum(a*b for a,b in zip(hist,cosine_weights))


def compare_scores(a,b,weights,size):
    if a==b:
        return 0
    difference=integer_score(a,weights)-integer_score(b,weights)
    if abs(difference)<size:
        raise ArithmeticError("distinct score intervals overlap; no uncertified tie decision")
    return 1 if difference>0 else -1


def passes(hist,threshold,weights,size):
    value=integer_score(hist,weights)
    boundary=Fraction(threshold)*size*COS_SCALE
    if value>=boundary:
        return True
    if value+size<=boundary:
        return False
    raise ArithmeticError("threshold interval unresolved")


def maximum(hists,weights,size):
    best=0
    for i in range(1,len(hists)):
        if compare_scores(hists[i],hists[best],weights,size)>0:
            best=i
    return best


def score_table(bank,cosine_weights):
    q,N=bank["q"],bank["size"]
    table=[]
    maximum_dft_delta=0.0
    cosine=[math.cos(2*math.pi*d/q) for d in range(q//2+1)]
    for b in itertools.product(range(q),repeat=2):
        bins=[0j]*q
        for row in bank["vectors"]:
            phase=sum(a*v for a,v in zip(row["y"],b))%q
            bins[row["c"]]+=cmath.exp(2j*math.pi*phase/q)
        hists=[]
        for u in range(q):
            hist=folded((sum(a*v for a,v in zip(row["y"],b))-row["c"]*u for row in bank["vectors"]),q)
            actual=math.fsum(a*c for a,c in zip(hist,cosine))/N
            dft=sum(z*cmath.exp(-2j*math.pi*c*u/q) for c,z in enumerate(bins)).real/N
            maximum_dft_delta=max(maximum_dft_delta,abs(actual-dft))
            hists.append(hist)
        maximum(hists,cosine_weights,N)
        table.append(dict(b=list(b),folds=hists))
    if maximum_dft_delta>1e-12:
        raise ArithmeticError("direct Fourier table disagrees with phase score")
    return table,maximum_dft_delta


def phi(a,q):
    return math.prod(math.cos(math.pi*centered(v,q)/q)**2 for v in a)


def analytic_moments(bank,offset):
    q,N=bank["q"],bank["size"]
    vectors=bank["vectors"]
    means=[phi(r["coefficient"],q)*math.cos(2*math.pi*r["c"]*offset/q) for r in vectors]
    covariance=[]
    diagonal=[]
    for i,a in enumerate(vectors):
        for j,b in enumerate(vectors):
            minus=[x-y for x,y in zip(a["coefficient"],b["coefficient"])]
            plus=[x+y for x,y in zip(a["coefficient"],b["coefficient"])]
            value=(phi(minus,q)*math.cos(2*math.pi*(a["c"]-b["c"])*offset/q)
                   +phi(plus,q)*math.cos(2*math.pi*(a["c"]+b["c"])*offset/q))/2-means[i]*means[j]
            covariance.append(value)
            if i==j:
                diagonal.append(value)
    return dict(mean=math.fsum(means)/N,variance=math.fsum(covariance)/N**2,
                diagonal_variance=math.fsum(diagonal)/N**2)


def evaluate(bank,law,table,cosine_weights):
    q,N=bank["q"],bank["size"]
    values={tuple(r["b"]):r["folds"] for r in table}
    cosines=[math.cos(2*math.pi*d/q) for d in range(q//2+1)]
    score=lambda h: math.fsum(a*c for a,c in zip(h,cosines))/N
    distributions=[Counter() for _ in range(q)]
    max_wrong=Counter()
    strict=member=0
    tie_success=Fraction(0)
    thresholds=(Fraction(0),Fraction(1,2))
    marginal_counts=[[0]*q for _ in thresholds]
    union_counts=[0]*len(thresholds)
    for row in law:
        hists=values[tuple(row["b"])]
        truth,weight=row["truth"],row["weight"]
        shifted=[hists[(truth+d)%q] for d in range(q)]
        for d,hist in enumerate(shifted):
            distributions[d][tuple(hist)]+=weight
        wrong=shifted[1:]
        best_wrong=wrong[maximum(wrong,cosine_weights,N)]
        max_wrong[tuple(best_wrong)]+=weight
        ordering=compare_scores(shifted[0],best_wrong,cosine_weights,N)
        if ordering>0:
            strict+=weight
        if ordering>=0:
            member+=weight
            tied=sum(compare_scores(hist,shifted[0],cosine_weights,N)==0 for hist in shifted)
            tie_success+=Fraction(weight,tied)
        for i,threshold in enumerate(thresholds):
            for d,hist in enumerate(shifted):
                marginal_counts[i][d]+=weight*passes(hist,threshold,cosine_weights,N)
            union_counts[i]+=weight*passes(best_wrong,threshold,cosine_weights,N)
    moments=[]
    for d,distribution in enumerate(distributions):
        mean=math.fsum(weight*score(hist) for hist,weight in distribution.items())/DENOMINATOR
        variance=math.fsum(weight*(score(hist)-mean)**2 for hist,weight in distribution.items())/DENOMINATOR
        theory=analytic_moments(bank,d)
        if abs(theory["mean"]-mean)>2e-12 or abs(theory["variance"]-variance)>2e-12:
            raise ArithmeticError("full CBD covariance formula disagrees with complete law")
        moments.append(dict(offset=d,enumerated_mean=mean,enumerated_variance=variance,**theory))
    tails=[]
    for threshold,counts,union in zip(thresholds,marginal_counts,union_counts):
        probabilities=[Fraction(c,DENOMINATOR) for c in counts[1:]]
        independent=1-math.prod(1-p for p in probabilities)
        bound=min(Fraction(1),sum(probabilities))
        if Fraction(union,DENOMINATOR)>bound:
            raise ArithmeticError("exact union bound failed")
        tails.append(dict(threshold=str(threshold),true_pass=probability(counts[0],DENOMINATOR),
                          false_offset_pass=[probability(p) for p in probabilities],
                          any_false_pass=probability(union,DENOMINATOR),
                          independence_prediction=probability(independent),exact_union_bound=probability(bound)))
    null_rows=[r["folds"] for r in table]
    null_mean=math.fsum(score(r[0]) for r in null_rows)/q**2
    null_variance=math.fsum((score(r[0])-null_mean)**2 for r in null_rows)/q**2
    if abs(null_mean)>2e-12 or abs(null_variance-1/(2*N))>2e-12:
        raise ArithmeticError("uniform-null mean/variance identity failed")
    null_tails=[]
    for threshold in thresholds:
        per_guess=[sum(passes(r[u],threshold,cosine_weights,N) for r in null_rows) for u in range(q)]
        any_pass=sum(any(passes(h,threshold,cosine_weights,N) for h in r) for r in null_rows)
        predicted=1-math.prod(1-Fraction(c,q**2) for c in per_guess)
        normal=math.erfc(float(threshold)*math.sqrt(N))/2
        null_tails.append(dict(threshold=str(threshold),fixed_guess_pass=probability(per_guess[0],q**2),
                               all_guess_marginals=[probability(c,q**2) for c in per_guess],
                               any_guess_pass=probability(any_pass,q**2),independence_prediction=probability(predicted),
                               Gaussian_fixed_guess_tail=normal))
    encode=lambda histogram:[dict(fold=list(h),weight=w) for h,w in sorted(histogram.items())]
    return dict(strict_success=probability(strict,DENOMINATOR),true_in_argmax=probability(member,DENOMINATOR),
                uniform_tie_success=probability(tie_success/DENOMINATOR),offset_moments=moments,tails=tails,
                true_distribution=encode(distributions[0]),pooled_false_distribution=encode(sum(distributions[1:],Counter())),
                maximum_false_distribution=encode(max_wrong),
                uniform_null=dict(mean=null_mean,variance=null_variance,independent_variance=1/(2*N),tails=null_tails))
