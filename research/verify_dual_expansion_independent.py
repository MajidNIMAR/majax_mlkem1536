"""Independent H07 certificates, literal CBD bits, exact score laws and events.

No project arithmetic imports. Gram matrices verify LLL; scores are rebuilt
directly from the public relations. Frozen interval tables certify decisions.
"""

from collections import Counter
from datetime import datetime,timezone
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/"results/j2/run-014"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def matrix(q,identifier):
    values=[]
    counter=0
    label=f"nist-j2-full-dual-v1:{q}:{identifier}".encode()
    while len(values)<10:
        block=hashlib.shake_256(label+counter.to_bytes(8,"little")).digest(4096)
        counter+=1
        for j in range(0,len(block),2):
            x=int.from_bytes(block[j:j+2],"little")
            if x<65536//q*q:
                values.append(x%q)
                if len(values)==10:
                    break
    return [values[:5],values[5:]]


def det(B):
    total=0
    for permutation in itertools.permutations(range(3)):
        inversions=sum(permutation[i]>permutation[j] for i in range(3) for j in range(i+1,3))
        total+=(-1)**inversions*math.prod(B[i][permutation[i]] for i in range(3))
    return total


def case_certificate(case):
    q,A=case["q"],case["A"]
    if A!=matrix(q,case["identifier"]):
        raise ValueError("independent matrix generation failed")
    r=case["reduction"]
    B,R,U=r["original"],r["reduced"],r["unimodular"]
    if B!=[[1,0,A[0][0]],[0,1,A[1][0]],[0,0,q]] or abs(det(U))!=1 or abs(det(R))!=q:
        raise ValueError("independent unimodular certificate failed")
    if [[sum(U[i][k]*B[k][j] for k in range(3)) for j in range(3)] for i in range(3)]!=R:
        raise ValueError("independent basis transform failed")
    replay=[row[:] for row in B]
    for operation in r["trace"]:
        if operation[0]=="reduce":
            _,i,j,m=operation
            replay[i]=[a-m*b for a,b in zip(replay[i],replay[j])]
        elif operation[0]=="swap":
            i=operation[1]
            replay[i],replay[i-1]=replay[i-1],replay[i]
        else:
            raise ValueError("independent trace operation invalid")
    if replay!=R:
        raise ValueError("independent trace replay failed")
    gram=[[sum(a*b for a,b in zip(v,w)) for w in R] for v in R]
    mu=[[Fraction(0)]*3 for _ in range(3)]
    norms=[]
    for i in range(3):
        for j in range(i):
            mu[i][j]=(Fraction(gram[i][j])-sum(mu[i][k]*mu[j][k]*norms[k] for k in range(j)))/norms[j]
            if abs(mu[i][j])>Fraction(1,2):
                raise ValueError("independent size reduction failed")
        norms.append(Fraction(gram[i][i])-sum(mu[i][j]**2*norms[j] for j in range(i)))
    if any(norms[i]<(Fraction(3,4)-mu[i][i-1]**2)*norms[i-1] for i in (1,2)):
        raise ValueError("independent Lovasz check failed")
    half=q//2
    center=lambda x:(x+half)%q-half
    reference=[]
    for a,b in itertools.product(range(-half,half+1),repeat=2):
        if a<0 or a==0 and b<=0:
            continue
        x=center(a*A[0][0]+b*A[1][0])
        reference.append(dict(y=[a,b],x=x,squared_norm=a*a+b*b+x*x))
    reduced={}
    for coefficients in itertools.product((-2,-1,0,1,2),repeat=3):
        v=[center(sum(c*R[i][j] for i,c in enumerate(coefficients))) for j in range(3)]
        if v[0]==0 and v[1]==0:
            continue
        negative=v[0]<0 or v[0]==0 and v[1]<0
        if negative:
            v=[-a for a in v]
        witness=[-c if negative else c for c in coefficients]
        reduced.setdefault(tuple(v),dict(y=v[:2],x=v[2],squared_norm=sum(a*a for a in v),coefficients=witness))
    order=lambda r:(r["squared_norm"],r["y"],r["x"])
    if sorted(reference,key=order)!=case["reference"] or sorted(reduced.values(),key=order)!=case["lll_box"]:
        raise ValueError("independent candidate enumeration failed")


def literal_laws(case):
    q,A=case["q"],case["A"]
    gs={tuple([1]*4),tuple(pow(1 if q==5 else 2,j,q) for j in range(4))}
    laws={g:Counter() for g in gs}
    for bits in itertools.product((0,1),repeat=14):
        state=[bits[i]-bits[i+1] for i in range(0,14,2)]
        b=tuple((sum(a*s for a,s in zip(row,state[2:]))+e)%q for row,e in zip(A,state[:2]))
        for g,law in laws.items():
            u=sum(a*s for a,s in zip(g,state[3:]))%q
            law[b+(u,)]+=1
    return laws


def pcheck(record,p):
    if Fraction(record["numerator"],record["denominator"])!=p:
        raise ValueError("independent exact probability failed")


def score_audit(record,law,t):
    bank,result=record["bank"],record["result"]
    q,N=bank["q"],bank["size"]
    weights=t["cosine_weights"]
    all_scores=[]
    lookup={}
    for b in itertools.product(range(q),repeat=2):
        histograms=[]
        for u in range(q):
            hist=[0]*(q//2+1)
            for v in bank["vectors"]:
                phase=(v["y"][0]*b[0]+v["y"][1]*b[1]-v["c"]*u)%q
                hist[min(phase,q-phase)]+=1
            histograms.append(hist)
        integers=[sum(a*c for a,c in zip(hist,weights)) for hist in histograms]
        sorted_ids=sorted(range(q),key=lambda i:integers[i])
        for i,j in zip(sorted_ids,sorted_ids[1:]):
            if histograms[i]!=histograms[j] and integers[j]-integers[i]<N:
                raise ValueError("independent score order not certified")
        for integer in integers:
            for threshold in (0,N//2*(1<<48)):
                if integer<threshold<integer+N:
                    raise ValueError("independent threshold not certified")
        all_scores.append(dict(b=list(b),folds=histograms))
        lookup[b]=(histograms,integers)
    if sha(all_scores)!=record["score_table_sha256"]:
        raise ValueError("independent score table hash failed")
    encoded_law=[dict(b=list(key[:2]),truth=key[2],weight=w) for key,w in sorted(law.items())]
    if sha(encoded_law)!=record["law_sha256"]:
        raise ValueError("literal bit law hash failed")
    strict=member=0
    tie=Fraction(0)
    counts=[[0]*q for _ in range(2)]
    unions=[0,0]
    true_dist,pooled_dist,max_dist=Counter(),Counter(),Counter()
    sums=[0.0]*q
    squares=[0.0]*q
    cosines=[math.cos(2*math.pi*d/q) for d in range(q//2+1)]
    score=lambda hist:math.fsum(a*c for a,c in zip(hist,cosines))/N
    for key,w in law.items():
        histograms,integers=lookup[key[:2]]
        truth=key[2]
        best=max(integers)
        other=max((v,i) for i,v in enumerate(integers) if i!=truth)[1]
        strict+=w*(integers[truth]>integers[other])
        member+=w*(integers[truth]==best)
        if integers[truth]==best:
            tie+=Fraction(w,integers.count(best))
        true_dist[tuple(histograms[truth])]+=w
        max_dist[tuple(histograms[other])]+=w
        for d in range(q):
            hist=histograms[(truth+d)%q]
            if d:
                pooled_dist[tuple(hist)]+=w
            value=score(hist)
            sums[d]+=w*value
            squares[d]+=w*value*value
            for j,boundary in enumerate((0,N//2*(1<<48))):
                counts[j][d]+=w*(integers[(truth+d)%q]>=boundary)
        for j,boundary in enumerate((0,N//2*(1<<48))):
            unions[j]+=w*(integers[other]>=boundary)
    pcheck(result["strict_success"],Fraction(strict,16384))
    pcheck(result["true_in_argmax"],Fraction(member,16384))
    pcheck(result["uniform_tie_success"],tie/16384)
    maximum_delta=0.0
    for d,m in enumerate(result["offset_moments"]):
        mean=sums[d]/16384
        variance=squares[d]/16384-mean*mean
        maximum_delta=max(maximum_delta,abs(mean-m["mean"]),abs(variance-m["variance"]))
    if maximum_delta>2e-12:
        raise ValueError("independent full score moments failed")
    encode=lambda counter:[dict(fold=list(h),weight=w) for h,w in sorted(counter.items())]
    for name,distribution in (("true_distribution",true_dist),("pooled_false_distribution",pooled_dist),("maximum_false_distribution",max_dist)):
        if sha(encode(distribution))!=result["exact_distribution_sha256"][name]:
            raise ValueError("independent exact distribution hash failed")
    for j,tail in enumerate(result["tails"]):
        ps=[Fraction(c,16384) for c in counts[j][1:]]
        pcheck(tail["true_pass"],Fraction(counts[j][0],16384))
        pcheck(tail["any_false_pass"],Fraction(unions[j],16384))
        for record,p in zip(tail["false_offset_pass"],ps):
            pcheck(record,p)
        pcheck(tail["independence_prediction"],1-math.prod(1-p for p in ps))
        pcheck(tail["exact_union_bound"],min(Fraction(1),sum(ps)))
    null_values=[score(h[0]) for h,ints in lookup.values()]
    if abs(sum(null_values)/q**2)>2e-12 or abs(sum(v*v for v in null_values)/q**2-1/(2*N))>2e-12:
        raise ValueError("independent uniform null variance failed")
    for j,tail in enumerate(result["uniform_null"]["tails"]):
        boundary=(0,N//2*(1<<48))[j]
        per=[sum(ints[u]>=boundary for h,ints in lookup.values()) for u in range(q)]
        pcheck(tail["fixed_guess_pass"],Fraction(per[0],q*q))
        pcheck(tail["any_guess_pass"],Fraction(sum(max(ints)>=boundary for h,ints in lookup.values()),q*q))
        pcheck(tail["independence_prediction"],1-math.prod(1-Fraction(c,q*q) for c in per))
    return q**3,maximum_delta


def replay():
    cases=read(RUN/"cases.json")
    panels=read(RUN/"panels.json")
    banks=[json.loads(s) for s in (RUN/"banks.jsonl").read_text().splitlines()]
    tables={t["q"]:t for t in read(ROOT/"results/j2/run-013/transcendental-tables.json")}
    if {(c["q"],c["identifier"]) for c in cases}!={(q,i) for q in (5,17) for i in range(16)} or len(cases)!=32 or len(panels)!=768:
        raise ValueError("independent family coverage failed")
    laws={}
    for case in cases:
        case_certificate(case)
        laws[case["case"]]=literal_laws(case)
    by_case={c["case"]:c for c in cases}
    by_bank={r["bank_id"]:r for r in banks}
    expected_panels={(c["case"],source,N,family,metric) for c in cases for source in ("reference","lll_box")
                     for N in (4,8,12) for family in ("repeated","radix") for metric in ("euclidean","cbd")}
    if {(p["case"],p["source"],p["N"],p["family"],p["metric"]) for p in panels}!=expected_panels:
        raise ValueError("independent panel cross product failed")
    used={}
    for panel in panels:
        case=by_case[panel["case"]]
        q,A=case["q"],case["A"]
        center=lambda x:(x+q//2)%q-q//2
        g=[1]*4 if panel["family"]=="repeated" else [pow(1 if q==5 else 2,j,q) for j in range(4)]
        vectors=[]
        for v in case[panel["source"]][:panel["N"]]:
            target=[sum(a*row[j] for a,row in zip(v["y"],A))%q for j in range(1,5)]
            errors=[[center(x-c*a) for x,a in zip(target,g)] for c in range(q)]
            costs=[sum(x*x for x in r) if panel["metric"]=="euclidean" else sum(tables[q]["cbd_weights"][abs(x)] for x in r) for r in errors]
            c=min(range(q),key=lambda i:(costs[i],i))
            vectors.append(dict(y=v["y"],x=v["x"],c=c,r=errors[c]))
        identity=dict(q=q,A=A,g=[g],vectors=vectors)
        if sha(identity)!=panel["bank_id"]:
            raise ValueError("independent bank/cache identity failed")
        bank=by_bank[panel["bank_id"]]["bank"]
        if [{k:v[k] for k in ("y","x","c","r")} for v in bank["vectors"]]!=vectors or bank["A"]!=A:
            raise ValueError("independent saved vectors failed")
        used[panel["bank_id"]]=(panel["case"],tuple(g))
    if set(used)!=set(by_bank):
        raise ValueError("unused or missing bank")
    scores=0
    delta=0.0
    for key,(case,g) in used.items():
        count,observed=score_audit(by_bank[key],laws[case][g],tables[by_case[case]["q"]])
        scores+=count
        delta=max(delta,observed)
    return dict(project_arithmetic_imported=False,matrices=32,LLL_certificates=32,panels=768,
                literal_CBD_bit_strings=32*16384,distinct_score_banks=len(banks),complete_guess_scores=scores,
                exact_laws_events_and_hashes_matched=True,maximum_absolute_moment_delta=delta)


def main():
    result=replay()
    output=RUN/"independent-verification.json"
    if output.exists():
        old=read(output)
        if {k:v for k,v in result.items() if k!="maximum_absolute_moment_delta"}!={k:v for k,v in old.items() if k!="maximum_absolute_moment_delta"}:
            raise ValueError("independent expansion replay changed")
    else:
        with output.open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(result,stream,indent=2)
            stream.write("\n")
        names=["research/verify_dual_expansion_independent.py","results/j2/run-013/transcendental-tables.json"]+[(RUN/n).relative_to(ROOT).as_posix() for n in ("cases.json","panels.json","banks.jsonl")]
        provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),
                        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                        output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()})
        with (RUN/"independent-provenance.json").open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(provenance,stream,indent=2)
            stream.write("\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
