"""Literal CBD-bit enumeration and independent finite coded-dual score replay."""

from collections import Counter
from datetime import datetime,timezone
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/"results/j2/run-013"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def equal_probability(record,value):
    if Fraction(record["numerator"],record["denominator"])!=value:
        raise ValueError("independent event probability disagrees")


def independent_matrix(q,identifier):
    label=f"nist-j2-full-dual-v1:{q}:{identifier}".encode("ascii")
    values=[]
    counter=0
    while len(values)<10:
        raw=hashlib.shake_256(label+counter.to_bytes(8,"little")).digest(4096)
        counter+=1
        for j in range(0,len(raw),2):
            x=int.from_bytes(raw[j:j+2],"little")
            if x<65536//q*q:
                values.append(x%q)
                if len(values)==10:
                    break
    return [values[:5],values[5:]]


def literal_laws(A,q):
    laws={family:Counter() for family in ("repeated","radix")}
    generators={"repeated":[1]*4,"radix":[pow(1 if q==5 else 2,j,q) for j in range(4)]}
    for bits in itertools.product((0,1),repeat=14):
        v=[bits[i]-bits[i+1] for i in range(0,14,2)]
        b=tuple((sum(a*s for a,s in zip(line,v[2:]))+e)%q for line,e in zip(A,v[:2]))
        for family,g in generators.items():
            u=sum(a*s for a,s in zip(g,v[3:]))%q
            laws[family][b+(u,)]+=1
    return laws


def replay():
    study=read(RUN/"study.json")
    tables={r["q"]:r for r in read(RUN/"transcendental-tables.json")}
    scores=[json.loads(s) for s in (RUN/"score-tables.jsonl").read_text().splitlines()]
    laws={}
    for q in (5,17):
        for identifier in (0,1):
            A=independent_matrix(q,identifier)
            laws[q,identifier]=literal_laws(A,q)
    checked_scores=0
    maximum_moment_delta=0.0
    for panel in study["panels"]:
        bank=panel["bank"]
        q,N,A=bank["q"],bank["size"],bank["A"]
        if A!=independent_matrix(q,panel["matrix_identifier"]):
            raise ValueError("independent matrix generation disagrees")
        expected=[]
        half=q//2
        center=lambda x:(x+half)%q-half
        for a,b in itertools.product(range(-half,half+1),repeat=2):
            if a<0 or a==0 and b<=0:
                continue
            x=center(a*A[0][0]+b*A[1][0])
            expected.append((a*a+b*b+x*x,(a,b),x))
        expected.sort()
        g=[1]*4 if bank["code"]["family"]=="repeated" else [pow(1 if q==5 else 2,j,q) for j in range(4)]
        if bank["code"]["generators"]!=[g]:
            raise ValueError("independent code construction disagrees")
        for row,(norm,y,x) in zip(bank["vectors"],expected[:N]):
            target=[(y[0]*A[0][j]+y[1]*A[1][j])%q for j in range(1,5)]
            errors=[[center(t-c*a) for t,a in zip(target,g)] for c in range(q)]
            costs=[sum(e*e for e in r) if bank["metric"]=="euclidean" else sum(tables[q]["cbd_weights"][abs(e)] for e in r) for r in errors]
            c=min(range(q),key=lambda i:(costs[i],i))
            if row["y"]!=list(y) or row["x"]!=x or row["squared_lattice_norm"]!=norm or row["c"]!=c or row["r"]!=errors[c] or row["coefficient"]!=list(y)+[x]+errors[c]:
                raise ValueError("independent dual/code vector disagrees")
        law=laws[q,panel["matrix_identifier"]][bank["code"]["family"]]
        supplied={tuple(r["b"])+(r["truth"],):r["weight"] for r in panel["observation_law"]}
        if law!=supplied:
            raise ValueError("literal CBD bit law disagrees with weighted states")
        actual={tuple(r["b"]):r["folds"] for r in scores if r["panel"]==panel["panel"]}
        exact={}
        cosine=tables[q]["cosine_weights"]
        for b in itertools.product(range(q),repeat=2):
            hists=[]
            for u in range(q):
                hist=[0]*(half+1)
                for row in bank["vectors"]:
                    p=(row["y"][0]*b[0]+row["y"][1]*b[1]-row["c"]*u)%q
                    hist[min(p,q-p)]+=1
                hists.append(hist)
                checked_scores+=1
            if hists!=actual[b]:
                raise ValueError("independent complete Fourier score table disagrees")
            integers=[sum(a*c for a,c in zip(h,cosine)) for h in hists]
            ordered=sorted(range(q),key=lambda i:integers[i])
            for i,j in zip(ordered,ordered[1:]):
                if hists[i]!=hists[j] and integers[j]-integers[i]<N:
                    raise ValueError("independent ranking interval unresolved")
            exact[b]=(hists,integers)
        strict=member=0
        tie=Fraction(0)
        counts=[[0]*q for _ in (0,1)]
        union=[0,0]
        empirical=[[] for _ in range(q)]
        distributions=[Counter() for _ in range(q)]
        max_dist=Counter()
        score=lambda hist:sum(a*math.cos(2*math.pi*d/q) for d,a in enumerate(hist))/N
        for key,weight in law.items():
            hists,integers=exact[key[:2]]
            truth=key[2]
            best=max(integers)
            correct=integers[truth]
            strict+=weight*(correct>max(v for i,v in enumerate(integers) if i!=truth))
            member+=weight*(correct==best)
            if correct==best:
                tie+=Fraction(weight,integers.count(best))
            best_wrong=max((v,i) for i,v in enumerate(integers) if i!=truth)[1]
            max_dist[tuple(hists[best_wrong])]+=weight
            for d in range(q):
                hist=hists[(truth+d)%q]
                empirical[d].append((score(hist),weight))
                distributions[d][tuple(hist)]+=weight
                t=integers[(truth+d)%q]
                for j,boundary in enumerate((0,N//2*(1<<48))):
                    if t<boundary<t+N:
                        raise ValueError("independent threshold interval unresolved")
                    counts[j][d]+=weight*(t>=boundary)
            for j,boundary in enumerate((0,N//2*(1<<48))):
                union[j]+=weight*any(v>=boundary for i,v in enumerate(integers) if i!=truth)
        equal_probability(panel["strict_success"],Fraction(strict,16384))
        equal_probability(panel["true_in_argmax"],Fraction(member,16384))
        equal_probability(panel["uniform_tie_success"],tie/16384)
        for i,tail in enumerate(panel["tails"]):
            equal_probability(tail["true_pass"],Fraction(counts[i][0],16384))
            probabilities=[Fraction(c,16384) for c in counts[i][1:]]
            for p,record in zip(probabilities,tail["false_offset_pass"]):
                equal_probability(record,p)
            equal_probability(tail["any_false_pass"],Fraction(union[i],16384))
            equal_probability(tail["independence_prediction"],1-math.prod(1-p for p in probabilities))
            equal_probability(tail["exact_union_bound"],min(Fraction(1),sum(probabilities)))
        encode=lambda distribution:[dict(fold=list(h),weight=w) for h,w in sorted(distribution.items())]
        if panel["true_distribution"]!=encode(distributions[0]) or panel["pooled_false_distribution"]!=encode(sum(distributions[1:],Counter())) or panel["maximum_false_distribution"]!=encode(max_dist):
            raise ValueError("independent exact score distributions disagree")
        for terms,moments in zip(empirical,panel["offset_moments"]):
            mean=math.fsum(value*w for value,w in terms)/16384
            variance=math.fsum((value-mean)**2*w for value,w in terms)/16384
            delta=max(abs(mean-moments["mean"]),abs(variance-moments["variance"]))
            maximum_moment_delta=max(maximum_moment_delta,delta)
            if delta>2e-12:
                raise ValueError("independent complete-score moments disagree")
        for j,tail in enumerate(panel["uniform_null"]["tails"]):
            boundary=(0,N//2*(1<<48))[j]
            per=[sum(values[u]>=boundary for h,values in exact.values()) for u in range(q)]
            all_count=sum(any(v>=boundary for v in values) for h,values in exact.values())
            equal_probability(tail["fixed_guess_pass"],Fraction(per[0],q*q))
            equal_probability(tail["any_guess_pass"],Fraction(all_count,q*q))
            equal_probability(tail["independence_prediction"],1-math.prod(1-Fraction(c,q*q) for c in per))
    if len(study["panels"])!=32:
        raise ValueError("32 panels required")
    return dict(project_arithmetic_imported=False,matrices=4,literal_CBD_bit_strings=4*2**14,
                panels=32,complete_guess_scores=checked_scores,all_exact_laws_and_events_matched=True,
                maximum_absolute_moment_delta=maximum_moment_delta)


def main():
    result=replay()
    output=RUN/"independent-verification.json"
    if output.exists():
        old=read(output)
        if {k:v for k,v in old.items() if k!="maximum_absolute_moment_delta"}!={k:v for k,v in result.items() if k!="maximum_absolute_moment_delta"}:
            raise ValueError("independent replay changed")
    else:
        with output.open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(result,stream,indent=2)
            stream.write("\n")
        names=["research/verify_full_dual_toy_independent.py"]+[(RUN/n).relative_to(ROOT).as_posix() for n in ("study.json","score-tables.jsonl","transcendental-tables.json")]
        provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),
                        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                        output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()})
        with (RUN/"independent-provenance.json").open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(provenance,stream,indent=2)
            stream.write("\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
