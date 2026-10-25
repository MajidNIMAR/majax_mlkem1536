"""Full-codebook and actual-block H05 integer oracles, no project imports."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/"results/j2/run-012"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def distance(target,word,q):
    return [min(abs(x-y),q-abs(x-y)) for x,y in zip(target,word)]


def replay():
    weights={r["q"]:r["weights"] for r in read(RUN/"weight-tables.json")}
    toys=read(RUN/"toy-comparison.json")
    targets=0
    for toy in toys:
        code=toy["code"]
        q=code["q"]
        words=[(list(labels),[a*g%q for a,block in zip(labels,code["generators"]) for g in block])
               for labels in itertools.product(range(q),repeat=code["k"])]
        for target,row in zip(itertools.product(range(q),repeat=code["n"]),toy["observations"]):
            costs=[(sum(e*e for e in distance(target,word,q)),sum(weights[q][e] for e in distance(target,word,q)),labels)
                   for labels,word in words]
            a=min((norm,labels) for norm,cost,labels in costs)
            b=min((cost,labels) for norm,cost,labels in costs)
            if a!=(row["euclidean"]["squared_norm"],row["euclidean"]["labels"]) or b!=(row["cbd"]["integer_cost"],row["cbd"]["labels"]):
                raise ValueError("independent complete codebook disagrees")
            targets+=1
    cases=read(RUN/"oracle-cases.json")
    symbols=0
    for case in cases:
        q=case["q"]
        histograms=[distance(case["values"],[a*g%q for g in case["generator"]],q) for a in range(q)]
        euclidean=[sum(e*e for e in r) for r in histograms]
        cbd=[sum(weights[q][e] for e in r) for r in histograms]
        a=min(range(q),key=lambda i:(euclidean[i],i))
        b=min(range(q),key=lambda i:(cbd[i],i))
        proof=case["certificate"]
        contenders=[i for i,c in enumerate(cbd) if c<cbd[b]+len(case["generator"])]
        certified=all(Counter(histograms[i])==Counter(histograms[b]) for i in contenders)
        if a!=case["euclidean_label"] or b!=case["cbd_label"]:
            raise ValueError("independent real-alphabet labels disagree")
        if proof!=dict(integer_cost=cbd[b],second_symbol_integer_gap=min(c for i,c in enumerate(cbd) if i!=b)-cbd[b],
                       interval_contenders=len(contenders),real_optimum_certified=certified):
            raise ValueError("independent interval certificate disagrees")
        symbols+=q
    if len(toys)!=6 or targets!=6302 or len(cases)!=64:
        raise ValueError("independent coverage incomplete")
    return dict(project_arithmetic_imported=False,complete_codebooks=6,classified_targets=targets,
                actual_modulus_blocks=len(cases),symbol_candidates_per_metric=symbols,all_matched=True)


def main():
    result=replay()
    output=RUN/"independent-verification.json"
    if output.exists():
        if read(output)!=result:
            raise ValueError("independent replay changed")
    else:
        with output.open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(result,stream,indent=2)
            stream.write("\n")
        names=["research/verify_cbd_decoder_independent.py"]+[(RUN/n).relative_to(ROOT).as_posix() for n in ("weight-tables.json","toy-comparison.json","oracle-cases.json")]
        provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),
                        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                        output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()})
        with (RUN/"independent-provenance.json").open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(provenance,stream,indent=2)
            stream.write("\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
