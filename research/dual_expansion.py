"""H07 expanded finite LWE scores, exact LLL certificates and shared exact data.

The small-dimensional experiment does not estimate full-size attack costs.
"""

import argparse
from datetime import datetime,timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from block_decoder import centered,make_code
from cbd_decoder import decode_scalar
from exact_lll import quotient_candidates,reduce_basis,reduced_candidates
from full_dual_toy import evaluate,lwe_law,matrix,score_table

ROOT=Path(__file__).resolve().parents[1]
SIZES=(4,8,12)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path,value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,indent=2,allow_nan=False)
        stream.write("\n")


def case_data(q,identifier):
    A=matrix(q,identifier)
    basis=[[1,0,A[0][0]],[0,1,A[1][0]],[0,0,q]]
    reduction=reduce_basis(basis)
    reference=quotient_candidates(A,q)
    reduced=reduced_candidates(A,q,reduction)
    if min(len(reference),len(reduced))<max(SIZES):
        raise ArithmeticError("preregistered list capacity not reached")
    for a,b in zip(reference,reduced):
        if a["squared_norm"]>b["squared_norm"]:
            raise ArithmeticError("bounded list beat exhaustive norm order")
    return dict(case=f"q{q}-matrix{identifier}",q=q,identifier=identifier,A=A,reduction=reduction,
                reference=reference,lll_box=reduced,coefficient_bound=2,enumerated_combinations=125)


def bank_for(case,source,N,family,metric,weights):
    if source not in ("reference","lll_box") or N not in SIZES:
        raise ValueError("preregistered source and list size required")
    q,A=case["q"],case["A"]
    code=make_code(q,4,1,family)
    rows=[]
    for vector in case[source][:N]:
        y,x=vector["y"],vector["x"]
        target=[sum(a*line[j] for a,line in zip(y,A))%q for j in range(1,5)]
        decoded=decode_scalar(code,target,weights,metric)
        c=decoded["labels"][0]
        residual=[centered(a-b,q) for a,b in zip(target,code.encode([c]))]
        rows.append(dict(y=y,x=x,t=target,c=c,r=residual,coefficient=y+[x]+residual,
                         squared_lattice_norm=vector["squared_norm"],certificates=decoded["certificates"]))
    return dict(q=q,A=A,code=code.record(),size=N,metric=metric,vectors=rows,
                selection="H07 "+source+" deterministic prefix")


def bank_key(bank):
    # Only exact data affecting the full score/law, not family or metric names.
    return fingerprint(dict(q=bank["q"],A=bank["A"],g=bank["code"]["generators"],
                            vectors=[{k:v[k] for k in ("y","x","c","r")} for v in bank["vectors"]]))


def pack(result):
    distributions=("true_distribution","pooled_false_distribution","maximum_false_distribution")
    return {k:v for k,v in result.items() if k not in distributions}|{
        "exact_distribution_sha256":{k:fingerprint(result[k]) for k in distributions}}


def fraction(record):
    return Fraction(record["numerator"],record["denominator"])


def summarize(cases,panels,banks):
    mapping={r["bank_id"]:r for r in banks}
    lookup={(p["case"],p["source"],p["N"],p["family"],p["metric"]):p for p in panels}
    comparisons=[]
    for q in (5,17):
        for source in ("reference","lll_box"):
            for family in ("repeated","radix"):
                for N in SIZES:
                    wins=losses=ties=paradoxes=0
                    successes={metric:[] for metric in ("euclidean","cbd")}
                    tied_successes={metric:[] for metric in successes}
                    for identifier in range(16):
                        records={metric:mapping[lookup[f"q{q}-matrix{identifier}",source,N,family,metric]["bank_id"]]["result"] for metric in successes}
                        for metric,r in records.items():
                            successes[metric].append(fraction(r["strict_success"]))
                            tied_successes[metric].append(fraction(r["uniform_tie_success"]))
                        delta=successes["cbd"][-1]-successes["euclidean"][-1]
                        wins+=delta>0
                        losses+=delta<0
                        ties+=delta==0
                        mean_delta=records["cbd"]["offset_moments"][0]["mean"]-records["euclidean"]["offset_moments"][0]["mean"]
                        paradoxes+=mean_delta>1e-12 and delta<0
                    from full_dual_toy import probability
                    comparisons.append(dict(q=q,source=source,family=family,N=N,matrices=16,
                                            CBD_wins=wins,CBD_losses=losses,identical_successes=ties,
                                            mean_improves_ranking_degrades=paradoxes,
                                            mean_strict_success={m:probability(sum(v)/16) for m,v in successes.items()},
                                            mean_uniform_tie_success={m:probability(sum(v)/16) for m,v in tied_successes.items()}))
    lists=[]
    null=[]
    for q in (5,17):
        selected=[c for c in cases if c["q"]==q]
        for N in SIZES:
            agrees=0
            excess=0
            for case in selected:
                first=[(r["y"],r["x"]) for r in case["reference"][:N]]
                second=[(r["y"],r["x"]) for r in case["lll_box"][:N]]
                agrees+=first==second
                excess+=sum(r["squared_norm"] for r in case["lll_box"][:N])-sum(r["squared_norm"] for r in case["reference"][:N])
            lists.append(dict(q=q,N=N,matrices=16,identical_prefixes=agrees,sum_squared_norm_excess=excess))
            for source in ("reference","lll_box"):
                tails=[]
                for identifier in range(16):
                    p=lookup[f"q{q}-matrix{identifier}",source,N,"repeated","euclidean"]
                    result=mapping[p["bank_id"]]["result"]
                    tails.append(fraction(result["uniform_null"]["tails"][1]["fixed_guess_pass"]))
                normal=math.erfc(math.sqrt(N)/2)/2
                null.append(dict(q=q,N=N,source=source,matrices=16,Gaussian_tail=normal,
                                 minimum_exact_tail=probability(min(tails)),maximum_exact_tail=probability(max(tails)),
                                 mean_exact_tail=probability(sum(tails)/16),
                                 mean_tail_over_Gaussian=float(sum(tails)/16)/normal))
    return dict(matrix_metric_comparisons=comparisons,list_comparisons=lists,uniform_null_tails=null,
                matrices=len(cases),panels=len(panels),distinct_score_banks=len(banks),
                attack_costs_updated=False,profile_selected=False,j2_closed=False,
                limits=["fixed deterministic matrices and dimension-three LLL; no statistical confidence or full-size cost",
                        "bounded reduced-basis combinations are projected and deduplicated in the quotient",
                        "identical panels are cached using equality of all exact score inputs, not independent replications",
                        "all complete score tables/distributions reconstructible from inputs with stored SHA-256"])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if output==ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new output directory below NIST required")
    from verify_full_dual_toy_results import verify
    verify()
    output.mkdir(parents=True)
    tables={r["q"]:r for r in read(ROOT/"results/j2/run-013/transcendental-tables.json")}
    cases=[case_data(q,i) for q in (5,17) for i in range(16)]
    save(output/"cases.json",cases)
    panels=[]
    banks={}
    laws={}
    with (output/"banks.jsonl").open("x",encoding="utf-8",newline="\n") as stream:
        for case in cases:
            q=case["q"]
            for source in ("reference","lll_box"):
                for N in SIZES:
                    for family in ("repeated","radix"):
                        for metric in ("euclidean","cbd"):
                            bank=bank_for(case,source,N,family,metric,tables[q]["cbd_weights"])
                            key=bank_key(bank)
                            if key not in banks:
                                law_key=fingerprint([case["A"],q,bank["code"]["generators"]])
                                if law_key not in laws:
                                    laws[law_key]=lwe_law(case["A"],bank["code"]["generators"][0],q)
                                scores,delta=score_table(bank,tables[q]["cosine_weights"])
                                result=evaluate(bank,laws[law_key],scores,tables[q]["cosine_weights"])
                                record=dict(bank_id=key,bank=bank,result=pack(result),law_sha256=fingerprint(laws[law_key]),
                                            score_table_sha256=fingerprint(scores),maximum_DFT_delta=delta)
                                banks[key]=record
                                stream.write(json.dumps(record,allow_nan=False)+"\n")
                            panels.append(dict(case=case["case"],source=source,N=N,family=family,metric=metric,bank_id=key))
            stream.flush()
            print(f"{case['case']}: LLL iterations={case['reduction']['iterations']}, candidates={len(case['lll_box'])}, "
                  f"panels={len(panels)}, distinct banks={len(banks)}",flush=True)
    save(output/"panels.json",panels)
    save(output/"summary.json",summarize(cases,panels,list(banks.values())))
    inputs=["research/exact_lll.py","research/dual_expansion.py","research/test_dual_expansion.py",
            "research/verify_dual_expansion_results.py","research/verify_dual_expansion_independent.py",
            "docs/PROTOCOLE_H07.md","research/full_dual_toy.py","research/block_decoder.py","research/cbd_decoder.py",
            "research/run_block_decoder.py","results/j2/run-013/transcendental-tables.json",
            "research/verify_full_dual_toy_results.py",
            "results/j2/run-013/provenance.json","results/j2/run-013/interval-provenance.json"]
    outputs=["cases.json","banks.jsonl","panels.json","summary.json"]
    save(output/"provenance.json",dict(created_utc=datetime.now(timezone.utc).isoformat(),protocol_commit="9dfeefa",
                                      input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in inputs},
                                      output_sha256={n:hashlib.sha256((output/n).read_bytes()).hexdigest() for n in outputs}))


if __name__=="__main__":
    main()
