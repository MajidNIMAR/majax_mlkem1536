"""Execute preregistered H08, exact laws for CBD1/2/3 and dimensions 3/5."""

import argparse
from datetime import datetime,timezone
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform

from higher_cbd import SIZES,array_hash,case_data,evaluate,fingerprint,law,make_bank,numpy,score_data
from full_dual_toy import probability

ROOT=Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path,value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,indent=2,allow_nan=False)
        stream.write("\n")


def as_fraction(p):
    return Fraction(p["numerator"],p["denominator"])


def summarize(cases,panels,banks):
    by_bank={b["bank_id"]:b for b in banks}
    lookup={(p["case"],p["source"],p["N"],p["family"],p["metric"],p["eta"]):p for p in panels}
    comparisons=[]
    null=[]
    agreement=[]
    for dimension in (3,5):
        selected=[c for c in cases if c["dimension"]==dimension]
        for N in SIZES:
            same=sum([(v["y"],v["x"]) for v in c["reference"][:N]]==[(v["y"],v["x"]) for v in c["lll_box"][:N]] for c in selected)
            agreement.append(dict(dimension=dimension,N=N,matrices=8,identical_prefixes=same,
                                  squared_norm_excess=sum(sum(v["squared_norm"] for v in c["lll_box"][:N])-sum(v["squared_norm"] for v in c["reference"][:N]) for c in selected)))
        for source in ("reference","lll_box"):
            for N in SIZES:
                for family in ("repeated","radix"):
                    for eta in (1,2,3):
                        strict={m:[] for m in ("euclidean","cbd")}
                        ties={m:[] for m in strict}
                        wins=losses=equal=paradoxes=0
                        for c in selected:
                            results={m:by_bank[lookup[c["case"],source,N,family,m,eta]["bank_id"]]["results"][str(eta)] for m in strict}
                            for m,r in results.items():
                                strict[m].append(as_fraction(r["strict_success"]))
                                ties[m].append(as_fraction(r["uniform_tie_success"]))
                            delta=strict["cbd"][-1]-strict["euclidean"][-1]
                            wins+=delta>0
                            losses+=delta<0
                            equal+=delta==0
                            mean_delta=results["cbd"]["offset_moments"][0]["mean"]-results["euclidean"]["offset_moments"][0]["mean"]
                            paradoxes+=mean_delta>1e-12 and delta<0
                        comparisons.append(dict(dimension=dimension,source=source,N=N,family=family,eta=eta,matrices=8,
                                                CBD_wins=wins,CBD_losses=losses,identical_successes=equal,
                                                mean_improves_ranking_degrades=paradoxes,
                                                mean_strict_success={m:probability(sum(v)/8) for m,v in strict.items()},
                                                mean_uniform_tie_success={m:probability(sum(v)/8) for m,v in ties.items()}))
                vals=[]
                for c in selected:
                    b=by_bank[lookup[c["case"],source,N,"repeated","euclidean",1]["bank_id"]]
                    vals.append(as_fraction(b["results"]["1"]["uniform_null"]["tails"][1]["fixed_guess_pass"]))
                normal=b["results"]["1"]["uniform_null"]["tails"][1]["Gaussian_fixed_guess_tail"]
                null.append(dict(dimension=dimension,source=source,N=N,mean_exact_tail=probability(sum(vals)/8),
                                 Gaussian_tail=normal,mean_tail_over_Gaussian=float(sum(vals)/8)/normal))
    return dict(matrices=16,panels=len(panels),distinct_score_banks=len(banks),law_groups=96,
                comparisons=comparisons,list_comparisons=agreement,uniform_null_tails=null,
                attack_costs_updated=False,profile_selected=False,j2_closed=False,
                limits=["q=17 and dimensions 3/5; no real-parameter cost, BKZ, MLWE rotations or CCA result",
                        "finite exact group convolutions, not literal enumeration of up to 2^54 bit strings",
                        "NumPy integer masses checked below 2^63; moments and DFT comparisons are numerical",
                        "fixed matrices and repeated banks do not give independent replications or confidence intervals"])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if output==ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new output directory below NIST required")
    np=numpy()
    from verify_dual_expansion_results import verify
    verify()
    output.mkdir(parents=True)
    table=next(t for t in read(ROOT/"results/j2/run-013/transcendental-tables.json") if t["q"]==17)
    old_banks={r['bank_id']:r for r in (json.loads(s) for s in (ROOT/'results/j2/run-014/banks.jsonl').read_text().splitlines())}
    old_panels={(p['case'],p['source'],p['N'],p['family'],p['metric']):p for p in read(ROOT/'results/j2/run-014/panels.json')}
    cases=[case_data(m,l,i) for m,l in ((2,1),(3,2)) for i in range(8)]
    save(output/"cases.json",cases)
    banks={}
    panels=[]
    laws={}
    law_records=[]
    with (output/"banks.jsonl").open("x",encoding="utf-8",newline="\n") as stream:
        for case in cases:
            for source in ("reference","lll_box"):
                for N in SIZES:
                    for family in ("repeated","radix"):
                        for metric in ("euclidean","cbd"):
                            bank=make_bank(case,source,N,family,metric,table["cbd_weights"])
                            key=fingerprint(bank)
                            if key not in banks:
                                data=score_data(bank,table["cosine_weights"])
                                results={}
                                for eta in (1,2,3):
                                    law_key=(case["case"],tuple(bank["g"]),eta)
                                    if law_key not in laws:
                                        weights=law(case["A"],bank["g"],eta)
                                        laws[law_key]=weights
                                        law_records.append(dict(case=case["case"],g=bank["g"],eta=eta,shape=list(weights.shape),
                                                                denominator=1<<(2*eta*(case["m"]+case["l"]+4)),sha256=array_hash(weights)))
                                    results[str(eta)]=evaluate(bank,laws[law_key],data,eta)
                                record=dict(bank_id=key,bank=bank,score_hashes=data["hashes"],maximum_DFT_delta=data["DFT_delta"],results=results)
                                banks[key]=record
                                stream.write(json.dumps(record,allow_nan=False)+"\n")
                            for eta in (1,2,3):
                                panels.append(dict(case=case["case"],source=source,N=N,family=family,metric=metric,eta=eta,bank_id=key))
                            if case['dimension']==3:
                                previous=old_panels[f"q17-matrix{case['identifier']}",source,N,family,metric]
                                old=old_banks[previous['bank_id']]['result']
                                new=banks[key]['results']['1']
                                for name in ('strict_success','true_in_argmax','uniform_tie_success'):
                                    if as_fraction(old[name])!=as_fraction(new[name]):
                                        raise ArithmeticError('H07 CBD1 calibration disagrees')
                                for a,b in zip(old['tails'],new['tails']):
                                    for name in ('true_pass','any_false_pass'):
                                        if as_fraction(a[name])!=as_fraction(b[name]):
                                            raise ArithmeticError('H07 exact tail calibration disagrees')
            stream.flush()
            print(f"{case['case']}: LLL d={case['dimension']}, candidates={len(case['lll_box'])}, panels={len(panels)}, banks={len(banks)}",flush=True)
    save(output/"laws.json",law_records)
    save(output/"panels.json",panels)
    summary=summarize(cases,panels,list(banks.values()))
    summary['control_CBD1_calibrations']=192
    save(output/"summary.json",summary)
    inputs=["research/lll_dimensions.py","research/higher_cbd.py","research/run_higher_cbd.py",
            "research/test_higher_cbd.py","research/verify_higher_cbd_results.py","research/verify_higher_cbd_independent.py",
            "research/requirements-cbd-dimensions.txt","docs/PROTOCOLE_H08.md","research/exact_lll.py",
            "research/block_decoder.py","research/cbd_decoder.py","research/full_dual_toy.py","research/run_block_decoder.py",
            "research/verify_full_dual_toy_results.py","results/j2/run-013/transcendental-tables.json",
            "results/j2/run-013/interval-provenance.json","results/j2/run-014/provenance.json","results/j2/run-014/summary.json"]
    inputs += ["results/j2/run-014/banks.jsonl","results/j2/run-014/panels.json"]
    outputs=["cases.json","laws.json","panels.json","banks.jsonl","summary.json"]
    save(output/"provenance.json",dict(created_utc=datetime.now(timezone.utc).isoformat(),protocol_commit="128c463",
                                      python=platform.python_version(),numpy=np.__version__,
                                      input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in inputs},
                                      output_sha256={n:hashlib.sha256((output/n).read_bytes()).hexdigest() for n in outputs}))


if __name__=="__main__":
    main()
