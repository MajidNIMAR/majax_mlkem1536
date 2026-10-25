"""Standard-library replay and provenance checks for H05 run-012."""

import hashlib
import itertools
import json
import math
from pathlib import Path

from block_decoder import make_code
from cbd_decoder import SCALE, decode_scalar, describe, summarize, validate_weights
from run_block_decoder import targets,target_hash

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/"results/j2/run-012"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def compare(a,b):
    if isinstance(a,float) or isinstance(b,float):
        if not math.isclose(a,b,abs_tol=1e-8,rel_tol=1e-10):
            raise ValueError("H05 numeric replay mismatch")
    elif isinstance(a,dict) and isinstance(b,dict):
        if set(a)!=set(b):
            raise ValueError("H05 dictionary fields mismatch")
        for key in a:
            compare(a[key],b[key])
    elif isinstance(a,list) and isinstance(b,list):
        if len(a)!=len(b):
            raise ValueError("H05 list length mismatch")
        for x,y in zip(a,b):
            compare(x,y)
    elif a!=b:
        raise ValueError("H05 exact replay mismatch")


def verify():
    for manifest in ("provenance.json","independent-provenance.json","interval-provenance.json"):
        data=read(RUN/manifest)
        for group,base in (("input_sha256",ROOT),("output_sha256",RUN)):
            for name,expected in data[group].items():
                path=(base/name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                    raise ValueError(f"H05 checksum mismatch: {name}")
    tables=read(RUN/"weight-tables.json")
    if [t["q"] for t in tables]!=[5,7,3329,7681] or any(t["scale"]!=SCALE for t in tables):
        raise ValueError("H05 weight table coverage mismatch")
    weights={t["q"]:t["weights"] for t in tables}
    for q,w in weights.items():
        validate_weights(q,w)
    study=read(RUN/"study.json")
    if study["scale"]!=SCALE or study["protocol_commit"]!="17f30d3" or any(study[k] for k in ("attack_costs_updated","profile_selected","j2_closed")):
        raise ValueError("H05 scope mismatch")
    parent=read(ROOT/"results/j2/run-010/study.json")
    old=[json.loads(s) for s in (ROOT/"results/j2/run-010/observations.jsonl").read_text().splitlines()]
    observations=[json.loads(s) for s in (RUN/"observations.jsonl").read_text().splitlines()]
    if len(observations)!=2048 or len(study["experiments"])!=8:
        raise ValueError("H05 expected 2048 paired targets")
    blocks=certified=0
    for experiment,summary in zip(parent["experiments"],study["experiments"]):
        definition=experiment["code"]
        code=make_code(definition["q"],definition["n"],definition["k"],definition["family"])
        q,eta=code.q,2 if code.q==3329 else 3
        actual=[r for r in observations if r["experiment"]==experiment["experiment"]]
        prior=[r for r in old if r["experiment"]==experiment["experiment"]]
        points=targets(q,code.n,256,experiment["seed_ascii"].encode("ascii"))
        if len(actual)!=256 or [r["index"] for r in actual]!=list(range(256)):
            raise ValueError("H05 target indexing mismatch")
        for target,row,source in zip(points,actual,prior):
            if row["target_sha256"]!=target_hash(target) or row["euclidean"]["labels"]!=source["labels"] or row["euclidean"]["squared_norm"]!=source["squared_norm"]:
                raise ValueError("H05 baseline changed")
            for metric in ("euclidean","cbd"):
                value=row[metric]
                replay=describe(code,target,dict(labels=value["labels"],certificates=value["certificates"]),weights[q],eta)
                compare(replay,value)
            if row["euclidean"]["certificates"] or len(row["cbd"]["certificates"])!=code.k:
                raise ValueError("H05 certificate shape mismatch")
            word=code.encode(row["cbd"]["labels"])
            offset=0
            for generator,proof in zip(code.generators,row["cbd"]["certificates"]):
                count=len(generator)
                cost=sum(weights[q][min(abs(x-y),q-abs(x-y))] for x,y in zip(target[offset:offset+count],word[offset:offset+count]))
                if cost!=proof["integer_cost"] or proof["second_symbol_integer_gap"]<0 or not 1<=proof["interval_contenders"]<=q:
                    raise ValueError("H05 certificate selected cost mismatch")
                if proof["second_symbol_integer_gap"]>=count and not proof["real_optimum_certified"]:
                    raise ValueError("H05 separated interval not certified")
                offset+=count
                blocks+=1
                certified+=proof["real_optimum_certified"]
            if row["cbd"]["integer_cost"]>row["euclidean"]["integer_cost"]:
                raise ValueError("H05 integer objective increased")
        expected=dict(experiment=experiment["experiment"],code=code.record(),candidates_per_decode=q*code.k,
                      coordinate_terms_per_decode=q*code.n,**summarize(actual,q,eta,code.n))
        compare(expected,summary)
    toys=read(RUN/"toy-comparison.json")
    total=0
    for toy in toys:
        definition=toy["code"]
        code=make_code(definition["q"],definition["n"],definition["k"],definition["family"])
        q=code.q
        if len(toy["observations"])!=q**code.n:
            raise ValueError("H05 incomplete toy")
        for target,row in zip(itertools.product(range(q),repeat=code.n),toy["observations"]):
            for metric in ("euclidean","cbd"):
                compare(describe(code,target,decode_scalar(code,target,weights[q],metric),weights[q],1),row[metric])
            total+=1
        compare(summarize(toy["observations"],q,1,code.n),toy["summary"])
    intervals=read(RUN/"interval-verification.json")
    if not intervals["all_passed"] or intervals["decimal_digits"]!=160 or intervals["weights_verified"]!=sum(len(t["weights"]) for t in tables):
        raise ValueError("H05 independent intervals missing")
    independent=read(RUN/"independent-verification.json")
    if not independent["all_matched"] or independent["classified_targets"]!=6302 or independent["actual_modulus_blocks"]!=64:
        raise ValueError("H05 independent oracle missing")
    timings=read(RUN/"timings.json")["measurements"]
    if len(timings)!=8:
        raise ValueError("H05 timing coverage mismatch")
    for timing in timings:
        if timing["batch_size"]!=8:
            raise ValueError("H05 timing batch mismatch")
        for metric,values in timing["batches_ns"].items():
            if metric not in ("euclidean","cbd") or len(values)!=7 or min(values)<=0 or timing["median_ns_per_decode"][metric]!=sorted(values)[3]/8:
                raise ValueError("H05 timing summary mismatch")
    if len(toys)!=6 or total!=6302:
        raise ValueError("H05 toy coverage mismatch")
    return dict(snapshot="run-012",paired_targets=2048,toy_targets=total,weight_intervals=intervals["weights_verified"],
                decoded_blocks=blocks,real_optimum_certified_blocks=certified,independent_actual_blocks=64,
                attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=="__main__":
    print(json.dumps(verify(),indent=2))
